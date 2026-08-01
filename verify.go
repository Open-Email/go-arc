package arc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
)

// VerifyResult reports the outcome of ARC chain validation.
type VerifyResult struct {
	Pass           bool     // chain validated (or no chain present)
	ChainValid     bool     // the ARC chain is intact and cryptographically valid
	Instance       int      // highest ARC instance number (0 = no ARC headers)
	FailureReasons []string // why validation failed, empty on success
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// LookupTXT resolves public keys. Defaults to DefaultLookupTXT.
	LookupTXT LookupTXT
	// Logger receives debug output. Defaults to a discard logger.
	Logger *slog.Logger
}

// arcSet is the three ARC headers sharing one instance number.
type arcSet struct {
	instance int
	aar      rawHeader
	ams      rawHeader
	seal     rawHeader
	hasAAR   bool
	hasAMS   bool
	hasSeal  bool
}

// Verify validates the ARC chain of a message per RFC 8617 §5.2.
//
// A message with no ARC headers passes (there is nothing to validate).
// A message with ARC headers passes only if every instance from 1 to N
// is complete, every cv= value is semantically correct (none at i=1,
// pass above), and every ARC-Message-Signature and ARC-Seal verifies
// cryptographically.
func Verify(rawMessage []byte, opts *VerifyOptions) (*VerifyResult, error) {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	lookup := opts.LookupTXT
	if lookup == nil {
		lookup = DefaultLookupTXT
	}

	raw := string(rawMessage)
	headers, _ := splitMessage(raw)
	sets, maxInstance, problems := extractARCSets(headers)

	if maxInstance == 0 && len(sets) == 0 && len(problems) == 0 {
		logger.Debug("no ARC headers found")
		return &VerifyResult{Pass: true, ChainValid: true, Instance: 0}, nil
	}

	result := &VerifyResult{Instance: maxInstance, FailureReasons: problems}
	if maxInstance > MaxChainLength {
		result.FailureReasons = append(result.FailureReasons,
			fmt.Sprintf("ARC instance %d exceeds the RFC 8617 limit of %d", maxInstance, MaxChainLength))
	}
	if len(result.FailureReasons) > 0 {
		return result, nil
	}

	valid, reasons := validateChain(raw, headers, sets, maxInstance, lookup, logger)
	result.ChainValid = valid
	result.Pass = valid
	result.FailureReasons = append(result.FailureReasons, reasons...)

	logger.Debug("ARC validation result",
		"instance", result.Instance, "pass", result.Pass, "reasons", result.FailureReasons)
	return result, nil
}

// extractARCSets organizes ARC headers by instance. Structural
// violations (missing/invalid i=, duplicate headers within an instance)
// are reported as problems; RFC 8617 §4.2.1 makes any of them fatal to
// the chain.
func extractARCSets(headers []rawHeader) (map[int]*arcSet, int, []string) {
	sets := make(map[int]*arcSet)
	maxInstance := 0
	var problems []string

	get := func(instance int) *arcSet {
		if sets[instance] == nil {
			sets[instance] = &arcSet{instance: instance}
		}
		if instance > maxInstance {
			maxInstance = instance
		}
		return sets[instance]
	}

	for _, h := range headers {
		var kind string
		switch {
		case strings.EqualFold(h.key, "ARC-Authentication-Results"):
			kind = "aar"
		case strings.EqualFold(h.key, "ARC-Message-Signature"):
			kind = "ams"
		case strings.EqualFold(h.key, "ARC-Seal"):
			kind = "seal"
		default:
			continue
		}
		if h.instance <= 0 {
			problems = append(problems, fmt.Sprintf("%s header with missing or invalid i= tag", h.key))
			continue
		}
		set := get(h.instance)
		switch kind {
		case "aar":
			if set.hasAAR {
				problems = append(problems, fmt.Sprintf("duplicate ARC-Authentication-Results at instance %d", h.instance))
			}
			set.aar, set.hasAAR = h, true
		case "ams":
			if set.hasAMS {
				problems = append(problems, fmt.Sprintf("duplicate ARC-Message-Signature at instance %d", h.instance))
			}
			set.ams, set.hasAMS = h, true
		case "seal":
			if set.hasSeal {
				problems = append(problems, fmt.Sprintf("duplicate ARC-Seal at instance %d", h.instance))
			}
			set.seal, set.hasSeal = h, true
		}
	}
	return sets, maxInstance, problems
}

// validateChain checks completeness, cv= semantics, then every AMS and
// AS signature from oldest to newest.
func validateChain(raw string, headers []rawHeader, sets map[int]*arcSet, maxInstance int, lookup LookupTXT, logger *slog.Logger) (bool, []string) {
	// Completeness: every instance 1..N with all three headers.
	for i := 1; i <= maxInstance; i++ {
		set := sets[i]
		if set == nil {
			return false, []string{fmt.Sprintf("missing ARC set for instance %d", i)}
		}
		if !set.hasAAR || !set.hasAMS || !set.hasSeal {
			return false, []string{fmt.Sprintf("incomplete ARC set at instance %d", i)}
		}
	}

	// cv= semantics (RFC 8617 §5.2): the first seal must claim none,
	// every later seal must claim pass; a cv=fail anywhere kills the
	// chain without any cryptography.
	for i := 1; i <= maxInstance; i++ {
		cv := ChainStatus(parseTags(sets[i].seal.value)["cv"])
		switch {
		case i == 1 && cv != ChainNone:
			return false, []string{fmt.Sprintf("ARC-Seal at instance 1 must have cv=none, found %q", cv)}
		case i > 1 && cv == ChainFail:
			return false, []string{fmt.Sprintf("ARC-Seal at instance %d declares cv=fail", i)}
		case i > 1 && cv != ChainPass:
			return false, []string{fmt.Sprintf("ARC-Seal at instance %d must have cv=pass, found %q", i, cv)}
		}
	}

	_, body := splitMessage(raw)
	for i := 1; i <= maxInstance; i++ {
		if err := verifyMessageSignature(headers, body, i, lookup); err != nil {
			reason := fmt.Sprintf("ARC-Message-Signature verification failed at instance %d: %v", i, err)
			logger.Debug(reason)
			return false, []string{reason}
		}
	}
	for i := 1; i <= maxInstance; i++ {
		if err := verifySeal(headers, i, lookup); err != nil {
			reason := fmt.Sprintf("ARC-Seal verification failed at instance %d: %v", i, err)
			logger.Debug(reason)
			return false, []string{reason}
		}
	}

	logger.Debug("ARC chain validated", "max_instance", maxInstance)
	return true, nil
}

// verifyMessageSignature verifies the AMS of one instance against the
// message as it existed at that hop (ARC headers of this and later
// instances removed).
func verifyMessageSignature(headers []rawHeader, body string, instance int, lookup LookupTXT) error {
	sig, ok := findARCHeader(headers, "ARC-Message-Signature", instance)
	if !ok {
		return fmt.Errorf("header not found")
	}
	var recHeaders []rawHeader
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h.key), "arc-") && h.instance >= instance {
			continue
		}
		recHeaders = append(recHeaders, h)
	}
	return verifySignature("ARC-Message-Signature", sig, recHeaders, body, lookup)
}

// verifySeal verifies the AS of one instance over the ARC headers of
// instances 1..i (excluding instance i's own seal), in RFC 8617 §5.1.2
// order.
func verifySeal(headers []rawHeader, instance int, lookup LookupTXT) error {
	sig, ok := findARCHeader(headers, "ARC-Seal", instance)
	if !ok {
		return fmt.Errorf("header not found")
	}
	sealed := arcHeadersUpTo(headers, instance)
	return verifySignature("ARC-Seal", sig, sealed, "", lookup)
}

func findARCHeader(headers []rawHeader, name string, instance int) (rawHeader, bool) {
	for _, h := range headers {
		if strings.EqualFold(h.key, name) && h.instance == instance {
			return h, true
		}
	}
	return rawHeader{}, false
}

// arcHeadersUpTo returns the ARC headers of instances 1..maxInstance —
// excluding the current instance's ARC-Seal, which cannot sign itself —
// ordered by increasing instance and AAR, AMS, AS within each instance
// (RFC 8617 §5.1.2).
func arcHeadersUpTo(headers []rawHeader, maxInstance int) []rawHeader {
	var out []rawHeader
	for _, h := range headers {
		if !strings.HasPrefix(strings.ToLower(h.key), "arc-") {
			continue
		}
		if h.instance <= 0 || h.instance > maxInstance {
			continue
		}
		if h.instance == maxInstance && strings.EqualFold(h.key, "ARC-Seal") {
			continue
		}
		out = append(out, h)
	}
	typeOrder := func(key string) int {
		switch {
		case strings.EqualFold(key, "ARC-Authentication-Results"):
			return 1
		case strings.EqualFold(key, "ARC-Message-Signature"):
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].instance != out[j].instance {
			return out[i].instance < out[j].instance
		}
		return typeOrder(out[i].key) < typeOrder(out[j].key)
	})
	return out
}

// verifySignature verifies one ARC signature header (AMS or AS) over
// the given headers (and body, for AMS).
func verifySignature(headerName string, sig rawHeader, headers []rawHeader, body string, lookup LookupTXT) error {
	tags := parseTags(sig.value)

	if a := tags["a"]; a != "rsa-sha256" {
		return fmt.Errorf("unsupported algorithm %q", a)
	}
	domain, selector := tags["d"], tags["s"]
	if domain == "" || selector == "" {
		return fmt.Errorf("missing d= or s= tag")
	}

	headerCanon, bodyCanon := parseCanonicalization(tags["c"])
	if headerName == "ARC-Seal" {
		// The seal has no c= tag; RFC 8617 fixes it to relaxed.
		headerCanon, bodyCanon = canonRelaxed, canonRelaxed
	}

	// Body hash — AMS only; the seal covers headers alone.
	if headerName == "ARC-Message-Signature" {
		bh := tags["bh"]
		if bh == "" {
			return fmt.Errorf("missing bh= tag")
		}
		want, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(bh), ""))
		if err != nil {
			return fmt.Errorf("invalid base64 body hash: %w", err)
		}
		got := sha256.Sum256(canonicalizeBody(body, bodyCanon))
		if string(got[:]) != string(want) {
			return fmt.Errorf("body hash mismatch")
		}
	}

	headersToSign, err := selectHeaders(headerName, tags["h"], headers)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	for _, h := range headersToSign {
		hasher.Write([]byte(canonicalizeHeaderRaw(h.raw, headerCanon)))
	}
	// The signature header itself, b= value emptied, no trailing CRLF
	// (RFC 6376 §3.7).
	selfCanon := canonicalizeHeaderRaw(removeSignatureValue(sig.raw), headerCanon)
	hasher.Write([]byte(strings.TrimRight(selfCanon, "\r\n")))
	hashed := hasher.Sum(nil)

	b := tags["b"]
	if b == "" {
		return fmt.Errorf("missing b= tag")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b), ""))
	if err != nil {
		return fmt.Errorf("invalid base64 signature: %w", err)
	}

	if lookup == nil {
		return fmt.Errorf("no DNS resolver provided")
	}
	txts, err := lookup(selector + "._domainkey." + domain)
	if err != nil {
		return fmt.Errorf("public key lookup failed: %w", err)
	}
	var record string
	for _, txt := range txts {
		if strings.Contains(txt, "p=") {
			record = txt
			break
		}
	}
	if record == "" && len(txts) > 0 {
		record = txts[0]
	}
	pub, err := parsePublicKey(record)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// selectHeaders picks the headers a signature covers. The seal's set is
// supplied by the caller (RFC 8617 fixes it); the AMS follows its h=
// tag, matching duplicates bottom-up per RFC 6376 §5.4.2 and skipping
// names with no remaining occurrence.
func selectHeaders(headerName, hTag string, headers []rawHeader) ([]rawHeader, error) {
	if headerName == "ARC-Seal" {
		return headers, nil
	}
	if hTag == "" {
		return nil, fmt.Errorf("missing h= tag")
	}
	var out []rawHeader
	used := make(map[int]bool)
	for _, name := range strings.Split(hTag, ":") {
		name = strings.ToLower(strings.TrimSpace(name))
		for i := len(headers) - 1; i >= 0; i-- {
			if used[i] || !strings.EqualFold(headers[i].key, name) {
				continue
			}
			out = append(out, headers[i])
			used[i] = true
			break
		}
	}
	return out, nil
}

// FindAuthenticationResults returns the value of the topmost
// Authentication-Results header whose authserv-id matches authservID
// (case-insensitive), unfolded. This is the input a forwarding sealer
// needs: the authentication results stamped by its own ADMD's receiving
// edge.
func FindAuthenticationResults(rawMessage []byte, authservID string) (string, bool) {
	headers, _ := splitMessage(string(rawMessage))
	for _, h := range headers {
		if !strings.EqualFold(h.key, "Authentication-Results") {
			continue
		}
		value := strings.Join(strings.Fields(h.value), " ")
		id := value
		if i := strings.IndexByte(id, ';'); i >= 0 {
			id = id[:i]
		}
		// The authserv-id may carry an optional version token.
		fields := strings.Fields(strings.TrimSpace(id))
		if len(fields) > 0 && strings.EqualFold(fields[0], authservID) {
			return value, true
		}
	}
	return "", false
}

// LatestARCAuthResults returns the instance number and payload
// (authserv-id and results, the i= tag stripped) of the newest
// ARC-Authentication-Results header, if any.
func LatestARCAuthResults(rawMessage []byte) (int, string, bool) {
	headers, _ := splitMessage(string(rawMessage))
	sets, maxInstance, _ := extractARCSets(headers)
	if maxInstance == 0 || sets[maxInstance] == nil || !sets[maxInstance].hasAAR {
		return 0, "", false
	}
	value := strings.Join(strings.Fields(sets[maxInstance].aar.value), " ")
	if rest, ok := strings.CutPrefix(value, "i="); ok {
		if i := strings.IndexByte(rest, ';'); i >= 0 {
			return maxInstance, strings.TrimSpace(rest[i+1:]), true
		}
	}
	return maxInstance, value, true
}
