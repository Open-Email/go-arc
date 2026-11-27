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
	"unicode/utf8"
)

// VerifyResult reports the outcome of ARC chain validation.
type VerifyResult struct {
	Pass           bool     // chain validated (or no chain present)
	ChainValid     bool     // the ARC chain is intact and cryptographically valid
	Instance       int      // highest ARC instance number (0 = no ARC headers)
	FailureReasons []string // why validation failed, empty on success

	// Instances reports what each ARC set in the chain actually says,
	// ordered OLDEST FIRST (i=1 .. i=N). It is populated whenever ARC
	// headers were found — a failing chain included, so a caller can log
	// who sealed a chain it just rejected.
	//
	// It exists because Pass alone cannot support a trust decision.
	// RFC 8617 5.2 verifies only the NEWEST ARC-Message-Signature, so a
	// chain can validate while an attacker holds the newest set: they take
	// a genuinely sealed message, replace the body, and add their own set
	// with cv=pass. A caller that wants to act on a chain's contents must
	// therefore see EVERY sealer, not just that it passed.
	Instances []InstanceResult
}

// InstanceResult is what one ARC set claims: who sealed it, who signed the
// message at that hop, the chain status it declared, and the authentication
// results it recorded.
type InstanceResult struct {
	// Instance is the i= tag shared by the set's three headers.
	Instance int
	// Sealer is the ARC-Seal d= — the ADMD that vouched for the chain at
	// this hop, and the identity whose key verified the seal.
	Sealer string
	// Signer is the ARC-Message-Signature d=. Normally equal to Sealer;
	// RFC 8617 does not require it, so both are reported.
	Signer string
	// ChainStatus is the seal's cv=. RFC 8617 §3.9 makes none, pass and
	// fail case-insensitive, so those are reported in lowercase, as
	// ChainNone, ChainPass and ChainFail; any other value is reported
	// exactly as found. Verify has already rejected the chain if it is not
	// none at i=1 and pass above, so on a passing result this carries no new
	// information. It is here for the failing ones.
	ChainStatus ChainStatus
	// AuthResults is the ARC-Authentication-Results payload with the i=
	// tag stripped and folds removed: the authserv-id followed by the
	// results that hop observed, e.g.
	// "mx.example.com; spf=pass smtp.mailfrom=a@b; dmarc=pass header.from=b".
	// It is an unverified CLAIM by Sealer, meaningful only to a caller that
	// trusts that domain.
	AuthResults string
}

// OldestInstance returns the i=1 ARC set: the hop that received the message
// from its ORIGINATOR and is therefore the only one whose authentication
// results describe the original sender rather than a previous forwarder.
//
// This is the set a DMARC override must read (RFC 8617 7.2.1). Every later
// AAR reports what that hop saw AFTER the message had already been forwarded
// — typically a broken DKIM signature and an SPF pass for the forwarder — so
// reading the newest one answers a different question than the one being
// asked.
func (r *VerifyResult) OldestInstance() (InstanceResult, bool) {
	if r == nil {
		return InstanceResult{}, false
	}
	for _, inst := range r.Instances {
		if inst.Instance == 1 {
			return inst, true
		}
	}
	return InstanceResult{}, false
}

// OldestAuthResults returns the i=1 ARC-Authentication-Results payload, the
// i= tag stripped. See OldestInstance for why it is the oldest and not the
// newest, and LatestARCAuthResults for the counterpart that is NOT usable for
// a trust decision.
func (r *VerifyResult) OldestAuthResults() (string, bool) {
	inst, ok := r.OldestInstance()
	if !ok || inst.AuthResults == "" {
		return "", false
	}
	return inst.AuthResults, true
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
// A message with no ARC headers passes if the complete header block was scanned.
// A message with ARC headers passes only if its header block is well
// formed (parseMessage: a line that mail readers may read differently
// fails the chain), every instance from 1 to N is complete, every cv=
// value is semantically correct (none at i=1, pass above), the newest
// (i=N) ARC-Message-Signature verifies cryptographically, and every
// ARC-Seal from 1 to N verifies cryptographically.
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

	headers, body, defect := parseMessage(string(rawMessage))
	sets, maxInstance, problems := extractARCSets(headers)

	if defect != errHeaderFieldLimit && maxInstance == 0 && len(sets) == 0 && len(problems) == 0 {
		logger.Debug("no ARC headers found")
		return &VerifyResult{Pass: true, ChainValid: true, Instance: 0}, nil
	}

	result := &VerifyResult{
		Instance:       maxInstance,
		FailureReasons: problems,
	}
	if maxInstance > MaxChainLength || len(sets) > MaxChainLength {
		result.FailureReasons = append(result.FailureReasons,
			fmt.Sprintf("ARC instance %d exceeds the RFC 8617 limit of %d", maxInstance, MaxChainLength))
		return result, nil
	}
	result.Instances = collectInstances(sets, maxInstance)
	if defect != nil {
		result.FailureReasons = append(result.FailureReasons, "malformed header block: "+defect.Error())
	}
	if len(result.FailureReasons) > 0 {
		return result, nil
	}

	valid, reasons := validateChain(headers, body, sets, maxInstance, lookup, logger)
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
		case asciiEqualFold(h.key, "ARC-Authentication-Results"):
			kind = "aar"
		case asciiEqualFold(h.key, "ARC-Message-Signature"):
			kind = "ams"
		case asciiEqualFold(h.key, "ARC-Seal"):
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

// RFC 8617 §3.9 uses case-insensitive ABNF literals for chain-status.
// Keep an unrecognized value intact for the failure report.
func parsedChainStatus(value string) ChainStatus {
	for _, status := range [...]ChainStatus{ChainNone, ChainPass, ChainFail} {
		if asciiEqualFold(value, string(status)) {
			return status
		}
	}
	return ChainStatus(value)
}

// collectInstances flattens the extracted sets into the per-instance report,
// oldest first. It reads the headers only — no cryptography — so it describes
// a failing chain as readily as a passing one; whether any of it may be
// BELIEVED is decided by Pass and by the caller's trust in each Sealer.
//
// A gap in the chain (an instance with no set) is skipped rather than filled
// with a zero entry: validateChain has already made the gap fatal, and an
// entry claiming instance N with an empty sealer would be a claim nobody made.
func collectInstances(sets map[int]*arcSet, maxInstance int) []InstanceResult {
	if maxInstance <= 0 || maxInstance > MaxChainLength {
		return nil
	}
	out := make([]InstanceResult, 0, len(sets))
	for i := 1; i <= maxInstance; i++ {
		set := sets[i]
		if set == nil {
			continue
		}
		inst := InstanceResult{Instance: i}
		if set.hasSeal {
			tags, _ := parseTagList(set.seal.value, true)
			inst.Sealer = tags["d"]
			inst.ChainStatus = parsedChainStatus(tags["cv"])
		}
		if set.hasAMS {
			inst.Signer = parseTags(set.ams.value)["d"]
		}
		if set.hasAAR {
			inst.AuthResults = authResultsPayload(set.aar.value)
		}
		out = append(out, inst)
	}
	return out
}

// validateChain checks completeness, cv= semantics, the newest AMS
// (RFC 8617 §5.2 Step 2), and every AS signature from oldest to newest
// (RFC 8617 §5.2 Step 3).
func validateChain(headers []rawHeader, body string, sets map[int]*arcSet, maxInstance int, lookup LookupTXT, logger *slog.Logger) (bool, []string) {
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
		tags, err := parseTagList(sets[i].seal.value, true)
		if err != nil {
			return false, []string{fmt.Sprintf("ARC-Seal at instance %d: %v", i, err)}
		}
		cv := parsedChainStatus(tags["cv"])
		switch {
		case i == 1 && cv != ChainNone:
			return false, []string{fmt.Sprintf("ARC-Seal at instance 1 must have cv=none, found %q", cv)}
		case i > 1 && cv == ChainFail:
			return false, []string{fmt.Sprintf("ARC-Seal at instance %d declares cv=fail", i)}
		case i > 1 && cv != ChainPass:
			return false, []string{fmt.Sprintf("ARC-Seal at instance %d must have cv=pass, found %q", i, cv)}
		}
	}

	if err := verifyMessageSignature(headers, body, maxInstance, lookup); err != nil {
		reason := fmt.Sprintf("ARC-Message-Signature verification failed at instance %d: %v", maxInstance, err)
		logger.Debug(reason)
		return false, []string{reason}
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
		if isARCHeader(h.key) && h.instance >= instance {
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
		if asciiEqualFold(h.key, name) && h.instance == instance {
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
		if !isARCHeader(h.key) {
			continue
		}
		if h.instance <= 0 || h.instance > maxInstance {
			continue
		}
		if h.instance == maxInstance && asciiEqualFold(h.key, "ARC-Seal") {
			continue
		}
		out = append(out, h)
	}
	typeOrder := func(key string) int {
		switch {
		case asciiEqualFold(key, "ARC-Authentication-Results"):
			return 1
		case asciiEqualFold(key, "ARC-Message-Signature"):
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
	tags, err := parseTagList(sig.value, headerName == "ARC-Seal")
	if err != nil {
		return err
	}
	if _, has := tags["h"]; has && headerName == "ARC-Seal" {
		// RFC 8617 §4.1.3: the h tag is not allowed in a seal, and one
		// that carries it must fail.
		return fmt.Errorf("ARC-Seal carries an h= tag")
	}

	if a := tags["a"]; a != "rsa-sha256" {
		return fmt.Errorf("unsupported algorithm %q", a)
	}
	domain, selector := tags["d"], tags["s"]
	if domain == "" || selector == "" {
		return fmt.Errorf("missing d= or s= tag")
	}
	if domain, selector, err = verifyKeyDNSNames(domain, selector); err != nil {
		return err
	}

	// RFC 8617 §4.1.3 fixes the seal to relaxed header canonicalization.
	// c= is not one of its tags, so one found there is ignored like any
	// unknown tag (RFC 6376 §3.2).
	headerCanon, bodyCanon := canonRelaxed, canonRelaxed
	if headerName != "ARC-Seal" {
		if headerCanon, bodyCanon, err = parseCanonicalization(tags["c"]); err != nil {
			return err
		}
	}

	// Body hash — AMS only; the seal covers headers alone.
	if headerName == "ARC-Message-Signature" {
		bh := tags["bh"]
		if bh == "" {
			return fmt.Errorf("missing bh= tag")
		}
		want, err := base64.StdEncoding.DecodeString(stripFWS(bh))
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
	hasher.Write([]byte(trimLineBreak(selfCanon)))
	hashed := hasher.Sum(nil)

	b := tags["b"]
	if b == "" {
		return fmt.Errorf("missing b= tag")
	}
	signature, err := base64.StdEncoding.DecodeString(stripFWS(b))
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

// maxSignedEntries bounds the h= list of one signature. Signers list a few
// dozen names, twice over when they oversign.
const maxSignedEntries = 1000

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
	// Index the fields by name once, top to bottom, so each h= entry takes
	// the bottom-most one left in constant time. Searching the whole block
	// per entry was quadratic in a message built for it.
	byName := make(map[string][]int)
	for i, h := range headers {
		if h.key != "" {
			name := asciiLower(h.key)
			byName[name] = append(byName[name], i)
		}
	}
	var out []rawHeader
	hasFrom := false
	entries := 0
	for more := true; more; {
		var name string
		name, hTag, more = strings.Cut(hTag, ":")
		if entries++; entries > maxSignedEntries {
			return nil, fmt.Errorf("h= tag lists more than %d fields", maxSignedEntries)
		}
		name = asciiLower(trimFWS(name))
		if name == "from" {
			hasFrom = true
		}
		// An empty entry names no field, and a name with none left selects
		// nothing (RFC 6376 §5.4.2).
		if left := byName[name]; name != "" && len(left) > 0 {
			out = append(out, headers[left[len(left)-1]])
			byName[name] = left[:len(left)-1]
		}
	}
	if !hasFrom {
		return nil, fmt.Errorf("ARC-Message-Signature h= tag must include From")
	}
	return out, nil
}

// verifyKeyDNSNames returns the DNS names to look a signer's key up under.
// U-labels are converted to A-labels (RFC 8616 §4). An ASCII name is used
// as written, as other verifiers do, as long as DNS can hold it: Sign's
// stricter host-name grammar would fail seals made by others with names
// such as "mail_relay.example" or "localhost".
func verifyKeyDNSNames(domain, selector string) (string, string, error) {
	if hasNonASCII(domain) || hasNonASCII(selector) {
		d, s, err := keyDNSNames(domain, selector)
		if err != nil {
			return "", "", fmt.Errorf("d= and s= do not form a DNS name for the key: %q, %q", domain, selector)
		}
		return d, s, nil
	}
	if !dnsHoldable(domain) || !dnsHoldable(selector) || len(selector)+len("._domainkey.")+len(domain) > 253 {
		return "", "", fmt.Errorf("d= and s= do not form a DNS name for the key: %q, %q", domain, selector)
	}
	return domain, selector, nil
}

// dnsHoldable reports whether an ASCII name is dot-separated labels of 1 to
// 63 printable characters.
func dnsHoldable(name string) bool {
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			if label[i] <= ' ' || label[i] > '~' {
				return false
			}
		}
	}
	return true
}

// FindAuthenticationResults returns the value of the topmost
// Authentication-Results header whose authserv-id is authservID
// (ASCII case-insensitive), with each run of whitespace, CR and LF turned
// into one space. Forwarding sealers can use CombinedAuthenticationResults
// to collect the service's assessments across multiple fields.
//
// The match is exact. What stands before the first ";" must be the
// authserv-id as a plain token, optionally followed by a version number
// (any digits), with comments and folding white space allowed around both
// (RFC 8601 §2.2). A second word, a quoted name, or a control or non-ASCII
// character next to the name, makes it another server's header.
//
// The search stops at the first line that is not a well-formed header
// field: what stands below it is a header to one parser and not to another.
// An edge prepends its stamp, so a genuine one is above any such line, and
// Sign then refuses the message and says why. The caller must still be sure
// that headers naming its own authserv-id can only come from its own edge
// (RFC 8601 §5).
func FindAuthenticationResults(rawMessage []byte, authservID string) (string, bool) {
	if authservID == "" {
		return "", false
	}
	headers, _ := splitMessage(string(rawMessage))
	for _, h := range headers {
		if _, _, defect := parseMessage(h.raw); defect != nil {
			return "", false
		}
		if asciiEqualFold(h.key, "Authentication-Results") {
			if _, _, ok := authservIDParts(h.value, authservID, false); ok {
				return collapseASCIIWSP(h.value), true
			}
		}
	}
	return "", false
}

// CombinedAuthenticationResults builds one ARC authentication payload from all
// version 1 Authentication-Results fields stamped by the named service, in
// wire order (RFC 8617 §4.1.1). The service identifier may be a token or a
// quoted string. A field stating "none" contributes no methods.
// As with FindAuthenticationResults, the caller must ensure that only its
// trusted ingress can supply fields naming this service (RFC 8601 §5): every
// such field is combined, wherever it stands.
//
// It reports nothing (false) rather than guess when the service's results
// cannot be read whole: a field with an unbalanced comment or quoted string,
// an empty result such as a trailing ";", "none" beside other results in one
// field, more than 64 KiB of results as they arrive, a combined value over
// 64 KiB (the most Sign accepts, counting the service identifier and the
// separators added here), or a header block of more than 10,000 fields.
// Like FindAuthenticationResults it stops at the first line that is not a
// well-formed header field, and fields of other versions are skipped.
func CombinedAuthenticationResults(rawMessage []byte, authservID string) (string, bool) {
	if authservID == "" {
		return "", false
	}
	headers, _, defect := parseMessage(string(rawMessage))
	if defect == errHeaderFieldLimit {
		return "", false
	}
	var payload strings.Builder
	hasMethods := false
	rawSize := 0
	for _, h := range headers {
		if defect != nil {
			// As in the topmost lookup, trust only the unambiguous prefix.
			if _, _, err := parseMessage(h.raw); err != nil {
				break
			}
		}
		if !asciiEqualFold(h.key, "Authentication-Results") {
			continue
		}
		version, rest, ok := authservIDParts(h.value, authservID, true)
		if !ok || rest == "" || version != "" && version != "1" {
			continue
		}
		if rawSize += len(rest); rawSize > maxAuthResultsBytes {
			return "", false
		}
		if payload.Len() == 0 {
			prefix, ok := unfoldAuthenticationResultsWithin(h.value[:len(h.value)-len(rest)], maxAuthResultsBytes)
			if !ok {
				return "", false
			}
			payload.WriteString(prefix)
		}
		clauses := splitAuthResultsClauses(rest[1:])
		if clauses == nil {
			return "", false
		}
		for _, clause := range clauses {
			value := unfoldAuthenticationResults(clause)
			if value == "" {
				return "", false
			}
			if isNoAuthResult(value) {
				if len(clauses) != 1 {
					return "", false
				}
				continue
			}
			if len("; ")+len(value) > maxAuthResultsBytes-payload.Len() {
				return "", false
			}
			payload.WriteString("; ")
			payload.WriteString(value)
			hasMethods = true
		}
	}
	if payload.Len() == 0 {
		return "", false
	}
	if !hasMethods {
		if len("; none") > maxAuthResultsBytes-payload.Len() {
			return "", false
		}
		payload.WriteString("; none")
	}
	return payload.String(), true
}

// The no-result production permits CFWS on both sides of "none".
func isNoAuthResult(value string) bool {
	rest, ok := skipCFWS(value)
	if !ok || len(rest) < 4 || !asciiEqualFold(rest[:4], "none") {
		return false
	}
	rest, ok = skipCFWS(rest[4:])
	return ok && rest == ""
}

// authservIDParts matches [CFWS] authservID [CFWS version] [CFWS] and returns
// the optional version and the remainder starting at the first real semicolon.
func authservIDParts(value, authservID string, allowQuoted bool) (version, rest string, ok bool) {
	rest, ok = skipCFWS(value)
	if !ok {
		return "", "", false
	}
	var id string
	if allowQuoted && strings.HasPrefix(rest, `"`) {
		id, rest, ok = quotedAuthservID(rest)
		if !ok {
			return "", "", false
		}
	} else {
		end := strings.IndexAny(rest, " \t\r\n;(")
		if end < 0 {
			end = len(rest)
		}
		id, rest = rest[:end], rest[end:]
	}
	if !asciiEqualFold(id, authservID) {
		return "", "", false
	}
	if rest, ok = skipCFWS(rest); !ok {
		return "", "", false
	}
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	version = rest[:digits]
	if rest, ok = skipCFWS(rest[digits:]); !ok {
		return "", "", false
	}
	if rest != "" && rest[0] != ';' {
		return "", "", false
	}
	// skipCFWS takes any CR or LF for white space. Here each must belong to
	// a fold, so that "id<CR>1" is not read as the id and a version.
	read := value[:len(value)-len(rest)]
	for i := 0; i < len(read); i++ {
		switch {
		case read[i] == '\r' && (i+1 == len(value) || value[i+1] != '\n'):
			return "", "", false
		case read[i] == '\n' && i+1 < len(value) && value[i+1] != ' ' && value[i+1] != '\t':
			return "", "", false
		}
	}
	return version, rest, true
}

// quotedAuthservID decodes qtext and quoted-pairs (RFC 5322 §3.2.4).
// The receiving edge compares a folded continuation after replacing its
// leading whitespace with one SP. Accept an internal fold only when that
// yields the same identifier as RFC unfolding.
func quotedAuthservID(value string) (id, rest string, ok bool) {
	var result strings.Builder
	for i := 1; i < len(value); i++ {
		c := value[i]
		switch c {
		case '"':
			id = result.String()
			return id, value[i+1:], utf8.ValidString(id)
		case '\\':
			i++
			if i == len(value) || (value[i] < ' ' && value[i] != '\t') || value[i] > '~' {
				return "", "", false
			}
			c = value[i]
		case '\r', '\n':
			if !strings.HasPrefix(value[i:], "\r\n ") {
				return "", "", false
			}
			i += 2
			if i+1 < len(value) && (value[i+1] == ' ' || value[i+1] == '\t') {
				return "", "", false
			}
			c = ' '
		default:
			if c < ' ' && c != '\t' || c == 0x7f {
				return "", "", false
			}
		}
		result.WriteByte(c)
	}
	return "", "", false
}

// authResultsPayload unfolds an ARC-Authentication-Results value and drops
// the leading i= tag, leaving the authserv-id and the results — the shape an
// ordinary Authentication-Results header has, so the same parser reads both.
// A value without a recognizable i= tag is returned unfolded and otherwise
// untouched: reporting it verbatim is more honest than guessing at it.
func authResultsPayload(value string) string {
	unfolded := unfoldAuthenticationResults(value)
	if n, rest, _ := parseInstanceClause(unfolded); n > 0 && strings.HasPrefix(rest, ";") {
		return strings.Trim(rest[1:], " \t")
	}
	return unfolded
}

// LatestARCAuthResults returns the instance number and payload
// (authserv-id and results, the i= tag stripped) of the newest
// ARC-Authentication-Results header, if any.
//
// This is the right header for a SIGNER (the newest results are what the
// previous hop observed) and the wrong one for anybody deciding whether to
// trust the chain's account of the ORIGINAL sender — use
// VerifyResult.OldestAuthResults for that, and read its comment for why.
// It reads the header as written and judges nothing: it also answers for a
// message whose chain Verify fails, a malformed header block included.
func LatestARCAuthResults(rawMessage []byte) (int, string, bool) {
	headers, _ := splitMessage(string(rawMessage))
	sets, maxInstance, _ := extractARCSets(headers)
	if maxInstance == 0 || sets[maxInstance] == nil || !sets[maxInstance].hasAAR {
		return 0, "", false
	}
	return maxInstance, authResultsPayload(sets[maxInstance].aar.value), true
}
