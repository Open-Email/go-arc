package arc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// SignConfig configures Sign.
type SignConfig struct {
	// Domain is the d= value: the domain of the sealing ADMD (the
	// forwarding platform), whose DNS publishes the public key.
	Domain string
	// Selector is the s= value.
	Selector string
	// PrivateKey signs both the AMS and the seal (RSA, 1024–4096 bits).
	PrivateKey *rsa.PrivateKey
	// AuthResults is the Authentication-Results payload observed when
	// the message entered the ADMD — authserv-id included, e.g.
	// "mx.example.com; spf=pass smtp.mailfrom=a@b; dkim=pass header.d=b".
	// It becomes the AAR. Required: a sealer that did not observe the
	// message's arrival has nothing truthful to seal.
	// CombinedAuthenticationResults collects it from the edge-stamped fields.
	AuthResults string
	// LookupTXT fetches public keys for validating an existing chain
	// (the cv= determination). Required when the message already
	// carries ARC sets; unused on a first hop. Defaults to
	// DefaultLookupTXT.
	LookupTXT LookupTXT
	// Now supplies the t= timestamp. Defaults to time.Now.
	Now func() time.Time
	// Logger receives debug output. Defaults to a discard logger.
	Logger *slog.Logger
}

// SignResult is the outcome of Sign or SignTransformed.
type SignResult struct {
	// Message is the input with the new ARC set prepended
	// (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results).
	Message []byte
	// Instance is the i= of the added set.
	Instance int
	// CV is the chain status the seal declares: none on a first hop,
	// pass or fail when a prior chain existed.
	CV ChainStatus
}

// maxLineLength is the RFC 5322 §2.1.1 limit on a line, CRLF excluded.
const maxLineLength = 998

// headers the AMS covers, in h= order: every field of each name, and the
// absence of any further one (see sign). ARC-* headers are forbidden here
// (RFC 8617 §4.1.2); Authentication-Results and trace headers are excluded
// because receivers add their own in transit.
var defaultSignedHeaders = []string{
	"from", "sender", "to", "cc", "reply-to", "subject", "date", "message-id",
	"in-reply-to", "references", "mime-version", "content-type",
	"content-transfer-encoding", "content-disposition",
}

// Sign adds one ARC set to a message per RFC 8617 §5.1.
//
// If the message already carries an ARC chain, the chain is validated
// first and the new seal declares the true cv= result. On cv=fail the
// seal covers only the new set (§5.1.2); on pass it covers every prior
// set plus the new one. A chain already at MaxChainLength is refused
// with ErrChainLimit — forward such a message without sealing.
//
// The three headers are prepended, so the input bytes are preserved
// verbatim: everything signed is exactly what is emitted.
func Sign(rawMessage []byte, cfg *SignConfig) (*SignResult, error) {
	return sign(rawMessage, rawMessage, cfg, false)
}

// SignTransformed adds an ARC set after the caller has transformed a message.
// It validates the prior chain on the original message and signs the outbound
// message. Pass the original bytes as they arrived, before any local changes,
// and the final outbound bytes after every change, including local DKIM signing.
// The outbound message must preserve all ARC-* headers and their order byte for
// byte. If a prior chain exists, it must validate on the original. A message
// without prior ARC gets a first-hop seal if the original header scan completed.
func SignTransformed(original, outbound []byte, cfg *SignConfig) (*SignResult, error) {
	return sign(original, outbound, cfg, true)
}

func sign(original, outbound []byte, cfg *SignConfig, transformed bool) (*SignResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("arc: nil SignConfig")
	}
	if cfg.Domain == "" || cfg.Selector == "" {
		return nil, fmt.Errorf("arc: Domain and Selector are required")
	}
	domain, selector, err := keyDNSNames(cfg.Domain, cfg.Selector)
	if err != nil {
		return nil, err
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("arc: PrivateKey is required")
	}
	if bits := cfg.PrivateKey.N.BitLen(); bits < 1024 || bits > 4096 {
		return nil, fmt.Errorf("arc: unsupported RSA key size %d bits (must be 1024–4096)", bits)
	}
	// The results are re-folded clause by clause. CR and LF in them become
	// spaces, so they can never end the header and start another one.
	var authResults []string
	for _, clause := range splitAuthResultsClauses(cfg.AuthResults) {
		authResults = append(authResults, collapseASCIIWSP(clause))
	}
	if len(authResults) == 0 || authResults[0] == "" {
		return nil, fmt.Errorf("arc: AuthResults is required and must begin with the authserv-id: the AAR must carry the results observed at ingress, never fabricated ones")
	}
	for _, clause := range authResults {
		for i := 0; i < len(clause); i++ {
			if clause[i] < ' ' || clause[i] == 0x7f {
				return nil, fmt.Errorf("arc: AuthResults holds a control character")
			}
		}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}

	raw := string(outbound)
	headers, body, defect := parseMessage(raw)
	if defect != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, defect)
	}
	if domain != cfg.Domain || selector != cfg.Selector {
		// RFC 8617 §4.1.4 permits U-labels in internationalized headers.
		// Use A-labels when the outbound headers still fit ASCII.
		headerBlock := raw[:len(raw)-len(body)]
		if hasNonASCII(headerBlock) && utf8.ValidString(headerBlock) {
			domain, selector = cfg.Domain, cfg.Selector
		}
	}
	if len(headers)+3 > maxHeaderFields {
		// With the three new fields Verify would refuse the result.
		return nil, fmt.Errorf("%w: more than %d header fields with the new ARC set", ErrMalformedMessage, maxHeaderFields)
	}
	if transformed {
		priorHeaders, _, priorDefect := parseMessage(string(original))
		if priorDefect == errHeaderFieldLimit {
			return nil, fmt.Errorf("%w: original has %v", ErrMalformedMessage, priorDefect)
		}
		if !slices.Equal(arcHeaderBytes(priorHeaders), arcHeaderBytes(headers)) {
			return nil, ErrARCHeadersChanged
		}
	}
	_, maxInstance, problems := extractARCSets(headers)

	if maxInstance >= MaxChainLength {
		return nil, ErrChainLimit
	}
	if maxInstance == 0 && len(problems) > 0 {
		// ARC headers exist but none carries a usable instance number:
		// there is no chain to extend and no honest i= to mint.
		return nil, ErrMalformedChain
	}

	// Determine cv= (§5.1.2): none on a first hop, otherwise the real
	// validation result of the existing chain. Structural problems in
	// the prior chain are a fail — never a guess.
	cv := ChainNone
	if maxInstance > 0 {
		lookup := cfg.LookupTXT
		if lookup == nil {
			lookup = DefaultLookupTXT
		}
		prior, err := Verify(original, &VerifyOptions{LookupTXT: lookup, Logger: logger})
		if err != nil {
			return nil, fmt.Errorf("arc: validating prior chain: %w", err)
		}
		if prior.Pass {
			cv = ChainPass
		} else {
			if transformed {
				return nil, fmt.Errorf("%w: %s", ErrPriorChainFailed, strings.Join(prior.FailureReasons, "; "))
			}
			cv = ChainFail
			logger.Debug("prior ARC chain failed validation, sealing cv=fail",
				"reasons", prior.FailureReasons)
		}
	}

	instance := maxInstance + 1
	timestamp := now().Unix()

	// ARC-Authentication-Results: i=N plus the ingress results, re-folded.
	aarTags := []string{fmt.Sprintf("i=%d", instance)}
	for _, clause := range authResults {
		if clause != "" {
			aarTags = append(aarTags, foldAuthResultsClause(clause))
		}
	}
	aarRaw := foldHeader("ARC-Authentication-Results", aarTags)

	// ARC-Message-Signature: DKIM-shaped, over the real body and the
	// real headers. No v= tag — RFC 8617 defines none.
	bodyHash := sha256.Sum256(canonicalizeBody(body, canonRelaxed))

	// Every default name goes into h= once per field of that name, bottom
	// up, and once more. The extra entry selects nothing now, so a field of
	// that name added later (a second Subject above the first, a Reply-To
	// or Content-Type the message never had) is selected by it and breaks
	// the signature (RFC 6376 §5.4 and §8.15).
	var signed []rawHeader
	var hNames []string
	for _, name := range defaultSignedHeaders {
		for i := len(headers) - 1; i >= 0; i-- {
			if asciiEqualFold(headers[i].key, name) {
				signed = append(signed, headers[i])
				hNames = append(hNames, name)
			}
		}
		if name == "from" && len(signed) == 0 {
			return nil, fmt.Errorf("arc: message has no From header")
		}
		hNames = append(hNames, name)
	}
	if transformed {
		// RFC 8617 §4.1.2 recommends covering DKIM-Signature fields.
		// Include every retained occurrence in DKIM verification order.
		for i := len(headers) - 1; i >= 0; i-- {
			if asciiEqualFold(headers[i].key, "DKIM-Signature") {
				signed = append(signed, headers[i])
				hNames = append(hNames, "dkim-signature")
			}
		}
	}
	if len(hNames) > maxSignedEntries {
		return nil, fmt.Errorf("%w: more than %d fields to sign", ErrMalformedMessage, maxSignedEntries)
	}

	amsTags := []string{
		fmt.Sprintf("i=%d", instance),
		"a=rsa-sha256",
		"c=relaxed/relaxed",
		"d=" + domain,
		"s=" + selector,
		fmt.Sprintf("t=%d", timestamp),
		"bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]),
		"h=" + foldHeaderNames(hNames),
		"b=",
	}
	amsUnsigned := foldHeader("ARC-Message-Signature", amsTags)

	amsHasher := sha256.New()
	for _, h := range signed {
		amsHasher.Write([]byte(canonicalizeHeaderRaw(h.raw, canonRelaxed)))
	}
	amsHasher.Write([]byte(trimLineBreak(canonicalizeHeaderRaw(amsUnsigned, canonRelaxed))))
	amsSig, err := signHash(cfg.PrivateKey, amsHasher.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("arc: signing ARC-Message-Signature: %w", err)
	}
	amsRaw, err := spliceSignature(amsUnsigned, amsSig)
	if err != nil {
		return nil, err
	}

	// ARC-Seal: headers only, relaxed, no bh=/h=/c=/v= tags (§4.1.3).
	sealTags := []string{
		fmt.Sprintf("i=%d", instance),
		"a=rsa-sha256",
		fmt.Sprintf("t=%d", timestamp),
		"cv=" + string(cv),
		"d=" + domain,
		"s=" + selector,
		"b=",
	}
	sealUnsigned := foldHeader("ARC-Seal", sealTags)

	// Seal scope (§5.1.2): all prior ARC sets in instance order plus
	// the new AAR and AMS — except on cv=fail, where only the sealer's
	// own set is covered.
	var sealScope []string
	if cv != ChainFail {
		// Cap at the NEW instance: every prior set is included in
		// full — a cap at maxInstance would drop the newest prior
		// seal, exactly the unsealed-prior-sets defect this package
		// exists to prevent.
		for _, h := range arcHeadersUpTo(headers, instance) {
			sealScope = append(sealScope, h.raw)
		}
	}
	sealScope = append(sealScope, aarRaw, amsRaw)

	sealHasher := sha256.New()
	for _, h := range sealScope {
		sealHasher.Write([]byte(canonicalizeHeaderRaw(h, canonRelaxed)))
	}
	sealHasher.Write([]byte(trimLineBreak(canonicalizeHeaderRaw(sealUnsigned, canonRelaxed))))
	sealSig, err := signHash(cfg.PrivateKey, sealHasher.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("arc: signing ARC-Seal: %w", err)
	}
	sealRaw, err := spliceSignature(sealUnsigned, sealSig)
	if err != nil {
		return nil, err
	}

	for _, header := range []string{sealRaw, amsRaw, aarRaw} {
		for _, line := range strings.Split(header, "\r\n") {
			if len(line) > maxLineLength {
				return nil, ErrLineTooLong
			}
		}
	}

	logger.Info("ARC set added", "instance", instance, "cv", cv,
		"domain", cfg.Domain, "selector", cfg.Selector)

	var out strings.Builder
	out.Grow(len(sealRaw) + len(amsRaw) + len(aarRaw) + len(raw))
	out.WriteString(sealRaw)
	out.WriteString(amsRaw)
	out.WriteString(aarRaw)
	out.WriteString(raw)

	return &SignResult{Message: []byte(out.String()), Instance: instance, CV: cv}, nil
}

// keyDNSNames validates the signing identities and returns their DNS form.
// The resolver requires A-labels even when the signed fields use U-labels.
func keyDNSNames(domain, selector string) (string, string, error) {
	d, validDomain := asciiDNSName(domain, false)
	s, validSelector := asciiDNSName(selector, true)
	if !validDomain || !strings.Contains(d, ".") || !validSelector || len(s)+len("._domainkey.")+len(d) > 253 {
		return "", "", fmt.Errorf("arc: Domain and Selector must form a valid DNS key name")
	}
	return d, s, nil
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

func asciiDNSName(name string, selector bool) (string, bool) {
	if name == "" || len(name) > 253*utf8.UTFMax {
		return "", false
	}
	international := hasNonASCII(name)
	var labels []string
	for label := range strings.SplitSeq(name, ".") {
		if !hasNonASCII(label) {
			if !validASCIIKeyLabel(label, selector) {
				return "", false
			}
			if international {
				label = asciiLower(label)
			}
		}
		if international {
			labels = append(labels, label)
		}
	}
	if !international {
		return name, len(name) <= 253
	}
	// Registration validates U-labels without mapping invalid spellings.
	ascii, err := idna.Registration.ToASCII(strings.Join(labels, "."))
	return ascii, err == nil && len(ascii) <= 253
}

// Signing domains use the host-label grammar from RFC 6376 §3.5. Keep the
// existing support for underscore selectors used by some installations.
func validASCIIKeyLabel(label string, selector bool) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := asciiLowerByte(label[i])
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || selector && c == '_') {
			return false
		}
	}
	if len(label) >= 4 && asciiEqualFold(label[:4], "xn--") {
		lower := asciiLower(label)
		canonical, err := idna.Registration.ToASCII(lower)
		return err == nil && canonical == lower
	}
	return true
}

func arcHeaderBytes(headers []rawHeader) []string {
	var fields []string
	for _, h := range headers {
		if isARCHeader(h.key) {
			fields = append(fields, h.raw)
		}
	}
	return fields
}

func signHash(key *rsa.PrivateKey, hashed []byte) (string, error) {
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// spliceSignature inserts the base64 signature into the empty b= tag of
// an unsigned header. The b= tag is always the final tag, so the bytes
// that were hashed are preserved exactly and a verifier emptying b=
// reconstructs the hashed input byte for byte.
func spliceSignature(unsigned, sig string) (string, error) {
	idx := strings.LastIndex(unsigned, "b=")
	if idx < 0 {
		return "", fmt.Errorf("arc: unsigned header lacks b= tag")
	}
	return unsigned[:idx+2] + sig + unsigned[idx+2:], nil
}
