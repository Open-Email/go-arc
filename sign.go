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
	"strings"
	"time"
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
	// FindAuthenticationResults extracts it from an edge-stamped header.
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

// SignResult is the outcome of Sign.
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

// headers the AMS covers when present, in h= order. ARC-* headers are
// forbidden here (RFC 8617 §4.1.2); Authentication-Results and trace
// headers are excluded because receivers add their own in transit.
var defaultSignedHeaders = []string{
	"from", "to", "cc", "reply-to", "subject", "date", "message-id",
	"in-reply-to", "references", "mime-version", "content-type",
	"content-transfer-encoding",
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
	if cfg == nil {
		return nil, fmt.Errorf("arc: nil SignConfig")
	}
	if cfg.Domain == "" || cfg.Selector == "" {
		return nil, fmt.Errorf("arc: Domain and Selector are required")
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("arc: PrivateKey is required")
	}
	if bits := cfg.PrivateKey.N.BitLen(); bits < 1024 || bits > 4096 {
		return nil, fmt.Errorf("arc: unsupported RSA key size %d bits (must be 1024–4096)", bits)
	}
	if strings.TrimSpace(cfg.AuthResults) == "" {
		return nil, fmt.Errorf("arc: AuthResults is required — the AAR must carry the results observed at ingress, never fabricated ones")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}

	raw := string(rawMessage)
	headers, _ := splitMessage(raw)
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
		prior, err := Verify(rawMessage, &VerifyOptions{LookupTXT: lookup, Logger: logger})
		if err != nil {
			return nil, fmt.Errorf("arc: validating prior chain: %w", err)
		}
		if prior.Pass {
			cv = ChainPass
		} else {
			cv = ChainFail
			logger.Debug("prior ARC chain failed validation, sealing cv=fail",
				"reasons", prior.FailureReasons)
		}
	}

	instance := maxInstance + 1
	timestamp := now().Unix()

	// ARC-Authentication-Results: i=N plus the ingress results, re-folded.
	aarTags := []string{fmt.Sprintf("i=%d", instance)}
	for _, part := range strings.Split(cfg.AuthResults, ";") {
		part = strings.Join(strings.Fields(part), " ")
		if part != "" {
			aarTags = append(aarTags, part)
		}
	}
	aarRaw := foldHeader("ARC-Authentication-Results", aarTags)

	// ARC-Message-Signature: DKIM-shaped, over the real body and the
	// real headers. No v= tag — RFC 8617 defines none.
	body := messageBody(raw)
	bodyHash := sha256.Sum256(canonicalizeBody(body, canonRelaxed))

	signed := selectSignedHeaders(headers)
	hNames := make([]string, 0, len(signed))
	for _, h := range signed {
		hNames = append(hNames, strings.ToLower(h.key))
	}
	if len(hNames) == 0 {
		return nil, fmt.Errorf("arc: message has none of the signable headers (no From?)")
	}

	amsTags := []string{
		fmt.Sprintf("i=%d", instance),
		"a=rsa-sha256",
		"c=relaxed/relaxed",
		"d=" + cfg.Domain,
		"s=" + cfg.Selector,
		fmt.Sprintf("t=%d", timestamp),
		"bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]),
		"h=" + strings.Join(hNames, ":"),
		"b=",
	}
	amsUnsigned := foldHeader("ARC-Message-Signature", amsTags)

	amsHasher := sha256.New()
	for _, h := range signed {
		amsHasher.Write([]byte(canonicalizeHeaderRaw(h.raw, canonRelaxed)))
	}
	amsHasher.Write([]byte(strings.TrimRight(canonicalizeHeaderRaw(amsUnsigned, canonRelaxed), "\r\n")))
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
		"d=" + cfg.Domain,
		"s=" + cfg.Selector,
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
	sealHasher.Write([]byte(strings.TrimRight(canonicalizeHeaderRaw(sealUnsigned, canonRelaxed), "\r\n")))
	sealSig, err := signHash(cfg.PrivateKey, sealHasher.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("arc: signing ARC-Seal: %w", err)
	}
	sealRaw, err := spliceSignature(sealUnsigned, sealSig)
	if err != nil {
		return nil, err
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

// selectSignedHeaders picks the AMS-covered headers: for each name in
// defaultSignedHeaders, the bottom-most unused occurrence — the mirror
// of RFC 6376 §5.4.2 verification order.
func selectSignedHeaders(headers []rawHeader) []rawHeader {
	var out []rawHeader
	used := make(map[int]bool)
	for _, name := range defaultSignedHeaders {
		for i := len(headers) - 1; i >= 0; i-- {
			if used[i] || !strings.EqualFold(headers[i].key, name) {
				continue
			}
			out = append(out, headers[i])
			used[i] = true
			break
		}
	}
	return out
}

func messageBody(raw string) string {
	_, body := splitMessage(raw)
	return body
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
