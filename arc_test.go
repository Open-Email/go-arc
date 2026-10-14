package arc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	keyOnce sync.Once
	keyA    *rsa.PrivateKey
	keyB    *rsa.PrivateKey
	keyC    *rsa.PrivateKey
	keyErrs []error
)

func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	keyOnce.Do(func() {
		gen := func() *rsa.PrivateKey {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				keyErrs = append(keyErrs, err)
			}
			return k
		}
		keyA, keyB, keyC = gen(), gen(), gen()
	})
	if len(keyErrs) > 0 {
		t.Fatalf("key generation failed: %v", keyErrs)
	}
	return keyA, keyB, keyC
}

func txtFor(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)
}

func dnsStub(records map[string]string) LookupTXT {
	return func(name string) ([]string, error) {
		if txt, ok := records[name]; ok {
			return []string{txt}, nil
		}
		return nil, fmt.Errorf("no TXT record for %q", name)
	}
}

const baseMessage = "From: Alice <alice@origin.example>\r\n" +
	"To: Bob <bob@dest.example>\r\n" +
	"Subject: Hello there\r\n" +
	"Date: Sat, 01 Aug 2026 12:00:00 +0000\r\n" +
	"Message-ID: <abc123@origin.example>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"Hello Bob,\r\n" +
	"\r\n" +
	"This is a forwarded test message.\r\n"

const authResultsA = "mx.forward-a.example; spf=pass smtp.mailfrom=alice@origin.example; dkim=pass header.d=origin.example; dmarc=pass header.from=origin.example"
const authResultsB = "mx.forward-b.example; spf=pass smtp.mailfrom=alice@origin.example; arc=pass"
const authResultsC = "mx.forward-c.example; spf=pass smtp.mailfrom=alice@origin.example; arc=pass"

func fixedNow() time.Time { return time.Unix(1754131200, 0) }

func signConfig(key *rsa.PrivateKey, domain, selector, authRes string, lookup LookupTXT) *SignConfig {
	return &SignConfig{
		Domain:      domain,
		Selector:    selector,
		PrivateKey:  key,
		AuthResults: authRes,
		LookupTXT:   lookup,
		Now:         fixedNow,
	}
}

// testChain signs baseMessage through one, two, or three hops and
// returns the final message plus a DNS stub covering all hops' keys.
func testChain(t *testing.T, hops int) ([]byte, LookupTXT) {
	t.Helper()
	ka, kb, kc := testKeys(t)
	records := map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, ka),
		"sel-b._domainkey.forward-b.example": txtFor(t, kb),
		"sel-c._domainkey.forward-c.example": txtFor(t, kc),
	}
	lookup := dnsStub(records)

	msg := []byte(baseMessage)
	steps := []struct {
		key      *rsa.PrivateKey
		domain   string
		selector string
		authRes  string
	}{
		{ka, "forward-a.example", "sel-a", authResultsA},
		{kb, "forward-b.example", "sel-b", authResultsB},
		{kc, "forward-c.example", "sel-c", authResultsC},
	}
	for i := 0; i < hops; i++ {
		s := steps[i]
		res, err := Sign(msg, signConfig(s.key, s.domain, s.selector, s.authRes, lookup))
		if err != nil {
			t.Fatalf("hop %d: Sign failed: %v", i+1, err)
		}
		if res.Instance != i+1 {
			t.Fatalf("hop %d: expected instance %d, got %d", i+1, i+1, res.Instance)
		}
		wantCV := ChainPass
		if i == 0 {
			wantCV = ChainNone
		}
		if res.CV != wantCV {
			t.Fatalf("hop %d: expected cv=%s, got cv=%s", i+1, wantCV, res.CV)
		}
		msg = res.Message
	}
	return msg, lookup
}

func mustVerify(t *testing.T, msg []byte, lookup LookupTXT) *VerifyResult {
	t.Helper()
	res, err := Verify(msg, &VerifyOptions{LookupTXT: lookup})
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	return res
}

func TestSignFirstHopRoundTrip(t *testing.T) {
	msg, lookup := testChain(t, 1)
	res := mustVerify(t, msg, lookup)
	if !res.Pass || res.Instance != 1 {
		t.Fatalf("expected pass at instance 1, got %+v", res)
	}
	// The original message bytes must be preserved verbatim.
	if !strings.HasSuffix(string(msg), baseMessage) {
		t.Error("original message bytes were modified by signing")
	}
}

func TestSignSecondHopRoundTrip(t *testing.T) {
	msg, lookup := testChain(t, 2)
	res := mustVerify(t, msg, lookup)
	if !res.Pass || res.Instance != 2 {
		t.Fatalf("expected pass at instance 2, got %+v", res)
	}
}

func TestSignThirdHopRoundTrip(t *testing.T) {
	msg, lookup := testChain(t, 3)
	res := mustVerify(t, msg, lookup)
	if !res.Pass || res.Instance != 3 {
		t.Fatalf("expected pass at instance 3, got %+v", res)
	}
}

// TestStrippedPriorSetFailsVerify pins the property the original
// implementation lacked: removing an earlier hop's ARC set must break
// every later seal.
func TestStrippedPriorSetFailsVerify(t *testing.T) {
	msg, lookup := testChain(t, 2)
	headers, body := splitMessage(string(msg))
	var sb strings.Builder
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h.key), "arc-") && h.instance == 1 {
			continue
		}
		sb.WriteString(h.raw)
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)

	res := mustVerify(t, []byte(sb.String()), lookup)
	if res.Pass {
		t.Fatal("verification passed after a prior ARC set was stripped — the seal does not cover the chain")
	}
}

func TestTamperedBodyFailsVerify(t *testing.T) {
	msg, lookup := testChain(t, 1)
	tampered := strings.Replace(string(msg), "This is a forwarded test message.", "This is a MODIFIED test message.", 1)
	res := mustVerify(t, []byte(tampered), lookup)
	if res.Pass {
		t.Fatal("verification passed after body tampering")
	}
}

func TestSealTagShape(t *testing.T) {
	msg, _ := testChain(t, 1)
	headers, _ := splitMessage(string(msg))
	seal, ok := findARCHeader(headers, "ARC-Seal", 1)
	if !ok {
		t.Fatal("no ARC-Seal emitted")
	}
	tags := parseTags(seal.value)
	// RFC 8617 §4.1.3: the seal has exactly i, a, b, cv, d, s, t —
	// no bh=, no h=, no c=, and no v= (the RFC defines no version tag).
	for _, forbidden := range []string{"bh", "h", "c", "v"} {
		if _, present := tags[forbidden]; present {
			t.Errorf("ARC-Seal carries forbidden tag %s=", forbidden)
		}
	}
	for _, required := range []string{"i", "a", "b", "cv", "d", "s", "t"} {
		if tags[required] == "" {
			t.Errorf("ARC-Seal missing required tag %s=", required)
		}
	}
	if tags["cv"] != "none" {
		t.Errorf("first seal must be cv=none, got %q", tags["cv"])
	}

	ams, ok := findARCHeader(headers, "ARC-Message-Signature", 1)
	if !ok {
		t.Fatal("no ARC-Message-Signature emitted")
	}
	amsTags := parseTags(ams.value)
	if _, present := amsTags["v"]; present {
		t.Error("ARC-Message-Signature carries a v= tag; RFC 8617 defines none")
	}
	if amsTags["bh"] == "" || amsTags["h"] == "" {
		t.Error("ARC-Message-Signature missing bh= or h=")
	}
	if strings.Contains(strings.ToLower(amsTags["h"]), "arc-") {
		t.Error("ARC-Message-Signature h= covers ARC headers, forbidden by §4.1.2")
	}

	aar, ok := findARCHeader(headers, "ARC-Authentication-Results", 1)
	if !ok {
		t.Fatal("no ARC-Authentication-Results emitted")
	}
	unfolded := strings.Join(strings.Fields(aar.value), " ")
	if !strings.HasPrefix(unfolded, "i=1; mx.forward-a.example;") {
		t.Errorf("AAR does not carry the ingress results: %q", unfolded)
	}
}

// TestBrokenPriorChainSealsCvFail: a corrupted prior seal must produce
// cv=fail, and the failed seal must cover only the sealer's own set
// (§5.1.2) — proven by verifying it in isolation.
func TestBrokenPriorChainSealsCvFail(t *testing.T) {
	msg, lookup := testChain(t, 1)

	// Corrupt the i=1 seal's signature.
	corrupted := corruptTag(t, string(msg), "ARC-Seal", 1)

	_, kb, _ := testKeys(t)
	res, err := Sign([]byte(corrupted), signConfig(kb, "forward-b.example", "sel-b", authResultsB, lookup))
	if err != nil {
		t.Fatalf("Sign over broken chain must not error: %v", err)
	}
	if res.CV != ChainFail {
		t.Fatalf("expected cv=fail over a corrupted prior chain, got cv=%s", res.CV)
	}

	// The whole chain is dead; Verify must refuse it.
	if v := mustVerify(t, res.Message, lookup); v.Pass {
		t.Fatal("verification passed a chain containing cv=fail")
	}

	// The failed seal covers ONLY the sealer's own AAR + AMS.
	headers, _ := splitMessage(string(res.Message))
	seal, _ := findARCHeader(headers, "ARC-Seal", 2)
	aar, _ := findARCHeader(headers, "ARC-Authentication-Results", 2)
	ams, _ := findARCHeader(headers, "ARC-Message-Signature", 2)
	if err := verifySignature("ARC-Seal", seal, []rawHeader{aar, ams}, "", lookup); err != nil {
		t.Errorf("cv=fail seal does not verify over the sealer's own set alone: %v", err)
	}
}

// corruptTag flips a character inside the b= value of the named ARC
// header at the given instance.
func corruptTag(t *testing.T, raw, name string, instance int) string {
	t.Helper()
	headers, body := splitMessage(raw)
	var sb strings.Builder
	found := false
	for _, h := range headers {
		if strings.EqualFold(h.key, name) && h.instance == instance {
			idx := strings.LastIndex(h.raw, "b=")
			if idx < 0 || idx+10 >= len(h.raw) {
				t.Fatalf("cannot corrupt %s: no b= value", name)
			}
			pos := idx + 10
			old := h.raw[pos]
			repl := byte('A')
			if old == 'A' {
				repl = 'B'
			}
			sb.WriteString(h.raw[:pos] + string(repl) + h.raw[pos+1:])
			found = true
			continue
		}
		sb.WriteString(h.raw)
	}
	if !found {
		t.Fatalf("header %s i=%d not found", name, instance)
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

func TestSignRefusesWithoutAuthResults(t *testing.T) {
	ka, _, _ := testKeys(t)
	cfg := signConfig(ka, "forward-a.example", "sel-a", "", nil)
	if _, err := Sign([]byte(baseMessage), cfg); err == nil {
		t.Fatal("Sign accepted an empty AuthResults — the AAR would be fabricated")
	}
}

func TestSignRefusesChainAtLimit(t *testing.T) {
	ka, _, _ := testKeys(t)
	msg := fmt.Sprintf("ARC-Seal: i=%d; a=rsa-sha256; t=1; cv=pass; d=x.example; s=s; b=Zm9v\r\n%s", MaxChainLength, baseMessage)
	_, err := Sign([]byte(msg), signConfig(ka, "forward-a.example", "sel-a", authResultsA, dnsStub(nil)))
	if err != ErrChainLimit {
		t.Fatalf("expected ErrChainLimit, got %v", err)
	}
}

func TestSignRefusesMalformedARCHeaders(t *testing.T) {
	ka, _, _ := testKeys(t)
	msg := "ARC-Seal: a=rsa-sha256; cv=none; d=x.example; s=s; b=Zm9v\r\n" + baseMessage
	_, err := Sign([]byte(msg), signConfig(ka, "forward-a.example", "sel-a", authResultsA, dnsStub(nil)))
	if err != ErrMalformedChain {
		t.Fatalf("expected ErrMalformedChain, got %v", err)
	}
}

func TestVerifyNoARCPasses(t *testing.T) {
	res := mustVerify(t, []byte(baseMessage), dnsStub(nil))
	if !res.Pass || res.Instance != 0 {
		t.Fatalf("message without ARC must pass with instance 0, got %+v", res)
	}
}

func TestVerifyDuplicateSetFails(t *testing.T) {
	msg, lookup := testChain(t, 1)
	headers, _ := splitMessage(string(msg))
	seal, _ := findARCHeader(headers, "ARC-Seal", 1)
	dup := seal.raw + string(msg)
	res := mustVerify(t, []byte(dup), lookup)
	if res.Pass {
		t.Fatal("verification passed with a duplicated ARC-Seal instance")
	}
}

func TestEmittedLinesStayWithinLimit(t *testing.T) {
	longAuthRes := authResultsA + "; dkim=pass header.d=another-very-long-domain-name.example header.s=selector2026 header.b=AbCdEfGh"
	ka, _, _ := testKeys(t)
	res, err := Sign([]byte(baseMessage), signConfig(ka, "forward-a.example", "sel-a", longAuthRes, nil))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	for _, line := range strings.Split(string(res.Message), "\n") {
		if len(line) > 998 {
			t.Errorf("emitted line exceeds RFC 5322 limit (%d bytes): %.60s…", len(line), line)
		}
	}
	// And the folded output must still verify.
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, ka)})
	if v := mustVerify(t, res.Message, lookup); !v.Pass {
		t.Fatalf("folded message failed verification: %+v", v)
	}
}

func TestFindAuthenticationResults(t *testing.T) {
	msg := "Authentication-Results: other.example; spf=fail\r\n" +
		"Authentication-Results: mx.forward-a.example;\r\n" +
		"\tspf=pass smtp.mailfrom=alice@origin.example;\r\n" +
		"\tdkim=pass header.d=origin.example\r\n" +
		baseMessage
	value, ok := FindAuthenticationResults([]byte(msg), "mx.forward-a.example")
	if !ok {
		t.Fatal("did not find the matching Authentication-Results header")
	}
	want := "mx.forward-a.example; spf=pass smtp.mailfrom=alice@origin.example; dkim=pass header.d=origin.example"
	if value != want {
		t.Fatalf("unfolded value mismatch:\n got %q\nwant %q", value, want)
	}
	if _, ok := FindAuthenticationResults([]byte(msg), "absent.example"); ok {
		t.Fatal("matched an authserv-id that is not present")
	}
}

func TestLatestARCAuthResults(t *testing.T) {
	msg, _ := testChain(t, 2)
	instance, value, ok := LatestARCAuthResults(msg)
	if !ok || instance != 2 {
		t.Fatalf("expected latest AAR at instance 2, got %d ok=%v", instance, ok)
	}
	if !strings.HasPrefix(value, "mx.forward-b.example;") {
		t.Fatalf("unexpected AAR payload: %q", value)
	}
}

func TestRemoveSignatureValue(t *testing.T) {
	cases := [][2]string{
		// Plain: value dropped up to the terminator.
		{"X: a=1; b=SIG; d=x\r\n", "X: a=1; b=; d=x\r\n"},
		// b= last, no terminator: everything after b= dropped.
		{"X: a=1; b=SIGSIG\r\n", "X: a=1; b="},
		// bh= value ending in "b=" (base64 padding) must not match.
		{"X: bh=AAb=; b=SIG; d=x\r\n", "X: bh=AAb=; b=; d=x\r\n"},
		// A folded bh= whose continuation starts with "b=" must not match.
		{"X: bh=AA\r\n\tb=; b=SIG\r\n", "X: bh=AA\r\n\tb=; b="},
		// No b= tag at all: unchanged.
		{"X: a=1; d=x\r\n", "X: a=1; d=x\r\n"},
	}
	for _, c := range cases {
		if got := removeSignatureValue(c[0]); got != c[1] {
			t.Errorf("removeSignatureValue(%q):\n got %q\nwant %q", c[0], got, c[1])
		}
	}
}

// TestGmailFixtureStructure exercises the verifier's parsing against a
// real Google-sealed message; cryptographic validation runs only when
// GOARC_LIVE_DNS=1 (it needs Google's real DNS records).
func TestGmailFixtureStructure(t *testing.T) {
	raw, err := os.ReadFile("testdata/arc-example.eml")
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	failClosed := dnsStub(nil)
	res := mustVerify(t, raw, failClosed)
	if res.Instance != 1 {
		t.Fatalf("expected to detect Google's ARC set at instance 1, got %d", res.Instance)
	}
	if res.Pass {
		t.Fatal("verification cannot pass without DNS — fail-closed is broken")
	}

	if os.Getenv("GOARC_LIVE_DNS") != "1" {
		t.Log("set GOARC_LIVE_DNS=1 to cryptographically verify the fixture against live DNS")
		return
	}
	live := mustVerify(t, raw, DefaultLookupTXT)
	if !live.Pass {
		t.Fatalf("live verification of the Google fixture failed: %+v", live.FailureReasons)
	}
}

// TestVerifyOnlyNewestAMSPerRFC8617 proves RFC 8617 §5.2 Step 2: only the
// highest-instance ARC-Message-Signature is validated against the message.
// When an intermediate forwarder (e.g. a mailing list at hop 2) validates
// hop 1's ARC set at ingress, modifies the Subject and body (breaking i=1's
// AMS), and seals the modified message as i=2 with cv=pass, the resulting
// chain must validate at hop 3 (and a third hop sealing it must emit cv=pass).
func TestVerifyOnlyNewestAMSPerRFC8617(t *testing.T) {
	ka, kb, kc := testKeys(t)
	lookup := dnsStub(map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, ka),
		"sel-b._domainkey.forward-b.example": txtFor(t, kb),
		"sel-c._domainkey.forward-c.example": txtFor(t, kc),
	})

	// Hop 1 seals the original message at ingress.
	hop1, err := Sign([]byte(baseMessage), signConfig(ka, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatalf("hop 1 Sign: %v", err)
	}

	// Hop 2 (a mailing list) validates hop 1 at ingress, then modifies Subject
	// and appends a footer before sealing i=2 at egress. To build hop 2's valid
	// i=2 set over the modified message while keeping hop 1's i=1 set intact,
	// sign the modified message at hop 1+2 and splice hop 1's original i=1 set
	// (with hop 2's ARC-Seal re-signed over hop 1's original i=1 headers).
	modifiedRaw := strings.Replace(string(hop1.Message), "Subject: Hello there\r\n", "Subject: [list] Hello there\r\n", 1) +
		"\r\n-- \r\nMailing list footer\r\n"
	modHeaders, modBody := splitMessage(modifiedRaw)

	// Build i=2 AAR and AMS over the modified message.
	aar2 := foldHeader("ARC-Authentication-Results", []string{"i=2", authResultsB})
	bodyHash := sha256.Sum256(canonicalizeBody(modBody, canonRelaxed))
	signed := selectSignedHeaders(modHeaders)
	var hNames []string
	for _, h := range signed {
		hNames = append(hNames, strings.ToLower(h.key))
	}
	ams2Unsigned := foldHeader("ARC-Message-Signature", []string{
		"i=2",
		"a=rsa-sha256",
		"c=relaxed/relaxed",
		"d=forward-b.example",
		"s=sel-b",
		fmt.Sprintf("t=%d", fixedNow().Unix()),
		"bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]),
		"h=" + strings.Join(hNames, ":"),
		"b=",
	})
	var amsInput strings.Builder
	for _, h := range signed {
		amsInput.WriteString(canonicalizeHeaderRaw(h.raw, canonRelaxed))
	}
	amsInput.WriteString(strings.TrimRight(canonicalizeHeaderRaw(ams2Unsigned, canonRelaxed), "\r\n"))
	ams2Hash := sha256.Sum256([]byte(amsInput.String()))
	ams2Sig, err := signHash(kb, ams2Hash[:])
	if err != nil {
		t.Fatalf("sign AMS i=2: %v", err)
	}
	ams2Raw, err := spliceSignature(ams2Unsigned, ams2Sig)
	if err != nil {
		t.Fatalf("splice AMS i=2: %v", err)
	}

	// Build i=2 ARC-Seal (cv=pass) covering i=1's intact headers plus i=2's AAR+AMS.
	seal2Unsigned := foldHeader("ARC-Seal", []string{
		"i=2",
		"a=rsa-sha256",
		fmt.Sprintf("t=%d", fixedNow().Unix()),
		"cv=pass",
		"d=forward-b.example",
		"s=sel-b",
		"b=",
	})
	var sealInput strings.Builder
	for _, h := range arcHeadersUpTo(modHeaders, 2) {
		sealInput.WriteString(canonicalizeHeaderRaw(h.raw, canonRelaxed))
	}
	sealInput.WriteString(canonicalizeHeaderRaw(aar2, canonRelaxed))
	sealInput.WriteString(canonicalizeHeaderRaw(ams2Raw, canonRelaxed))
	sealInput.WriteString(strings.TrimRight(canonicalizeHeaderRaw(seal2Unsigned, canonRelaxed), "\r\n"))
	seal2Hash := sha256.Sum256([]byte(sealInput.String()))
	seal2Sig, err := signHash(kb, seal2Hash[:])
	if err != nil {
		t.Fatalf("sign AS i=2: %v", err)
	}
	seal2Raw, err := spliceSignature(seal2Unsigned, seal2Sig)
	if err != nil {
		t.Fatalf("splice AS i=2: %v", err)
	}

	hop2Message := []byte(seal2Raw + ams2Raw + aar2 + modifiedRaw)

	// Verify at hop 3: i=2 AMS and i=1..2 seals are valid; i=1 AMS is stale.
	res := mustVerify(t, hop2Message, lookup)
	if !res.Pass || !res.ChainValid {
		t.Fatalf("expected multi-hop modified chain to pass RFC 8617 §5.2 verification, got pass=%v reasons=%v", res.Pass, res.FailureReasons)
	}

	// And sealing at hop 3 must record cv=pass.
	hop3, err := Sign(hop2Message, signConfig(kc, "forward-c.example", "sel-c", authResultsC, lookup))
	if err != nil {
		t.Fatalf("hop 3 Sign: %v", err)
	}
	if hop3.CV != ChainPass {
		t.Fatalf("hop 3 sealed cv=%s, want pass", hop3.CV)
	}
}

// TestExtractInstanceBounds verifies RFC 8617 §4.1.1 / §5.2 instance-value
// syntax: 1–2 ASCII digits in the range 1..50 without leading zeros.
func TestExtractInstanceBounds(t *testing.T) {
	valid := map[string]int{
		"i=1; a=rsa-sha256":   1,
		"i=9; a=rsa-sha256":   9,
		"i=10; a=rsa-sha256":  10,
		"i=50; a=rsa-sha256":  50,
		" i = 1 ; cv=none":    0, // space before '=' is not a valid i= prefix
		"a=rsa-sha256; i=25;": 25,
	}
	for input, want := range valid {
		if got := extractInstance(input); got != want {
			t.Errorf("extractInstance(%q) = %d, want %d", input, got, want)
		}
	}

	invalid := []string{
		"i=0; a=rsa-sha256",
		"i=-1; a=rsa-sha256",
		"i=+1; a=rsa-sha256",
		"i=01; a=rsa-sha256",
		"i=001; a=rsa-sha256",
		"i=51; a=rsa-sha256",
		"i=99; a=rsa-sha256",
		"i=100; a=rsa-sha256",
		"i=1000000000; a=rsa-sha256",
		"i=9223372036854775807; a=rsa-sha256",
		"i=1a; a=rsa-sha256",
		"i=; a=rsa-sha256",
	}
	for _, input := range invalid {
		if got := extractInstance(input); got != 0 {
			t.Errorf("extractInstance(%q) = %d, want 0 (invalid)", input, got)
		}
	}
}

// TestVerifyInstanceTagBounds checks that Verify rejects out-of-range or
// syntactically invalid i= values (RFC 8617 §5.2) and bounds Instances slice
// allocation regardless of the raw i= value.
func TestVerifyInstanceTagBounds(t *testing.T) {
	invalidTags := []string{
		"0",
		"-1",
		"01",
		"001",
		"51",
		"100000",
		"9223372036854775807",
	}

	for _, tag := range invalidTags {
		t.Run("i="+tag, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Verify panicked on i=%s: %v", tag, r)
				}
			}()

			msg := []byte(fmt.Sprintf(
				"ARC-Seal: i=%s; a=rsa-sha256; cv=none; d=x.example; s=s; t=1; b=AAAA\r\n%s",
				tag, baseMessage,
			))

			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			res, err := Verify(msg, &VerifyOptions{LookupTXT: dnsStub(nil)})
			runtime.ReadMemStats(&after)

			if err != nil {
				t.Fatalf("Verify returned error for i=%s: %v", tag, err)
			}
			if res.Pass || res.ChainValid {
				t.Fatalf("expected Verify to fail for i=%s, got %+v", tag, res)
			}
			if len(res.Instances) != 0 {
				t.Errorf("expected no Instances for invalid i=%s, got %+v", tag, res.Instances)
			}
			allocDelta := after.TotalAlloc - before.TotalAlloc
			if allocDelta >= 1<<20 {
				t.Errorf("Verify allocated %d bytes (>= 1 MiB) for i=%s", allocDelta, tag)
			}
		})
	}
}

// TestVerifyMultiHopCorruptedNewestSealFails verifies that validateChain does
// not skip the newest ARC-Seal when len(sets) > 1 (RFC 8617 §5.2 Step 3).
func TestVerifyMultiHopCorruptedNewestSealFails(t *testing.T) {
	msg, lookup := testChain(t, 2)
	corrupted := corruptTag(t, string(msg), "ARC-Seal", 2)

	res := mustVerify(t, []byte(corrupted), lookup)
	if res.Pass || res.ChainValid {
		t.Fatalf("expected Verify to fail when ARC-Seal i=2 is corrupted, got %+v", res)
	}
}

// TestVerifyMultiHopCorruptedOldestSealUnderValidNewestSealFails verifies that
// validateChain checks every ARC-Seal from 1..N rather than only the newest:
// when AAR(1) is modified before hop 2 seals over it, AS(2) and AMS(2) are
// cryptographically valid over the modified headers, but AS(1) no longer
// matches AAR(1) and the chain must fail.
func TestVerifyMultiHopCorruptedOldestSealUnderValidNewestSealFails(t *testing.T) {
	ka, kb, _ := testKeys(t)
	lookup := dnsStub(map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, ka),
		"sel-b._domainkey.forward-b.example": txtFor(t, kb),
	})

	hop1, err := Sign([]byte(baseMessage), signConfig(ka, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatalf("hop 1 Sign: %v", err)
	}

	// Edit AAR(1) after hop 1 sealed it so AS(1) becomes invalid.
	tamperedHop1 := strings.Replace(string(hop1.Message), "dmarc=pass", "dmarc=fail", 1)
	if tamperedHop1 == string(hop1.Message) {
		t.Fatal("failed to edit AAR(1)")
	}
	modHeaders, modBody := splitMessage(tamperedHop1)

	// Build a cryptographically valid i=2 set (with cv=pass) over the edited i=1 headers.
	aar2 := foldHeader("ARC-Authentication-Results", []string{"i=2", authResultsB})
	bodyHash := sha256.Sum256(canonicalizeBody(modBody, canonRelaxed))
	signed := selectSignedHeaders(modHeaders)
	var hNames []string
	for _, h := range signed {
		hNames = append(hNames, strings.ToLower(h.key))
	}
	ams2Unsigned := foldHeader("ARC-Message-Signature", []string{
		"i=2",
		"a=rsa-sha256",
		"c=relaxed/relaxed",
		"d=forward-b.example",
		"s=sel-b",
		fmt.Sprintf("t=%d", fixedNow().Unix()),
		"bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]),
		"h=" + strings.Join(hNames, ":"),
		"b=",
	})
	var amsInput strings.Builder
	for _, h := range signed {
		amsInput.WriteString(canonicalizeHeaderRaw(h.raw, canonRelaxed))
	}
	amsInput.WriteString(strings.TrimRight(canonicalizeHeaderRaw(ams2Unsigned, canonRelaxed), "\r\n"))
	ams2Hash := sha256.Sum256([]byte(amsInput.String()))
	ams2Sig, err := signHash(kb, ams2Hash[:])
	if err != nil {
		t.Fatalf("sign AMS i=2: %v", err)
	}
	ams2Raw, err := spliceSignature(ams2Unsigned, ams2Sig)
	if err != nil {
		t.Fatalf("splice AMS i=2: %v", err)
	}

	seal2Unsigned := foldHeader("ARC-Seal", []string{
		"i=2",
		"a=rsa-sha256",
		fmt.Sprintf("t=%d", fixedNow().Unix()),
		"cv=pass",
		"d=forward-b.example",
		"s=sel-b",
		"b=",
	})
	var sealInput strings.Builder
	for _, h := range arcHeadersUpTo(modHeaders, 2) {
		sealInput.WriteString(canonicalizeHeaderRaw(h.raw, canonRelaxed))
	}
	sealInput.WriteString(canonicalizeHeaderRaw(aar2, canonRelaxed))
	sealInput.WriteString(canonicalizeHeaderRaw(ams2Raw, canonRelaxed))
	sealInput.WriteString(strings.TrimRight(canonicalizeHeaderRaw(seal2Unsigned, canonRelaxed), "\r\n"))
	seal2Hash := sha256.Sum256([]byte(sealInput.String()))
	seal2Sig, err := signHash(kb, seal2Hash[:])
	if err != nil {
		t.Fatalf("sign AS i=2: %v", err)
	}
	seal2Raw, err := spliceSignature(seal2Unsigned, seal2Sig)
	if err != nil {
		t.Fatalf("splice AS i=2: %v", err)
	}

	hop2Message := []byte(seal2Raw + ams2Raw + aar2 + tamperedHop1)
	res := mustVerify(t, hop2Message, lookup)
	if res.Pass || res.ChainValid {
		t.Fatalf("expected Verify to fail when AS(1) is invalid under a valid AS(2), got %+v", res)
	}
}

// TestVerifyAMSRequiresFromInHTag verifies that Verify rejects an
// ARC-Message-Signature whose h= tag omits From (RFC 8617 §4.1.2 / RFC 6376 §5.4).
func TestVerifyAMSRequiresFromInHTag(t *testing.T) {
	ka, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, ka),
	})

	headers, body := splitMessage(baseMessage)
	aar1 := foldHeader("ARC-Authentication-Results", []string{"i=1", authResultsA})
	bodyHash := sha256.Sum256(canonicalizeBody(body, canonRelaxed))

	// Select only To, Subject, Date (omitting From).
	var signed []rawHeader
	for _, want := range []string{"to", "subject", "date"} {
		for _, h := range headers {
			if strings.EqualFold(h.key, want) {
				signed = append(signed, h)
				break
			}
		}
	}

	ams1Unsigned := foldHeader("ARC-Message-Signature", []string{
		"i=1",
		"a=rsa-sha256",
		"c=relaxed/relaxed",
		"d=forward-a.example",
		"s=sel-a",
		fmt.Sprintf("t=%d", fixedNow().Unix()),
		"bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]),
		"h=to:subject:date",
		"b=",
	})
	var amsInput strings.Builder
	for _, h := range signed {
		amsInput.WriteString(canonicalizeHeaderRaw(h.raw, canonRelaxed))
	}
	amsInput.WriteString(strings.TrimRight(canonicalizeHeaderRaw(ams1Unsigned, canonRelaxed), "\r\n"))
	ams1Hash := sha256.Sum256([]byte(amsInput.String()))
	ams1Sig, err := signHash(ka, ams1Hash[:])
	if err != nil {
		t.Fatalf("sign AMS i=1: %v", err)
	}
	ams1Raw, err := spliceSignature(ams1Unsigned, ams1Sig)
	if err != nil {
		t.Fatalf("splice AMS i=1: %v", err)
	}

	seal1Unsigned := foldHeader("ARC-Seal", []string{
		"i=1",
		"a=rsa-sha256",
		fmt.Sprintf("t=%d", fixedNow().Unix()),
		"cv=none",
		"d=forward-a.example",
		"s=sel-a",
		"b=",
	})
	var sealInput strings.Builder
	sealInput.WriteString(canonicalizeHeaderRaw(aar1, canonRelaxed))
	sealInput.WriteString(canonicalizeHeaderRaw(ams1Raw, canonRelaxed))
	sealInput.WriteString(strings.TrimRight(canonicalizeHeaderRaw(seal1Unsigned, canonRelaxed), "\r\n"))
	seal1Hash := sha256.Sum256([]byte(sealInput.String()))
	seal1Sig, err := signHash(ka, seal1Hash[:])
	if err != nil {
		t.Fatalf("sign AS i=1: %v", err)
	}
	seal1Raw, err := spliceSignature(seal1Unsigned, seal1Sig)
	if err != nil {
		t.Fatalf("splice AS i=1: %v", err)
	}

	msg := []byte(seal1Raw + ams1Raw + aar1 + baseMessage)
	res := mustVerify(t, msg, lookup)
	if res.Pass || res.ChainValid {
		t.Fatalf("expected Verify to reject ARC-Message-Signature without From in h=, got %+v", res)
	}
}
