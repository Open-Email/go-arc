package arc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
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
