package arc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

var original8BitMessage = []byte("From: alice@origin.example\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain; charset=UTF-8\r\n" +
	"Content-Transfer-Encoding: 8bit\r\n" +
	"\r\n" +
	"café\r\n")

func transformedMessage(original []byte) []byte {
	outbound := bytes.Replace(original, []byte("Content-Transfer-Encoding: 8bit"), []byte("Content-Transfer-Encoding: base64"), 1)
	return bytes.Replace(outbound, []byte("café\r\n"), []byte("Y2Fmw6kNCg==\r\n"), 1)
}

func TestSignTransformedValidatesPriorARCOnOriginal(t *testing.T) {
	priorKey, relayKey, _ := testKeys(t)
	lookup := dnsStub(map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, priorKey),
		"sel-b._domainkey.forward-b.example": txtFor(t, relayKey),
	})
	prior, err := Sign(original8BitMessage, signConfig(priorKey, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatal(err)
	}
	outbound := transformedMessage(prior.Message)
	if result := mustVerify(t, outbound, lookup); result.Pass {
		t.Fatal("the prior AMS should fail on the rewritten body")
	}

	got, err := SignTransformed(prior.Message, outbound, signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup))
	if err != nil {
		t.Fatal(err)
	}
	if got.CV != ChainPass || got.Instance != 2 {
		t.Fatalf("transformed seal has cv=%s, instance=%d, want cv=pass, instance=2", got.CV, got.Instance)
	}
	if !bytes.HasSuffix(got.Message, outbound) {
		t.Fatal("the new ARC set must preserve all outbound bytes")
	}
	verified := mustVerify(t, got.Message, lookup)
	if !verified.Pass || !verified.ChainValid || verified.Instance != 2 {
		t.Fatalf("downstream ARC verification failed: %+v", verified)
	}
	if results, ok := verified.OldestAuthResults(); !ok || results != authResultsA {
		t.Fatalf("original ARC authentication results changed: %q", results)
	}
}

func TestSignTransformedPreservesNonUTF8OriginalBodyHash(t *testing.T) {
	const headers = "From: alice@origin.example\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=windows-1252\r\n"
	const body = "  caf\xe9\t\r\n\r\n"
	const canonicalBody = " caf\xe9\r\n"
	original := []byte(headers + "Content-Transfer-Encoding: 8bit\r\n\r\n" + body)
	priorKey, relayKey, _ := testKeys(t)
	lookup := dnsStub(map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, priorKey),
		"sel-b._domainkey.forward-b.example": txtFor(t, relayKey),
	})
	prior, err := Sign(original, signConfig(priorKey, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatal(err)
	}
	priorHeaders, _ := splitMessage(string(prior.Message))
	ams, ok := findARCHeader(priorHeaders, "ARC-Message-Signature", 1)
	if !ok {
		t.Fatal("original ARC message signature missing")
	}
	wantHash := sha256.Sum256([]byte(canonicalBody))
	if got, want := parseTags(ams.value)["bh"], base64.StdEncoding.EncodeToString(wantHash[:]); got != want {
		t.Fatalf("original body hash = %q, want %q for exact Windows-1252 octets", got, want)
	}

	outbound := bytes.Replace(prior.Message, []byte("Content-Transfer-Encoding: 8bit"), []byte("Content-Transfer-Encoding: base64"), 1)
	outbound = bytes.Replace(outbound, []byte(body), []byte(base64.StdEncoding.EncodeToString([]byte(body))+"\r\n"), 1)
	got, err := SignTransformed(prior.Message, outbound, signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup))
	if err != nil {
		t.Fatal(err)
	}
	if got.CV != ChainPass || !bytes.HasSuffix(got.Message, outbound) || !mustVerify(t, got.Message, lookup).Pass {
		t.Fatal("rewritten message did not preserve its outbound bytes and ARC chain")
	}
}

func TestSignTransformedRequiresIdenticalPriorARCHeaders(t *testing.T) {
	original, lookup := testChain(t, 1)
	_, relayKey, _ := testKeys(t)
	cfg := signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup)

	headers, _ := splitMessage(string(original))
	first, second := headers[0].raw, headers[1].raw
	for _, tt := range []struct {
		name               string
		original, outbound []byte
	}{
		{"rewritten", original, bytes.Replace(original, []byte("ARC-Seal:"), []byte("Arc-Seal:"), 1)},
		{"removed", original, original[len(first):]},
		{"added", original, append([]byte(first), original...)},
		{"reordered", original, append([]byte(second+first), original[len(first)+len(second):]...)},
		{"introduced chain", []byte(baseMessage), original},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SignTransformed(tt.original, tt.outbound, cfg)
			if result != nil || !errors.Is(err, ErrARCHeadersChanged) {
				t.Fatalf("SignTransformed returned %v, %v, want ErrARCHeadersChanged", result, err)
			}
		})
	}
}

func TestSignTransformedRefusesUnvalidatedPriorChain(t *testing.T) {
	original, lookup := testChain(t, 1)
	_, relayKey, _ := testKeys(t)
	invalid := append(bytes.Clone(original), []byte("altered body\r\n")...)
	malformed := append([]byte("ARC-Seal: invalid instance\r\n"), []byte(baseMessage)...)
	dnsUnavailable := func(string) ([]string, error) {
		return nil, errors.New("DNS unavailable")
	}
	for _, tt := range []struct {
		name     string
		original []byte
		lookup   LookupTXT
		want     error
	}{
		{"invalid original", invalid, lookup, ErrPriorChainFailed},
		{"DNS unavailable", original, dnsUnavailable, ErrPriorChainFailed},
		{"malformed prior headers", malformed, lookup, ErrMalformedChain},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outbound := bytes.Replace(tt.original, []byte("Subject: Hello there"), []byte("Subject: altered"), 1)
			cfg := signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, tt.lookup)
			got, err := SignTransformed(tt.original, outbound, cfg)
			if got != nil || !errors.Is(err, tt.want) {
				t.Fatalf("SignTransformed returned %v, %v, want %v", got, err, tt.want)
			}
		})
	}
}

func TestSignTransformedCreatesFirstARCSet(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	outbound := transformedMessage(original8BitMessage)
	got, err := SignTransformed(original8BitMessage, outbound, signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatal(err)
	}
	if got.CV != ChainNone || got.Instance != 1 || !bytes.HasSuffix(got.Message, outbound) {
		t.Fatalf("wrong first-hop seal: %+v", got)
	}
	if verified := mustVerify(t, got.Message, lookup); !verified.Pass || !verified.ChainValid || verified.Instance != 1 {
		t.Fatalf("downstream ARC verification failed: %+v", verified)
	}
}

func TestSignTransformedCoversRetainedDKIMHeaders(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	original := append([]byte("DKIM-Signature: v=1; d=origin.example; b=original\r\n"), original8BitMessage...)
	outbound := append([]byte("DKIM-Signature: v=1; d=forward.example; b=local\r\n"), transformedMessage(original)...)
	got, err := SignTransformed(original, outbound, signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatal(err)
	}
	if !mustVerify(t, got.Message, lookup).Pass {
		t.Fatal("the unmodified transformed message must verify")
	}
	for _, signature := range []string{"b=original", "b=local"} {
		tampered := bytes.Replace(got.Message, []byte(signature), []byte("b=changed"), 1)
		if mustVerify(t, tampered, lookup).Pass {
			t.Errorf("the transformed seal did not cover DKIM signature %q", signature)
		}
	}
}

func TestSignIgnoresNonStandardARCPrefixedHeaders(t *testing.T) {
	priorKey, relayKey, _ := testKeys(t)
	lookup := dnsStub(map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, priorKey),
		"sel-b._domainkey.forward-b.example": txtFor(t, relayKey),
	})

	t.Run("first hop with non-standard ARC-Foo i=1", func(t *testing.T) {
		original := append([]byte("ARC-Foo: i=1; vendor-extension\r\n"), original8BitMessage...)
		outbound := transformedMessage(original)
		for _, fn := range []struct {
			name string
			sign func() (*SignResult, error)
		}{
			{"Sign", func() (*SignResult, error) {
				return Sign(original, signConfig(priorKey, "forward-a.example", "sel-a", authResultsA, lookup))
			}},
			{"SignTransformed", func() (*SignResult, error) {
				return SignTransformed(original, outbound, signConfig(priorKey, "forward-a.example", "sel-a", authResultsA, lookup))
			}},
		} {
			t.Run(fn.name, func(t *testing.T) {
				got, err := fn.sign()
				if err != nil {
					t.Fatalf("%s failed: %v", fn.name, err)
				}
				if verified := mustVerify(t, got.Message, lookup); !verified.Pass || !verified.ChainValid || verified.Instance != 1 {
					t.Fatalf("%s emitted an invalid seal when ARC-Foo: i=1 was present: %+v", fn.name, verified)
				}
				// Verify that the RFC 8617 seal scope excludes ARC-Foo completely.
				headers, _ := splitMessage(string(got.Message))
				seal, _ := findARCHeader(headers, "ARC-Seal", 1)
				aar, _ := findARCHeader(headers, "ARC-Authentication-Results", 1)
				ams, _ := findARCHeader(headers, "ARC-Message-Signature", 1)
				if err := verifySignature("ARC-Seal", seal, []rawHeader{aar, ams}, "", lookup); err != nil {
					t.Fatalf("RFC 8617 seal verification without ARC-Foo failed: %v", err)
				}
			})
		}
	})

	t.Run("second hop with valid i=1 chain and ARC-Foo i=2", func(t *testing.T) {
		hop1, err := Sign(original8BitMessage, signConfig(priorKey, "forward-a.example", "sel-a", authResultsA, lookup))
		if err != nil {
			t.Fatal(err)
		}
		original := append([]byte("ARC-Foo: i=2; vendor-extension\r\n"), hop1.Message...)
		outbound := transformedMessage(original)
		got, err := SignTransformed(original, outbound, signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup))
		if err != nil {
			t.Fatalf("SignTransformed failed: %v", err)
		}
		if verified := mustVerify(t, got.Message, lookup); !verified.Pass || !verified.ChainValid || verified.Instance != 2 {
			t.Fatalf("SignTransformed emitted an invalid seal when ARC-Foo: i=2 was present: %+v", verified)
		}
	})
}

func TestSignTransformedFoldsLongHeaderListWithinLineLimit(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})

	var dkims strings.Builder
	for i := 0; i < 65; i++ {
		fmt.Fprintf(&dkims, "DKIM-Signature: v=1; d=d%d.example; b=sig%d\r\n", i, i)
	}
	original := append([]byte(dkims.String()), original8BitMessage...)
	outbound := transformedMessage(original)

	got, err := SignTransformed(original, outbound, signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatalf("SignTransformed failed: %v", err)
	}
	for _, line := range strings.Split(string(got.Message), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("emitted line exceeds RFC 5322 998-byte limit (%d bytes): %.80q...", len(line), line)
		}
	}
	if verified := mustVerify(t, got.Message, lookup); !verified.Pass || !verified.ChainValid {
		t.Fatalf("folded transformed AMS failed verification: %+v", verified)
	}
	for _, marker := range []string{"b=sig0", "b=sig32", "b=sig64"} {
		tampered := bytes.Replace(got.Message, []byte(marker), []byte("b=tampered"), 1)
		if mustVerify(t, tampered, lookup).Pass {
			t.Errorf("folded h= failed to cover DKIM signature %q", marker)
		}
	}
}

func TestSignTransformedPreservesNonASCIIHeaderOctets(t *testing.T) {
	// RFC 6376 §3.4.2 relaxed header canonicalization touches ASCII SP/HTAB
	// and CRLF folds only. Non-ASCII bytes that decode as Unicode whitespace
	// (UTF-8 U+00A0 NBSP / Windows-1252 "Â\xa0", U+0085 NEL, U+202F NNBSP)
	// must be preserved byte for byte.
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"NBSP_0xC2_0xA0", "Subject: Price:\xc2\xa0100\r\n", "subject:Price:\xc2\xa0100\r\n"},
		{"NEL_0xC2_0x85", "Subject: Line1\xc2\x85Line2\r\n", "subject:Line1\xc2\x85Line2\r\n"},
		{"NNBSP_0xE2_0x80_0xAF", "Subject: 12:30\xe2\x80\xafPM\r\n", "subject:12:30\xe2\x80\xafPM\r\n"},
		{"folded_with_NBSP", "Subject:  Price:\r\n\t\xc2\xa0 100 \t\r\n", "subject:Price: \xc2\xa0 100\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalizeHeaderRaw(tc.raw, canonRelaxed); got != tc.want {
				t.Fatalf("canonicalizeHeaderRaw(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}

	priorKey, relayKey, _ := testKeys(t)
	lookup := dnsStub(map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, priorKey),
		"sel-b._domainkey.forward-b.example": txtFor(t, relayKey),
	})
	subjRaw := "Subject: Price:\xc2\xa0100\r\n"
	subjCanon := "subject:Price:\xc2\xa0100\r\n"
	body := "caf\xe9\r\n"
	msg := "From: alice@origin.example\r\n" + subjRaw +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=windows-1252\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + body

	// Build a strictly RFC 6376 / RFC 8617 compliant i=1 ARC set over msg.
	aar1 := "ARC-Authentication-Results: i=1; " + authResultsA + "\r\n"
	bh := sha256.Sum256([]byte(body))
	ams1Unsigned := fmt.Sprintf("ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=forward-a.example; s=sel-a; t=%d; bh=%s; h=from:subject; b=\r\n",
		fixedNow().Unix(), base64.StdEncoding.EncodeToString(bh[:]))
	amsHash := sha256.New()
	amsHash.Write([]byte("from:alice@origin.example\r\n"))
	amsHash.Write([]byte(subjCanon))
	amsHash.Write([]byte(strings.TrimRight(canonicalizeHeaderRaw(ams1Unsigned, canonRelaxed), "\r\n")))
	ams1Sig, err := signHash(priorKey, amsHash.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	ams1, err := spliceSignature(ams1Unsigned, ams1Sig)
	if err != nil {
		t.Fatal(err)
	}
	seal1Unsigned := fmt.Sprintf("ARC-Seal: i=1; a=rsa-sha256; t=%d; cv=none; d=forward-a.example; s=sel-a; b=\r\n", fixedNow().Unix())
	sealHash := sha256.New()
	sealHash.Write([]byte(canonicalizeHeaderRaw(aar1, canonRelaxed)))
	sealHash.Write([]byte(canonicalizeHeaderRaw(ams1, canonRelaxed)))
	sealHash.Write([]byte(strings.TrimRight(canonicalizeHeaderRaw(seal1Unsigned, canonRelaxed), "\r\n")))
	seal1Sig, err := signHash(priorKey, sealHash.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	seal1, err := spliceSignature(seal1Unsigned, seal1Sig)
	if err != nil {
		t.Fatal(err)
	}

	original := []byte(seal1 + ams1 + aar1 + msg)
	outbound := bytes.Replace(original, []byte("Content-Transfer-Encoding: 8bit"), []byte("Content-Transfer-Encoding: base64"), 1)
	outbound = bytes.Replace(outbound, []byte(body), []byte(base64.StdEncoding.EncodeToString([]byte(body))+"\r\n"), 1)

	got, err := SignTransformed(original, outbound, signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup))
	if err != nil {
		t.Fatalf("SignTransformed rejected a valid RFC 6376 prior chain with 0xC2 0xA0 in Subject: %v", err)
	}
	if got.CV != ChainPass || got.Instance != 2 || !mustVerify(t, got.Message, lookup).Pass {
		t.Fatalf("transformed seal failed downstream verification: %+v", got)
	}
}
