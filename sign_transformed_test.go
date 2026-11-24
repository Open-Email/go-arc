package arc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
