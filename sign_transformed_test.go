package arc

import (
	"bytes"
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
