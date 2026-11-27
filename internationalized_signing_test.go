package arc

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestInternationalizedSigningIdentity(t *testing.T) {
	const (
		domain    = "bücher.example"
		selector  = "märz"
		aDomain   = "xn--bcher-kva.example"
		aSelector = "xn--mrz-qla"
	)
	key, relay, _ := testKeys(t)
	lookup := dnsStub(map[string]string{
		aSelector + "._domainkey." + aDomain: txtFor(t, key),
		"next._domainkey.relay.example":      txtFor(t, relay),
	})
	cfg := signConfig(key, domain, selector, "auth.example; none", lookup)
	for _, tc := range []struct {
		name, msg, wantDomain, wantSelector string
	}{
		// A-labels even in an internationalized message: a verifier that
		// does not convert U-labels would find no key (RFC 8616 §4 permits,
		// but does not require, U-labels there).
		{"EAI headers", "Subject: Réunion\r\nFrom: mélo@example.org\r\n\r\nBonjour.\r\n", aDomain, aSelector},
		{"ASCII headers and UTF-8 body", "Subject: Reunion\r\nFrom: melo@example.org\r\n\r\nRéunion.\r\n", aDomain, aSelector},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := Sign([]byte(tc.msg), cfg)
			if err != nil {
				t.Fatal(err)
			}
			headers, _ := splitMessage(string(first.Message))
			for _, name := range []string{"ARC-Message-Signature", "ARC-Seal"} {
				field, ok := findARCHeader(headers, name, 1)
				tags := parseTags(field.value)
				if !ok || tags["d"] != tc.wantDomain || tags["s"] != tc.wantSelector {
					t.Fatalf("%s identity = %q, %q; want %q, %q", name, tags["d"], tags["s"], tc.wantDomain, tc.wantSelector)
				}
			}
			if verified := mustVerify(t, first.Message, lookup); !verified.Pass {
				t.Fatalf("ARC verification with A-label DNS records failed: %v", verified.FailureReasons)
			}
			outbound := append(bytes.Clone(first.Message), []byte("Forwarded.\r\n")...)
			second, err := SignTransformed(first.Message, outbound, signConfig(relay, "relay.example", "next", "relay.example; arc=pass", lookup))
			if err != nil {
				t.Fatal(err)
			}
			if second.CV != ChainPass || !bytes.HasSuffix(second.Message, outbound) || !mustVerify(t, second.Message, lookup).Pass {
				t.Fatal("transformed chain did not preserve and verify the original ARC fields")
			}
		})
	}
}

func TestInternationalizedSigningIdentityValidation(t *testing.T) {
	key, _, _ := testKeys(t)
	const message = "From: mélo@example.org\r\n\r\nBonjour.\r\n"
	for _, label := range []string{"a\u200db", "bu\u0308cher", strings.Repeat("é", 64), "bücher\u3002example", "bücher\x00"} {
		for _, ids := range [][2]string{{label + ".example", "mail"}, {"example.org", label}} {
			if _, err := Sign([]byte(message), signConfig(key, ids[0], ids[1], authResultsA, nil)); err == nil {
				t.Errorf("Sign accepted invalid internationalized DNS identity %q, %q", ids[0], ids[1])
			}
		}
	}
}

// A seal made by another implementation with U-labels in d= and s= is
// verified under the A-label name, and ASCII names that DNS can hold but the
// signer's host-name grammar refuses are looked up as written.
func TestVerifyLooksKeysUpUnderTheirDNSName(t *testing.T) {
	key, _, _ := testKeys(t)
	for _, tc := range []struct{ domain, selector, lookupName string }{
		{"bücher.example", "märz", "xn--mrz-qla._domainkey.xn--bcher-kva.example"},
		{"mail_relay.example", "sel", "sel._domainkey.mail_relay.example"},
		{"localhost", "sel", "sel._domainkey.localhost"},
		{"Forward-A.Example", "Sel_1", "Sel_1._domainkey.Forward-A.Example"},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			lookup := dnsStub(map[string]string{tc.lookupName: txtFor(t, key)})
			msg := handSealIdentity(t, key, baseMessage, tc.domain, tc.selector)
			if res := mustVerify(t, msg, lookup); !res.Pass {
				t.Fatalf("seal by d=%s s=%s does not verify: %v", tc.domain, tc.selector, res.FailureReasons)
			}
		})
	}
	for _, bad := range [][2]string{{"a..example", "sel"}, {"example.", "sel"}, {"a b.example", "sel"}, {"example.org", strings.Repeat("s", 64)}, {strings.Repeat("a.", 125) + "example", "sel"}} {
		lookup := func(string) ([]string, error) { return []string{txtFor(t, key)}, nil }
		msg := handSealIdentity(t, key, baseMessage, bad[0], bad[1])
		if res := mustVerify(t, msg, lookup); res.Pass {
			t.Errorf("a seal by d=%q s=%q verified", bad[0], bad[1])
		}
	}
}

// handSealIdentity builds a first-hop ARC set signed as the given d= and s=,
// written exactly as given, the way another implementation might.
func handSealIdentity(t *testing.T, key *rsa.PrivateKey, msg, domain, selector string) []byte {
	t.Helper()
	headers, body := splitMessage(msg)
	signed := selectSignedHeaders(headers)
	var names []string
	for _, h := range signed {
		names = append(names, asciiLower(h.key))
	}
	bodyHash := sha256.Sum256(canonicalizeBody(body, canonRelaxed))
	aar := foldHeader("ARC-Authentication-Results", []string{"i=1", authResultsA})
	amsUnsigned := foldHeader("ARC-Message-Signature", []string{
		"i=1", "a=rsa-sha256", "c=relaxed/relaxed", "d=" + domain, "s=" + selector,
		"bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]), "h=" + strings.Join(names, ":"), "b=",
	})
	hasher := sha256.New()
	for _, h := range signed {
		hasher.Write([]byte(canonicalizeHeaderRaw(h.raw, canonRelaxed)))
	}
	hasher.Write([]byte(strings.TrimSuffix(canonicalizeHeaderRaw(amsUnsigned, canonRelaxed), "\r\n")))
	amsSig, err := signHash(key, hasher.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	ams, err := spliceSignature(amsUnsigned, amsSig)
	if err != nil {
		t.Fatal(err)
	}
	sealUnsigned := foldHeader("ARC-Seal", []string{"i=1", "a=rsa-sha256", "cv=none", "d=" + domain, "s=" + selector, "b="})
	hasher = sha256.New()
	hasher.Write([]byte(canonicalizeHeaderRaw(aar, canonRelaxed)))
	hasher.Write([]byte(canonicalizeHeaderRaw(ams, canonRelaxed)))
	hasher.Write([]byte(strings.TrimSuffix(canonicalizeHeaderRaw(sealUnsigned, canonRelaxed), "\r\n")))
	sealSig, err := signHash(key, hasher.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	seal, err := spliceSignature(sealUnsigned, sealSig)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(seal + ams + aar + msg)
}
