package arc

import (
	"bytes"
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
		{"EAI headers", "Subject: Réunion\r\nFrom: mélo@example.org\r\n\r\nBonjour.\r\n", domain, selector},
		{"ASCII headers and UTF-8 body", "Subject: Reunion\r\nFrom: melo@example.org\r\n\r\nRéunion.\r\n", aDomain, aSelector},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := Sign([]byte(tc.msg), cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"ARC-Message-Signature", "ARC-Seal"} {
				headers, _ := splitMessage(string(first.Message))
				field, ok := findARCHeader(headers, name, 1)
				tags := parseTags(field.value)
				if !ok || tags["d"] != tc.wantDomain || tags["s"] != tc.wantSelector {
					t.Fatalf("%s identity = %q, %q; want %q, %q", name, tags["d"], tags["s"], tc.wantDomain, tc.wantSelector)
				}
			}
			if verified := mustVerify(t, first.Message, lookup); !verified.Pass {
				t.Fatalf("ARC verification with A-label DNS records failed: %v", verified.FailureReasons)
			}
			outbound := bytes.Replace(first.Message, []byte("Bonjour."), []byte("Bonjour de Paris."), 1)
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
