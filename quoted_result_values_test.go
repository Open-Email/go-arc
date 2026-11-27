package arc

import (
	"strings"
	"testing"
)

func TestCombinedResultsMatchQuotedServiceIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, service, spelling string
		want                    bool
	}{
		{"quoted DNS name", "edge.example", `"EDGE.example"`, true},
		{"quoted-pair", "edge.example", `"edge\.example"`, true},
		{"comments and folds", "edge.example", "(edge; one)\r\n\t\"edge.example\" (local) 1", true},
		{"quoted delimiters", "edge; (one)", `"edge; (one)"`, true},
		{"literal spaces", "edge  service", `"edge  service"`, true},
		{"safe fold within ID", "edge service", "\"edge\r\n service\"", true},
		{"another service", "edge.example", `"other.example"`, false},
		{"space difference", "edge service", `"edge  service"`, false},
		{"unclosed quote", "edge.example", `"edge.example`, false},
		{"unexpected text after ID", "edge.example", `"edge.example"x`, false},
		// The ingress stripping walker replaces all leading WSP in a
		// continuation line with one space. Trust only an ID it would strip.
		{"ambiguous folded spaces", "edge  service", "\"edge\r\n  service\"", false},
		{"ambiguous folded tab", "edge\tservice", "\"edge\r\n\tservice\"", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte("Authentication-Results: " + tc.spelling + "; dkim=pass\r\n" + baseMessage)
			payload, ok := CombinedAuthenticationResults(msg, tc.service)
			if ok != tc.want || ok && !strings.HasSuffix(payload, "; dkim=pass") {
				t.Fatalf("combined = %q, %t; want match %t", payload, ok, tc.want)
			}
			if _, ok := FindAuthenticationResults(msg, tc.service); ok {
				t.Fatal("legacy topmost lookup started accepting quoted identifiers")
			}
		})
	}
}

func TestQuotedAuthenticationResultWhitespaceRoundTrip(t *testing.T) {
	const reason = "dkim=pass reason=\"two  spaces; a\ttab and escaped\\  space\""
	const folded = "dkim=pass reason=\"two\r\n  spaces; a\ttab and escaped\\  space\""
	const want = "edge.example; " + reason
	msg := []byte("Authentication-Results: edge.example;\r\n\t" + folded + "\r\n" + baseMessage)
	if value, ok := CombinedAuthenticationResults(msg, "edge.example"); !ok || value != want {
		t.Errorf("combined = %q, %t; want %q", value, ok, want)
	}
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"m1._domainkey.relay.example": txtFor(t, key)})
	signed, err := Sign([]byte(baseMessage), signConfig(key, "relay.example", "m1", want, lookup))
	if err != nil {
		t.Fatal(err)
	}
	// Unfold only CRLF, preserving the actual bytes in the quoted value.
	headers, _ := splitMessage(string(signed.Message))
	aar, ok := findARCHeader(headers, "ARC-Authentication-Results", 1)
	if !ok || !strings.Contains(strings.ReplaceAll(aar.value, "\r\n", ""), `"two  spaces; a`+"\t"+`tab and escaped\  space"`) {
		t.Errorf("signed AAR changed the quoted value: %q", aar.value)
	}
	if _, value, ok := LatestARCAuthResults(signed.Message); !ok || value != want {
		t.Errorf("latest = %q, %t; want %q", value, ok, want)
	}
	verified := mustVerify(t, signed.Message, lookup)
	value, ok := verified.OldestAuthResults()
	if !verified.Pass || !ok || value != want {
		t.Errorf("verified oldest = %q, %t, pass=%t; want %q", value, ok, verified.Pass, want)
	}
}
