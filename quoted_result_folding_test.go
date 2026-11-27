package arc

import (
	"strings"
	"testing"
)

func TestLegalFoldsInLongQuotedResult(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"m1._domainkey.relay.example": txtFor(t, key)})
	for _, tc := range []struct{ name, text string }{
		{"unescaped and escaped tabs", strings.Repeat("amber\\\tgold\r\n\t", 100) + "done"},
		{"folded whitespace within one quoted value", "amber" + strings.Repeat("\t", 80) + "\r\n" + strings.Repeat("\t", 80) + "gold"},
		{"fold inside a long whitespace run", "amber" + strings.Repeat("\t", 760) + "\r\n" + strings.Repeat("\t", 760) + "gold"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const prefix = "relay.example; dkim=neutral reason=\""
			auth := prefix + tc.text + "\""
			signed, err := Sign([]byte(baseMessage), signConfig(key, "relay.example", "m1", auth, lookup))
			if err != nil {
				t.Fatal(err)
			}
			headers, _ := splitMessage(string(signed.Message))
			aar, _ := findARCHeader(headers, "ARC-Authentication-Results", 1)
			for _, line := range strings.Split(strings.TrimSuffix(aar.raw, "\r\n"), "\r\n") {
				if len(line) > 998 || strings.Trim(line, " \t") == "" {
					t.Fatalf("AAR contains an invalid folded line of %d bytes", len(line))
				}
				if strings.HasSuffix(line, "\\") {
					t.Fatal("A quoted-pair was split across a fold")
				}
			}
			verified := mustVerify(t, signed.Message, lookup)
			got, ok := verified.OldestAuthResults()
			if !verified.Pass || !ok || got != strings.ReplaceAll(auth, "\r\n", "") {
				t.Fatal("signed result did not round-trip with the original whitespace")
			}
		})
	}
}
