package arc

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSignFoldsQuotedAuthResultsWithinLineLimit(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	var props []string
	for i := 0; i < 60; i++ {
		props = append(props, fmt.Sprintf("policy.p%02d=v%02d.example.org", i, i))
	}
	long := strings.Join(props, " ")
	for name, ar := range map[string]string{
		"quote inside a comment": "forward-a.example; dkim=pass (it\"s fine) " + long,
		"long quoted string":     "forward-a.example; dkim=pass reason=\"" + long + "\"",
		"semicolon in quotes":    "forward-a.example; dkim=pass reason=\"a;b\" " + long,
		"semicolon in comment":   "forward-a.example; dkim=pass (a;b) " + long,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Sign(original8BitMessage, signConfig(key, "forward-a.example", "sel-a", ar, lookup))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(got.Message), "\r\n") {
				if len(line) > 998 {
					t.Fatalf("emitted a %d-byte line: %.80q...", len(line), line)
				}
			}
			if verified := mustVerify(t, got.Message, lookup); !verified.Pass || !verified.ChainValid {
				t.Fatalf("folded AAR failed verification: %+v", verified)
			}
			if _, payload, ok := LatestARCAuthResults(got.Message); !ok || payload != ar {
				t.Fatalf("LatestARCAuthResults() = (%q, %t), want (%q, true)", payload, ok, ar)
			}
		})
	}
}

func TestSplitAuthResultsClausesKeepsQuotedAndCommentedSemicolons(t *testing.T) {
	got := splitAuthResultsClauses(`mx.example; dkim=pass reason="a;b\";c" (x;(y;z)"q;) header.d=d; spf=pass`)
	want := []string{`mx.example`, ` dkim=pass reason="a;b\";c" (x;(y;z)"q;) header.d=d`, ` spf=pass`}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("splitAuthResultsClauses = %q, want %q", got, want)
	}
}

// Header names are ASCII (RFC 5322 §3.6.8). A Unicode look-alike such as
// "ſubject" (U+017F, which strings.EqualFold folds to "s") is a different
// header to every other implementation, so it must never take a signed
// name's place.
func TestHeaderNamesFoldASCIIOnly(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"Subject", "subject", true},
		{"ARC-SEAL", "ARC-Seal", true},
		{"ſubject", "subject", false},
		{"Keywords", "keywords", false}, // Kelvin sign
		{"ARC-ſeal", "ARC-Seal", false},
	} {
		if got := asciiEqualFold(tc.a, tc.b); got != tc.want {
			t.Errorf("asciiEqualFold(%q, %q) = %t, want %t", tc.a, tc.b, got, tc.want)
		}
	}
	if got := asciiLower("SUBJECT-K"); got != "subject-K" {
		t.Errorf("asciiLower changed a non-ASCII rune: %q", got)
	}
}

// A name that only looks like "Subject" is no header field at all (its name
// is not printable ASCII), so the message is refused: a signer does not seal
// it, and a chain fails once such a line has been added.
func TestLookAlikeHeaderIsRefused(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	head, body, _ := strings.Cut(baseMessage, "\r\n\r\n")
	withDecoy := head + "\r\nſubject: decoy\r\n\r\n" + body

	if got, err := Sign([]byte(withDecoy), signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup)); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("Sign over a look-alike header = %v, %v; want ErrMalformedMessage", got, err)
	}
	sealed, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatal(err)
	}
	h, b, _ := strings.Cut(string(sealed.Message), "\r\n\r\n")
	if res := mustVerify(t, []byte(h+"\r\nſubject: decoy\r\n\r\n"+b), lookup); res.Pass {
		t.Fatal("the chain still verifies with a look-alike header added below the signed one")
	}
}
