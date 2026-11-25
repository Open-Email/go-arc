package arc

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRelaxedHeaderCanonicalizationReadsBareCRAndLFAsWhitespace(t *testing.T) {
	for raw, want := range map[string]string{
		"Subject: Hel\rlo there\r\n":    "subject:Hel lo there\r\n",
		"Subject: Hel\nlo there\r\n":    "subject:Hel lo there\r\n",
		"Subject: Hel \r lo\r\n":        "subject:Hel lo\r\n",
		"Subject: folded\r\n\tline\r\n": "subject:folded line\r\n",
		"Subject: \r trailing \r\r\n":   "subject:trailing\r\n",
	} {
		if got := canonicalizeHeaderRaw(raw, canonRelaxed); got != want {
			t.Errorf("canonicalizeHeaderRaw(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestBareCRInsertedAfterSealingBreaksTheChain(t *testing.T) {
	original, lookup := testChain(t, 1)
	tampered := bytes.Replace(original, []byte("Subject: Hello there"), []byte("Subject: Hel\rlo there"), 1)
	if bytes.Equal(tampered, original) {
		t.Fatal("test chain has no Subject to alter")
	}
	if res := mustVerify(t, tampered, lookup); res.Pass {
		t.Fatal("the seal still verifies after a bare CR was inserted into the signed Subject")
	}
	_, relayKey, _ := testKeys(t)
	got, err := SignTransformed(tampered, tampered, signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup))
	if !errors.Is(err, ErrPriorChainFailed) {
		t.Fatalf("SignTransformed over the altered chain = %+v, %v; want ErrPriorChainFailed", got, err)
	}
}

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

func TestLookAlikeHeaderCannotTakeTheSignedSubjectSlot(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	head, body, _ := strings.Cut(baseMessage, "\r\n\r\n")
	withDecoy := head + "\r\nſubject: decoy\r\n\r\n" + body

	t.Run("signer covers the real Subject", func(t *testing.T) {
		sealed, err := Sign([]byte(withDecoy), signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
		if err != nil {
			t.Fatal(err)
		}
		if !mustVerify(t, sealed.Message, lookup).Pass {
			t.Fatal("the sealed message does not verify")
		}
		forged := bytes.Replace(sealed.Message, []byte("Subject: Hello there"), []byte("Subject: Pay this invoice"), 1)
		if mustVerify(t, forged, lookup).Pass {
			t.Fatal("the real Subject changed after sealing and the seal still verifies")
		}
	})
	t.Run("verifier ignores a look-alike added later", func(t *testing.T) {
		sealed, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
		if err != nil {
			t.Fatal(err)
		}
		h, b, _ := strings.Cut(string(sealed.Message), "\r\n\r\n")
		if res := mustVerify(t, []byte(h+"\r\nſubject: decoy\r\n\r\n"+b), lookup); !res.Pass {
			t.Fatalf("a look-alike header added below the signed one broke verification: %+v", res)
		}
	})
}

// Expected values are what go-msgauth's dkim package computes, which is
// what smtp-out signs DKIM with. A bare CR ends a run of WSP and trailing
// CR/LF runs are dropped; nothing else changes.
func TestRelaxedBodyCanonicalizationReadsBareCRLikeGoMsgauth(t *testing.T) {
	for body, want := range map[string]string{
		"":                           "",
		"\r\n\r\n":                   "",
		"a  b \t\r\n\r\n":            "a b\r\n",
		" lead\r\n":                  " lead\r\n",
		"a\nb":                       "a\r\nb\r\n",
		"a \nb\n\n":                  "a\r\nb\r\n",
		"a \rb\r\n":                  "a\rb\r\n",
		"a\r b\r\n":                  "a\r b\r\n",
		"a\r\r\n":                    "a\r\n",
		"a \r\r\nb\r\n":              "a\r\r\nb\r\n",
		"a\r":                        "a\r\n",
		"Gr\xfc\xdfe \xa0 x\r\n":     "Gr\xfc\xdfe \xa0 x\r\n",
		"a\r\n \r\n\t\r\nb\r\n\r\n ": "a\r\n\r\n\r\nb\r\n",
	} {
		if got := string(canonicalizeBody(body, canonRelaxed)); got != want {
			t.Errorf("canonicalizeBody(%q) = %q, want %q", body, got, want)
		}
	}
}
