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
