package arc

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Lines that are not a Subject field to any reader of RFC 5322, where a field
// name is printable ASCII followed by optional SP or HTAB and a colon. Each
// one used to be read as "Subject" because the name was trimmed of Unicode
// whitespace, or of CR and LF.
var subjectDecoys = map[string]string{
	"bare CR before the name":  "\rSubject: Hello there",
	"bare CR before the colon": "Subject\r: Hello there",
	"CR and space":             "Subject \r : Hello there",
	"no-break space":           "Subject : Hello there",
	"form feed":                "Subject\f: Hello there",
	"vertical tab":             "Subject\v: Hello there",
	"em space before the name": " Subject: Hello there",
	"next line U+0085":         "Subject\u0085: Hello there",
	"long s":                   "ſubject: Hello there",
	"no colon":                 "Subject",
	"NUL before the name":      "\x00Subject: Hello there",
}

func withHeaderLine(msg, line string) string {
	head, body, _ := strings.Cut(msg, "\r\n\r\n")
	return head + "\r\n" + line + "\r\n\r\n" + body
}

func TestFieldNameIsExactASCII(t *testing.T) {
	for name, line := range subjectDecoys {
		headers, _ := splitMessage(line + "\r\n\r\nbody\r\n")
		if len(headers) != 1 {
			t.Fatalf("%s: parsed %d headers", name, len(headers))
		}
		if asciiEqualFold(headers[0].key, "subject") {
			t.Errorf("%s: %q was read as a Subject field", name, line)
		}
	}
	for _, line := range []string{"Subject: x", "SUBJECT:x", "subject : x", "Subject\t \t: x", "Subject:"} {
		headers, _ := splitMessage(line + "\r\n\r\nbody\r\n")
		if len(headers) != 1 || !asciiEqualFold(headers[0].key, "subject") {
			t.Errorf("%q was not read as a Subject field: %+v", line, headers)
		}
	}
}

// An attacker rewrites the signed Subject and adds a line that canonicalizes
// to the original one. If the verifier takes that line for the Subject, the
// seal still verifies over a message whose real Subject has changed.
func TestDecoyLineCannotStandInForTheSignedSubject(t *testing.T) {
	sealed, lookup := testChain(t, 1)
	if !mustVerify(t, sealed, lookup).Pass {
		t.Fatal("the sealed message does not verify")
	}
	for name, line := range subjectDecoys {
		t.Run(name, func(t *testing.T) {
			forged := strings.Replace(string(sealed), "Subject: Hello there", "Subject: Pay this invoice", 1)
			if forged == string(sealed) {
				t.Fatal("test chain has no Subject to alter")
			}
			if mustVerify(t, []byte(withHeaderLine(forged, line)), lookup).Pass {
				t.Fatal("the real Subject changed after sealing and the seal still verifies")
			}
		})
	}
}

// The same line present before sealing must not be signed in the Subject's
// place: that would leave the real Subject outside the signature.
func TestSignerCoversTheRealSubjectDespiteADecoyLine(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for name, line := range subjectDecoys {
		t.Run(name, func(t *testing.T) {
			sealed, err := Sign([]byte(withHeaderLine(baseMessage, line)), signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
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
	}
}

// RFC 6376 §3.4.2: lowercase the name, drop WSP around the colon, remove the
// line break of each fold, turn each run of SP and HTAB into one SP, and drop
// trailing WSP. A CR that is not part of a line break is an ordinary octet.
func TestRelaxedHeaderCanonicalization(t *testing.T) {
	for raw, want := range map[string]string{
		"Subject: Hello there\r\n":          "subject:Hello there\r\n",
		"SUBJECT \t:  a \t b  \r\n":         "subject:a b\r\n",
		"Subject: folded\r\n\tline\r\n":     "subject:folded line\r\n",
		"Subject: folded\n\tline\n":         "subject:folded line\r\n",
		"Subject:\r\n folded\r\n":           "subject:folded\r\n",
		"Subject: a\r\n \r\n":               "subject:a\r\n",
		"Subject: a\r\n\t\r\n  b\r\n":       "subject:a b\r\n",
		"Subject: no line break":            "subject:no line break\r\n",
		"Subject:\r\n":                      "subject:\r\n",
		"Subject: Gr\xfc\xdfe \xa0 x\r\n":   "subject:Gr\xfc\xdfe \xa0 x\r\n",
		"Subject: a  b\r\n":                 "subject:a  b\r\n",
		"Subject: Hel\rlo there\r\n":        "subject:Hel\rlo there\r\n",
		"Subject: Hello\rthere\r\n":         "subject:Hello\rthere\r\n",
		"Subject: Hel \r lo\r\n":            "subject:Hel \r lo\r\n",
		"Subject:\rHello\r\n":               "subject:\rHello\r\n",
		"Subject: Hello\r\r\n":              "subject:Hello\r\r\n",
		"Subject: Hello \r\r\n":             "subject:Hello \r\r\n",
		"Subject: a\r\r\n b\r\n":            "subject:a\r b\r\n",
		"Subject: a\x0b\x0c\x00b\r\n":       "subject:a\x0b\x0c\x00b\r\n",
		"Subject\r: Hello\r\n":              "subject\r:Hello\r\n",
		"Subject : Hello\r\n":               "subject :Hello\r\n",
		"ſubject: Hello\r\n":                "ſubject:Hello\r\n",
		"Subject: one: two : three\r\n":     "subject:one: two : three\r\n",
		"X-Long:   \t  \r\n \t x\r\n":       "x-long:x\r\n",
		"Subject: trailing\t\r\n":           "subject:trailing\r\n",
		"Subject: tab\tinside\r\n":          "subject:tab inside\r\n",
		"Subject: a\r\n b\r\n\tc\r\n   d\n": "subject:a b c d\r\n",
	} {
		if got := canonicalizeHeaderRaw(raw, canonRelaxed); got != want {
			t.Errorf("canonicalizeHeaderRaw(%q) = %q, want %q", raw, got, want)
		}
	}
	// A line with no colon is not a header field and is hashed as found.
	if got := canonicalizeHeaderRaw("Subject\r\n", canonRelaxed); got != "Subject\r\n" {
		t.Errorf("colon-less line was rewritten to %q", got)
	}
}

func TestBareCRChangeAfterSealingBreaksTheChain(t *testing.T) {
	original, lookup := testChain(t, 1)
	_, relayKey, _ := testKeys(t)
	for name, subject := range map[string]string{
		"inserted":            "Subject: Hel\rlo there",
		"in place of a space": "Subject: Hello\rthere",
		"beside a space":      "Subject: Hello \rthere",
		"after the colon":     "Subject:\rHello there",
		"before the colon":    "Subject\r: Hello there",
		"before the name":     "\rSubject: Hello there",
		"at the end":          "Subject: Hello there\r",
	} {
		t.Run(name, func(t *testing.T) {
			tampered := bytes.Replace(original, []byte("Subject: Hello there"), []byte(subject), 1)
			if bytes.Equal(tampered, original) {
				t.Fatal("test chain has no Subject to alter")
			}
			if mustVerify(t, tampered, lookup).Pass {
				t.Fatalf("the seal still verifies with the Subject line changed to %q", subject)
			}
			got, err := SignTransformed(tampered, tampered, signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup))
			if !errors.Is(err, ErrPriorChainFailed) {
				t.Fatalf("SignTransformed over the altered chain = %+v, %v; want ErrPriorChainFailed", got, err)
			}
		})
	}
}

// The values Mail::DKIM 0.58 computes for a body in wire form (CRLF line
// endings). A CR that is not part of a CRLF is an ordinary octet (RFC 6376
// §3.4.4 names only SP and HTAB as whitespace). Two conveniences for input
// that is not in wire form mirror what an SMTP DATA writer does to it: a lone
// LF is a line break, and a CR at the very end is the start of the final one.
func TestRelaxedBodyCanonicalization(t *testing.T) {
	for body, want := range map[string]string{
		"":                           "",
		"\r\n\r\n":                   "",
		"a  b \t\r\n\r\n":            "a b\r\n",
		" lead\r\n":                  " lead\r\n",
		"a":                          "a\r\n",
		"a \rb\r\n":                  "a \rb\r\n",
		"a\r b\r\n":                  "a\r b\r\n",
		"a\r\r\n":                    "a\r\r\n",
		"a \r\r\nb\r\n":              "a \r\r\nb\r\n",
		"a \r \r\n":                  "a \r\r\n",
		"\ra\r\n":                    "\ra\r\n",
		"a\r\n\r\r\n":                "a\r\n\r\r\n",
		"line1\r\r\nline2\r\r\n":     "line1\r\r\nline2\r\r\n",
		"Gr\xfc\xdfe \xa0 x\r\n":     "Gr\xfc\xdfe \xa0 x\r\n",
		"a\r\n \r\n\t\r\nb\r\n\r\n ": "a\r\n\r\n\r\nb\r\n",
		// Not in wire form.
		"a\nb":      "a\r\nb\r\n",
		"a \nb\n\n": "a\r\nb\r\n",
		"a\r":       "a\r\n",
		"a\r\n\r":   "a\r\n",
	} {
		if got := string(canonicalizeBody(body, canonRelaxed)); got != want {
			t.Errorf("canonicalizeBody(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestBareCRInTheBodyAfterSealingBreaksTheChain(t *testing.T) {
	original, lookup := testChain(t, 1)
	for name, edit := range map[string][2]string{
		"space before a CR removed": {"Hello Bob,\r\n", "Hello Bob, \r\r\n"},
		"CR after a space":          {"Hello Bob,", "Hello \rBob,"},
		"CR before the line break":  {"Hello Bob,\r\n", "Hello Bob,\r\r\n"},
		"CR line at the end":        {"test message.\r\n", "test message.\r\n\r\r\n"},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := bytes.Replace(original, []byte(edit[0]), []byte(edit[1]), 1)
			if bytes.Equal(tampered, original) {
				t.Fatal("nothing was altered")
			}
			if mustVerify(t, tampered, lookup).Pass {
				t.Fatal("the seal still verifies over the altered body")
			}
		})
	}
	// Sealing a body that already holds bare CRs still round-trips.
	key, _, _ := testKeys(t)
	withCR := strings.Replace(baseMessage, "Hello Bob,\r\n", "Hello \rBob, \r\r\n\r\r\n", 1)
	sealed, err := Sign([]byte(withCR), signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatal(err)
	}
	if !mustVerify(t, sealed.Message, lookup).Pass {
		t.Fatal("a body with bare CRs does not verify after sealing")
	}
	for _, edit := range [][2]string{{"Hello \rBob, \r\r\n", "Hello Bob,\r\n"}, {"Hello \rBob,", "Hello\rBob,"}, {"\r\r\n\r\r\n", "\r\r\n"}} {
		tampered := bytes.Replace(sealed.Message, []byte(edit[0]), []byte(edit[1]), 1)
		if bytes.Equal(tampered, sealed.Message) {
			t.Fatalf("%q was not found", edit[0])
		}
		if mustVerify(t, tampered, lookup).Pass {
			t.Fatalf("the seal still verifies with %q changed to %q", edit[0], edit[1])
		}
	}
}

func TestParseTagsTrimsOnlyFoldingWhitespace(t *testing.T) {
	tags := parseTags(" a = rsa-sha256 ;\r\n\td\t=\texample.org\r\n ; s=sel;")
	for name, want := range map[string]string{"a": "rsa-sha256", "d": "example.org", "s": "sel"} {
		if tags[name] != want {
			t.Errorf("tag %q = %q, want %q", name, tags[name], want)
		}
	}
	for _, value := range []string{
		"d =example.org", " d=example.org", " d=example.org", "d\u0085=example.org", "\fd=example.org", "d\v=example.org",
	} {
		if got, ok := parseTags(value)["d"]; ok {
			t.Errorf("parseTags(%q) read a d= tag: %q", value, got)
		}
	}
	for _, value := range []string{"d=example.org ", "d= example.org", "d=example.org\f"} {
		if got := parseTags(value)["d"]; got == "example.org" {
			t.Errorf("parseTags(%q) dropped a non-ASCII or control character from the value", value)
		}
	}
}

func TestCanonicalizationTagAcceptsOnlyKnownValues(t *testing.T) {
	for c, want := range map[string][2]canonicalization{
		"":                      {canonSimple, canonSimple},
		"simple":                {canonSimple, canonSimple},
		"relaxed":               {canonRelaxed, canonSimple},
		"simple/relaxed":        {canonSimple, canonRelaxed},
		"relaxed/relaxed":       {canonRelaxed, canonRelaxed},
		"relaxed/simple":        {canonRelaxed, canonSimple},
		"relaxed/\r\n\trelaxed": {canonRelaxed, canonRelaxed},
	} {
		header, body, err := parseCanonicalization(c)
		if err != nil || header != want[0] || body != want[1] {
			t.Errorf("parseCanonicalization(%q) = %q, %q, %v; want %q, %q", c, header, body, err, want[0], want[1])
		}
	}
	for _, c := range []string{
		"bogus", "bogus/bogus", "relaxed/bogus", "bogus/relaxed", "Relaxed/Relaxed", "relaxed/relaxed/relaxed",
		"relaxed/", "/relaxed", "/", "relaxed /relaxed", "relaxed/relaxed ", "nofws", "relaxed/rel axed",
	} {
		if header, body, err := parseCanonicalization(c); err == nil {
			t.Errorf("parseCanonicalization(%q) = %q, %q; want an error", c, header, body)
		}
	}
}

// handSeal builds a first-hop ARC set over msg with the given AMS c= tag,
// canonicalizing as relaxed/relaxed whatever the tag says, and returns the
// sealed message. mutate may change the AMS before the seal covers it.
func handSeal(t *testing.T, key *rsa.PrivateKey, msg, cTag string, mutate func(ams string) string) []byte {
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
		"i=1", "a=rsa-sha256", "c=" + cTag, "d=forward-a.example", "s=sel-a",
		fmt.Sprintf("t=%d", fixedNow().Unix()),
		"bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]),
		"h=" + strings.Join(names, ":"), "b=",
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
	if mutate != nil {
		ams = mutate(ams)
	}
	sealUnsigned := foldHeader("ARC-Seal", []string{
		"i=1", "a=rsa-sha256", fmt.Sprintf("t=%d", fixedNow().Unix()), "cv=none", "d=forward-a.example", "s=sel-a", "b=",
	})
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

func TestVerifyRejectsUnknownCanonicalization(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	if res := mustVerify(t, handSeal(t, key, baseMessage, "relaxed/relaxed", nil), lookup); !res.Pass {
		t.Fatalf("the hand-built set does not verify: %+v", res)
	}
	for _, c := range []string{"bogus/bogus", "relaxed/bogus", "Relaxed/Relaxed", "relaxed/relaxed/x", "relaxed /relaxed"} {
		if res := mustVerify(t, handSeal(t, key, baseMessage, c, nil), lookup); res.Pass {
			t.Errorf("a signature with c=%s verified as if it were relaxed/relaxed", c)
		}
	}
}

// FWS inside a base64 tag value is ignored (RFC 6376 §3.5); nothing else is.
func TestSignatureBase64AllowsOnlyFoldingWhitespace(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	splitB := func(sep string) func(string) string {
		return func(ams string) string {
			i := strings.Index(ams, " b=") + 3 + 40
			return ams[:i] + sep + ams[i:]
		}
	}
	for _, sep := range []string{"\r\n\t", "\r\n ", " "} {
		if res := mustVerify(t, handSeal(t, key, baseMessage, "relaxed/relaxed", splitB(sep)), lookup); !res.Pass {
			t.Errorf("a b= value folded with %q does not verify: %+v", sep, res)
		}
	}
	for _, sep := range []string{" ", " ", "\u0085", "\f", "\v"} {
		if res := mustVerify(t, handSeal(t, key, baseMessage, "relaxed/relaxed", splitB(sep)), lookup); res.Pass {
			t.Errorf("a b= value containing %q verified", sep)
		}
	}
}

func TestHeaderListNamesTrimOnlyFoldingWhitespace(t *testing.T) {
	headers, _ := splitMessage(baseMessage)
	pick := func(hTag string) []string {
		selected, err := selectHeaders("ARC-Message-Signature", hTag, headers)
		if err != nil {
			t.Fatalf("selectHeaders(%q): %v", hTag, err)
		}
		var names []string
		for _, h := range selected {
			names = append(names, asciiLower(h.key))
		}
		return names
	}
	if got := pick("from :\r\n\t subject\t: To"); fmt.Sprint(got) != "[from subject to]" {
		t.Errorf("folded h= list selected %v", got)
	}
	for _, hTag := range []string{"from: subject", "from:subject ", "from:\fsubject", "from:subject\v", "from:ſubject", "from::"} {
		if got := pick(hTag); fmt.Sprint(got) != "[from]" {
			t.Errorf("selectHeaders(%q) selected %v, want only From", hTag, got)
		}
	}
}

func TestFindAuthenticationResultsRequiresTheExactAuthservID(t *testing.T) {
	const id = "mx.example.com"
	find := func(line string) (string, bool) {
		return FindAuthenticationResults([]byte(line+"\r\n"+baseMessage), id)
	}
	for _, line := range []string{
		"Authentication-Results: mx.example.com; dmarc=pass",
		"Authentication-Results: MX.Example.COM; dmarc=pass",
		"authentication-results:mx.example.com;dmarc=pass",
		"Authentication-Results:\r\n mx.example.com\r\n\t; dmarc=pass",
		"Authentication-Results: mx.example.com 1; dmarc=pass",
		"Authentication-Results : mx.example.com\t 1 ; dmarc=pass",
		"Authentication-Results: mx.example.com; none",
	} {
		if _, ok := find(line); !ok {
			t.Errorf("%q was not found", line)
		}
	}
	for _, line := range []string{
		"Authentication-Results: mx.example.com attacker; dmarc=pass",
		"Authentication-Results: mx.example.com\fattacker; dmarc=pass",
		"Authentication-Results: mx.example.com\vattacker; dmarc=pass",
		"Authentication-Results: mx.example.com\rattacker; dmarc=pass",
		"Authentication-Results: mx.example.com\r1; dmarc=pass",
		"Authentication-Results: mx.example.com 1; dmarc=pass",
		"Authentication-Results: mx.example.com attacker; dmarc=pass",
		"Authentication-Results: mx.example.com 1 attacker; dmarc=pass",
		"Authentication-Results: mx.example.com 1x; dmarc=pass",
		"Authentication-Results: mx.example.com.evil.example; dmarc=pass",
		"Authentication-Results: evil.mx.example.com; dmarc=pass",
		"Authentication-Results:  mx.example.com; dmarc=pass",
		"Authentication-Results : mx.example.com; dmarc=pass",
		"\rAuthentication-Results: mx.example.com; dmarc=pass",
		"Authentication-Results: ; dmarc=pass",
	} {
		if value, ok := find(line); ok {
			t.Errorf("%q matched %s and returned %q", line, id, value)
		}
	}
	if _, ok := FindAuthenticationResults([]byte("Authentication-Results: ; dmarc=pass\r\n"+baseMessage), ""); ok {
		t.Error("an empty authserv-id matched")
	}
	// The value returned is safe to place in a new header: no CR or LF.
	value, ok := find("Authentication-Results: mx.example.com;\r\n\tdkim=pass\rheader.d=a.example;\r\n spf=pass")
	if !ok || strings.ContainsAny(value, "\r\n") {
		t.Errorf("FindAuthenticationResults returned %q, %t", value, ok)
	}
}

// Every restart inside a nested comment used to rescan the rest of it.
func TestExtractInstanceTimeIsLinear(t *testing.T) {
	const n = 400_000
	for name, value := range map[string]string{
		"nested comments":    strings.Repeat("(;", n) + strings.Repeat(")", n) + " a=b",
		"comments after i":   strings.Repeat("i (;", n) + strings.Repeat(")", n),
		"one closed comment": "(" + strings.Repeat(";", 2*n) + ") a=b; i=7",
	} {
		done := make(chan int, 1)
		go func() { done <- extractInstance(value) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: extractInstance did not finish %d bytes in 10 s", name, len(value))
		}
	}
}

func TestExtractInstanceSkipsLeadingComments(t *testing.T) {
	for value, want := range map[string]int{
		"i=1; a=b":                      1,
		" (c;d) i (e;f) = (g) 2 (h); a": 2,
		"a=b; (c;d) i=3; e=f":           3,
		"(x; i=1; y) a=b":               0, // an i= inside a comment is not a tag
		"(x; i=1; y) a=b; i=4":          4,
		"a=(; i=5":                      5, // '(' inside another tag's value is not a comment
		"a=b; (unclosed; i=6":           0,
		"i (c) x=1; i=7":                7,
		"i=8) a=b":                      0,
		"z=From:a (b|c); i=9; d=x":      9,
		"a=b; i=0":                      0,
		"a=b; i=51":                     0,
		"a=b; i=10; i=11":               10,
	} {
		if got := extractInstance(value); got != want {
			t.Errorf("extractInstance(%q) = %d, want %d", value, got, want)
		}
	}
}

func TestSignRefusesAuthResultsItCannotFold(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for name, ar := range map[string]string{
		"long token":       "mx.forward-a.example; dkim=pass header.d=" + strings.Repeat("a", 1200) + ".example",
		"long authserv-id": strings.Repeat("a", 1200) + ".example; dkim=pass",
		"long comment":     "mx.forward-a.example; dkim=pass (" + strings.Repeat("x", 1200) + ")",
	} {
		got, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", ar, lookup))
		if !errors.Is(err, ErrLineTooLong) {
			t.Errorf("%s: Sign = %v, %v; want ErrLineTooLong", name, got, err)
		}
	}
	// 990 bytes still fit on a line of their own.
	ar := "mx.forward-a.example; dkim=pass header.d=" + strings.Repeat("a", 970) + ".example"
	got, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", ar, lookup))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(got.Message), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("emitted a %d-byte line", len(line))
		}
	}
	if !mustVerify(t, got.Message, lookup).Pass {
		t.Fatal("the sealed message does not verify")
	}
}

func TestSignRequiresAnAuthservID(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for _, ar := range []string{"", " \t\r\n", ";", " ; dkim=pass", "\r\n; spf=pass; dkim=pass", ";;"} {
		if got, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", ar, lookup)); err == nil {
			t.Errorf("Sign with AuthResults %q added %q", ar, firstLine(got.Message, "ARC-Authentication-Results"))
		}
	}
}

func firstLine(msg []byte, name string) string {
	for _, h := range strings.Split(string(msg), "\r\n") {
		if strings.HasPrefix(h, name) {
			return h
		}
	}
	return ""
}

// CR and LF in the results would otherwise end the header and start a new one.
func TestSignNeverEmitsBareCROrLFFromAuthResults(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	ar := "mx.forward-a.example; dkim=pass\r\nX-Injected: yes\rheader.d=a.example\nspf=pass"
	got, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", ar, lookup))
	if err != nil {
		t.Fatal(err)
	}
	headers, _ := splitMessage(string(got.Message))
	for _, h := range headers {
		if asciiEqualFold(h.key, "X-Injected") {
			t.Fatal("AuthResults injected a header field")
		}
	}
	if stripped := strings.ReplaceAll(string(got.Message), "\r\n", ""); strings.ContainsAny(stripped, "\r\n") {
		t.Fatal("the sealed message holds a CR or LF outside a CRLF")
	}
	if !mustVerify(t, got.Message, lookup).Pass {
		t.Fatal("the sealed message does not verify")
	}
}

// The new headers go on top, so a message that opens with a continuation
// line would have that line folded into the ARC-Authentication-Results.
func TestSignRefusesAMessageThatOpensWithAContinuationLine(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for _, prefix := range []string{" orphan\r\n", "\torphan\r\n", " \r\n"} {
		cfg := signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup)
		if got, err := Sign([]byte(prefix+baseMessage), cfg); !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("Sign(%q...) = %v, %v; want ErrMalformedMessage", prefix, got, err)
		}
		if got, err := SignTransformed([]byte(baseMessage), []byte(prefix+baseMessage), cfg); !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("SignTransformed(%q...) = %v, %v; want ErrMalformedMessage", prefix, got, err)
		}
	}
}

func TestPublicKeyRecordTrimsOnlyFoldingWhitespace(t *testing.T) {
	key, _, _ := testKeys(t)
	record := txtFor(t, key)
	p := record[strings.Index(record, "p=")+2:]
	for _, txt := range []string{
		"v=DKIM1; k=rsa; p=" + p,
		"v=DKIM1;k=rsa;p=" + p[:60] + " " + p[60:],
		"v=DKIM1; k=rsa;\r\n\tp = " + p + " ;",
	} {
		if _, err := parsePublicKey(txt); err != nil {
			t.Errorf("parsePublicKey(%.40q...) failed: %v", txt, err)
		}
	}
	for _, txt := range []string{
		"v=DKIM1; k=rsa; p =" + p,
		"v=DKIM1; k=rsa;  p=" + p,
		"v=DKIM1; k=rsa; p=" + p[:60] + " " + p[60:],
		"v=DKIM1; k=rsa; p=" + p[:60] + "\f" + p[60:],
	} {
		if _, err := parsePublicKey(txt); err == nil {
			t.Errorf("parsePublicKey(%.40q...) accepted a record with non-folding whitespace", txt)
		}
	}
}

// Only an empty line ends the header block. A line holding a bare CR is not
// empty: other parsers keep reading header fields after it, so if it ended
// the block here, inserting one CR would turn the top of a sealed body into
// header fields for them while the seal went on verifying.
func TestOnlyAnEmptyLineEndsTheHeaderBlock(t *testing.T) {
	for msg, wantBody := range map[string]string{
		"A: 1\r\n\r\nbody\r\n":           "body\r\n",
		"A: 1\n\nbody\n":                 "body\n",
		"A: 1\r\n\nbody\r\n":             "body\r\n",
		"A: 1\r\n\r\r\nB: 2\r\n\r\nbody": "body",
		"A: 1\r\n\r\r\r\nB: 2\r\n":       "",
		"A: 1\r\n \r\nB: 2\r\n\r\nbody":  "body",
		"A: 1\r\n":                       "",
		"\r\nbody":                       "body",
	} {
		if _, body := splitMessage(msg); body != wantBody {
			t.Errorf("splitMessage(%q) body = %q, want %q", msg, body, wantBody)
		}
	}
	headers, _ := splitMessage("A: 1\r\n\r\r\nB: 2\r\n\r\nbody")
	if len(headers) != 3 || headers[1].key != "" || headers[2].key != "B" {
		t.Errorf("a CR-only line was not kept as a line of the header block: %+v", headers)
	}

	sealed, lookup := testChain(t, 1)
	const forgedTop = "From: Mallory <mallory@evil.example>\r\nSubject: Pay this invoice\r\n\r\n"
	key, _, _ := testKeys(t)
	withHeaderLikeBody := strings.Replace(baseMessage, "\r\n\r\n", "\r\n\r\n"+forgedTop, 1)
	resealed, err := Sign([]byte(withHeaderLikeBody), signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatal(err)
	}
	for name, msg := range map[string][]byte{"plain body": sealed, "body that opens like a header block": resealed.Message} {
		if !mustVerify(t, msg, lookup).Pass {
			t.Fatalf("%s: the sealed message does not verify", name)
		}
		for _, separator := range []string{"\r\n\r\r\n", "\r\n\r\r\r\n", "\r\n\r\n\r\r\n"} {
			tampered := bytes.Replace(msg, []byte("\r\n\r\n"), []byte(separator), 1)
			if mustVerify(t, tampered, lookup).Pass {
				t.Errorf("%s: the seal still verifies with the header separator changed to %q", name, separator)
			}
		}
	}
}

// Whatever the message looks like, a set that Sign adds with cv=none or
// cv=pass must verify, the three new fields must read back as written, and
// nothing may panic.
func FuzzSignVerifyRoundTrip(f *testing.F) {
	for _, seed := range []string{
		baseMessage,
		strings.ReplaceAll(baseMessage, "\r\n", "\n"),
		withHeaderLine(baseMessage, "\rSubject: Hello there"),
		withHeaderLine(baseMessage, "Subject : x"),
		withHeaderLine(baseMessage, "Subject"),
		strings.Replace(baseMessage, "\r\n\r\n", "\r\n\r\r\n", 1),
		strings.Replace(baseMessage, "Hello Bob,\r\n", "Hello \rBob, \r\r\n\r\r\n", 1),
		"From: a@b.example\r\nSubject: a\r\n \r\n\tb\r\n\r\nbody\r",
		"From : a@b.example\nARC-Seal: i=1; (x;i=2) cv=none\n\nbody",
		"From:a@b.example\r\nARC-Authentication-Results: i=1; x\r\nARC-Message-Signature: i=1; b=\r\nARC-Seal: i=1; cv=none; b=\r\n\r\n",
		" orphan\r\nFrom: a@b.example\r\n\r\n",
		"From: a@b.example",
		"\r\nFrom: a@b.example\r\n",
	} {
		f.Add([]byte(seed), authResultsA)
	}
	f.Add([]byte(baseMessage), "mx.example; dkim=pass (a;b\\) \"c;d\r\n e\" "+strings.Repeat("x=y ", 60))
	key, _, _ := testKeys(f)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(f, key)})
	f.Fuzz(func(t *testing.T, msg []byte, authResults string) {
		cfg := signConfig(key, "forward-a.example", "sel-a", authResults, lookup)
		got, err := Sign(msg, cfg)
		if err != nil {
			return
		}
		if !bytes.HasSuffix(got.Message, msg) {
			t.Fatal("Sign changed the message it was given")
		}
		added := string(got.Message[:len(got.Message)-len(msg)])
		for _, line := range strings.Split(added, "\r\n") {
			if len(line) > 998 || strings.ContainsAny(line, "\r\n") {
				t.Fatalf("Sign emitted a bad line: %q", line)
			}
		}
		headers, _ := splitMessage(string(got.Message))
		if len(headers) < 3 || headers[0].key != "ARC-Seal" || headers[1].key != "ARC-Message-Signature" ||
			headers[2].key != "ARC-Authentication-Results" || headers[0].raw+headers[1].raw+headers[2].raw != added {
			t.Fatalf("the new ARC set does not read back as written: %q", added)
		}
		for _, h := range headers[:3] {
			if h.instance != got.Instance {
				t.Fatalf("%s reads back as instance %d, want %d", h.key, h.instance, got.Instance)
			}
		}
		res, err := Verify(got.Message, &VerifyOptions{LookupTXT: lookup})
		if err != nil {
			t.Fatal(err)
		}
		if got.CV != ChainFail && !res.Pass {
			t.Fatalf("a set sealed with cv=%s does not verify: %v", got.CV, res.FailureReasons)
		}
		if got.CV == ChainFail && res.Pass {
			t.Fatal("a chain sealed with cv=fail verifies")
		}
	})
}
