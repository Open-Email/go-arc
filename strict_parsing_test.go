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

// Lines that are not a Subject header field: a field name is printable ASCII
// directly followed by a colon (RFC 5322 §2.2). Software disagrees on them.
// This package once read most of them as the Subject, because it trimmed the
// name of Unicode whitespace, CR and LF; a mail reader such as postal-mime
// still does. So a message that holds one is refused as a whole.
var subjectDecoys = map[string]string{
	"bare CR before the name":  "\rSubject: Hello there",
	"bare CR before the colon": "Subject\r: Hello there",
	"CR and space":             "Subject \r : Hello there",
	"space before the colon":   "Subject : Hello there",
	"tab before the colon":     "Subject\t: Hello there",
	"no-break space":           "Subject\u00a0: Hello there",
	"form feed":                "Subject\f: Hello there",
	"vertical tab":             "Subject\v: Hello there",
	"em space before the name": "\u2003Subject: Hello there",
	"next line U+0085":         "Subject\u0085: Hello there",
	"long s":                   "ſubject: Hello there",
	"byte order mark":          "\xef\xbb\xbfSubject: Hello there",
	"no colon":                 "Subject",
	"NUL before the name":      "\x00Subject: Hello there",
	"empty name":               ": Hello there",
}

func withHeaderLine(msg, line string) string {
	head, body, _ := strings.Cut(msg, "\r\n\r\n")
	return head + "\r\n" + line + "\r\n\r\n" + body
}

func TestFieldNameIsExactASCII(t *testing.T) {
	for name, line := range subjectDecoys {
		headers, _, defect := parseMessage(line + "\r\n\r\nbody\r\n")
		if len(headers) != 1 {
			t.Fatalf("%s: parsed %d headers", name, len(headers))
		}
		if defect == nil {
			t.Errorf("%s: %q passed as a well-formed header block", name, line)
		}
		if asciiEqualFold(headers[0].key, "subject") && !strings.HasPrefix(line, "Subject ") && !strings.HasPrefix(line, "Subject\t") {
			t.Errorf("%s: %q was read as a Subject field", name, line)
		}
	}
	for _, line := range []string{"Subject: x", "SUBJECT:x", "subject:", "X-Odd!#$%&'*+-.^_`|~0: x", "Subject:\r\n folded"} {
		headers, _, defect := parseMessage(line + "\r\n\r\nbody\r\n")
		if defect != nil || len(headers) != 1 || asciiEqualFold(headers[0].key, "subject") == strings.HasPrefix(line, "X-") {
			t.Errorf("%q: defect %v, headers %+v", line, defect, headers)
		}
	}
}

// Every kind of line that makes a header block ambiguous, and well-formed
// blocks that must stay acceptable.
func TestParseMessageReportsAMalformedHeaderBlock(t *testing.T) {
	const ok = "From: a@b.example\r\n"
	for name, tc := range map[string]struct{ msg, defect string }{
		"well formed":                      {ok + "Subject: x\r\n\tfolded\r\n\r\nbody", ""},
		"bare LF line endings":             {"From: a@b.example\nSubject: x\n folded\n\nbody", ""},
		"no body":                          {ok + "Subject: x\r\n", ""},
		"no final line break":              {ok + "Subject: x", ""},
		"CR ends the input":                {ok + "Subject: x\r", ""},
		"lone CR ends the input":           {ok + "\r", ""},
		"8-bit and control bytes in value": {ok + "Subject: Gr\xfc\xdfe \x00\x0b\x0c\u00a0\r\n\r\n", ""},
		"empty message":                    {"", ""},
		"body only":                        {"\r\nbody", ""},
		"defect in the body is ignored":    {ok + "\r\nSubject\f: x\r\n\r\r\n", ""},
		"CR-only line":                     {ok + "\r\r\nSubject: x\r\n\r\n", "CR"},
		"CR CR LF line ending":             {ok + "Subject: x\r\r\n\r\n", "CR"},
		"CR inside a value":                {ok + "Subject: a\rb\r\n\r\n", "CR"},
		"CR inside a continuation":         {ok + "Subject: a\r\n b\rc\r\n\r\n", "CR"},
		"white-space-only continuation":    {ok + " \t \r\nSubject: x\r\n \r\n\r\n", ""},
		"DEL in the name":                  {ok + "Subject\x7f: x\r\n\r\n", "printable ASCII"},
		"CR in an unterminated last line":  {ok + "Subject: a\rb", "CR"},
		"continuation first":               {" orphan\r\n" + ok + "\r\n", "continuation"},
		"no colon":                         {ok + "xx\r\n\r\n", "not a header field"},
		"empty name":                       {ok + ": x\r\n\r\n", "not a header field"},
		"space before the colon":           {ok + "Subject : x\r\n\r\n", "printable ASCII"},
		"form feed in the name":            {ok + "Subject\f: x\r\n\r\n", "printable ASCII"},
		"8-bit name":                       {ok + "S\xfcbject: x\r\n\r\n", "printable ASCII"},
		"byte order mark":                  {"\xef\xbb\xbf" + ok + "\r\n", "printable ASCII"},
		"mbox From line":                   {"From a@b.example Sat Aug  1 12:00:00 2026\r\n" + ok + "\r\n", "printable ASCII"},
		"too many fields":                  {strings.Repeat("a:\n", maxHeaderFields+1) + "\nbody", "more than"},
	} {
		_, _, defect := parseMessage(tc.msg)
		if (tc.defect == "") != (defect == nil) || (defect != nil && !strings.Contains(defect.Error(), tc.defect)) {
			t.Errorf("%s: defect = %v, want one about %q", name, defect, tc.defect)
		}
	}
	if headers, _, defect := parseMessage(strings.Repeat("a:\n", maxHeaderFields) + "\nbody"); defect != nil || len(headers) != maxHeaderFields {
		t.Errorf("%d fields: defect %v, %d headers", maxHeaderFields, defect, len(headers))
	}
	if headers, body, _ := parseMessage(strings.Repeat("a:\n", 5*maxHeaderFields) + "\nbody"); len(headers) != maxHeaderFields || body != "" {
		t.Errorf("past the bound parseMessage kept %d headers and body %q", len(headers), body)
	}
}

// Two ways to use such a line against a sealed message. The attacker rewrites
// the signed Subject and adds a line that canonicalizes to the original one;
// if the verifier takes that line for the Subject, the seal still verifies.
// Or the attacker leaves the Subject alone and adds a line a mail reader
// shows in its place; if the verifier ignores that line, the seal still
// verifies too. Either way the chain must fail.
func TestDecoyLineBreaksTheChain(t *testing.T) {
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
				t.Error("the real Subject changed after sealing and the seal still verifies")
			}
			shown := strings.Replace(line, "Hello there", "Pay this invoice", 1)
			res := mustVerify(t, []byte(withHeaderLine(string(sealed), shown)), lookup)
			if res.Pass || res.ChainValid {
				t.Errorf("the seal still verifies with %q added below the signed Subject", shown)
			}
			if len(res.Instances) != 1 || res.Instances[0].Sealer != "forward-a.example" {
				t.Errorf("the failing result does not say who sealed: %+v", res.Instances)
			}
		})
	}
	for name, tampered := range map[string]string{
		"From with a form feed": withHeaderLine(string(sealed), "From\f: Bank CEO <ceo@bank.example>"),
		"line that continues the Subject for a reader that trims it": strings.Replace(string(sealed),
			"Subject: Hello there\r\n", "Subject: Hello there\r\n\f- URGENT: pay invoice 4471 today\r\n", 1),
		"line with no colon, where some parsers start the body": strings.Replace(string(sealed),
			"From: Alice", "Subject: Pay this invoice\r\nContent-Type: text/html\r\nxx\r\n<p>Wire 5000 EUR.</p><!--\r\nFrom: Alice", 1),
	} {
		if tampered == string(sealed) {
			t.Fatalf("%s: nothing was altered", name)
		}
		if mustVerify(t, []byte(tampered), lookup).Pass {
			t.Errorf("the seal still verifies with a %s", name)
		}
	}
}

// The same line present before sealing: Sign must not seal the message, in
// either reading it would vouch for something some reader does not see.
func TestSignRefusesAMessageWithADecoyLine(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for name, line := range subjectDecoys {
		cfg := signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup)
		msg := []byte(withHeaderLine(baseMessage, line))
		if got, err := Sign(msg, cfg); !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("%s: Sign = %v, %v; want ErrMalformedMessage", name, got, err)
		}
		if got, err := SignTransformed([]byte(baseMessage), msg, cfg); !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("%s: SignTransformed = %v, %v; want ErrMalformedMessage", name, got, err)
		}
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
			cfg := signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup)
			if got, err := SignTransformed(tampered, tampered, cfg); !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("SignTransformed of the altered message = %+v, %v; want ErrMalformedMessage", got, err)
			}
			// Altered on the way in and repaired before sending: the chain
			// did not validate on what arrived.
			if got, err := SignTransformed(tampered, original, cfg); !errors.Is(err, ErrPriorChainFailed) {
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

// relaxedBodyReference is the relaxed body canonicalization of origin/main
// (a0495e8), kept as the oracle for the one-pass version.
func relaxedBodyReference(body string) []byte {
	lines := strings.Split(body, "\n")
	canonical := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimRight(line, " \t")
		var sb strings.Builder
		spaceSeen := false
		for i := 0; i < len(line); i++ {
			b := line[i]
			if b == ' ' || b == '\t' {
				if !spaceSeen {
					sb.WriteByte(' ')
					spaceSeen = true
				}
			} else {
				sb.WriteByte(b)
				spaceSeen = false
			}
		}
		canonical = append(canonical, sb.String())
	}
	for len(canonical) > 0 && canonical[len(canonical)-1] == "" {
		canonical = canonical[:len(canonical)-1]
	}
	var out strings.Builder
	for _, line := range canonical {
		out.WriteString(line)
		out.WriteString("\r\n")
	}
	return []byte(out.String())
}

func FuzzRelaxedBodyMatchesMain(f *testing.F) {
	for _, seed := range []string{
		"", "\n", "\r\n\r\n", "a  b \t\r\n\r\n", " lead\r\n", "a", "a \rb\r\n", "a\r\r\n", "a \r \r\n", "\ra\r\n",
		"a\r\n \r\n\t\r\nb\r\n\r\n ", "a\nb", "a \nb\n\n", "a\r", "a\r\n\r", " \t\r\n \r\n", "\t a \t b\r", "\r\r\r", "x\n\n\n\ny\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if got, want := canonicalizeBody(body, canonRelaxed), relaxedBodyReference(body); !bytes.Equal(got, want) {
			t.Fatalf("canonicalizeBody(%q) = %q, main gives %q", body, got, want)
		}
	})
}

// A body of millions of empty lines used to cost a slice entry and an
// allocation for each.
func TestRelaxedBodyCanonicalizationStaysInOneBuffer(t *testing.T) {
	body := strings.Repeat("\n", 1<<20) + "x"
	allocs := testing.AllocsPerRun(3, func() { canonicalizeBody(body, canonRelaxed) })
	if allocs > 16 {
		t.Errorf("canonicalizeBody made %.0f allocations for %d lines", allocs, 1<<20)
	}
	if got := canonicalizeBody(body, canonRelaxed); len(got) != 2*(1<<20)+3 {
		t.Errorf("canonical length = %d", len(got))
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

// handSealOptions change the first-hop ARC set that handSeal builds.
type handSealOptions struct {
	amsC       string              // AMS c= tag; default relaxed/relaxed
	bh         func(string) string // rewrites the bh= value before signing
	amsTags    []string            // extra AMS tags, before b=
	sealTags   []string            // extra seal tags, before b=
	mutateAMS  func(string) string // changes the signed AMS before the seal covers it
	formatSeal func(string) string // changes the unsigned seal before hashing
}

// handSeal builds a first-hop ARC set over msg by hand, canonicalizing as
// relaxed/relaxed whatever the tags say, and returns the sealed message.
func handSeal(t *testing.T, key *rsa.PrivateKey, msg string, opt handSealOptions) []byte {
	t.Helper()
	if opt.amsC == "" {
		opt.amsC = "relaxed/relaxed"
	}
	headers, body := splitMessage(msg)
	signed := selectSignedHeaders(headers)
	var names []string
	for _, h := range signed {
		names = append(names, asciiLower(h.key))
	}
	bodyHash := sha256.Sum256(canonicalizeBody(body, canonRelaxed))
	bh := base64.StdEncoding.EncodeToString(bodyHash[:])
	if opt.bh != nil {
		bh = opt.bh(bh)
	}
	aar := foldHeader("ARC-Authentication-Results", []string{"i=1", authResultsA})
	amsTags := []string{
		"i=1", "a=rsa-sha256", "c=" + opt.amsC, "d=forward-a.example", "s=sel-a",
		fmt.Sprintf("t=%d", fixedNow().Unix()), "bh=" + bh, "h=" + strings.Join(names, ":"),
	}
	amsUnsigned := foldHeader("ARC-Message-Signature", append(append(amsTags, opt.amsTags...), "b="))
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
	if opt.mutateAMS != nil {
		ams = opt.mutateAMS(ams)
	}
	sealTags := []string{"i=1", "a=rsa-sha256", fmt.Sprintf("t=%d", fixedNow().Unix()), "cv=none", "d=forward-a.example", "s=sel-a"}
	sealUnsigned := foldHeader("ARC-Seal", append(append(sealTags, opt.sealTags...), "b="))
	if opt.formatSeal != nil {
		sealUnsigned = opt.formatSeal(sealUnsigned)
	}
	hasher = sha256.New()
	hasher.Write([]byte(canonicalizeHeaderRaw(aar, canonRelaxed)))
	hasher.Write([]byte(canonicalizeHeaderRaw(ams, canonRelaxed)))
	hasher.Write([]byte(strings.TrimSuffix(canonicalizeHeaderRaw(sealUnsigned, canonRelaxed), "\r\n")))
	sealSig, err := signHash(key, hasher.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	// The fixture puts the signature last, also when the b tag is folded.
	seal := strings.TrimSuffix(sealUnsigned, "\r\n") + sealSig + "\r\n"
	return []byte(seal + ams + aar + msg)
}

func TestVerifyRejectsUnknownCanonicalization(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	if res := mustVerify(t, handSeal(t, key, baseMessage, handSealOptions{}), lookup); !res.Pass {
		t.Fatalf("the hand-built set does not verify: %+v", res)
	}
	for _, c := range []string{"bogus/bogus", "relaxed/bogus", "Relaxed/Relaxed", "relaxed/relaxed/x", "relaxed\u00a0/relaxed"} {
		if res := mustVerify(t, handSeal(t, key, baseMessage, handSealOptions{amsC: c}), lookup); res.Pass {
			t.Errorf("a signature with c=%s verified as if it were relaxed/relaxed", c)
		}
	}
}

// A tag given twice makes the tag-list invalid (RFC 6376 §3.2): one reader
// would take the first d= or cv= and another the last. A seal must not carry
// h= (RFC 8617 §4.1.3).
func TestVerifyRejectsDuplicateTagsAndASealWithH(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for name, opt := range map[string]handSealOptions{
		"AMS with two d=":        {amsTags: []string{"d=forward-a.example"}},
		"AMS with two i=":        {amsTags: []string{"i=1"}},
		"seal with two d=":       {sealTags: []string{"d=forward-a.example"}},
		"seal with two cv=":      {sealTags: []string{"cv=none"}},
		"seal with cv=fail last": {sealTags: []string{"cv=fail"}},
		"seal with h=":           {sealTags: []string{"h=from"}},
		"seal with an empty h=":  {sealTags: []string{"h="}},
	} {
		if res := mustVerify(t, handSeal(t, key, baseMessage, opt), lookup); res.Pass {
			t.Errorf("%s: the chain verified", name)
		}
	}
	// Tags this package does not know are ignored, once. c= is not a seal
	// tag (RFC 8617 §4.1.3), so its value there decides nothing.
	for name, opt := range map[string]handSealOptions{
		"AMS with x=":  {amsTags: []string{"x=9999999999", "z=From:a"}},
		"seal with x=": {sealTags: []string{"x=1"}},
		"seal with c=": {sealTags: []string{"c=bogus"}},
	} {
		if res := mustVerify(t, handSeal(t, key, baseMessage, opt), lookup); !res.Pass {
			t.Errorf("%s: the chain failed: %v", name, res.FailureReasons)
		}
	}
	if _, err := parseTagList("a=1; b=2; a=3"); err == nil {
		t.Error("parseTagList accepted a tag given twice")
	}
	if tags, err := parseTagList(" (c;i=9) i = 2 ; a=1; b=2"); err != nil || tags["i"] != "2" {
		t.Errorf("parseTagList with an instance clause = %v, %v", tags, err)
	}
}

// FWS inside a base64 tag value is ignored (RFC 6376 §3.5); nothing else is.
func TestSignatureBase64AllowsOnlyFoldingWhitespace(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	splitB := func(sep string) handSealOptions {
		return handSealOptions{mutateAMS: func(ams string) string {
			i := strings.Index(ams, " b=") + 3 + 40
			return ams[:i] + sep + ams[i:]
		}}
	}
	splitBH := func(sep string) handSealOptions {
		return handSealOptions{bh: func(bh string) string { return bh[:20] + sep + bh[20:] }}
	}
	for _, sep := range []string{"\r\n\t", "\r\n ", " "} {
		if res := mustVerify(t, handSeal(t, key, baseMessage, splitB(sep)), lookup); !res.Pass {
			t.Errorf("a b= value folded with %q does not verify: %+v", sep, res)
		}
		if res := mustVerify(t, handSeal(t, key, baseMessage, splitBH(sep)), lookup); !res.Pass {
			t.Errorf("a bh= value folded with %q does not verify: %+v", sep, res)
		}
	}
	for _, sep := range []string{"\u00a0", "\u2003", "\u0085", "\f", "\v"} {
		if res := mustVerify(t, handSeal(t, key, baseMessage, splitB(sep)), lookup); res.Pass {
			t.Errorf("a b= value containing %q verified", sep)
		}
		if res := mustVerify(t, handSeal(t, key, baseMessage, splitBH(sep)), lookup); res.Pass {
			t.Errorf("a bh= value containing %q verified", sep)
		}
	}
}

func TestHeaderListNamesTrimOnlyFoldingWhitespace(t *testing.T) {
	headers, _ := splitMessage(baseMessage)
	pick := func(hTag string, headers []rawHeader) []string {
		selected, err := selectHeaders("ARC-Message-Signature", hTag, headers)
		if err != nil {
			t.Fatalf("selectHeaders(%q): %v", hTag, err)
		}
		var names []string
		for _, h := range selected {
			names = append(names, h.raw)
		}
		return names
	}
	if got := pick("from :\r\n\t subject\t: To", headers); len(got) != 3 || !strings.HasPrefix(got[0], "From:") || !strings.HasPrefix(got[1], "Subject:") || !strings.HasPrefix(got[2], "To:") {
		t.Errorf("folded h= list selected %q", got)
	}
	for _, hTag := range []string{"from:\u00a0subject", "from:subject\u2003", "from:\fsubject", "from:subject\v", "from:\u017fubject", "from::"} {
		if got := pick(hTag, headers); len(got) != 1 || !strings.HasPrefix(got[0], "From:") {
			t.Errorf("selectHeaders(%q) selected %q, want only From", hTag, got)
		}
	}
	// An empty entry never selects a line that has no name.
	nameless := append([]rawHeader{{raw: "no colon\r\n"}}, headers...)
	if got := pick("from::", nameless); len(got) != 1 {
		t.Errorf("an empty h= entry selected %q", got)
	}
	// Repeated names take the fields from the bottom up, and a name with
	// none left selects nothing (RFC 6376 §5.4.2).
	dup, _ := splitMessage("X: 1\r\nFrom: a@b.example\r\nX: 2\r\nx: 3\r\n\r\n")
	if got := strings.Join(pick("x:from:X:x:x:from", dup), ""); got != "x: 3\r\nFrom: a@b.example\r\nX: 2\r\nX: 1\r\n" {
		t.Errorf("repeated h= names selected %q", got)
	}
}

// A message with a malformed header block and no ARC header passes like any
// message without a chain: there is nothing to vouch for.
func TestMalformedMessageWithoutAChainStillPasses(t *testing.T) {
	for _, msg := range []string{withHeaderLine(baseMessage, "Subject\f: x"), strings.Replace(baseMessage, "\r\n\r\n", "\r\n\r\r\n", 1), " orphan\r\n" + baseMessage} {
		res := mustVerify(t, []byte(msg), nil)
		if !res.Pass || !res.ChainValid || res.Instance != 0 || len(res.FailureReasons) != 0 {
			t.Errorf("Verify(%.30q...) = %+v, want a pass with no chain", msg, res)
		}
	}
}

func TestVerifyDistinguishesIncompleteHeaderScanFromNoChain(t *testing.T) {
	fields := strings.Repeat("X-Trace: relay.example\r\n", maxHeaderFields)
	const end = "\r\nOrdinary mail.\r\n"
	if got := mustVerify(t, []byte(fields+end), nil); !got.Pass || !got.ChainValid || got.Instance != 0 || len(got.FailureReasons) != 0 {
		t.Errorf("Verify at the limit = %+v, want a pass with no chain", got)
	}
	for _, field := range []string{"X-Trace: next.example\r\n", "Invalid field\r\n"} {
		got := mustVerify(t, []byte(field+fields+end), nil)
		if got.Pass || got.ChainValid || got.Instance != 0 || !strings.Contains(strings.Join(got.FailureReasons, " "), "more than") {
			t.Errorf("Verify over the limit beginning with %q = %+v, want a header limit failure", field, got)
		}
	}
}

func TestSignTransformedRequiresACompleteOriginalHeaderScan(t *testing.T) {
	key, _, _ := testKeys(t)
	cfg := signConfig(key, "forward-a.example", "sel-a", authResultsA, nil)
	headers, _ := splitMessage(baseMessage)
	fields := strings.Repeat("X-Trace: relay.example\r\n", maxHeaderFields-len(headers))
	result, err := SignTransformed([]byte(fields+baseMessage), []byte(baseMessage), cfg)
	if err != nil || result.Instance != 1 || result.CV != ChainNone {
		t.Fatalf("SignTransformed at the limit = %v, %v, want a first-hop seal", result, err)
	}
	for _, field := range []string{"X-Trace: next.example\r\n", "Invalid field\r\n"} {
		result, err := SignTransformed([]byte(field+fields+baseMessage), []byte(baseMessage), cfg)
		if result != nil || !errors.Is(err, ErrMalformedMessage) || !strings.Contains(err.Error(), "more than") {
			t.Errorf("SignTransformed over the limit beginning with %q = (%t, %v), want a header limit failure", field, result != nil, err)
		}
	}
}

// The signature lists every default name once per field of that name and
// once more (RFC 6376 §5.4, §8.15), so no field of such a name can be added
// after sealing: not a second copy above the signed one, and not one the
// message never had.
func TestSignCoversAbsentAndRepeatedFields(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	cfg := signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup)
	// A plain message: no Reply-To, Cc, Content-Type or transfer encoding.
	const plain = "From: Alice <alice@origin.example>\r\nTo: Bob <bob@dest.example>\r\nSubject: Hello there\r\n" +
		"Date: Sat, 01 Aug 2026 12:00:00 +0000\r\nMessage-ID: <abc123@origin.example>\r\n\r\nPGI+UGF5IDUwMDAgRVVSPC9iPg==\r\n"
	sealed, err := Sign([]byte(plain), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !mustVerify(t, sealed.Message, lookup).Pass {
		t.Fatal("the sealed message does not verify")
	}
	headers, _ := splitMessage(string(sealed.Message))
	gotH := stripFWS(parseTags(headers[1].value)["h"])
	const wantH = "from:from:sender:to:to:cc:reply-to:subject:subject:date:date:message-id:message-id:in-reply-to:references:mime-version:content-type:content-transfer-encoding:content-disposition"
	if gotH != wantH {
		t.Errorf("h= %s\nwant %s", gotH, wantH)
	}
	head, body, _ := strings.Cut(string(sealed.Message), "\r\n\r\n")
	for name, tampered := range map[string]string{
		"Reply-To added below":            head + "\r\nReply-To: mallory@evil.example\r\n\r\n" + body,
		"Reply-To added above":            strings.Replace(string(sealed.Message), "From: Alice", "Reply-To: mallory@evil.example\r\nFrom: Alice", 1),
		"Cc added":                        head + "\r\nCc: mallory@evil.example\r\n\r\n" + body,
		"Content-Type and encoding added": head + "\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n" + body,
		"transfer encoding added":         head + "\r\ncontent-transfer-encoding: base64\r\n\r\n" + body,
		"MIME-Version added":              head + "\r\nMIME-Version: 1.0\r\n\r\n" + body,
		"Content-Disposition added":       "Content-Disposition: attachment; filename=\"invoice.html\"\r\n" + string(sealed.Message),
		"Sender added":                    head + "\r\nSENDER: mallory@evil.example\r\n\r\n" + body,
		"second Subject above":            strings.Replace(string(sealed.Message), "Subject: Hello there", "Subject: Pay this invoice\r\nSubject: Hello there", 1),
		"second Subject below":            strings.Replace(string(sealed.Message), "Subject: Hello there", "Subject: Hello there\r\nSubject: Pay this invoice", 1),
		"second From above":               strings.Replace(string(sealed.Message), "From: Alice", "From: Mallory <m@evil.example>\r\nFrom: Alice", 1),
		"second Date above":               strings.Replace(string(sealed.Message), "Date: Sat", "Date: Sun, 02 Aug 2026 12:00:00 +0000\r\nDate: Sat", 1),
	} {
		if tampered == string(sealed.Message) {
			t.Fatalf("%s: nothing was altered", name)
		}
		if mustVerify(t, []byte(tampered), lookup).Pass {
			t.Errorf("the seal still verifies with %s", name)
		}
	}
	// A field outside the signed names may still be added: that is how
	// Received and the next hop's own headers arrive.
	if !mustVerify(t, []byte("Received: from relay.example by mx.example\r\nX-Spam: no\r\n"+string(sealed.Message)), lookup).Pass {
		t.Error("the seal fails once an unsigned trace field is added")
	}

	// Fields that repeat at signing time are all covered, bottom up.
	repeated := strings.Replace(plain, "Subject: Hello there", "Subject: first\r\nSubject: second", 1)
	sealed, err = Sign([]byte(repeated), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !mustVerify(t, sealed.Message, lookup).Pass {
		t.Fatal("a message with a repeated Subject does not verify after sealing")
	}
	for _, edit := range [][2]string{{"Subject: first", "Subject: forged"}, {"Subject: second", "Subject: forged"}, {"Subject: first\r\nSubject: second", "Subject: second\r\nSubject: first"}} {
		if tampered := bytes.Replace(sealed.Message, []byte(edit[0]), []byte(edit[1]), 1); mustVerify(t, tampered, lookup).Pass {
			t.Errorf("the seal still verifies with %q changed to %q", edit[0], edit[1])
		}
	}
	// A second hop over the oversigned set extends the chain as usual.
	_, relayKey, _ := testKeys(t)
	lookup2 := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key), "sel-b._domainkey.forward-b.example": txtFor(t, relayKey)})
	second, err := Sign(sealed.Message, signConfig(relayKey, "forward-b.example", "sel-b", authResultsB, lookup2))
	if err != nil || second.CV != ChainPass || !mustVerify(t, second.Message, lookup2).Pass {
		t.Fatalf("second hop = %+v, %v", second, err)
	}
}

// DKIM-Signature fields are covered as they stand but not oversigned: a later
// hop adds its own, and that must not break this hop's signature.
func TestSignTransformedLeavesRoomForALaterDKIMSignature(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	original := []byte("DKIM-Signature: v=1; a=rsa-sha256; d=origin.example; s=s; h=from; bh=x; b=y\r\n" + baseMessage)
	sealed, err := SignTransformed(original, original, signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatal(err)
	}
	headers, _ := splitMessage(string(sealed.Message))
	if h := stripFWS(parseTags(headers[1].value)["h"]); strings.Count(h, "dkim-signature") != 1 || !strings.HasSuffix(h, ":dkim-signature") {
		t.Errorf("h= %s, want one dkim-signature entry at the end", h)
	}
	later := append([]byte("DKIM-Signature: v=1; a=rsa-sha256; d=relay.example; s=s; h=from; bh=x; b=y\r\n"), sealed.Message...)
	if !mustVerify(t, later, lookup).Pass {
		t.Error("the seal fails once a later hop adds its own DKIM-Signature")
	}
	changed := bytes.Replace(sealed.Message, []byte("d=origin.example"), []byte("d=forged.example"), 1)
	if mustVerify(t, changed, lookup).Pass {
		t.Error("the seal still verifies with the covered DKIM-Signature changed")
	}
}

// A tag list or an h= list far beyond what any signer writes is refused, and
// reading one made of separators alone costs no memory per separator.
func TestTagAndHeaderListsAreBounded(t *testing.T) {
	var many strings.Builder
	for i := 0; i <= maxTags; i++ {
		fmt.Fprintf(&many, "t%d=1; ", i)
	}
	if _, err := parseTagList(many.String()); err == nil {
		t.Errorf("parseTagList accepted %d tags", maxTags+1)
	}
	if tags, err := parseTagList("a=1" + strings.Repeat(";", 1<<20) + "b=2"); err != nil || tags["a"] != "1" || tags["b"] != "2" {
		t.Errorf("parseTagList over a run of separators = %v tags, %v", len(tags), err)
	}
	value := "a=1" + strings.Repeat(";", 1<<20)
	if allocs := testing.AllocsPerRun(3, func() { parseTagList(value) }); allocs > 8 {
		t.Errorf("parseTagList made %.0f allocations for %d separators", allocs, 1<<20)
	}
	headers, _ := splitMessage(baseMessage)
	if _, err := selectHeaders("ARC-Message-Signature", "from"+strings.Repeat(":x", maxSignedEntries-1), headers); err != nil {
		t.Errorf("selectHeaders refused %d entries: %v", maxSignedEntries, err)
	}
	if _, err := selectHeaders("ARC-Message-Signature", "from"+strings.Repeat(":x", maxSignedEntries), headers); err == nil {
		t.Errorf("selectHeaders accepted %d entries", maxSignedEntries+1)
	}
	if _, err := selectHeaders("ARC-Message-Signature", "from"+strings.Repeat(":", 1<<20), headers); err == nil {
		t.Error("selectHeaders accepted a million empty entries")
	}
	// The signer stops at the same bound, so what it seals always verifies.
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	cfg := signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup)
	const minimal = "From: a@b.example\r\n"
	entries := func(msg string) int {
		sealed, err := Sign([]byte(msg), cfg)
		if err != nil {
			t.Fatal(err)
		}
		headers, _ := splitMessage(string(sealed.Message))
		return strings.Count(stripFWS(parseTags(headers[1].value)["h"]), ":") + 1
	}
	base := entries(minimal + "\r\nbody\r\n")
	atBound := minimal + strings.Repeat("To: b@c.example\r\n", maxSignedEntries-base) + "\r\nbody\r\n"
	sealed, err := Sign([]byte(atBound), cfg)
	if err != nil || !mustVerify(t, sealed.Message, lookup).Pass {
		t.Fatalf("Sign with exactly %d h= entries: %v", maxSignedEntries, err)
	}
	overBound := minimal + strings.Repeat("To: b@c.example\r\n", maxSignedEntries-base+1) + "\r\nbody\r\n"
	if got, err := Sign([]byte(overBound), cfg); !errors.Is(err, ErrMalformedMessage) {
		t.Errorf("Sign with %d h= entries = %v, %v; want ErrMalformedMessage", maxSignedEntries+1, got, err)
	}
	// DKIM-Signature entries count as well.
	withDKIM := func(n int) []byte {
		return []byte(strings.Repeat("DKIM-Signature: v=1; d=o.example; s=s; h=from; bh=x; b=y\r\n", n) + minimal + "\r\nbody\r\n")
	}
	msg := withDKIM(maxSignedEntries - base)
	sealed, err = SignTransformed(msg, msg, cfg)
	if err != nil || !mustVerify(t, sealed.Message, lookup).Pass {
		t.Fatalf("SignTransformed with exactly %d h= entries: %v", maxSignedEntries, err)
	}
	msg = withDKIM(maxSignedEntries - base + 1)
	if got, err := SignTransformed(msg, msg, cfg); !errors.Is(err, ErrMalformedMessage) {
		t.Errorf("SignTransformed with %d h= entries = %v, %v; want ErrMalformedMessage", maxSignedEntries+1, got, err)
	}

	// Three fields are added on top, so a message that close to the field
	// bound is refused rather than sealed into one Verify would not read.
	full := minimal + strings.Repeat("X-A: 1\r\n", maxHeaderFields-4) + "\r\nbody\r\n"
	sealed, err = Sign([]byte(full), cfg)
	if err != nil || !mustVerify(t, sealed.Message, lookup).Pass {
		t.Fatalf("Sign with %d header fields: %v", maxHeaderFields-3, err)
	}
	if got, err := Sign([]byte(minimal+strings.Repeat("X-A: 1\r\n", maxHeaderFields-3)+"\r\nbody\r\n"), cfg); !errors.Is(err, ErrMalformedMessage) {
		t.Errorf("Sign with %d header fields = %v, %v; want ErrMalformedMessage", maxHeaderFields-2, got, err)
	}
}

// Selecting the h= fields used to search the whole header block per entry,
// before any key was fetched.
func TestHeaderSelectionTimeIsLinear(t *testing.T) {
	const n = 400_000
	sum := sha256.Sum256([]byte("x\r\n"))
	msg := []byte("ARC-Seal: i=1; a=rsa-sha256; t=1; cv=none; d=x.example; s=s; b=AAAA\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=x.example; s=s; t=1; bh=" +
		base64.StdEncoding.EncodeToString(sum[:]) + "; h=from:" + strings.Repeat("a:", n) + "; b=AAAA\r\n" +
		"ARC-Authentication-Results: i=1; mx.x.example; none\r\n" +
		"From: a@b.example\r\n" + strings.Repeat("a:\n", maxHeaderFields-10) + "\r\nx\r\n")
	done := make(chan *VerifyResult, 1)
	go func() {
		res, _ := Verify(msg, &VerifyOptions{LookupTXT: func(string) ([]string, error) { return nil, fmt.Errorf("no such key") }})
		done <- res
	}()
	select {
	case res := <-done:
		if res.Pass {
			t.Fatal("a chain with no key verified")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Verify did not finish %d bytes in 10 s", len(msg))
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
		"Authentication-Results: mx.example.com\t 1 ; dmarc=pass",
		"Authentication-Results: mx.example.com; none",
		"Authentication-Results: mx.example.com",
		// RFC 8601 §2.2 allows comments around the authserv-id and version.
		"Authentication-Results: mx.example.com (amavisd-new); dmarc=pass",
		"Authentication-Results: mx.example.com(a;b (nested \\) x)); dmarc=pass",
		"Authentication-Results: (c) mx.example.com (c) 1 (c); dmarc=pass",
	} {
		if _, ok := find(line); !ok {
			t.Errorf("%q was not found", line)
		}
	}
	for _, line := range []string{
		"Authentication-Results: mx.example.com\u00a0attacker; dmarc=pass",
		"Authentication-Results: mx.example.com\fattacker; dmarc=pass",
		"Authentication-Results: mx.example.com\vattacker; dmarc=pass",
		"Authentication-Results: mx.example.com\rattacker; dmarc=pass",
		"Authentication-Results: mx.example.com\r1; dmarc=pass",
		"Authentication-Results: mx.example.com\u20031; dmarc=pass",
		"Authentication-Results: mx.example.com attacker; dmarc=pass",
		"Authentication-Results: mx.example.com 1 attacker; dmarc=pass",
		"Authentication-Results: mx.example.com 1x; dmarc=pass",
		"Authentication-Results: mx.example.com 1 2; dmarc=pass",
		"Authentication-Results: mx.example.com (unclosed; dmarc=pass",
		"Authentication-Results: mx.example.com.evil.example; dmarc=pass",
		"Authentication-Results: evil.mx.example.com; dmarc=pass",
		"Authentication-Results: \u00a0mx.example.com; dmarc=pass",
		"Authentication-Results\u00a0: mx.example.com; dmarc=pass",
		"\rAuthentication-Results: mx.example.com; dmarc=pass",
		"Authentication-Results: mx.example.com\r; dmarc=pass",
		"Authentication-Results: mx.example.com (a\rb); dmarc=pass",
		"Authentication-Results: ; dmarc=pass",
	} {
		if value, ok := find(line); ok {
			t.Errorf("%q matched %s and returned %q", line, id, value)
		}
	}
	// ASCII letters fold, nothing else does: the Kelvin sign is not "k".
	if _, ok := FindAuthenticationResults([]byte("Authentication-Results: mx.\u212aelvin.example; dmarc=pass\r\n"+baseMessage), "mx.kelvin.example"); ok {
		t.Error("an authserv-id spelled with a Kelvin sign matched")
	}
	if _, ok := FindAuthenticationResults([]byte("Authentication-Results: MX.KELVIN.example; dmarc=pass\r\n"+baseMessage), "mx.kelvin.example"); !ok {
		t.Error("an authserv-id in upper case did not match")
	}
	if _, ok := FindAuthenticationResults([]byte("Authentication-Results: ; dmarc=pass\r\n"+baseMessage), ""); ok {
		t.Error("an empty authserv-id matched")
	}

	// The topmost header of this authserv-id wins, also when it carries a
	// comment and a plainer one sits below it.
	stacked := "Authentication-Results: other.example; dmarc=pass\r\n" +
		"Authentication-Results: mx.example.com (amavisd-new); dmarc=fail header.from=bank.example\r\n" +
		"Received: from evil.example by mx.example.com\r\n" +
		"Authentication-Results: mx.example.com; dmarc=pass header.from=bank.example\r\n" + baseMessage
	if value, ok := FindAuthenticationResults([]byte(stacked), id); !ok || value != "mx.example.com (amavisd-new); dmarc=fail header.from=bank.example" {
		t.Errorf("FindAuthenticationResults = %q, %t; want the topmost header of this authserv-id", value, ok)
	}

	// The value returned is safe to place in a new header: folds become one
	// space each and no CR or LF is left.
	value, ok := find("Authentication-Results: mx.example.com;\r\n\tdkim=pass\r\n  header.d=a.example;\r\n spf=pass")
	if !ok || value != "mx.example.com; dkim=pass header.d=a.example; spf=pass" {
		t.Errorf("FindAuthenticationResults returned %q, %t", value, ok)
	}
	if got := collapseASCIIWSP(" a\r\nb\rc\nd \t e\r\n"); got != "a b c d e" {
		t.Errorf("collapseASCIIWSP = %q", got)
	}
	// Nothing below a line that is not a well-formed header field counts:
	// it is a header to one parser and not to another.
	for _, above := range []string{"no colon here", "\r", "X-Old : style", "Subject\f: x", "X-A: a\rb"} {
		if value, ok := FindAuthenticationResults([]byte(above+"\r\nAuthentication-Results: mx.example.com; dmarc=pass\r\n"+baseMessage), id); ok {
			t.Errorf("found %q below the line %q", value, above)
		}
	}
	if _, ok := find("Authentication-Results : mx.example.com; dmarc=pass"); ok {
		t.Error("found a header written with a space before its colon")
	}
	// A defect further down is Sign's to judge: it refuses the message and
	// says why, which "no results found" would hide.
	malformed := []byte("Authentication-Results: mx.example.com; dmarc=pass\r\nSubject\f: x\r\n" + baseMessage)
	results, ok := FindAuthenticationResults(malformed, id)
	if !ok {
		t.Fatal("found no results in a message whose defect lies elsewhere")
	}
	key, _, _ := testKeys(t)
	if _, err := Sign(malformed, signConfig(key, "forward-a.example", "sel-a", results, nil)); !errors.Is(err, ErrMalformedMessage) || !strings.Contains(err.Error(), "printable ASCII") {
		t.Errorf("Sign = %v, want ErrMalformedMessage naming the defect", err)
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
	// The limit is 998 bytes without the CRLF (RFC 5322 §2.1.1). The last
	// token stands on a line of its own behind one space.
	for length, wantErr := range map[int]bool{996: false, 997: false, 998: true, 1100: true} {
		ar := "mx.forward-a.example; dkim=pass " + strings.Repeat("a", length)
		got, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", ar, lookup))
		if wantErr {
			if !errors.Is(err, ErrLineTooLong) {
				t.Errorf("a %d-byte line: Sign = %v, %v; want ErrLineTooLong", length+1, got, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("a %d-byte line: %v", length+1, err)
		}
		longest := 0
		for _, line := range strings.Split(string(got.Message), "\r\n") {
			longest = max(longest, len(line))
		}
		if longest != length+1 {
			t.Fatalf("longest emitted line is %d bytes, want %d", longest, length+1)
		}
		if !mustVerify(t, got.Message, lookup).Pass {
			t.Fatal("the sealed message does not verify")
		}
	}
}

// Domain and Selector go into the new headers and into a DNS name, so they
// must be DNS names; a control character in the results is refused as well.
func TestSignValidatesWhatItWritesIntoHeaders(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for _, bad := range []string{
		"forward-a.example\r\nX-Injected: yes", "a b.example", "a;b=c", "a..example", ".example", "example.",
		"\u200dbücher.example", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "a", "a\x00.example",
	} {
		if got, err := Sign([]byte(baseMessage), signConfig(key, bad, "sel-a", authResultsA, lookup)); err == nil {
			t.Errorf("Sign accepted Domain %q: %q", bad, firstLine(got.Message, "ARC-Seal"))
		}
		if got, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", bad, authResultsA, lookup)); err == nil {
			t.Errorf("Sign accepted Selector %q: %q", bad, firstLine(got.Message, "ARC-Seal"))
		}
	}
	for _, good := range [][2]string{{"forward-a.example", "sel-a"}, {"xn--bcher-kva.example", "s2026_11"}, {"A.B.C.example", "0"}} {
		lookup := dnsStub(map[string]string{good[1] + "._domainkey." + good[0]: txtFor(t, key)})
		got, err := Sign([]byte(baseMessage), signConfig(key, good[0], good[1], authResultsA, lookup))
		if err != nil || !mustVerify(t, got.Message, lookup).Pass {
			t.Errorf("Sign with Domain %q and Selector %q: %v", good[0], good[1], err)
		}
	}
	for _, ar := range []string{"mx.forward-a.example; dkim=pass\x00", "mx.forward-a.example; dkim=pass reason=\"a\x1bb\"", "mx.forward-a.example\x7f; none", "mx.forward-a.example; a\fb"} {
		if got, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", ar, lookup)); err == nil {
			t.Errorf("Sign accepted AuthResults %q: %q", ar, firstLine(got.Message, "ARC-Authentication-Results"))
		}
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

// Parsers disagree on a line that holds only CRs. Some end the header block
// there (postal-mime, Python's email package, MIME::Parser), some read on
// (Mail::DKIM, anything that looks for CRLF CRLF). Either reading lets a
// forger show one of them a body or a header block the other never hashed,
// so the message is refused.
func TestCROnlyLineIsRefused(t *testing.T) {
	for msg, wantBody := range map[string]string{
		"A: 1\r\n\r\nbody\r\n":           "body\r\n",
		"A: 1\n\nbody\n":                 "body\n",
		"A: 1\r\n\nbody\r\n":             "body\r\n",
		"A: 1\r\n\r\r\nB: 2\r\n\r\nbody": "body",
		"A: 1\r\n":                       "",
		"\r\nbody":                       "body",
	} {
		if _, body := splitMessage(msg); body != wantBody {
			t.Errorf("splitMessage(%q) body = %q, want %q", msg, body, wantBody)
		}
	}

	sealed, lookup := testChain(t, 1)
	key, _, _ := testKeys(t)
	cfg := signConfig(key, "forward-a.example", "sel-a", authResultsA, lookup)

	// A forged header block and body in front of the sealed message, ended
	// by a CR-only line. The real message hides inside an HTML comment.
	const fake = "From: Alice <alice@origin.example>\r\nSubject: Pay this invoice\r\nContent-Type: text/html\r\n" +
		"\r\r\n" + "<p>Wire 5000 EUR to the new account today.</p><!--\r\n"
	if tampered := bytes.Replace(sealed, []byte("From: Alice"), []byte(fake+"From: Alice"), 1); mustVerify(t, tampered, lookup).Pass {
		t.Error("the seal still verifies with a forged header block and body in front of a CR-only line")
	}
	for _, separator := range []string{"\r\n\r\r\n", "\r\n\r\r\r\n", "\r\n\r\n\r\r\n"} {
		if tampered := bytes.Replace(sealed, []byte("\r\n\r\n"), []byte(separator), 1); mustVerify(t, tampered, lookup).Pass {
			t.Errorf("the seal still verifies with the header separator changed to %q", separator)
		}
	}

	// Signing: with such a separator the body would be read as header lines
	// and left outside the body hash.
	for name, msg := range map[string]string{
		"CR CR LF separator":  strings.Replace(baseMessage, "\r\n\r\n", "\r\n\r\r\n", 1),
		"CR CR LF every line": strings.ReplaceAll(baseMessage, "\r\n", "\r\r\n"),
	} {
		if got, err := Sign([]byte(msg), cfg); !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("%s: Sign = %v, %v; want ErrMalformedMessage", name, got, err)
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
