package arc

import (
	"strings"
	"testing"
)

func TestCombinedAuthenticationResults(t *testing.T) {
	const edge = "edge.example"
	const first = "EDGE.example (incoming; edge) 1; spf=pass"
	const dkim = "dkim = pass reason=\"verified; eligible\" header.d=origin.example"
	for _, tc := range []struct {
		name   string
		fields []string
		want   string
	}{
		{"separate assessments in wire order", []string{first, "other.example; dmarc=pass", edge + "; " + dkim}, first + "; " + dkim},
		{"none with assessments", []string{edge + "; (edge) none (done)", edge + "; dkim=pass", edge + "; NONE"}, edge + "; dkim=pass"},
		{"none alone", []string{edge + "; none", edge + "; none"}, edge + "; none"},
		{"none mixed with a method in the same field", []string{edge + "; none; dkim=pass"}, ""},
		{"unclosed reason cannot absorb another field", []string{edge + "; spf=fail reason=\"unknown", edge + "; dkim=pass"}, ""},
		{"folded result", []string{edge + "; spf=pass", edge + " (incoming) 1; dkim\r\n\t= pass"}, edge + "; spf=pass; dkim = pass"},
		{"unknown field version excluded", []string{edge + " 2; dkim=fail", edge + "; spf=pass"}, edge + "; spf=pass"},
		{"unknown field version alone", []string{edge + " 2; dkim=pass"}, ""},
		{"no matching service", []string{"other.example; dkim=pass"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var headers strings.Builder
			for _, field := range tc.fields {
				headers.WriteString("Authentication-Results: " + field + "\r\n")
			}
			message := []byte(headers.String() + baseMessage)
			got, ok := CombinedAuthenticationResults(message, edge)
			if ok != (tc.want != "") || got != tc.want {
				t.Errorf("result = %q, %t; want %q", got, ok, tc.want)
			}
			if tc.name == "separate assessments in wire order" {
				if top, ok := FindAuthenticationResults(message, edge); !ok || top != first {
					t.Errorf("topmost result = %q, %t; want %q", top, ok, first)
				}
			}
		})
	}
}

func TestAuthenticationResultsStopAtFirstDefectiveField(t *testing.T) {
	const edge = "edge.example"
	const value = edge + "; none"
	const field = "Authentication-Results: " + value + "\r\n"
	for name, lookup := range map[string]func([]byte, string) (string, bool){
		"topmost": FindAuthenticationResults, "combined": CombinedAuthenticationResults,
	} {
		for _, tc := range []struct{ name, message, want string }{
			{"valid folded subject", "Subject: meeting\r\n notes\r\n" + field, value},
			{"orphan continuation", "\tmeeting notes\r\n" + field, ""},
			{"field before defect", field + "missing colon\r\n", value},
			{"invalid continuation of field", field + " notes\rfrom calendar\r\n", ""},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				got, ok := lookup([]byte(tc.message+"\r\n"), edge)
				if got != tc.want || ok != (tc.want != "") {
					t.Fatalf("got (%q, %t), want (%q, %t)", got, ok, tc.want, tc.want != "")
				}
			})
		}
	}
}

// The combined lookup trusts only the unambiguous top of the header block,
// refuses a block it could not read to the end, and refuses results it would
// have to hold too much of.
func TestCombinedAuthenticationResultsBounds(t *testing.T) {
	const edge = "edge.example"
	const field = "Authentication-Results: " + edge + "; dkim=pass\r\n"
	for name, message := range map[string]string{
		"below a malformed field":    "Subject\f: x\r\n" + field + baseMessage,
		"below a line with no colon": "not a field\r\n" + field + baseMessage,
		"past the field limit":       field + strings.Repeat("X-A: 1\r\n", maxHeaderFields) + baseMessage,
		"over the size bound":        "Authentication-Results: " + edge + "; " + strings.Repeat("x=y ", maxAuthResultsBytes/4) + "\r\n" + baseMessage,
		"over the size bound in all": strings.Repeat("Authentication-Results: "+edge+"; "+strings.Repeat("x=y ", maxAuthResultsBytes/40)+"\r\n", 12) + baseMessage,
	} {
		if got, ok := CombinedAuthenticationResults([]byte(message), edge); ok {
			t.Errorf("%s: combined %.60q", name, got)
		}
	}
	if got, ok := CombinedAuthenticationResults([]byte(field+"Subject\f: x\r\n"+baseMessage), edge); !ok || got != edge+"; dkim=pass" {
		t.Errorf("a field above the defect = %q, %t", got, ok)
	}
	key, _, _ := testKeys(t)
	big := edge + "; " + strings.Repeat("x=y ", maxAuthResultsBytes/4)
	if _, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", big, nil)); err == nil {
		t.Error("Sign accepted results over the size bound")
	}
}

// A quoted service ID is matched only as RFC 5322 decodes it: a quoted-pair
// may escape printable ASCII and tabs, nothing else.
func TestQuotedServiceIDsDecodeStrictly(t *testing.T) {
	for value, want := range map[string]bool{
		`"edge.example"; dkim=pass`:         true,
		`"edge\.example"; dkim=pass`:        true,
		"\"edge\\\xe9.example\"; dkim=pass": false,
		"\"edge\\\x01.example\"; dkim=pass": false,
		`"edge.example; dkim=pass`:          false,
	} {
		_, ok := CombinedAuthenticationResults([]byte("Authentication-Results: "+value+"\r\n"+baseMessage), "edge.example")
		if ok != want {
			t.Errorf("%q matched = %t, want %t", value, ok, want)
		}
	}
	// A line break inside a quoted result becomes one space when combined,
	// never a stray CR or LF in the sealed field.
	got, ok := CombinedAuthenticationResults([]byte("Authentication-Results: edge.example; dkim=pass reason=\"a\r\n\tb\"\r\n"+baseMessage), "edge.example")
	if !ok || strings.ContainsAny(got, "\r\n") || !strings.Contains(got, `"a`) {
		t.Errorf("folded quoted result combined as %q, %t", got, ok)
	}
	// A stray ")" makes the results unreadable rather than shorter.
	if got, ok := CombinedAuthenticationResults([]byte("Authentication-Results: edge.example; dkim=pass) spf=pass\r\n"+baseMessage), "edge.example"); ok {
		t.Errorf("a stray ')' was combined as %q", got)
	}
}

// A stray line break inside a quoted value of the results handed to Sign
// becomes one space in the sealed field: never a raw CR or LF, and never
// two words run together.
func TestSignTurnsAStrayLineBreakInQuotesIntoASpace(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for _, br := range []string{"\r", "\n", "\r\n"} {
		results := "mx.forward-a.example; dkim=pass reason=\"a" + br + "b\""
		sealed, err := Sign([]byte(baseMessage), signConfig(key, "forward-a.example", "sel-a", results, lookup))
		if err != nil {
			t.Fatalf("%q: %v", br, err)
		}
		if _, payload, ok := LatestARCAuthResults(sealed.Message); !ok || !strings.Contains(payload, `reason="a b"`) {
			t.Errorf("%q: sealed results %q", br, payload)
		}
		if !mustVerify(t, sealed.Message, lookup).Pass {
			t.Errorf("%q: the seal does not verify", br)
		}
	}
}

func TestCombinedAuthenticationResultsPayloadLimit(t *testing.T) {
	const edge = "edge.example"
	const field = "Authentication-Results: "
	for _, n := range []int{maxAuthResultsBytes, maxAuthResultsBytes + 1} {
		// Fold the service comment at spaces. Unfolding removes each CRLF
		// but retains its following space in the returned prefix.
		commentBytes := n - len(edge+" () 1; none")
		line := strings.Repeat("x", 850)
		complete, extra := commentBytes/(len(line)+1), commentBytes%(len(line)+1)
		comment := strings.Repeat(line+"\r\n ", complete) + strings.Repeat("y", extra)
		value := edge + " (" + comment + ") 1; none"
		got, ok := CombinedAuthenticationResults([]byte(field+value+"\r\n"+baseMessage), edge)
		if n == maxAuthResultsBytes {
			if !ok || got != strings.ReplaceAll(value, "\r\n", "") {
				t.Errorf("at %d bytes: got %d bytes, ok=%t", n, len(got), ok)
			}
		} else if ok || got != "" {
			t.Errorf("at %d bytes: got %d bytes, ok=%t", n, len(got), ok)
		}
	}

	// Each method below is separated by one semicolon on input. The
	// combiner joins methods with a semicolon and a space. This field is
	// under the input cap, but its assembled payload exceeds the limit.
	line := strings.Repeat(";spf=pass", 70)
	value := edge + strings.Repeat(line+"\r\n ", 99) + ";dkim=pass"
	if len(value) >= maxAuthResultsBytes {
		t.Fatal("separator fixture exceeds raw input limit")
	}
	if got, ok := CombinedAuthenticationResults([]byte(field+value+"\r\n"+baseMessage), edge); ok || got != "" {
		t.Errorf("added separators: got %d bytes, ok=%t", len(got), ok)
	}
}
