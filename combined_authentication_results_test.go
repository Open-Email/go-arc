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
