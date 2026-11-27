package arc

import (
	"strings"
	"testing"
)

func TestSealAuthenticationResultsAcrossFullContinuations(t *testing.T) {
	const id = "relay.example"
	// A quoted result word or entire clause occupies the rest of a legal
	// 998-octet continuation after its leading space.
	reason := `reason="` + strings.Repeat("x", 988) + `"`
	commented := "dkim=pass(" + strings.Repeat("n", 986) + ")"
	longID := strings.Repeat("a", 997)
	for _, tc := range []struct {
		name, service, field, want string
	}{
		{"full final word before separator", id,
			id + "; dkim=neutral\r\n " + reason + "\r\n ; spf=pass",
			id + "; dkim=neutral " + reason + "; spf=pass"},
		{"consecutive full clauses", id,
			id + ";\r\n " + commented + "\r\n ;\r\n " + commented,
			id + "; " + commented + "; " + commented},
		{"full service ID before separator", longID,
			"\r\n " + longID + "\r\n ; dkim=pass",
			longID + "; dkim=pass"},
		{"full final word at end of field", id,
			id + "; dkim=neutral\r\n " + reason,
			id + "; dkim=neutral " + reason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("Authentication-Results: " + tc.field + "\r\n" + baseMessage)
			for _, line := range strings.Split(string(raw), "\r\n") {
				if len(line) > 998 {
					t.Fatalf("input line exceeds the RFC 5322 limit: %d", len(line))
				}
			}
			auth, ok := CombinedAuthenticationResults(raw, tc.service)
			if !ok || auth != tc.want {
				t.Fatal("input authentication results did not round-trip")
			}
			key, _, _ := testKeys(t)
			lookup := dnsStub(map[string]string{"m1._domainkey.relay.example": txtFor(t, key)})
			set, err := Sign(raw, signConfig(key, id, "m1", auth, lookup))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(set.Message), "\r\n") {
				if len(line) > 998 || len(line) != 0 && strings.Trim(line, " \t") == "" {
					t.Fatalf("invalid emitted physical line of %d bytes", len(line))
				}
			}
			verified := mustVerify(t, set.Message, lookup)
			got, ok := verified.OldestAuthResults()
			// A fold before a separator adds insignificant CFWS outside the
			// quoted reason. Compare the service and each result separately.
			clauses := splitAuthResultsClauses(got)
			for i := range clauses {
				clauses[i] = strings.TrimSpace(clauses[i])
			}
			if !verified.Pass || !ok || strings.Join(clauses, "; ") != tc.want {
				t.Fatal("signed authentication results did not round-trip")
			}
		})
	}
}
