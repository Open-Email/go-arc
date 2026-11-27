package arc

import "testing"

func TestSignValidatesASCIIAndInternationalizedDNSLabels(t *testing.T) {
	key, _, _ := testKeys(t)
	for _, tc := range []struct {
		domain, selector string
		valid            bool
	}{
		{"xn--a.example", "mail", false},
		{"example.org", "xn--a", false},
		{"xn--abc-.example", "mail", false},
		{"xn--a.bücher.example", "mail", false},
		{"mail-.example", "mail", false},
		{"-mail.example", "mail", false},
		{"mail_edge.example", "mail", false},
		{"localhost", "mail", false},
		{"bücher", "mail", false},
		{"example.org", "mail-", false},
		{"XN--BCHER-KVA.EXAMPLE", "mail", true},
		{"XN--BCHER-KVA.märz.Example", "mail", true},
		{"example.org", "legacy_selector", true},
	} {
		t.Run(tc.domain+"/"+tc.selector, func(t *testing.T) {
			_, err := Sign([]byte(baseMessage), signConfig(key, tc.domain, tc.selector, authResultsA, nil))
			if (err == nil) != tc.valid {
				t.Errorf("Sign error = %v, want valid = %t", err, tc.valid)
			}
		})
	}
}
