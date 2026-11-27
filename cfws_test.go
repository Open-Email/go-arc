package arc

import (
	"crypto/sha256"
	"strings"
	"testing"
)

var signatureCommentInstances = []struct {
	name, clause string
}{
	{"trailing", "i=1 (note; b=comment);"},
	{"leading", "(note; b=comment) i=1;"},
	{"nested", "i (note (nested; b=comment)) = 1;"},
	{"escaped", "i=1 (note\\); b=comment);"},
	{"folded", "i=\r\n\t(note;\r\n\tb=comment) 1;"},
}

func TestRemoveSignatureValueInstanceComments(t *testing.T) {
	for _, tc := range signatureCommentInstances {
		t.Run(tc.name, func(t *testing.T) {
			prefix := "ARC-Seal: " + tc.clause + " a=rsa-sha256; "
			for _, suffix := range []string{"\r\n", "; d=example.org\r\n"} {
				raw := prefix + "b=SIGNATURE" + suffix
				want := prefix + "b="
				if strings.HasPrefix(suffix, ";") {
					want += suffix
				}
				if got := removeSignatureValue(raw); got != want {
					t.Errorf("removeSignatureValue(%q) = %q, want %q", raw, got, want)
				}
			}
			// A b= inside a comment must not count as a signature tag.
			if got := removeSignatureValue(prefix); got != prefix {
				t.Errorf("header without b= changed: got %q, want %q", got, prefix)
			}
		})
	}
}

func TestParseTagsIgnoresInstanceComments(t *testing.T) {
	value := "(note; a=not-an-algorithm; h=from; b=not-a-signature;) i=01; d=example.org"
	tags := parseTags(value)
	if tags["i"] != "1" || tags["d"] != "example.org" {
		t.Fatalf("missing instance or real tag: %v", tags)
	}
	for _, name := range []string{"a", "h", "b"} {
		if _, ok := tags[name]; ok {
			t.Errorf("comment supplied a %s= tag: %v", name, tags)
		}
	}
}

// Sign the complete unsigned header before inserting the real b= value.
// This keeps the signing input independent of the signature-removal parser.
func TestVerifyInstanceCommentsContainingSignatureTag(t *testing.T) {
	msg, lookup := testChain(t, 1)
	key, _, _ := testKeys(t)
	headers, _ := splitMessage(string(msg))
	for _, headerName := range []string{"ARC-Message-Signature", "ARC-Seal"} {
		for _, tc := range signatureCommentInstances {
			t.Run(headerName+"/"+tc.name, func(t *testing.T) {
				var aar, ams, seal string
				for _, h := range headers {
					if h.key == "ARC-Authentication-Results" {
						aar = h.raw
						continue
					}
					if h.key != "ARC-Message-Signature" && h.key != "ARC-Seal" {
						continue
					}
					unsigned := removeSignatureValue(h.raw) + "\r\n"
					if h.key == headerName {
						unsigned = strings.Replace(unsigned, "i=1;", tc.clause, 1)
					}
					if h.key == "ARC-Message-Signature" {
						ams = unsigned
					} else {
						seal = unsigned
					}
				}
				resign := func(unsigned, input string) string {
					t.Helper()
					hash := sha256.Sum256([]byte(input))
					sig, err := signHash(key, hash[:])
					if err != nil {
						t.Fatal(err)
					}
					signed, err := spliceSignature(unsigned, sig)
					if err != nil {
						t.Fatal(err)
					}
					return signed
				}
				originalAMS, ok := findARCHeader(headers, "ARC-Message-Signature", 1)
				if !ok {
					t.Fatal("fixture has no AMS")
				}
				signedHeaders, err := selectHeaders("ARC-Message-Signature", parseTags(originalAMS.value)["h"], headers)
				if err != nil {
					t.Fatal(err)
				}
				var amsInput strings.Builder
				for _, h := range signedHeaders {
					amsInput.WriteString(canonicalizeHeaderRaw(h.raw, canonRelaxed))
				}
				amsInput.WriteString(strings.TrimRight(canonicalizeHeaderRaw(ams, canonRelaxed), "\r\n"))
				ams = resign(ams, amsInput.String())
				sealInput := canonicalizeHeaderRaw(aar, canonRelaxed) + canonicalizeHeaderRaw(ams, canonRelaxed) + strings.TrimRight(canonicalizeHeaderRaw(seal, canonRelaxed), "\r\n")
				seal = resign(seal, sealInput)
				signedMsg := []byte(seal + ams + aar + baseMessage)
				res := mustVerify(t, signedMsg, lookup)
				if !res.Pass || !res.ChainValid || res.Instance != 1 {
					t.Fatalf("valid commented chain rejected: %+v", res)
				}
				// Comment text remains part of the signed bytes.
				tampered := []byte(strings.Replace(string(signedMsg), "note", "changed", 1))
				if mustVerify(t, tampered, lookup).Pass {
					t.Fatal("changing a signed comment must invalidate the chain")
				}
			})
		}
	}
}

func TestVerifySealTagFoldingAndComments(t *testing.T) {
	key, _, _ := testKeys(t)
	lookup := dnsStub(map[string]string{"sel-a._domainkey.forward-a.example": txtFor(t, key)})
	for _, tc := range []struct {
		name, cv, b string
	}{
		{"ordinary", "cv=none", "b="},
		{"fold before signature equals", "cv=none", "b\r\n\t="},
		{"comment before status", "cv= (first hop) none", "b="},
		{"comments around status equals", "cv (relay; east) =\r\n\t(message (received); morning) none", "b="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := handSeal(t, key, baseMessage, handSealOptions{formatSeal: func(unsigned string) string {
				unsigned = strings.Replace(unsigned, "cv=none", tc.cv, 1)
				return strings.TrimSuffix(unsigned, "b=\r\n") + tc.b + "\r\n"
			}})
			got := mustVerify(t, msg, lookup)
			if !got.Pass || !got.ChainValid || len(got.Instances) != 1 || got.Instances[0].ChainStatus != ChainNone {
				t.Fatalf("first-hop seal failed: %+v", got)
			}
		})
	}
}

func TestVerifySealStatusCase(t *testing.T) {
	keyA, keyB, _ := testKeys(t)
	for _, tc := range []struct {
		status   string
		hops     int
		expected ChainStatus
	}{
		{"none", 1, ChainNone},
		{"NONE", 1, ChainNone},
		{"PaSs", 2, ChainPass},
	} {
		t.Run(tc.status, func(t *testing.T) {
			chain, lookup := testChain(t, tc.hops)
			headers, _ := splitMessage(string(chain))
			seal := headers[0]
			unsigned := strings.Replace(removeSignatureValue(seal.raw), "cv="+string(tc.expected), "cv="+tc.status, 1) + "\r\n"
			hasher := sha256.New()
			for _, field := range arcHeadersUpTo(headers, tc.hops) {
				hasher.Write([]byte(canonicalizeHeaderRaw(field.raw, canonRelaxed)))
			}
			hasher.Write([]byte(trimLineBreak(canonicalizeHeaderRaw(unsigned, canonRelaxed))))
			key := keyA
			if tc.hops == 2 {
				key = keyB
			}
			signature, err := signHash(key, hasher.Sum(nil))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := spliceSignature(unsigned, signature)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte(signed + string(chain[len(seal.raw):]))
			got := mustVerify(t, msg, lookup)
			if !got.Pass || !got.ChainValid || len(got.Instances) != tc.hops || got.Instances[tc.hops-1].ChainStatus != tc.expected {
				t.Fatalf("cv=%s: %+v", tc.status, got)
			}
			if tc.status != string(tc.expected) {
				edited := strings.Replace(string(msg), "cv="+tc.status, "cv="+string(tc.expected), 1)
				if mustVerify(t, []byte(edited), lookup).Pass {
					t.Fatal("changing signed status bytes without signing again passed verification")
				}
			}
		})
	}
}
