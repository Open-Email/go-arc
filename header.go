package arc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
)

// rawHeader is one header field with its exact wire bytes preserved.
// Signatures are computed over raw bytes (canonicalized), so parsing
// must never normalize what it stores.
type rawHeader struct {
	key      string // field name, surrounding whitespace trimmed
	value    string // everything after the first colon, folds preserved
	raw      string // exact bytes including folds and trailing line break
	instance int    // parsed i= tag for ARC-* headers, else 0
}

// splitMessage splits a message into its header fields and body,
// preserving each header's exact raw bytes. Both CRLF and bare LF line
// endings are tolerated; the raw bytes are kept as found.
func splitMessage(raw string) ([]rawHeader, string) {
	var headers []rawHeader
	curStart := -1

	flush := func(end int) {
		if curStart < 0 {
			return
		}
		rawH := raw[curStart:end]
		key, value := rawH, ""
		if colon := strings.Index(rawH, ":"); colon >= 0 {
			key = rawH[:colon]
			value = rawH[colon+1:]
		}
		h := rawHeader{key: strings.TrimSpace(key), value: value, raw: rawH}
		if strings.HasPrefix(strings.ToLower(h.key), "arc-") {
			h.instance = extractInstance(h.value)
		}
		headers = append(headers, h)
		curStart = -1
	}

	pos := 0
	for pos < len(raw) {
		lineEnd := strings.IndexByte(raw[pos:], '\n')
		var next int
		if lineEnd < 0 {
			next = len(raw)
		} else {
			next = pos + lineEnd + 1
		}
		line := raw[pos:next]
		if strings.TrimRight(line, "\r\n") == "" {
			// Blank line: end of the header block.
			flush(pos)
			return headers, raw[next:]
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush(pos)
			curStart = pos
		}
		// Continuation lines extend the current header; nothing to do
		// until the next flush.
		pos = next
	}
	flush(len(raw))
	return headers, ""
}

// extractInstance parses the i= tag out of an ARC header value per
// RFC 8617 §3.9 / §4.1.1 / §5.2 ([CFWS] "i" [CFWS] "=" [CFWS] 1*2DIGIT,
// range 1..MaxChainLength).
func extractInstance(value string) int {
	for s := value; s != ""; {
		if n, _, matched := parseInstanceClause(s); matched {
			return n
		}
		semi := strings.IndexByte(s, ';')
		if semi < 0 {
			return 0
		}
		s = s[semi+1:]
	}
	return 0
}

// parseInstanceClause checks whether s begins with an RFC 8617 §3.9
// instance tag ([CFWS] "i" [CFWS] "=" [CFWS] 1*2DIGIT [CFWS]) followed
// by either end-of-string or ';'.
//
// matched reports whether s started with an "i=" tag name (or had
// malformed leading CFWS); when matched is true and n is 0, the tag
// value is invalid and callers must fail closed rather than searching
// later tags.
func parseInstanceClause(s string) (n int, rest string, matched bool) {
	s, ok := skipCFWS(s)
	if !ok {
		return 0, "", true
	}
	if len(s) == 0 || s[0] != 'i' {
		return 0, "", false
	}
	s, ok = skipCFWS(s[1:])
	if !ok {
		return 0, "", true
	}
	if len(s) == 0 || s[0] != '=' {
		return 0, "", false
	}
	s, ok = skipCFWS(s[1:])
	if !ok {
		return 0, "", true
	}
	d := 0
	for d < len(s) && s[d] >= '0' && s[d] <= '9' {
		d++
	}
	if d < 1 || d > 2 {
		return 0, "", true
	}
	// The ABNF permits 1–2 DIGITs, including 01..09. Enforce the
	// numeric lower bound below, rather than rejecting a leading zero.
	v, err := strconv.Atoi(s[:d])
	if err != nil || v < 1 || v > MaxChainLength {
		return 0, "", true
	}
	s, ok = skipCFWS(s[d:])
	if !ok {
		return 0, "", true
	}
	if len(s) > 0 && s[0] != ';' {
		return 0, "", true
	}
	return v, s, true
}

// skipCFWS advances past leading RFC 5322 folding whitespace and
// (possibly nested) parenthesized comments. It returns false if a
// comment is unclosed or ends with a trailing backslash escape.
func skipCFWS(s string) (string, bool) {
	for {
		i := 0
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
			i++
		}
		s = s[i:]
		if len(s) == 0 || s[0] != '(' {
			return s, true
		}
		depth := 0
		for j := 0; j < len(s); j++ {
			switch s[j] {
			case '\\':
				j++
				if j >= len(s) {
					return "", false
				}
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					s = s[j+1:]
					goto nextCFWS
				}
			}
		}
		return "", false
	nextCFWS:
	}
}

// parseTags splits a signature header value into its tag/value pairs.
// Malformed tags are skipped; required-tag enforcement is the caller's.
func parseTags(value string) map[string]string {
	tags := make(map[string]string)
	// The ARC instance clause permits comments containing semicolons
	// and tag-shaped text. Only the following tag-list contains tags.
	if n, rest, matched := parseInstanceClause(value); matched {
		if n == 0 {
			return tags
		}
		tags["i"] = strconv.Itoa(n)
		value = strings.TrimPrefix(rest, ";")
	}
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return tags
}

type canonicalization string

const (
	canonSimple  canonicalization = "simple"
	canonRelaxed canonicalization = "relaxed"
)

func parseCanonicalization(c string) (header, body canonicalization) {
	if c == "" {
		return canonSimple, canonSimple
	}
	parts := strings.Split(c, "/")
	header = canonicalization(strings.TrimSpace(parts[0]))
	body = canonSimple
	if len(parts) > 1 {
		body = canonicalization(strings.TrimSpace(parts[1]))
	}
	return header, body
}

// canonicalizeHeaderRaw applies RFC 6376 header canonicalization to one
// raw header line (folds included). Relaxed: lowercase the field name,
// unfold, collapse whitespace runs to a single space, trim.
func canonicalizeHeaderRaw(raw string, canon canonicalization) string {
	if canon == canonSimple {
		return raw
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) < 2 {
		return raw
	}
	key := strings.ToLower(strings.TrimSpace(parts[0]))
	val := strings.Join(strings.Fields(parts[1]), " ")
	return key + ":" + val + "\r\n"
}

// canonicalizeBody applies RFC 6376 body canonicalization and returns
// the canonical bytes.
func canonicalizeBody(body string, canon canonicalization) []byte {
	if canon == canonSimple {
		for strings.HasSuffix(body, "\r\n") {
			body = strings.TrimSuffix(body, "\r\n")
		}
		return []byte(body + "\r\n")
	}

	// Relaxed: strip trailing WSP per line, collapse interior WSP runs
	// to one space, drop trailing empty lines, CRLF line endings. An
	// empty body canonicalizes to zero bytes.
	lines := strings.Split(body, "\n")
	canonical := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimRight(line, " \t")
		var sb strings.Builder
		spaceSeen := false
		for _, r := range line {
			if r == ' ' || r == '\t' {
				if !spaceSeen {
					sb.WriteRune(' ')
					spaceSeen = true
				}
			} else {
				sb.WriteRune(r)
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

// removeSignatureValue empties the b= tag's value in a raw signature
// header, per RFC 6376 §3.7 (the signature header is hashed with a null
// b= value). It walks tag STARTS (after the header colon or a ';'), so
// a "b=" occurring inside another tag's folded base64 value — 'b'
// followed by padding after a fold — can never match. The ARC instance
// clause is skipped as a whole so its comments remain signed verbatim.
func removeSignatureValue(raw string) string {
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return raw
	}
	i := colon + 1
	if n, rest, matched := parseInstanceClause(raw[i:]); matched {
		if n == 0 || rest == "" {
			return raw
		}
		// rest starts at the semicolon after the complete instance clause.
		i = len(raw) - len(rest) + 1
	}
	for i < len(raw) {
		// Skip FWS to the start of the next tag.
		j := i
		for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\r' || raw[j] == '\n') {
			j++
		}
		if j >= len(raw) {
			return raw
		}
		if raw[j] == 'b' {
			k := j + 1
			for k < len(raw) && (raw[k] == ' ' || raw[k] == '\t') {
				k++
			}
			if k < len(raw) && raw[k] == '=' {
				end := strings.IndexByte(raw[k:], ';')
				if end < 0 {
					return raw[:k+1]
				}
				return raw[:k+1] + raw[k+end:]
			}
		}
		// Not the b= tag: skip this whole tag (values contain no ';').
		next := strings.IndexByte(raw[j:], ';')
		if next < 0 {
			return raw
		}
		i = j + next + 1
	}
	return raw
}

// parsePublicKey extracts the RSA public key from a DKIM-style TXT
// record ("v=DKIM1; k=rsa; p=<base64>").
func parsePublicKey(record string) (*rsa.PublicKey, error) {
	var p string
	for _, part := range strings.Split(record, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && kv[0] == "p" {
			p = kv[1]
			break
		}
	}
	if p == "" {
		return nil, fmt.Errorf("no public key in record")
	}
	data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(p), ""))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		// Some records carry PKCS#1 despite the spec.
		if pk1, err1 := x509.ParsePKCS1PublicKey(data); err1 == nil {
			return pk1, nil
		}
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPub, nil
}

// LoadPrivateKeyPEM parses a PEM-encoded RSA private key in PKCS#1
// ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY") form.
func LoadPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// foldHeader renders a header as "Name: tag1; tag2; ..." folded between
// tags so no line exceeds the wrap width. Tag values are never split
// internally; the b= value is spliced in after signing, so the fold
// layout is frozen before the hash is computed.
func foldHeader(name string, tags []string) string {
	const wrap = 76
	var sb strings.Builder
	sb.WriteString(name)
	sb.WriteString(":")
	lineLen := len(name) + 1
	for i, tag := range tags {
		chunk := " " + tag
		if i < len(tags)-1 {
			chunk += ";"
		}
		if lineLen+len(chunk) > wrap && lineLen > len(name)+1 {
			sb.WriteString("\r\n\t")
			lineLen = 1
		}
		sb.WriteString(chunk)
		lineLen += len(chunk)
	}
	sb.WriteString("\r\n")
	return sb.String()
}
