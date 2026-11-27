package arc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// rawHeader is one header field with its exact wire bytes preserved.
// Signatures are computed over raw bytes (canonicalized), so parsing
// must never normalize what it stores.
type rawHeader struct {
	key      string // field name as fieldName reads it; "" if the line has no colon
	value    string // everything after the first colon, folds preserved
	raw      string // exact bytes including folds and trailing line break
	instance int    // parsed i= tag for ARC-* headers, else 0
}

// asciiEqualFold compares header field names (and authserv-ids, which are
// domain names). RFC 5322 §3.6.8 limits a field name to printable US-ASCII,
// so only ASCII letters fold. strings.EqualFold also folds Unicode, letting
// "ſubject" (U+017F) or a Kelvin sign (U+212A) stand in for an ASCII name
// that every other implementation reads as a different header: a signer
// would then cover the look-alike instead of the real Subject.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if asciiLowerByte(a[i]) != asciiLowerByte(b[i]) {
			return false
		}
	}
	return true
}

// fieldName splits a raw header field at its first colon. The name is every
// byte before the colon, less SP and HTAB directly before it (the obsolete
// syntax of RFC 5322 §4.5 lets them stand there, and RFC 6376 §3.4.2 deletes
// them). Nothing else is trimmed: a CR, a no-break space or any other byte in
// the name makes it a different name, so a line such as "\rSubject: x" or
// "Subject\u00a0: x" is never taken for the Subject. ok is false for a line
// with no colon, which matches no name.
//
// Matching names exactly is not enough on its own. A mail reader may still
// take such a line for the Subject, so a message that holds one is refused
// as a whole: see parseMessage.
func fieldName(raw string) (name, value string, ok bool) {
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return "", "", false
	}
	return strings.TrimRight(raw[:colon], " \t"), raw[colon+1:], true
}

// trimFWS removes the bytes folding whitespace is made of (SP, HTAB, CR, LF)
// from both ends of a tag name or value. strings.TrimSpace would also remove
// Unicode whitespace, which no other DKIM or ARC implementation ignores.
func trimFWS(s string) string {
	return strings.Trim(s, " \t\r\n")
}

// stripFWS removes every SP, HTAB, CR and LF, for base64 tag values, which
// may be folded anywhere (RFC 6376 §3.5). Any other byte is left for the
// base64 decoder to reject.
func stripFWS(s string) string {
	if !strings.ContainsAny(s, " \t\r\n") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// trimLineBreak removes the one CRLF, or bare LF, that ends s.
func trimLineBreak(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	return strings.TrimSuffix(s, "\n")
}

// asciiLower lowercases ASCII letters only, for the same reason.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = asciiLowerByte(b[i])
	}
	return string(b)
}

func asciiLowerByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// isARCHeader reports whether key names one of the three RFC 8617 §4.1
// ARC header fields. Non-standard "ARC-*" fields are not part of an ARC set.
func isARCHeader(key string) bool {
	return asciiEqualFold(key, "ARC-Authentication-Results") ||
		asciiEqualFold(key, "ARC-Message-Signature") ||
		asciiEqualFold(key, "ARC-Seal")
}

// maxHeaderFields bounds the header fields of one message. Ordinary mail
// has a few dozen; the bound keeps a message made of millions of short lines
// from costing gigabytes.
const maxHeaderFields = 10000

var errHeaderFieldLimit = fmt.Errorf("more than %d header fields", maxHeaderFields)

// splitMessage splits a message into its header fields and body,
// preserving each header's exact raw bytes. Both CRLF and bare LF line
// endings are tolerated; the raw bytes are kept as found.
func splitMessage(raw string) ([]rawHeader, string) {
	headers, body, _ := parseMessage(raw)
	return headers, body
}

// parseMessage is splitMessage, and also reports the first defect of the
// header block, or nil when every line of it is one of:
//
//   - a header field: a name of printable ASCII characters other than ":",
//     directly followed by ":" (RFC 5322 §2.2);
//   - a continuation of the field before it: a line that starts with SP or
//     HTAB.
//
// Anything else is read differently by different software. A line such as
// "Subject<FF>: x" or "<BOM>Subject: x" is no Subject here, but a mail reader
// that trims the name shows it as one. A line that holds only CRs, or no
// colon, or a space before its colon, ends the header block for some parsers
// and not for others, so one of them shows as the body what another reads as
// header fields. No reading is safe for all of them. A signature must mean
// the same header block to every reader, so Sign refuses such a message and
// Verify fails any ARC chain on it.
//
// The body is outside this check. Relaxed body canonicalization (RFC 6376
// §3.4.4) deliberately lets white space at line ends change, and this
// package reads a bare LF as a line break, so software that splits MIME
// parts more strictly can still be shown a part boundary differently.
//
// The header block ends at the first empty line (CRLF or LF alone), or at a
// lone CR that ends the input. Past maxHeaderFields it returns a partial
// header block, an empty body and errHeaderFieldLimit even if an earlier
// line was malformed.
func parseMessage(raw string) (headers []rawHeader, body string, defect error) {
	curStart := -1
	note := func(d string) {
		if defect == nil {
			defect = errors.New(d)
		}
	}
	flush := func(end int) {
		if curStart < 0 {
			return
		}
		rawH := raw[curStart:end]
		key, value, _ := fieldName(rawH)
		h := rawHeader{key: key, value: value, raw: rawH}
		if isARCHeader(h.key) {
			h.instance = extractInstance(h.value)
		}
		headers = append(headers, h)
		curStart = -1
	}

	pos := 0
	for pos < len(raw) {
		lineEnd := strings.IndexByte(raw[pos:], '\n')
		next := len(raw)
		if lineEnd >= 0 {
			next = pos + lineEnd + 1
		}
		line := raw[pos:next]
		if line == "\r\n" || line == "\n" {
			// Empty line: end of the header block.
			flush(pos)
			return headers, raw[next:], defect
		}
		content := trimLineBreak(line)
		if lineEnd < 0 {
			// A CR that ends the input is the start of its last line
			// break, as in canonicalizeBody.
			content = strings.TrimSuffix(content, "\r")
			if content == "" {
				flush(pos)
				return headers, "", defect
			}
		}
		if strings.IndexByte(content, '\r') >= 0 {
			note("a CR that is not part of a line break")
		}
		if line[0] == ' ' || line[0] == '\t' {
			// A continuation line extends the current header. One that
			// holds only white space is obsolete syntax that no parser
			// tried reads differently, and that mail software emits.
			if curStart < 0 {
				note("a continuation line with no header field before it")
			}
		} else {
			flush(pos)
			if len(headers) >= maxHeaderFields {
				return headers, "", errHeaderFieldLimit
			}
			curStart = pos
			colon := strings.IndexByte(content, ':')
			if colon <= 0 {
				note("a line that is not a header field")
			}
			for i := 0; i < colon; i++ {
				if content[i] < 33 || content[i] > 126 {
					note("a header field name that is not printable ASCII followed by a colon")
					break
				}
			}
		}
		pos = next
	}
	flush(len(raw))
	return headers, "", defect
}

// extractInstance parses the i= tag out of an ARC header value per
// RFC 8617 §3.9 / §4.1.1 / §5.2 ([CFWS] "i" [CFWS] "=" [CFWS] 1*2DIGIT,
// range 1..MaxChainLength).
//
// The tag may follow other tags. A clause that is not the instance tag ends
// at the first ';' after any comments it opens with: a ';' inside such a
// comment separates nothing, as inside the instance clause itself. Resuming
// after what parseInstanceClause already read also keeps the scan linear;
// restarting inside a nested comment made it quadratic.
func extractInstance(value string) int {
	for s := value; s != ""; {
		n, rest, matched := parseInstanceClause(s)
		if matched {
			return n
		}
		semi := strings.IndexByte(rest, ';')
		if semi < 0 {
			return 0
		}
		s = rest[semi+1:]
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
// later tags. When matched is false, rest is what follows the CFWS (and
// the "i") that were read.
func parseInstanceClause(s string) (n int, rest string, matched bool) {
	s, ok := skipCFWS(s)
	if !ok {
		return 0, "", true
	}
	if len(s) == 0 || s[0] != 'i' {
		return 0, s, false
	}
	s, ok = skipCFWS(s[1:])
	if !ok {
		return 0, "", true
	}
	if len(s) == 0 || s[0] != '=' {
		return 0, s, false
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
// Malformed tags are skipped; required-tag enforcement is the caller's. A
// tag given twice keeps its last value: use parseTagList wherever the value
// decides something.
func parseTags(value string) map[string]string {
	tags, _ := parseTagList(value)
	return tags
}

// maxTags bounds the tags of one signature header. RFC 8617 and RFC 6376
// define about a dozen.
const maxTags = 64

// parseTagList is parseTags, and also reports a tag name that occurs more
// than once, or more than maxTags tags. RFC 6376 §3.2 makes the whole
// tag-list invalid for a duplicate: one reader would take the first d= or
// cv= and another the last.
func parseTagList(value string) (map[string]string, error) {
	tags := make(map[string]string)
	var invalid error
	// The ARC instance clause permits comments containing semicolons
	// and tag-shaped text. Only the following tag-list contains tags.
	if n, rest, matched := parseInstanceClause(value); matched {
		if n == 0 {
			return tags, nil
		}
		tags["i"] = strconv.Itoa(n)
		value = strings.TrimPrefix(rest, ";")
	}
	// Walk the list in place: a value made of millions of ";" must not
	// cost a slice entry each.
	for more := true; more; {
		var part string
		part, value, more = strings.Cut(value, ";")
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		// RFC 6376 §3.2: [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS].
		if name = trimFWS(name); name != "" {
			if _, seen := tags[name]; seen && invalid == nil {
				invalid = fmt.Errorf("tag %q occurs more than once", name)
			}
			if len(tags) >= maxTags {
				return tags, fmt.Errorf("more than %d tags", maxTags)
			}
			tags[name] = trimFWS(val)
		}
	}
	return tags, invalid
}

type canonicalization string

const (
	canonSimple  canonicalization = "simple"
	canonRelaxed canonicalization = "relaxed"
)

// parseCanonicalization reads a c= tag: "header" or "header/body", each
// simple or relaxed, body defaulting to simple (RFC 6376 §3.5). Any other
// value is an error; it must not be read as one of the two.
func parseCanonicalization(c string) (header, body canonicalization, err error) {
	if c == "" {
		return canonSimple, canonSimple, nil
	}
	h, b, hasBody := strings.Cut(c, "/")
	header, body = canonicalization(trimFWS(h)), canonSimple
	if hasBody {
		body = canonicalization(trimFWS(b))
	}
	for _, v := range []canonicalization{header, body} {
		if v != canonSimple && v != canonRelaxed {
			return "", "", fmt.Errorf("unsupported canonicalization %q", c)
		}
	}
	return header, body, nil
}

// collapseASCIIWSP turns each run of SP, HTAB, CR and LF into one SP and
// trims both ends, leaving every other octet as found. It is for values that
// are read or written again (an authserv-id, the results put into a new
// ARC-Authentication-Results), where a CR or LF must not survive to end a
// header line. It is NOT a canonicalization: relaxedHeaderValue is.
func collapseASCIIWSP(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	inSpace := false
	for i := 0; i < len(s); i++ {
		switch b := s[i]; b {
		case ' ', '\t', '\r', '\n':
			if sb.Len() > 0 {
				inSpace = true
			}
		default:
			if inSpace {
				sb.WriteByte(' ')
				inSpace = false
			}
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// unfoldAuthenticationResults retains quoted-string content and comments.
// Unfolding removes a line break before WSP, leaving the whitespace itself
// intact (RFC 5322 §§2.2.3, 3.2.4). Outside those constructs, whitespace
// separates tokens and can be normalized for the combined AAR.
func unfoldAuthenticationResults(value string) string {
	if !strings.ContainsAny(value, "\"(") {
		return collapseASCIIWSP(value)
	}
	var out strings.Builder
	out.Grow(len(value))
	depth := 0
	quoted, escaped, pendingSpace := false, false, false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !quoted && depth == 0 {
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				pendingSpace = out.Len() > 0
				continue
			}
			if pendingSpace {
				out.WriteByte(' ')
				pendingSpace = false
			}
		} else if c == '\r' || c == '\n' {
			if c == '\r' && i+1 < len(value) && value[i+1] == '\n' {
				i++
			}
			if i+1 == len(value) || value[i+1] != ' ' && value[i+1] != '\t' {
				out.WriteByte(' ') // never emit a stray line break
			}
			escaped = false
			continue
		}
		out.WriteByte(c)
		switch {
		case escaped:
			escaped = false
		case c == '\\' && (quoted || depth > 0):
			escaped = true
		case c == '"' && depth == 0:
			quoted = !quoted
		case c == '(' && !quoted:
			depth++
		case c == ')' && depth > 0:
			depth--
		}
	}
	return out.String()
}

// relaxedHeaderValue applies RFC 6376 §3.4.2 to a field value, read exactly:
// the line break of every fold is removed, every run of WSP (SP and HTAB)
// becomes one SP, and WSP at either end goes. A fold is a line break followed
// by WSP; a bare LF counts as a line break there because splitMessage accepts
// bare-LF messages. A CR that is not part of a line break is an ordinary
// octet. Reading it as whitespace would let "Hello there" be changed to
// "Hello\rthere" under a valid signature, and deleting it would do the same
// for "Hel\rlo".
func relaxedHeaderValue(value string) string {
	value = trimLineBreak(value)
	var sb strings.Builder
	sb.Grow(len(value))
	inSpace := false
	for i := 0; i < len(value); i++ {
		b := value[i]
		if n := lineBreakLen(value[i:]); n > 0 && i+n < len(value) && (value[i+n] == ' ' || value[i+n] == '\t') {
			i += n - 1
			continue
		}
		if b == ' ' || b == '\t' {
			inSpace = sb.Len() > 0
			continue
		}
		if inSpace {
			sb.WriteByte(' ')
			inSpace = false
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

// lineBreakLen returns the length of the CRLF or bare LF that s starts with,
// or 0.
func lineBreakLen(s string) int {
	switch {
	case strings.HasPrefix(s, "\r\n"):
		return 2
	case strings.HasPrefix(s, "\n"):
		return 1
	}
	return 0
}

// canonicalizeHeaderRaw applies RFC 6376 header canonicalization to one
// raw header field (folds and final line break included). Relaxed: the
// field name in lowercase, a colon, relaxedHeaderValue, CRLF. A line with
// no colon is not a header field and is returned as found.
func canonicalizeHeaderRaw(raw string, canon canonicalization) string {
	if canon == canonSimple {
		return raw
	}
	name, value, ok := fieldName(raw)
	if !ok {
		return raw
	}
	return asciiLower(name) + ":" + relaxedHeaderValue(value) + "\r\n"
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

	// Relaxed (RFC 6376 §3.4.4): strip trailing WSP per line, collapse
	// interior WSP runs to one space, drop trailing empty lines, CRLF line
	// endings. An empty body canonicalizes to zero bytes. Only SP and HTAB
	// are whitespace, so a CR that is not part of a line break is an
	// ordinary octet, as Mail::DKIM reads it. Two readings cover input that
	// is not in wire form, and match what a DATA writer sends for it: a
	// lone LF is a line break, and a CR ending the last, unterminated line
	// is the start of its line break.
	//
	// One pass, one buffer: a body of millions of short lines must not cost
	// a slice entry and an allocation per line.
	out := make([]byte, 0, len(body)+2)
	emptyLines := 0 // empty lines seen since the last line with content
	for pos := 0; ; {
		line, last := body[pos:], true
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line, last = line[:nl], false
			pos += nl + 1
		}
		line = strings.TrimRight(strings.TrimSuffix(line, "\r"), " \t")
		if line == "" {
			emptyLines++
		} else {
			for ; emptyLines > 0; emptyLines-- {
				out = append(out, '\r', '\n')
			}
			inSpace := false
			for i := 0; i < len(line); i++ {
				switch b := line[i]; {
				case b != ' ' && b != '\t':
					out = append(out, b)
					inSpace = false
				case !inSpace:
					out = append(out, ' ')
					inSpace = true
				}
			}
			out = append(out, '\r', '\n')
		}
		if last {
			return out
		}
	}
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
		if name, val, ok := strings.Cut(part, "="); ok && trimFWS(name) == "p" {
			p = stripFWS(val)
			break
		}
	}
	if p == "" {
		return nil, fmt.Errorf("no public key in record")
	}
	data, err := base64.StdEncoding.DecodeString(p)
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

const headerFoldWrap = 76

// foldHeaderNames joins a colon-separated h= header list, wrapping after ':'
// with RFC 6376 §3.5 FWS so no emitted line exceeds headerFoldWrap bytes.
func foldHeaderNames(names []string) string {
	if len(names) == 0 {
		return ""
	}
	var sb strings.Builder
	// Account for a folded continuation prefix ("\t h=" = 4 bytes) and a
	// trailing ";" (1 byte) so the tag fits within headerFoldWrap even on
	// its own continuation line.
	lineLen := 4 + len(names[0])
	sb.WriteString(names[0])
	for _, name := range names[1:] {
		// Reserve 1 byte for the trailing ":" or ";" after this name.
		if lineLen+1+len(name)+1 > headerFoldWrap {
			sb.WriteString(":\r\n\t")
			sb.WriteString(name)
			lineLen = 1 + len(name)
			continue
		}
		sb.WriteByte(':')
		sb.WriteString(name)
		lineLen += 1 + len(name)
	}
	return sb.String()
}

// foldAuthResultsClause folds a single already-unfolded Authentication-Results
// clause before unescaped SP or HTAB, including in quotes and comments.
// RFC 5322 §3.2.1 requires a quoted-pair to stay on the same physical line.
// Sign checks the 998-byte limit when there is no legal fold point.
func foldAuthResultsClause(clause string) string {
	// Account for a continuation prefix ("\t " = 2 bytes) and trailing ";".
	if 2+len(clause)+1 <= headerFoldWrap {
		return clause
	}
	if folded, ok := foldAuthResultsWords(clause, false); ok {
		return folded
	}
	folded, _ := foldAuthResultsWords(clause, true)
	return folded
}

// The first pass prefers the usual line width. If it reaches the physical
// limit, fold at every available whitespace run and place as much of that
// run as possible on the preceding line. This leaves the shortest possible
// continuation for each word, maximizing room for all subsequent folds.
func foldAuthResultsWords(clause string, useAllFolds bool) (string, bool) {
	var sb strings.Builder
	sb.Grow(len(clause) + len(clause)/headerFoldWrap*2)
	lineLen := 2
	if useAllFolds {
		lineLen = 1 // foldHeader can use a single continuation SP at the limit.
	}
	for start := 0; start < len(clause); {
		word := start
		for word < len(clause) && (clause[word] == ' ' || clause[word] == '\t') {
			word++
		}
		end := word
		for end < len(clause) && clause[end] != ' ' && clause[end] != '\t' {
			if clause[end] == '\\' && end+1 < len(clause) {
				end++ // A quoted-pair, including its WSP, is indivisible.
			}
			end++
		}
		if word > start && (useAllFolds || lineLen+end-start+1 > headerFoldWrap) {
			// A whitespace run can take only one fold: a second would
			// create a WSP-only physical line (RFC 5322 §2.2.3). For a
			// long run leave enough of it here for the next line to fit.
			before := max(0, end-start+1-maxLineLength)
			if useAllFolds {
				before = word - start - 1
			}
			before = min(before, word-start-1, max(0, maxLineLength-lineLen))
			sb.WriteString(clause[start : start+before])
			sb.WriteString("\r\n")
			start += before
			lineLen = 0
		}
		sb.WriteString(clause[start:end])
		lineLen += end - start
		if !useAllFolds && (lineLen > maxLineLength || end == len(clause) && lineLen+1 > maxLineLength) {
			return "", false
		}
		start = end
	}
	return sb.String(), true
}

// splitAuthResultsClauses splits an Authentication-Results value at the ";"
// separators between its clauses. A ";" inside a quoted string or a comment
// is part of the value, not a separator (RFC 8601 §2.2). An unbalanced
// comment or quoted string cannot be joined to another field and yields nil.
func splitAuthResultsClauses(value string) []string {
	var clauses []string
	start, depth := 0, 0
	inQuote := false
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c == '\\' && (inQuote || depth > 0):
			i++ // quoted-pair
		case inQuote:
			if c == '"' {
				inQuote = false
			}
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case c == ')':
			return nil
		case depth > 0:
			// ctext, including '"'
		case c == '"':
			inQuote = true
		case c == ';':
			clauses = append(clauses, value[start:i])
			start = i + 1
		}
	}
	if inQuote || depth != 0 {
		return nil
	}
	return append(clauses, value[start:])
}

// foldHeader renders a header as "Name: tag1; tag2; ..." folded between
// tags so no line exceeds the wrap width. Pre-folded tags (such as h=) are
// kept intact; the b= value is spliced in after signing, so the fold
// layout is frozen before the hash is computed.
func foldHeader(name string, tags []string) string {
	var sb strings.Builder
	sb.WriteString(name)
	sb.WriteString(":")
	lineLen := len(name) + 1
	for i, tag := range tags {
		chunk := " " + tag
		if i < len(tags)-1 {
			chunk += ";"
		}
		firstLineLen := len(chunk)
		if nl := strings.Index(chunk, "\r\n"); nl >= 0 {
			firstLineLen = nl
		}
		if i > 0 && lineLen+firstLineLen > headerFoldWrap {
			sb.WriteString("\r\n")
			lineLen = 0
			if firstLineLen < maxLineLength {
				sb.WriteByte('\t')
				lineLen = 1
			}
			// chunk itself starts with SP, sufficient for a continuation.
		}
		sb.WriteString(chunk)
		if nl := strings.LastIndex(chunk, "\r\n"); nl >= 0 {
			lineLen = len(chunk) - nl - 2
		} else {
			lineLen += len(chunk)
		}
	}
	sb.WriteString("\r\n")
	return sb.String()
}
