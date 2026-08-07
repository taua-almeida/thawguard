package forgeconnection

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxBaseURLBytes = 2048

// CanonicalBaseURL normalizes a Forgejo installation root URL to the one
// stored representation: lowercase scheme and host, default ports removed,
// no trailing slash, valid installation subpaths preserved. HTTPS is
// required except for exact localhost or literal loopback hosts. The API
// path is never stored here; endpoint builders join "api" and "v1" as
// relative segments so a subpath installation keeps its prefix.
func CanonicalBaseURL(raw string) (string, error) {
	invalid := func(message string) (string, error) {
		return "", ValidationError{Message: message}
	}
	value := strings.Trim(raw, " \t\n\r\v\f")
	if len(value) < 1 || len(value) > maxBaseURLBytes {
		return invalid("connection URL must be between 1 and 2048 bytes")
	}
	for i := range len(value) {
		if value[i] <= 0x20 || value[i] >= 0x7f {
			return invalid("connection URL must contain only printable ASCII characters")
		}
	}
	if strings.ContainsAny(value, `\`) {
		return invalid("connection URL must not contain backslashes")
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return invalid("connection URL must be an absolute URL with a host")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return invalid("connection URL must use HTTPS")
	}
	if parsed.User != nil {
		return invalid("connection URL must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return invalid("connection URL must not contain a query")
	}
	if strings.Contains(value, "#") {
		return invalid("connection URL must not contain a fragment")
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return invalid("connection URL must include a host")
	}
	// An IPv6 zone identifier is host-local routing state; it has no
	// canonical form worth storing and would put a literal '%' into the
	// authority of every credential-bearing request.
	if strings.Contains(host, "%") {
		return invalid("connection URL host must not contain an IPv6 zone identifier")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return invalid("connection URL port must be a canonical number from 1 to 65535")
		}
	}
	if scheme == "http" && !loopbackHost(host) {
		return invalid("HTTP is allowed only for localhost or literal loopback hosts")
	}

	rawPath := rawURLPath(value)
	canonicalPath, err := canonicalBasePath(rawPath)
	if err != nil {
		return "", err
	}

	authority := canonicalAuthority(scheme, host, parsed.Port())
	return scheme + "://" + authority + canonicalPath, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func canonicalAuthority(scheme, host, port string) string {
	// A parsed IPv6 host loses its brackets; restore them.
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return host
	}
	return host + ":" + port
}

// rawURLPath extracts the undecoded path from an absolute URL so escaping
// is validated exactly as submitted.
func rawURLPath(value string) string {
	_, authorityAndPath, found := strings.Cut(value, "://")
	if !found {
		return ""
	}
	pathStart := strings.IndexByte(authorityAndPath, '/')
	if pathStart < 0 {
		return ""
	}
	return authorityAndPath[pathStart:]
}

// canonicalBasePath validates a raw installation subpath and returns its
// canonical form without a trailing slash. It rejects dot segments, empty
// segments (duplicate separators), non-canonical percent escapes, and
// every escape that decodes to an ASCII byte: escapes exist here solely to
// carry non-ASCII UTF-8, so separators, request delimiters ('?', '#',
// ' '), '%', controls, and unreserved characters must all appear literally
// or not at all. A decode-and-reparse intermediary therefore can never
// reinterpret a stored path — no decode round can surface a byte with
// syntactic meaning. The decoded path must additionally be valid UTF-8
// with no control runes (including the C1 range).
func canonicalBasePath(rawPath string) (string, error) {
	invalid := func(message string) (string, error) {
		return "", ValidationError{Message: message}
	}
	if rawPath == "" || rawPath == "/" {
		return "", nil
	}
	trimmed := strings.TrimSuffix(rawPath, "/")
	decodedPath := make([]byte, 0, len(trimmed))
	for i := 0; i < len(trimmed); i++ {
		character := trimmed[i]
		if isURIUnreservedByte(character) || strings.ContainsRune("!$&'()*+,;=:@/", rune(character)) {
			decodedPath = append(decodedPath, character)
			continue
		}
		if character != '%' {
			return invalid("connection URL path contains invalid characters")
		}
		if i+2 >= len(trimmed) || !isUppercaseHexDigit(trimmed[i+1]) || !isUppercaseHexDigit(trimmed[i+2]) {
			return invalid("connection URL path must use canonical uppercase percent-escaping")
		}
		decoded := hexValue(trimmed[i+1])<<4 | hexValue(trimmed[i+2])
		if decoded < 0x80 {
			return invalid("connection URL path may use percent-escapes only for non-ASCII UTF-8 bytes")
		}
		decodedPath = append(decodedPath, decoded)
		i += 2
	}
	if !utf8.Valid(decodedPath) {
		return invalid("connection URL path must decode to valid UTF-8")
	}
	for _, character := range string(decodedPath) {
		if character < 0x20 || character == 0x7f || (character >= 0x80 && character <= 0x9f) {
			return invalid("connection URL path must not contain control characters")
		}
	}
	for segment := range strings.SplitSeq(strings.TrimPrefix(trimmed, "/"), "/") {
		if segment == "" {
			return invalid("connection URL path must not contain duplicate separators")
		}
		if isDotSegment(segment) {
			return invalid("connection URL path must not contain dot segments")
		}
	}
	return trimmed, nil
}

// isDotSegment matches "." and ".." including their escaped spellings.
func isDotSegment(segment string) bool {
	decoded := strings.ReplaceAll(segment, "%2E", ".")
	return decoded == "." || decoded == ".."
}

func isURIUnreservedByte(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '-' || character == '.' || character == '_' || character == '~'
}

func isUppercaseHexDigit(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'A' && character <= 'F'
}

func hexValue(character byte) byte {
	if character >= '0' && character <= '9' {
		return character - '0'
	}
	return character - 'A' + 10
}
