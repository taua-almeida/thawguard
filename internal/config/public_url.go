package config

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var errInvalidPublicURL = errors.New("THAWGUARD_PUBLIC_URL must use a root-only HTTPS origin with a non-punycode ASCII DNS hostname or literal IP; HTTP is allowed only for localhost or a literal loopback IP")

// CanonicalPublicURL validates the configured browser origin without DNS
// lookup. Rejected values are deliberately absent from its error.
func CanonicalPublicURL(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "?#") {
		return "", errInvalidPublicURL
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil {
		return "", errInvalidPublicURL
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errInvalidPublicURL
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", errInvalidPublicURL
	}

	host, rawPort, hasPort, ok := splitPublicURLAuthority(parsed.Host)
	if !ok || !isASCII(host) {
		return "", errInvalidPublicURL
	}

	canonicalHost := ""
	isIPv6 := false
	bracketedHost := strings.HasPrefix(parsed.Host, "[")
	ip := net.ParseIP(host)
	if ip != nil {
		isIPv6 = strings.Contains(host, ":")
		if bracketedHost != isIPv6 {
			return "", errInvalidPublicURL
		}
		if mapped := ip.To4(); isIPv6 && mapped != nil {
			canonicalHost = "::ffff:" +
				strconv.FormatUint(uint64(mapped[0])<<8|uint64(mapped[1]), 16) + ":" +
				strconv.FormatUint(uint64(mapped[2])<<8|uint64(mapped[3]), 16)
		} else {
			canonicalHost = ip.String()
		}
	} else {
		if bracketedHost {
			return "", errInvalidPublicURL
		}
		canonicalHost = strings.ToLower(host)
		if !validDNSHostname(canonicalHost) {
			return "", errInvalidPublicURL
		}
	}
	if scheme == "http" && canonicalHost != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errInvalidPublicURL
	}

	port := ""
	if hasPort {
		if !allASCIIDigits(rawPort) {
			return "", errInvalidPublicURL
		}
		parsedPort, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || parsedPort == 0 {
			return "", errInvalidPublicURL
		}
		port = strconv.FormatUint(parsedPort, 10)
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			port = ""
		}
	}

	authority := canonicalHost
	if isIPv6 {
		authority = "[" + canonicalHost + "]"
	}
	if port != "" {
		authority += ":" + port
	}
	return scheme + "://" + authority, nil
}

func splitPublicURLAuthority(authority string) (host, port string, hasPort, ok bool) {
	if authority == "" || strings.Contains(authority, "%") {
		return "", "", false, false
	}
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing <= 1 {
			return "", "", false, false
		}
		host = authority[1:closing]
		rest := authority[closing+1:]
		switch {
		case rest == "":
			return host, "", false, true
		case strings.HasPrefix(rest, ":") && len(rest) > 1:
			return host, rest[1:], true, true
		default:
			return "", "", false, false
		}
	}
	if strings.ContainsAny(authority, "[]") || strings.Count(authority, ":") > 1 {
		return "", "", false, false
	}
	if before, after, found := strings.Cut(authority, ":"); found {
		if before == "" || after == "" {
			return "", "", false, false
		}
		return before, after, true, true
	}
	return authority, "", false, authority != ""
}

func validDNSHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if browserIPv4Number(labels[len(labels)-1]) {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if strings.HasPrefix(label, "xn--") {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func browserIPv4Number(label string) bool {
	if allASCIIDigits(label) {
		return true
	}
	return strings.HasPrefix(label, "0x") && (len(label) == 2 || allASCIIHex(label[2:]))
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func allASCIIHex(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isASCII(value string) bool {
	for i := range len(value) {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}
