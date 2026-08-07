package forgeconnection

import (
	"strings"
	"testing"
)

func TestCanonicalBaseURLAcceptsAndNormalizes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain https", raw: "https://forge.example.test", want: "https://forge.example.test"},
		{name: "outer whitespace", raw: " \thttps://forge.example.test\r\n", want: "https://forge.example.test"},
		{name: "uppercase scheme and host", raw: "HTTPS://Forge.Example.TEST", want: "https://forge.example.test"},
		{name: "default https port stripped", raw: "https://forge.example.test:443", want: "https://forge.example.test"},
		{name: "custom port kept", raw: "https://forge.example.test:8443", want: "https://forge.example.test:8443"},
		{name: "root slash removed", raw: "https://forge.example.test/", want: "https://forge.example.test"},
		{name: "subpath preserved", raw: "https://forge.example.test/git", want: "https://forge.example.test/git"},
		{name: "subpath trailing slash removed", raw: "https://forge.example.test/git/", want: "https://forge.example.test/git"},
		{name: "deep subpath", raw: "https://forge.example.test/tools/git", want: "https://forge.example.test/tools/git"},
		{name: "canonical escape kept", raw: "https://forge.example.test/%C3%A9quipe", want: "https://forge.example.test/%C3%A9quipe"},
		{name: "localhost http", raw: "http://localhost:3000", want: "http://localhost:3000"},
		{name: "localhost http default port stripped", raw: "http://localhost:80", want: "http://localhost"},
		{name: "ipv4 loopback http", raw: "http://127.0.0.1:3000", want: "http://127.0.0.1:3000"},
		{name: "ipv6 loopback http", raw: "http://[::1]:3000", want: "http://[::1]:3000"},
		{name: "ipv4 https", raw: "https://192.0.2.10", want: "https://192.0.2.10"},
		{name: "ipv4 https with port and subpath", raw: "https://192.0.2.10:8443/forge", want: "https://192.0.2.10:8443/forge"},
		{name: "ipv6 https", raw: "https://[2001:db8::10]:8443/git", want: "https://[2001:db8::10]:8443/git"},
		{name: "uppercase ipv6 lowered", raw: "https://[2001:DB8::10]", want: "https://[2001:db8::10]"},
		{name: "ipv6 default port stripped", raw: "https://[2001:db8::10]:443", want: "https://[2001:db8::10]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalBaseURL(tc.raw)
			if err != nil {
				t.Fatalf("CanonicalBaseURL(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("CanonicalBaseURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			again, err := CanonicalBaseURL(got)
			if err != nil || again != got {
				t.Fatalf("canonical form is not a fixed point: %q -> %q (%v)", got, again, err)
			}
		})
	}
}

func TestCanonicalBaseURLRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: " \t"},
		{name: "too long", raw: "https://forge.example.test/" + strings.Repeat("a", 2049)},
		{name: "relative", raw: "/git"},
		{name: "opaque", raw: "https:git"},
		{name: "missing host", raw: "https:///git"},
		{name: "unsupported scheme", raw: "ftp://forge.example.test"},
		{name: "http non-loopback", raw: "http://forge.example.test"},
		{name: "http public ip", raw: "http://192.0.2.10"},
		{name: "ipv6 zone identifier", raw: "https://[fe80::1%25eth0]/git"},
		{name: "ipv6 loopback zone identifier", raw: "http://[::1%25lo]"},
		{name: "port zero", raw: "https://forge.example.test:0"},
		{name: "port out of range", raw: "https://forge.example.test:99999"},
		{name: "port with leading zeros", raw: "https://forge.example.test:0443"},
		{name: "userinfo", raw: "https://user@forge.example.test"},
		{name: "userinfo with password", raw: "https://user:pass@forge.example.test"},
		{name: "query", raw: "https://forge.example.test?x=1"},
		{name: "empty query", raw: "https://forge.example.test?"},
		{name: "fragment", raw: "https://forge.example.test#git"},
		{name: "empty fragment", raw: "https://forge.example.test#"},
		{name: "backslash", raw: `https://forge.example.test/git\repo`},
		{name: "interior space", raw: "https://forge.example.test/git repo"},
		{name: "control", raw: "https://forge.example.test/git\nrepo"},
		{name: "non-ASCII", raw: "https://forge.example.test/équipe"},
		{name: "duplicate separators", raw: "https://forge.example.test//git"},
		{name: "interior duplicate separators", raw: "https://forge.example.test/git//sub"},
		{name: "trailing duplicate separators", raw: "https://forge.example.test/git//"},
		{name: "dot segment", raw: "https://forge.example.test/./git"},
		{name: "dot dot segment", raw: "https://forge.example.test/git/.."},
		{name: "escaped dot segment", raw: "https://forge.example.test/%2E%2E/git"},
		{name: "encoded slash", raw: "https://forge.example.test/git%2Frepo"},
		{name: "encoded lowercase slash", raw: "https://forge.example.test/git%2frepo"},
		{name: "encoded backslash", raw: "https://forge.example.test/git%5Crepo"},
		{name: "lowercase hex escape", raw: "https://forge.example.test/%c3%a9quipe"},
		{name: "escaped unreserved", raw: "https://forge.example.test/%41git"},
		{name: "truncated escape", raw: "https://forge.example.test/git%C"},
		{name: "escaped percent", raw: "https://forge.example.test/git%25sub"},
		{name: "escaped question mark", raw: "https://forge.example.test/git%3Fsub"},
		{name: "escaped hash", raw: "https://forge.example.test/git%23sub"},
		{name: "escaped space", raw: "https://forge.example.test/git%20sub"},
		{name: "escaped C1 control", raw: "https://forge.example.test/git%C2%85sub"},
		{name: "double-encoded slash", raw: "https://forge.example.test/forge%252F..%252Fother"},
		{name: "double-encoded backslash", raw: "https://forge.example.test/git%255Csub"},
		{name: "double-encoded dot segment", raw: "https://forge.example.test/git%252E%252E"},
		{name: "double-encoded NUL", raw: "https://forge.example.test/git%2500"},
		{name: "escaped NUL", raw: "https://forge.example.test/git%00"},
		{name: "escaped line feed", raw: "https://forge.example.test/git%0Asub"},
		{name: "escaped carriage return", raw: "https://forge.example.test/git%0D"},
		{name: "escaped DEL", raw: "https://forge.example.test/git%7F"},
		{name: "escaped invalid UTF-8 byte", raw: "https://forge.example.test/git%FF"},
		{name: "escaped truncated UTF-8 sequence", raw: "https://forge.example.test/git%C3"},
		{name: "escaped bare continuation byte", raw: "https://forge.example.test/git%A9sub"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CanonicalBaseURL(tc.raw); !IsValidationError(err) {
				t.Fatalf("CanonicalBaseURL(%q) = %v, want validation error", tc.raw, err)
			}
		})
	}
}
