package config

import (
	"strings"
	"testing"
)

func TestCanonicalPublicURLAcceptsAndCanonicalizesOrigins(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "https://Example.COM", want: "https://example.com"},
		{raw: "HTTPS://Release.Example/", want: "https://release.example"},
		{raw: "https://example.com:443/", want: "https://example.com"},
		{raw: "https://example.com:00444", want: "https://example.com:444"},
		{raw: "http://LOCALHOST:80/", want: "http://localhost"},
		{raw: "http://localhost:08080", want: "http://localhost:8080"},
		{raw: "http://127.0.0.1:8080/", want: "http://127.0.0.1:8080"},
		{raw: "http://[0:0:0:0:0:0:0:1]:80", want: "http://[::1]"},
		{raw: "http://[::ffff:127.0.0.1]", want: "http://[::ffff:7f00:1]"},
		{raw: "http://[::ffff:7f00:1]", want: "http://[::ffff:7f00:1]"},
		{raw: "https://192.0.2.1:443/", want: "https://192.0.2.1"},
		{raw: "https://[2001:0db8::1]:0443/", want: "https://[2001:db8::1]"},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := CanonicalPublicURL(test.raw)
			if err != nil {
				t.Fatalf("canonicalize public URL: %v", err)
			}
			if got != test.want {
				t.Fatalf("canonical public URL = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCanonicalPublicURLRejectsUnsafeOrAmbiguousOrigins(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example"
	longHost := strings.Repeat("a.", 126) + "example"
	tests := []string{
		"",
		" https://example.com",
		"https://example.com ",
		"ftp://example.com",
		"mailto:admin@example.com",
		"https:///",
		"https://user@example.com",
		"https://user:password@example.com",
		"https://example.com?",
		"https://example.com?mode=recovery",
		"https://example.com#",
		"https://example.com#token=value",
		"https://example.com/path",
		"https://example.com/%2f",
		"https://example.com//",
		"https://example.com/.",
		"https://bad_host.example",
		"https://example.com.",
		"https://one..example",
		"https://-bad.example",
		"https://bad-.example",
		"https://" + longLabel,
		"https://" + longHost,
		"https://example.123",
		"https://example.0x7f",
		"https://example.0x",
		"https://example.com:",
		"https://example.com:0",
		"https://example.com:65536",
		"https://example.com:+443",
		"https://example.com:port",
		"http://example.com",
		"http://192.168.1.1",
		"http://localhost.example",
		"http://[fe80::1%25eth0]",
		"https://[127.0.0.1]",
		"https://[not-an-ip]",
		"https://2001:db8::1",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if canonical, err := CanonicalPublicURL(raw); err == nil {
				t.Fatalf("expected rejection, got %q", canonical)
			}
		})
	}
}

func TestCanonicalPublicURLRejectsUnicodeAndPunycodeHostnames(t *testing.T) {
	for _, raw := range []string{
		"https://bücher.example",
		"https://İ.example",
		"https://K.example",
		"https://%C4%B0.example",
		"https://%E2%84%AA.example",
		"https://xn--bcher-kva.example",
		"https://XN--BCHER-KVA.example",
		"https://www.xn--bcher-kva.example",
	} {
		t.Run(raw, func(t *testing.T) {
			if canonical, err := CanonicalPublicURL(raw); err == nil {
				t.Fatalf("expected internationalized hostname rejection, got %q", canonical)
			}
		})
	}
}

func TestCanonicalPublicURLRejectsLegacyIPv4Forms(t *testing.T) {
	for _, raw := range []string{
		"https://127.1",
		"https://2130706433",
		"https://0177.0.0.1",
		"https://0x7f000001",
		"https://127.0x1",
	} {
		t.Run(raw, func(t *testing.T) {
			if canonical, err := CanonicalPublicURL(raw); err == nil {
				t.Fatalf("expected legacy IPv4 rejection, got %q", canonical)
			}
		})
	}
}

func TestCanonicalPublicURLErrorRedactsRejectedValue(t *testing.T) {
	const canary = "public-url-leak-canary"
	_, err := CanonicalPublicURL("https://example.com/" + canary)
	if err == nil {
		t.Fatal("expected invalid public URL")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("public URL error exposed rejected input: %q", err)
	}
}
