package companyoidc

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestParseJWKSResultCategoriesAndKeyLimits(t *testing.T) {
	eligible := validRSAJWK("eligible-2026")
	unsupported := map[string]any{"kty": "EC", "kid": "ec-2026", "crv": "P-256"}

	tests := []struct {
		name      string
		body      []byte
		wantError bool
		wantKeys  int
	}{
		{name: "invalid JSON", body: []byte(`{"keys":`), wantError: true},
		{name: "invalid top-level array", body: []byte(`[]`), wantError: true},
		{name: "missing keys", body: []byte(`{}`), wantError: true},
		{name: "empty keys", body: []byte(`{"keys":[]}`), wantError: true},
		{name: "non-object key", body: []byte(`{"keys":[7]}`), wantError: true},
		{name: "null key", body: []byte(`{"keys":[null]}`), wantError: true},
		{name: "zero eligible keys", body: mustJSON(t, map[string]any{"keys": []any{unsupported}})},
		{name: "one eligible key", body: mustJSON(t, map[string]any{"keys": []any{eligible}}), wantKeys: 1},
		{name: "mixed keys", body: mustJSON(t, map[string]any{"keys": []any{unsupported, eligible}}), wantKeys: 1},
		{name: "duplicate eligible kid", body: mustJSON(t, map[string]any{"keys": []any{
			validRSAJWK("duplicate-2026"), validRSAJWK("duplicate-2026"),
		}}), wantError: true},
		{name: "oversized body", body: []byte(strings.Repeat(" ", setupCheckMaxBodySize+1)), wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jwks, err := parseJWKS(tc.body)
			if (err != nil) != tc.wantError {
				t.Fatalf("parseJWKS error = %v, wantError %v", err, tc.wantError)
			}
			if err == nil && len(jwks.keys) != tc.wantKeys {
				t.Fatalf("eligible keys = %d, want %d", len(jwks.keys), tc.wantKeys)
			}
		})
	}

	for _, count := range []int{100, 101} {
		t.Run(fmt.Sprintf("%d keys", count), func(t *testing.T) {
			keys := make([]any, 0, count)
			for i := range count {
				if i == maxJWKSKeys-1 {
					keys = append(keys, validRSAJWK("eligible-at-limit"))
					continue
				}
				keys = append(keys, map[string]any{"kty": "EC", "kid": encodeUInt(uint64(i + 1))})
			}
			jwks, err := parseJWKS(mustJSON(t, map[string]any{"keys": keys}))
			if count == maxJWKSKeys {
				if err != nil || len(jwks.keys) != 1 {
					t.Fatalf("100-key set = keys %d, error %v", len(jwks.keys), err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted 101-key JWKS")
			}
		})
	}
}

func TestEligibleRSAKeyRequiresBoundedIdentifierAndIntegers(t *testing.T) {
	modulus2048 := testModulus(0x80, 0x01)
	modulus8192 := make([]byte, 1024)
	modulus8192[0] = 0x80
	modulus8192[len(modulus8192)-1] = 0x01

	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   bool
	}{
		{name: "2048-bit modulus", want: true},
		{name: "8192-bit modulus", mutate: func(key map[string]any) {
			key["n"] = base64.RawURLEncoding.EncodeToString(modulus8192)
		}, want: true},
		{name: "2047-bit modulus", mutate: func(key map[string]any) {
			key["n"] = base64.RawURLEncoding.EncodeToString(testModulus(0x40, 0x01))
		}},
		{name: "8193-bit encoded modulus", mutate: func(key map[string]any) {
			value := make([]byte, 1025)
			value[0] = 0x01
			value[len(value)-1] = 0x01
			key["n"] = base64.RawURLEncoding.EncodeToString(value)
		}},
		{name: "encoded modulus over boundary", mutate: func(key map[string]any) {
			key["n"] = strings.Repeat("A", maxRSAModulusEncodedSize+1)
		}},
		{name: "missing kid", mutate: func(key map[string]any) { delete(key, "kid") }},
		{name: "empty kid", mutate: func(key map[string]any) { key["kid"] = "" }},
		{name: "128-byte kid", mutate: func(key map[string]any) {
			key["kid"] = strings.Repeat("k", maxJWKKeyIDBytes)
		}, want: true},
		{name: "129-byte kid", mutate: func(key map[string]any) {
			key["kid"] = strings.Repeat("k", maxJWKKeyIDBytes+1)
		}},
		{name: "six-character exponent encoding", mutate: func(key map[string]any) {
			key["e"] = encodeUInt(1<<31 - 1)
		}, want: true},
		{name: "seven-character exponent encoding", mutate: func(key map[string]any) {
			key["e"] = "AAAAAAE"
		}},
		{name: "decoded exponent over boundary", mutate: func(key map[string]any) {
			key["e"] = encodeUInt(1<<31 + 1)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := validRSAJWK("bounded-key-2026")
			key["n"] = base64.RawURLEncoding.EncodeToString(modulus2048)
			if tc.mutate != nil {
				tc.mutate(key)
			}
			object, ok := decodeJSONObject(mustJSON(t, key))
			if !ok {
				t.Fatal("test JWK did not decode")
			}
			_, publicKey, got := eligibleRSAKey(object)
			if got != tc.want {
				t.Fatalf("eligibleRSAKey = %v, want %v", got, tc.want)
			}
			if got && (publicKey.N == nil || publicKey.E < 3) {
				t.Fatal("eligible key did not construct the trusted RSA public key")
			}
		})
	}
}

func TestParseJWKSAllKidlessAndOversizedKidSetsHaveNoEligibleKeys(t *testing.T) {
	kidless := validRSAJWK("ignored")
	delete(kidless, "kid")
	oversized := validRSAJWK(strings.Repeat("k", maxJWKKeyIDBytes+1))
	jwks, err := parseJWKS(mustJSON(t, map[string]any{"keys": []any{kidless, oversized}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.keys) != 0 {
		t.Fatalf("eligible keys = %d, want zero", len(jwks.keys))
	}
}

func TestParseJWKSPreservesValidLargeNumberExtensions(t *testing.T) {
	key := validRSAJWK("large-number-extension")
	body := mustJSON(t, map[string]any{"keys": []any{key}})
	body = appendRawJSONObjectMember(t, body, `"extension":1e400`)
	body = []byte(strings.Replace(
		string(body),
		`"kid":"large-number-extension"`,
		`"kid":"large-number-extension","extension":1e400`,
		1,
	))
	jwks, err := parseJWKS(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.keys) != 1 {
		t.Fatalf("eligible keys = %d, want one", len(jwks.keys))
	}
}

func TestParseJWKSAcceptsIgnoredNestedExtensionAboveRootKeyLimit(t *testing.T) {
	key := validRSAJWK("nested-extension")
	key["extension"] = make([]int, maxJWKSKeys+1)
	jwks, err := parseJWKS(mustJSON(t, map[string]any{"keys": []any{key}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.keys) != 1 {
		t.Fatalf("eligible keys = %d, want one", len(jwks.keys))
	}
}
