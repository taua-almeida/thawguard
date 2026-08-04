package companyoidc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	testRSAOnce sync.Once
	testRSAKey  *rsa.PrivateKey
	testRSAErr  error
)

type idTokenFixture struct {
	key      *rsa.PrivateKey
	verifier idTokenVerifier
	header   map[string]any
	claims   map[string]any
	nonce    string
	now      time.Time
	created  time.Time
}

func TestIDTokenVerifierAcceptsStrictRS256TokenAndCapturesNowOnce(t *testing.T) {
	fixture := newIDTokenFixture(t)
	var calls atomic.Int32
	fixture.verifier.now = func() time.Time {
		calls.Add(1)
		return fixture.now
	}
	token := fixture.sign(t, fixture.header, fixture.claims)
	verified, err := fixture.verifier.verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if verified.subject != "provider-subject-123" {
		t.Fatalf("verified subject = %q", verified.subject)
	}
	if verified.emailDomain != "example.test" {
		t.Fatalf("verified email domain = %q", verified.emailDomain)
	}
	if calls.Load() != 1 {
		t.Fatalf("clock calls = %d, want one", calls.Load())
	}
}

func TestCompactIDTokenPreflightBoundaries(t *testing.T) {
	fixture := newIDTokenFixture(t)
	valid := fixture.sign(t, fixture.header, fixture.claims)
	parts := strings.Split(valid, ".")

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "over total limit", token: strings.Repeat("A", maxCompactIDTokenSize+1)},
		{name: "one segment", token: "AA"},
		{name: "two segments", token: "AA.AA"},
		{name: "four segments", token: "AA.AA.AA.AA"},
		{name: "empty header", token: ".AA.AA"},
		{name: "empty payload", token: "AA..AA"},
		{name: "empty signature", token: "AA.AA."},
		{name: "padded header", token: parts[0] + "=." + parts[1] + "." + parts[2]},
		{name: "noncanonical base64url", token: "AB." + parts[1] + "." + parts[2]},
		{name: "invalid header UTF-8", token: compactSegments([]byte{0xff}, []byte(`{}`), []byte{1})},
		{name: "invalid payload UTF-8", token: compactSegments([]byte(`{"alg":"RS256","kid":"provider-key-2026"}`), []byte{0xff}, []byte{1})},
		{name: "invalid payload JSON", token: compactSegments([]byte(`{"alg":"RS256","kid":"provider-key-2026"}`), []byte(`{"iss":`), []byte{1})},
		{name: "header over decoded limit", token: compactSegments(
			[]byte(`{"alg":"RS256","kid":"provider-key-2026","padding":"`+strings.Repeat("x", maxProtectedHeaderSize)+`"}`),
			[]byte(`{}`),
			[]byte{1},
		)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := preflightCompactIDToken(tc.token); err == nil {
				t.Fatal("accepted invalid compact token")
			}
		})
	}
}

func TestProtectedIDTokenHeaderUsesExactAllowlist(t *testing.T) {
	fixture := newIDTokenFixture(t)

	for _, member := range []string{"crit", "b64", "jwk", "jku", "x5u", "x5c", "cty"} {
		t.Run("rejects "+member, func(t *testing.T) {
			header := maps.Clone(fixture.header)
			header[member] = "untrusted-header-value"
			assertIDTokenRejected(t, fixture.verifier, fixture.sign(t, header, fixture.claims))
		})
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
		wantOK bool
	}{
		{name: "typ absent", mutate: func(header map[string]any) { delete(header, "typ") }, wantOK: true},
		{name: "typ exact JWT", wantOK: true},
		{name: "wrong algorithm", mutate: func(header map[string]any) { header["alg"] = "PS256" }},
		{name: "missing algorithm", mutate: func(header map[string]any) { delete(header, "alg") }},
		{name: "empty kid", mutate: func(header map[string]any) { header["kid"] = "" }},
		{name: "oversized kid", mutate: func(header map[string]any) { header["kid"] = strings.Repeat("k", maxJWKKeyIDBytes+1) }},
		{name: "wrong kid type", mutate: func(header map[string]any) { header["kid"] = 7 }},
		{name: "wrong typ", mutate: func(header map[string]any) { header["typ"] = "at+jwt" }},
		{name: "null typ", mutate: func(header map[string]any) { header["typ"] = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := maps.Clone(fixture.header)
			if tc.mutate != nil {
				tc.mutate(header)
			}
			token := fixture.sign(t, header, fixture.claims)
			_, err := fixture.verifier.verify(token)
			if (err == nil) != tc.wantOK {
				t.Fatalf("verification error = %v, want success %v", err, tc.wantOK)
			}
		})
	}

	duplicate := []byte(`{"alg":"RS256","alg":"RS256","kid":"provider-key-2026"}`)
	assertIDTokenRejected(t, fixture.verifier, signTestCompact(t, fixture.key, duplicate, mustMarshalJSON(t, fixture.claims)))
}

func TestIDTokenVerifierRejectsKeyAndSignatureFailures(t *testing.T) {
	fixture := newIDTokenFixture(t)
	valid := fixture.sign(t, fixture.header, fixture.claims)
	parts := strings.Split(valid, ".")

	unknownHeader := maps.Clone(fixture.header)
	unknownHeader["kid"] = "unknown-provider-key"
	assertIDTokenRejected(t, fixture.verifier, fixture.sign(t, unknownHeader, fixture.claims))

	invalidSignature := base64.RawURLEncoding.EncodeToString(make([]byte, fixture.key.Size()))
	assertIDTokenRejected(t, fixture.verifier, parts[0]+"."+parts[1]+"."+invalidSignature)
	assertIDTokenRejected(t, fixture.verifier, parts[0]+"."+parts[1]+".AA")

	malformed := parts[0] + "." + parts[1] + ".!"
	assertIDTokenRejected(t, fixture.verifier, malformed)
}

func TestIDTokenVerifierAudienceAndAuthorizedPartyPolicy(t *testing.T) {
	fixture := newIDTokenFixture(t)
	tests := []struct {
		name   string
		aud    any
		azp    any
		hasAZP bool
		wantOK bool
	}{
		{name: "scalar audience", aud: "client-id", wantOK: true},
		{name: "singleton audience", aud: []string{"client-id"}, wantOK: true},
		{name: "scalar with matching azp", aud: "client-id", azp: "client-id", hasAZP: true, wantOK: true},
		{name: "multiple with matching azp", aud: []string{"other-client", "client-id"}, azp: "client-id", hasAZP: true, wantOK: true},
		{name: "multiple missing azp", aud: []string{"client-id", "other-client"}},
		{name: "duplicate audience", aud: []string{"client-id", "client-id"}},
		{name: "empty scalar", aud: ""},
		{name: "empty array", aud: []string{}},
		{name: "empty array member", aud: []string{"client-id", ""}},
		{name: "missing client", aud: []string{"other-client"}},
		{name: "null audience", aud: nil},
		{name: "wrong audience type", aud: 7},
		{name: "empty azp", aud: "client-id", azp: "", hasAZP: true},
		{name: "mismatched azp", aud: "client-id", azp: "other-client", hasAZP: true},
		{name: "null azp", aud: "client-id", azp: nil, hasAZP: true},
		{name: "wrong azp type", aud: "client-id", azp: []string{"client-id"}, hasAZP: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := maps.Clone(fixture.claims)
			claims["aud"] = tc.aud
			if tc.hasAZP {
				claims["azp"] = tc.azp
			} else {
				delete(claims, "azp")
			}
			_, err := fixture.verifier.verify(fixture.sign(t, fixture.header, claims))
			if (err == nil) != tc.wantOK {
				t.Fatalf("verification error = %v, want success %v", err, tc.wantOK)
			}
		})
	}
}

func TestNumericDateStrictGrammarAndBounds(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "0", want: "0"},
		{value: "-0", want: "0"},
		{value: "1.25", want: "5/4"},
		{value: "125e-2", want: "5/4"},
		{value: "1E+2", want: "100"},
		{value: "0e18", want: "0"},
		{value: "253402300799", want: "253402300799"},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			parsed, ok := parseNumericDate([]byte(tc.value))
			if !ok {
				t.Fatal("rejected valid NumericDate")
			}
			if got := parsed.seconds.RatString(); got != tc.want {
				t.Fatalf("value = %s, want %s", got, tc.want)
			}
		})
	}

	for _, value := range []string{
		"", "+1", ".1", "1.", "01", "--1", "1e", "1e+", "1e19", "1e-19",
		"-0.000000001", "253402300799.000000001", "100000000000000000000000000000000",
		strings.Repeat("1", maxNumericDateSize+1), "1 true",
	} {
		t.Run("reject "+value, func(t *testing.T) {
			if _, ok := parseNumericDate([]byte(value)); ok {
				t.Fatal("accepted invalid NumericDate")
			}
		})
	}

	if _, ok := parseNumericDate([]byte(strings.Repeat("9", maxSignificandDigits))); ok {
		t.Fatal("accepted in-range grammar fixture that is numerically out of range")
	}
	if parsed, ok := parseNumericDate([]byte("0." + strings.Repeat("0", maxSignificandDigits-1))); !ok || parsed.seconds.Sign() != 0 {
		t.Fatal("rejected exact 32-significand-digit fraction")
	}
	if _, ok := parseNumericDate([]byte("0." + strings.Repeat("0", maxSignificandDigits))); ok {
		t.Fatal("accepted 33 significand digits")
	}
}

func TestIDTokenVerifierTimePolicyExactSkewBoundaries(t *testing.T) {
	fixture := newIDTokenFixture(t)
	now := fixture.now.Unix()
	created := fixture.created.Unix()
	tests := []struct {
		name   string
		mutate func(map[string]any)
		wantOK bool
	}{
		{name: "expiration just inside skew", mutate: func(claims map[string]any) {
			claims["exp"] = numericJSON(fmt.Sprintf("%d.000000001", now-60))
		}, wantOK: true},
		{name: "expiration skew equality", mutate: func(claims map[string]any) { claims["exp"] = now - 60 }},
		{name: "expiration beyond skew", mutate: func(claims map[string]any) {
			claims["exp"] = numericJSON(fmt.Sprintf("%d.999999999", now-61))
		}},
		{name: "not before skew equality", mutate: func(claims map[string]any) { claims["nbf"] = now + 60 }, wantOK: true},
		{name: "not before beyond skew", mutate: func(claims map[string]any) {
			claims["nbf"] = numericJSON(fmt.Sprintf("%d.000000001", now+60))
		}},
		{name: "issued at transaction lower equality", mutate: func(claims map[string]any) { claims["iat"] = created - 60 }, wantOK: true},
		{name: "issued at before transaction lower bound", mutate: func(claims map[string]any) {
			claims["iat"] = numericJSON(fmt.Sprintf("%d.999999999", created-61))
		}},
		{name: "issued at current upper equality", mutate: func(claims map[string]any) { claims["iat"] = now + 60 }, wantOK: true},
		{name: "issued at beyond current upper bound", mutate: func(claims map[string]any) {
			claims["iat"] = numericJSON(fmt.Sprintf("%d.000000001", now+60))
		}},
		{name: "expiration equals issued at", mutate: func(claims map[string]any) { claims["exp"] = claims["iat"] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := maps.Clone(fixture.claims)
			tc.mutate(claims)
			_, err := fixture.verifier.verify(fixture.sign(t, fixture.header, claims))
			if (err == nil) != tc.wantOK {
				t.Fatalf("verification error = %v, want success %v", err, tc.wantOK)
			}
		})
	}
}

func TestIDTokenVerifierClaimTypesNonceAndDuplicateClaims(t *testing.T) {
	fixture := newIDTokenFixture(t)
	for _, member := range []string{"iss", "sub", "aud", "exp", "iat", "nonce"} {
		t.Run("missing "+member, func(t *testing.T) {
			claims := maps.Clone(fixture.claims)
			delete(claims, member)
			assertIDTokenRejected(t, fixture.verifier, fixture.sign(t, fixture.header, claims))
		})
	}
	for _, tc := range []struct {
		name  string
		field string
		value any
	}{
		{name: "issuer mismatch", field: "iss", value: "https://other.example.test"},
		{name: "empty subject", field: "sub", value: ""},
		{name: "null subject", field: "sub", value: nil},
		{name: "string expiration", field: "exp", value: "100"},
		{name: "null issued at", field: "iat", value: nil},
		{name: "wrong nonce type", field: "nonce", value: 7},
		{name: "noncanonical nonce", field: "nonce", value: fixture.nonce + "="},
		{name: "nonce mismatch", field: "nonce", value: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, testSignInTokenBytes))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := maps.Clone(fixture.claims)
			claims[tc.field] = tc.value
			assertIDTokenRejected(t, fixture.verifier, fixture.sign(t, fixture.header, claims))
		})
	}

	rawClaims := []byte(fmt.Sprintf(`{"iss":%q,"iss":%q,"sub":"provider-subject-123","aud":"client-id","exp":%d,"iat":%d,"nonce":%q}`,
		fixture.verifier.issuer,
		fixture.verifier.issuer,
		fixture.now.Add(5*time.Minute).Unix(),
		fixture.created.Unix(),
		fixture.nonce,
	))
	assertIDTokenRejected(t, fixture.verifier, signTestCompact(t, fixture.key, mustMarshalJSON(t, fixture.header), rawClaims))
}

func TestIDTokenVerifierDoesNotDecodeClaimsBeforeSignatureVerification(t *testing.T) {
	fixture := newIDTokenFixture(t)
	rawClaims := []byte(fmt.Sprintf(`{"iss":%q,"iss":"duplicate-canary","sub":"subject","aud":"client-id","exp":%d,"iat":%d,"nonce":%q}`,
		fixture.verifier.issuer,
		fixture.now.Add(time.Minute).Unix(),
		fixture.created.Unix(),
		fixture.nonce,
	))
	valid := signTestCompact(t, fixture.key, mustMarshalJSON(t, fixture.header), rawClaims)
	parts := strings.Split(valid, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, fixture.key.Size()))
	err := verifyIDTokenError(fixture.verifier, strings.Join(parts, "."))
	if err != errIDTokenValidation || strings.Contains(err.Error(), "duplicate-canary") {
		t.Fatalf("signature failure was not sanitized: %v", err)
	}
}

func TestIDTokenVerifierPreservesValidLargeNumberExtensions(t *testing.T) {
	fixture := newIDTokenFixture(t)
	payload := appendRawJSONObjectMember(t, mustMarshalJSON(t, fixture.claims), `"extension":1e400`)
	token := signTestCompact(t, fixture.key, mustMarshalJSON(t, fixture.header), payload)
	if _, err := fixture.verifier.verify(token); err != nil {
		t.Fatal(err)
	}
}

func TestIDTokenVerifierAcceptsIgnoredLargeGroupsClaim(t *testing.T) {
	fixture := newIDTokenFixture(t)
	groups := make([]string, maxJWKSKeys+1)
	for i := range groups {
		groups[i] = fmt.Sprintf("provider-group-%d", i)
	}
	claims := maps.Clone(fixture.claims)
	claims["groups"] = groups

	if _, err := fixture.verifier.verify(fixture.sign(t, fixture.header, claims)); err != nil {
		t.Fatal(err)
	}
}

func TestIDTokenVerifierEmailVerifiedRequiresExactJSONTrue(t *testing.T) {
	fixture := newIDTokenFixture(t)
	tests := []struct {
		name   string
		value  any
		remove bool
	}{
		{name: "missing", remove: true},
		{name: "false", value: false},
		{name: "string true", value: "true"},
		{name: "number one", value: 1},
		{name: "null", value: nil},
		{name: "array", value: []bool{true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := maps.Clone(fixture.claims)
			if tc.remove {
				delete(claims, "email_verified")
			} else {
				claims["email_verified"] = tc.value
			}
			assertIDTokenRejected(t, fixture.verifier, fixture.sign(t, fixture.header, claims))
		})
	}

	for _, tc := range []struct {
		name   string
		member string
	}{
		{name: "duplicate email_verified", member: `"email_verified":true`},
		{name: "duplicate email", member: `"email":"person@example.test"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := appendRawJSONObjectMember(t, mustMarshalJSON(t, fixture.claims), tc.member)
			assertIDTokenRejected(t, fixture.verifier, signTestCompact(t, fixture.key, mustMarshalJSON(t, fixture.header), payload))
		})
	}
}

func TestIDTokenVerifierEmailAdmissionPolicyMatrix(t *testing.T) {
	fixture := newIDTokenFixture(t)
	boundaryLocal := strings.Repeat("a", maxEmailClaimBytes-len("@example.test"))
	tests := []struct {
		name       string
		email      any
		remove     bool
		wantDomain string
	}{
		{name: "plain ASCII", email: "person@example.test", wantDomain: "example.test"},
		{name: "mixed-case ASCII domain folds", email: "Person@EXAMPLE.Test", wantDomain: "example.test"},
		{name: "subdomain is its own domain", email: "person@mail.example.test", wantDomain: "mail.example.test"},
		{name: "non-ASCII local part with ASCII domain", email: "pérson@example.test", wantDomain: "example.test"},
		{name: "boundary 254 bytes", email: boundaryLocal + "@example.test", wantDomain: "example.test"},

		{name: "missing email", remove: true},
		{name: "null email", email: nil},
		{name: "numeric email", email: 7},
		{name: "empty email", email: ""},
		{name: "oversized 255 bytes", email: boundaryLocal + "a@example.test"},
		{name: "leading ASCII space", email: " person@example.test"},
		{name: "trailing ASCII space", email: "person@example.test "},
		{name: "leading tab", email: "\tperson@example.test"},
		{name: "trailing Unicode whitespace", email: "person@example.test\u00a0"},
		{name: "embedded NUL", email: "per\x00son@example.test"},
		{name: "embedded newline", email: "person@exam\nple.test"},
		{name: "line separator Zl", email: "person\u2028@example.test"},
		{name: "paragraph separator Zp", email: "person\u2029@example.test"},
		{name: "no at sign", email: "person.example.test"},
		{name: "two at signs", email: "person@extra@example.test"},
		{name: "empty local part", email: "@example.test"},
		{name: "empty domain part", email: "person@"},
		{name: "non-ASCII domain byte", email: "person@exämple.test"},
		{name: "Cyrillic lookalike domain", email: "person@еxample.test"},
		{name: "uppercase non-ASCII domain", email: "person@EXÄMPLE.TEST"},
		{name: "kelvin sign folding into ASCII domain", email: "person@EXAMPLE.TES\u212a"},
		{name: "trailing dot domain", email: "person@example.test."},
		{name: "IPv4 literal domain", email: "person@192.0.2.1"},
		{name: "bracketed IPv6 domain", email: "person@[2001:db8::1]"},
		{name: "leading hyphen label", email: "person@-example.test"},
		{name: "empty domain label", email: "person@example..test"},
		{name: "underscore label", email: "person@ex_ample.test"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := maps.Clone(fixture.claims)
			if tc.remove {
				delete(claims, "email")
			} else {
				claims["email"] = tc.email
			}
			verified, err := fixture.verifier.verify(fixture.sign(t, fixture.header, claims))
			if tc.wantDomain == "" {
				if err != errIDTokenValidation {
					t.Fatalf("verification error = %v, want generic validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if verified.emailDomain != tc.wantDomain {
				t.Fatalf("email domain = %q, want %q", verified.emailDomain, tc.wantDomain)
			}
		})
	}
}

func TestIDTokenVerifierBaseClaimValidationPrecedesEmailPolicy(t *testing.T) {
	fixture := newIDTokenFixture(t)
	claims := maps.Clone(fixture.claims)
	claims["exp"] = fixture.now.Add(-5 * time.Minute).Unix()
	assertIDTokenRejected(t, fixture.verifier, fixture.sign(t, fixture.header, claims))
}

func newIDTokenFixture(t *testing.T) idTokenFixture {
	t.Helper()
	key := sharedTestRSAKey(t)
	now := time.Date(2026, 7, 29, 15, 0, 0, 0, time.UTC)
	created := now.Add(-5 * time.Minute)
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, testSignInTokenBytes))
	jwksBody := mustJSON(t, map[string]any{"keys": []any{map[string]any{
		"kty":     "RSA",
		"kid":     "provider-key-2026",
		"alg":     "RS256",
		"use":     "sig",
		"key_ops": []string{"verify"},
		"n":       base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":       encodeUInt(uint64(key.E)),
	}}})
	keys, err := parseJWKS(jwksBody)
	if err != nil {
		t.Fatal(err)
	}
	return idTokenFixture{
		key: key,
		verifier: idTokenVerifier{
			issuer:               "https://id.example.test/tenant",
			clientID:             "client-id",
			keys:                 keys,
			nonceDigest:          testSignInDigest(testSignInNonceDigestPurpose, nonce),
			nonceDigestPurpose:   testSignInNonceDigestPurpose,
			transactionCreatedAt: created,
			now:                  func() time.Time { return now },
		},
		header: map[string]any{"alg": "RS256", "kid": "provider-key-2026", "typ": "JWT"},
		claims: map[string]any{
			"iss":   "https://id.example.test/tenant",
			"sub":   "provider-subject-123",
			"aud":   "client-id",
			"exp":   now.Add(5 * time.Minute).Unix(),
			"iat":   created.Unix(),
			"nonce": nonce,

			"email":          "person@example.test",
			"email_verified": true,
		},
		nonce:   nonce,
		now:     now,
		created: created,
	}
}

func sharedTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAOnce.Do(func() {
		testRSAKey, testRSAErr = rsa.GenerateKey(rand.Reader, minRSAModulusBits)
	})
	if testRSAErr != nil {
		t.Fatal(testRSAErr)
	}
	return testRSAKey
}

func (fixture idTokenFixture) sign(t *testing.T, header, claims any) string {
	t.Helper()
	return signTestCompact(t, fixture.key, mustMarshalJSON(t, header), mustMarshalJSON(t, claims))
}

func signTestCompact(t *testing.T, key *rsa.PrivateKey, header, payload []byte) string {
	t.Helper()
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := headerSegment + "." + payloadSegment
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func compactSegments(header, payload, signature []byte) string {
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func numericJSON(value string) json.RawMessage {
	return json.RawMessage(value)
}

func assertIDTokenRejected(t *testing.T, verifier idTokenVerifier, token string) {
	t.Helper()
	if err := verifyIDTokenError(verifier, token); err != errIDTokenValidation {
		t.Fatalf("verification error = %v, want generic validation error", err)
	}
}

func verifyIDTokenError(verifier idTokenVerifier, token string) error {
	_, err := verifier.verify(token)
	return err
}
