package companyoidc

import (
	"encoding/base64"
	"math/big"
	"testing"
)

func FuzzStrictCompactIDToken(f *testing.F) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"provider-key-2026"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"subject"}`))
	f.Add(header + "." + payload + ".AA")
	f.Add("AA.AA.AA")
	f.Add("AB.AA.AA")
	f.Add("")

	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > maxCompactIDTokenSize+1 {
			return
		}
		_, _, _ = preflightCompactIDToken(token)
	})
}

func FuzzStrictJSONAndJWKSBoundaries(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"key","n":"AQ","e":"Aw"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","kty":"EC"}]}`))
	f.Add([]byte(`{"keys":[]}`))
	f.Add(nestedJSONArray(maxJSONNestingDepth))
	f.Add(nestedJSONArray(maxJSONNestingDepth + 1))
	f.Add(jsonObjectWithMembers(maxJSONContainerValues))
	f.Add(jsonObjectWithMembers(maxJSONContainerValues + 1))
	f.Add(jsonArrayWithElements(maxJSONContainerValues, "null"))
	f.Add(jsonArrayWithElements(maxJSONContainerValues+1, "null"))
	f.Add(jwksWithKeyCount(maxJWKSKeys))
	f.Add(jwksWithKeyCount(maxJWKSKeys + 1))
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > setupCheckMaxBodySize+1 {
			return
		}
		var object map[string]jsonRawMessage
		_ = strictJSONUnmarshal(body, &object)
		_, _ = parseJWKS(body)
	})
}

func FuzzNumericDateBoundaries(f *testing.F) {
	for _, value := range []string{
		"0",
		"1.5",
		"253402300799",
		"253402300799.000000001",
		"1e18",
		"1e19",
		"01",
	} {
		f.Add([]byte(value))
	}

	maximum := big.NewRat(maxNumericDateSeconds, 1)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxNumericDateSize+1 {
			return
		}
		parsed, ok := parseNumericDate(raw)
		if ok && (parsed.seconds == nil || parsed.seconds.Sign() < 0 || parsed.seconds.Cmp(maximum) > 0) {
			t.Fatal("accepted NumericDate outside the bounded range")
		}
	})
}

func FuzzAuthorizationResponseBoundaries(f *testing.F) {
	const state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, raw := range []string{
		"state=" + state + "&code=authorization-code",
		"state=" + state + "&error=access_denied",
		"state=" + state + "&code=one&code=two",
		"state=" + state + "&code=%ZZ",
		"state=" + state + "&extension=ignored",
		"",
	} {
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > testSignInMaxRawQueryBytes+1 {
			return
		}
		extracted, stateOK := TestSignInStateFromRawQuery(raw)
		if stateOK && !canonicalTestToken(extracted) {
			t.Fatal("state extraction accepted noncanonical state")
		}
		response, valid := parseAuthorizationResponse(raw, state)
		if valid && (response.code == "") == (response.providerError == "") {
			t.Fatal("authorization response did not contain exactly one terminal value")
		}
	})
}
