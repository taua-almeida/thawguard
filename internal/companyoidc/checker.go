package companyoidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	setupCheckTimeout     = 10 * time.Second
	setupCheckMaxBodySize = 1 << 20
)

type Checker struct {
	client *http.Client
}

func NewChecker(transport http.RoundTripper) *Checker {
	return &Checker{client: &http.Client{
		Transport: transport,
		Jar:       nil,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (c *Checker) Check(ctx context.Context, issuer string) SetupCheckReport {
	if c == nil || c.client == nil {
		return SetupCheckReport{ResultCode: SetupCheckDiscoveryUnavailable}
	}
	if !validExactIssuer(issuer) {
		return SetupCheckReport{ResultCode: SetupCheckDiscoveryInvalid}
	}
	runCtx, cancel := context.WithTimeout(ctx, setupCheckTimeout)
	defer cancel()

	discoveryBody, status := c.readJSON(
		runCtx,
		discoveryURL(issuer),
		"application/json",
	)
	if status == fetchUnavailable {
		return SetupCheckReport{ResultCode: SetupCheckDiscoveryUnavailable}
	}
	if status == fetchInvalid {
		return SetupCheckReport{ResultCode: SetupCheckDiscoveryInvalid}
	}

	discovery, ok := decodeJSONObject(discoveryBody)
	if !ok {
		return SetupCheckReport{ResultCode: SetupCheckDiscoveryInvalid}
	}
	observedIssuer, ok := requiredJSONString(discovery, "issuer")
	if !ok || !validExactIssuer(observedIssuer) {
		return SetupCheckReport{ResultCode: SetupCheckIssuerInvalid}
	}
	if observedIssuer != issuer {
		return SetupCheckReport{
			ResultCode:     SetupCheckIssuerMismatch,
			ObservedIssuer: new(observedIssuer),
		}
	}

	jwksURI, ok := compatibleDiscoveryMetadata(discovery)
	if !ok {
		return SetupCheckReport{ResultCode: SetupCheckMetadataIncompatible}
	}
	jwksBody, status := c.readJSON(
		runCtx,
		jwksURI,
		"application/json",
		"application/jwk-set+json",
	)
	if status == fetchUnavailable {
		return SetupCheckReport{ResultCode: SetupCheckJWKSUnavailable}
	}
	if status == fetchInvalid {
		return SetupCheckReport{ResultCode: SetupCheckJWKSInvalid}
	}

	candidates, ok := supportedRSACandidateCount(jwksBody)
	if !ok {
		return SetupCheckReport{ResultCode: SetupCheckJWKSInvalid}
	}
	if candidates == 0 {
		return SetupCheckReport{
			ResultCode:              SetupCheckJWKSNoCandidate,
			PublicKeyCandidateCount: new(int64(0)),
		}
	}
	return SetupCheckReport{
		ResultCode:              SetupCheckVerified,
		PublicKeyCandidateCount: new(candidates),
	}
}

type fetchStatus uint8

const (
	fetchOK fetchStatus = iota
	fetchUnavailable
	fetchInvalid
)

func (c *Checker) readJSON(
	ctx context.Context,
	requestURL string,
	acceptedMediaTypes ...string,
) ([]byte, fetchStatus) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fetchUnavailable
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fetchUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fetchUnavailable
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !slices.Contains(acceptedMediaTypes, mediaType) {
		return nil, fetchInvalid
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, setupCheckMaxBodySize+1))
	if err != nil || ctx.Err() != nil {
		return nil, fetchUnavailable
	}
	if len(body) > setupCheckMaxBodySize || !utf8.Valid(body) {
		return nil, fetchInvalid
	}
	return body, fetchOK
}

func discoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

func decodeJSONObject(body []byte) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func requiredJSONString(object map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := object[key]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func requiredStringSlice(object map[string]json.RawMessage, key string) ([]string, bool) {
	raw, ok := object[key]
	if !ok {
		return nil, false
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, false
	}
	return values, true
}

func validExactIssuer(value string) bool {
	normalized, err := normalizeIssuer(value)
	return err == nil && normalized == value
}

func compatibleDiscoveryMetadata(discovery map[string]json.RawMessage) (string, bool) {
	authorizationEndpoint, authorizationOK := requiredJSONString(discovery, "authorization_endpoint")
	tokenEndpoint, tokenOK := requiredJSONString(discovery, "token_endpoint")
	jwksURI, jwksOK := requiredJSONString(discovery, "jwks_uri")
	if !authorizationOK || !tokenOK || !jwksOK ||
		!validHTTPSProviderURL(authorizationEndpoint) ||
		!validHTTPSProviderURL(tokenEndpoint) ||
		!validHTTPSProviderURL(jwksURI) {
		return "", false
	}

	responseTypes, ok := requiredStringSlice(discovery, "response_types_supported")
	if !ok || !slices.Contains(responseTypes, "code") {
		return "", false
	}
	subjectTypes, ok := requiredStringSlice(discovery, "subject_types_supported")
	if !ok || (!slices.Contains(subjectTypes, "public") && !slices.Contains(subjectTypes, "pairwise")) {
		return "", false
	}
	signingAlgorithms, ok := requiredStringSlice(discovery, "id_token_signing_alg_values_supported")
	if !ok || !slices.Contains(signingAlgorithms, "RS256") {
		return "", false
	}
	if _, present := discovery["grant_types_supported"]; present {
		grantTypes, ok := requiredStringSlice(discovery, "grant_types_supported")
		if !ok || !slices.Contains(grantTypes, "authorization_code") {
			return "", false
		}
	}
	return jwksURI, true
}

func validHTTPSProviderURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.User != nil || strings.Contains(value, "#") {
		return false
	}
	return true
}

func supportedRSACandidateCount(body []byte) (int64, bool) {
	jwks, ok := decodeJSONObject(body)
	if !ok {
		return 0, false
	}
	rawKeys, ok := jwks["keys"]
	if !ok {
		return 0, false
	}
	var keys []json.RawMessage
	if err := json.Unmarshal(rawKeys, &keys); err != nil || len(keys) == 0 {
		return 0, false
	}

	var candidates int64
	for _, rawKey := range keys {
		var key map[string]json.RawMessage
		if err := json.Unmarshal(rawKey, &key); err != nil || key == nil {
			return 0, false
		}
		if supportedRSACandidate(key) {
			candidates++
		}
	}
	return candidates, true
}

func supportedRSACandidate(key map[string]json.RawMessage) bool {
	kty, ok := requiredJSONString(key, "kty")
	if !ok || kty != "RSA" {
		return false
	}
	modulusText, ok := requiredJSONString(key, "n")
	if !ok {
		return false
	}
	exponentText, ok := requiredJSONString(key, "e")
	if !ok {
		return false
	}
	modulus, ok := canonicalBase64URLUInt(modulusText)
	if !ok || new(big.Int).SetBytes(modulus).BitLen() < 2048 || modulus[len(modulus)-1]&1 == 0 {
		return false
	}
	exponentBytes, ok := canonicalBase64URLUInt(exponentText)
	if !ok || len(exponentBytes) > 4 {
		return false
	}
	exponent := new(big.Int).SetBytes(exponentBytes).Uint64()
	if exponent < 3 || exponent > math.MaxInt32 || exponent&1 == 0 {
		return false
	}

	if value, present := key["alg"]; present && !exactJSONString(value, "RS256") {
		return false
	}
	if value, present := key["use"]; present && !exactJSONString(value, "sig") {
		return false
	}
	if value, present := key["key_ops"]; present {
		var operations []string
		if err := json.Unmarshal(value, &operations); err != nil || len(operations) != 1 || operations[0] != "verify" {
			return false
		}
	}
	for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, present := key[privateField]; present {
			return false
		}
	}
	return true
}

func canonicalBase64URLUInt(value string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || decoded[0] == 0 {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}

func exactJSONString(raw json.RawMessage, wanted string) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && value == wanted
}
