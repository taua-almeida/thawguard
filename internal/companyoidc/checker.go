package companyoidc

import (
	"context"
	"io"
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

	discovery := c.discover(runCtx, issuer, false)
	if discovery.resultCode == SetupCheckIssuerMismatch {
		return SetupCheckReport{
			ResultCode:     discovery.resultCode,
			ObservedIssuer: new(discovery.observedIssuer),
		}
	}
	if discovery.resultCode != SetupCheckVerified {
		return SetupCheckReport{ResultCode: discovery.resultCode}
	}

	jwks, status := c.fetchJWKS(runCtx, discovery.metadata.jwksURI)
	if status == fetchUnavailable {
		return SetupCheckReport{ResultCode: SetupCheckJWKSUnavailable}
	}
	if status == fetchInvalid {
		return SetupCheckReport{ResultCode: SetupCheckJWKSInvalid}
	}
	candidates := int64(len(jwks.keys))
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

type discoveryMetadata struct {
	authorizationEndpoint string
	tokenEndpoint         string
	jwksURI               string
}

type discoveryCheck struct {
	metadata       discoveryMetadata
	resultCode     SetupCheckResultCode
	observedIssuer string
}

func (c *Checker) discover(ctx context.Context, issuer string, testSignIn bool) discoveryCheck {
	body, status := c.readJSON(ctx, discoveryURL(issuer), "application/json")
	if status == fetchUnavailable {
		return discoveryCheck{resultCode: SetupCheckDiscoveryUnavailable}
	}
	if status == fetchInvalid {
		return discoveryCheck{resultCode: SetupCheckDiscoveryInvalid}
	}

	document, ok := decodeJSONObject(body)
	if !ok {
		return discoveryCheck{resultCode: SetupCheckDiscoveryInvalid}
	}
	observedIssuer, ok := requiredJSONString(document, "issuer")
	if !ok || !validExactIssuer(observedIssuer) {
		return discoveryCheck{resultCode: SetupCheckIssuerInvalid}
	}
	if observedIssuer != issuer {
		return discoveryCheck{resultCode: SetupCheckIssuerMismatch, observedIssuer: observedIssuer}
	}

	metadata, ok := compatibleDiscoveryMetadata(document)
	if !ok || testSignIn && !testSignInCompatibleDiscovery(document) {
		return discoveryCheck{resultCode: SetupCheckMetadataIncompatible}
	}
	return discoveryCheck{metadata: metadata, resultCode: SetupCheckVerified}
}

func (c *Checker) fetchJWKS(ctx context.Context, jwksURI string) (trustedJWKS, fetchStatus) {
	body, status := c.readJSON(ctx, jwksURI, "application/json", "application/jwk-set+json")
	if status != fetchOK {
		return trustedJWKS{}, status
	}
	jwks, err := parseJWKS(body)
	if err != nil {
		return trustedJWKS{}, fetchInvalid
	}
	return jwks, fetchOK
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

func validExactIssuer(value string) bool {
	normalized, err := normalizeIssuer(value)
	return err == nil && normalized == value
}

func compatibleDiscoveryMetadata(discovery map[string]jsonRawMessage) (discoveryMetadata, bool) {
	authorizationEndpoint, authorizationOK := requiredJSONString(discovery, "authorization_endpoint")
	tokenEndpoint, tokenOK := requiredJSONString(discovery, "token_endpoint")
	jwksURI, jwksOK := requiredJSONString(discovery, "jwks_uri")
	if !authorizationOK || !tokenOK || !jwksOK ||
		!validHTTPSProviderURL(authorizationEndpoint) ||
		!validHTTPSProviderURL(tokenEndpoint) ||
		!validHTTPSProviderURL(jwksURI) {
		return discoveryMetadata{}, false
	}

	responseTypes, ok := requiredStringSlice(discovery, "response_types_supported")
	if !ok || !slices.Contains(responseTypes, "code") {
		return discoveryMetadata{}, false
	}
	subjectTypes, ok := requiredStringSlice(discovery, "subject_types_supported")
	if !ok || (!slices.Contains(subjectTypes, "public") && !slices.Contains(subjectTypes, "pairwise")) {
		return discoveryMetadata{}, false
	}
	signingAlgorithms, ok := requiredStringSlice(discovery, "id_token_signing_alg_values_supported")
	if !ok || !slices.Contains(signingAlgorithms, "RS256") {
		return discoveryMetadata{}, false
	}
	if _, present := discovery["grant_types_supported"]; present {
		grantTypes, ok := requiredStringSlice(discovery, "grant_types_supported")
		if !ok || !slices.Contains(grantTypes, "authorization_code") {
			return discoveryMetadata{}, false
		}
	}
	return discoveryMetadata{
		authorizationEndpoint: authorizationEndpoint,
		tokenEndpoint:         tokenEndpoint,
		jwksURI:               jwksURI,
	}, true
}

func testSignInCompatibleDiscovery(discovery map[string]jsonRawMessage) bool {
	scopes, ok := requiredStringSlice(discovery, "scopes_supported")
	if !ok || !slices.Contains(scopes, "openid") {
		return false
	}
	if _, present := discovery["token_endpoint_auth_methods_supported"]; present {
		methods, ok := requiredStringSlice(discovery, "token_endpoint_auth_methods_supported")
		if !ok || !slices.Contains(methods, "client_secret_basic") {
			return false
		}
	}
	if _, present := discovery["response_modes_supported"]; present {
		modes, ok := requiredStringSlice(discovery, "response_modes_supported")
		if !ok || !slices.Contains(modes, "query") {
			return false
		}
	}
	if _, present := discovery["code_challenge_methods_supported"]; present {
		methods, ok := requiredStringSlice(discovery, "code_challenge_methods_supported")
		if !ok || !slices.Contains(methods, "S256") {
			return false
		}
	}
	return true
}

func validHTTPSProviderURL(value string) bool {
	if len(value) < len("https://a") || len(value) > 2048 {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.User != nil || strings.Contains(value, "#") {
		return false
	}
	return true
}
