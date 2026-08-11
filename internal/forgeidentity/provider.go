package forgeidentity

import (
	"context"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	providerRequestTimeout  = 10 * time.Second
	maxProviderBodyBytes    = 64 << 10
	maxProviderAccessToken  = 32 << 10
	maxProviderTokenType    = 64
	tokenEndpointPath       = "/login/oauth/access_token"
	currentUserEndpointPath = "/api/v1/user"
)

// exchangeAndReadUser redeems the authorization code and reads the current
// provider account. The client secret, verifier, code, access token, and
// response bodies stay request-local; nothing provider-supplied is retained
// beyond the validated numeric id and username.
func (s *Service) exchangeAndReadUser(ctx context.Context, claim linkClaim, code string) (remoteAccount, LinkResultCode) {
	if s.secrets == nil {
		return remoteAccount{}, LinkConfigurationUnavailable
	}
	secretPlaintext, err := s.secrets.Decrypt(ctx, claim.clientSecretCiphertext)
	if err != nil {
		clearBytes(secretPlaintext)
		return remoteAccount{}, LinkConfigurationUnavailable
	}
	secret, err := unwrapEnvelope(oauthClientSecretEnvelopeHeader, secretPlaintext)
	if err != nil {
		return remoteAccount{}, LinkConfigurationUnavailable
	}
	defer clearBytes(secret)
	verifierPlaintext, err := s.secrets.Decrypt(ctx, claim.pkceCiphertext)
	if err != nil {
		clearBytes(verifierPlaintext)
		return remoteAccount{}, LinkConfigurationUnavailable
	}
	verifier, err := unwrapEnvelope(pkceVerifierEnvelopeHeader, verifierPlaintext)
	if err != nil {
		return remoteAccount{}, LinkConfigurationUnavailable
	}
	defer clearBytes(verifier)

	// One deadline bounds the whole provider conversation: the token
	// exchange and the current-user read together finish inside ten
	// seconds, or the callback fails as unavailable.
	providerCtx, cancel := context.WithTimeout(ctx, providerRequestTimeout)
	defer cancel()
	accessToken, result := s.exchangeAuthorizationCode(providerCtx, claim, string(secret), code, string(verifier))
	if result != LinkLinked {
		return remoteAccount{}, result
	}
	return s.readCurrentUser(providerCtx, claim.boundBaseURL, accessToken)
}

// exchangeAuthorizationCode POSTs the token request with the client
// credentials in the Basic header only, never in the body.
func (s *Service) exchangeAuthorizationCode(
	ctx context.Context,
	claim linkClaim,
	secret string,
	code string,
	verifier string,
) (string, LinkResultCode) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {claim.redirectURI},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		claim.boundBaseURL+tokenEndpointPath,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", LinkProviderUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(url.QueryEscape(claim.clientID), url.QueryEscape(secret))

	body, result := s.boundedProviderJSON(request)
	if result != LinkLinked {
		return "", result
	}
	defer clearBytes(body)
	object, ok := strictProviderObject(body, []string{"access_token", "token_type", "refresh_token", "error"})
	if !ok {
		return "", LinkProviderInvalid
	}
	if _, hasError := object["error"]; hasError {
		return "", LinkProviderInvalid
	}
	accessToken, tokenOK := providerJSONString(object, "access_token")
	tokenType, typeOK := providerJSONString(object, "token_type")
	// The optional refresh token is discarded without inspection.
	if !tokenOK || len(accessToken) == 0 || len(accessToken) > maxProviderAccessToken ||
		!typeOK || len(tokenType) == 0 || len(tokenType) > maxProviderTokenType ||
		!strings.EqualFold(tokenType, "Bearer") {
		return "", LinkProviderInvalid
	}
	return accessToken, LinkLinked
}

// readCurrentUser fetches the provider account behind the access token and
// validates the numeric id and username strictly.
func (s *Service) readCurrentUser(ctx context.Context, baseURL, accessToken string) (remoteAccount, LinkResultCode) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+currentUserEndpointPath, nil)
	if err != nil {
		return remoteAccount{}, LinkProviderUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)

	body, result := s.boundedProviderJSON(request)
	if result != LinkLinked {
		return remoteAccount{}, result
	}
	defer clearBytes(body)
	object, ok := strictProviderObject(body, []string{"id", "login"})
	if !ok {
		return remoteAccount{}, LinkProviderInvalid
	}
	remoteUserID, idOK := providerJSONPositiveInt(object, "id")
	login, loginOK := providerJSONString(object, "login")
	if !idOK || !loginOK || !validUsernameAtLink(login) {
		return remoteAccount{}, LinkProviderInvalid
	}
	return remoteAccount{remoteUserID: remoteUserID, username: login}, LinkLinked
}

// boundedProviderJSON performs one provider request under the strict
// response contract: HTTP 200 only, bounded UTF-8 JSON body with the exact
// media type, redirects never followed.
func (s *Service) boundedProviderJSON(request *http.Request) ([]byte, LinkResultCode) {
	if s.client == nil {
		return nil, LinkProviderUnavailable
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, LinkProviderUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProviderBodyBytes+1))
	if err != nil || request.Context().Err() != nil {
		clearBytes(body)
		return nil, LinkProviderUnavailable
	}
	if response.StatusCode != http.StatusOK {
		clearBytes(body)
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests ||
			(response.StatusCode >= http.StatusInternalServerError && response.StatusCode <= 599) {
			return nil, LinkProviderUnavailable
		}
		return nil, LinkProviderInvalid
	}
	if !validProviderContentType(response.Header.Get("Content-Type")) ||
		len(body) > maxProviderBodyBytes || !utf8.Valid(body) {
		clearBytes(body)
		return nil, LinkProviderInvalid
	}
	return body, LinkLinked
}

// validProviderContentType accepts application/json with no parameters or
// with only charset=utf-8.
func validProviderContentType(value string) bool {
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return false
	}
	if len(params) == 0 {
		return true
	}
	charset, hasCharset := params["charset"]
	return len(params) == 1 && hasCharset && strings.EqualFold(charset, "utf-8")
}
