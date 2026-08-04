package companyoidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const (
	TestSignInCallbackPath = "/settings/authentication/oidc/callback"

	testSignInProviderTimeout  = 10 * time.Second
	testSignInMaxRawQueryBytes = 8 << 10
	testSignInMaxCodeBytes     = 4096
	testSignInMaxErrorBytes    = 256
	testSignInMaxTokenBody     = 64 << 10
	testSignInMaxAccessToken   = 32 << 10
	testSignInMaxTokenType     = 64
)

var (
	ErrTestProviderUnavailable = errors.New("company OIDC Test sign-in provider is unavailable")
	ErrTestProviderInvalid     = errors.New("company OIDC Test sign-in provider response is invalid")
)

type TestSignInResultCode string

const (
	TestSignInVerified                 TestSignInResultCode = "verified"
	TestSignInProviderDenied           TestSignInResultCode = "provider_denied"
	TestSignInProviderUnavailable      TestSignInResultCode = "provider_unavailable"
	TestSignInProviderInvalid          TestSignInResultCode = "provider_invalid"
	TestSignInConfigurationUnavailable TestSignInResultCode = "configuration_unavailable"
)

func (code TestSignInResultCode) Valid() bool {
	switch code {
	case TestSignInVerified,
		TestSignInProviderDenied,
		TestSignInProviderUnavailable,
		TestSignInProviderInvalid,
		TestSignInConfigurationUnavailable:
		return true
	default:
		return false
	}
}

type TestSignInStartInput struct {
	ActorUserID      int64
	SessionID        string
	ExpectedRevision int64
	CallbackURI      string
}

type TestSignInStart struct {
	AuthorizationURL string
}

type TestSignInCallbackInput struct {
	State     string
	SessionID string
	RawQuery  string
}

func (s *Service) StartTestSignIn(
	ctx context.Context,
	input TestSignInStartInput,
) (TestSignInStart, error) {
	if s == nil || s.db == nil {
		return TestSignInStart{}, ErrTestSignInUnavailable
	}
	if input.ActorUserID <= 0 || input.ExpectedRevision <= 0 || !validTestSessionID(input.SessionID) {
		return TestSignInStart{}, ErrTestSignInAuthorization
	}
	if s.secrets == nil {
		return TestSignInStart{}, ErrConfiguration
	}
	if s.checker == nil || !s.validTestSignInRedirectURI(input.CallbackURI) {
		return TestSignInStart{}, ErrTestSignInUnavailable
	}

	connection, found, err := s.Current(ctx)
	if err != nil || !found || connection.Revision != input.ExpectedRevision ||
		connection.SetupCheck == nil || connection.SetupCheck.ResultCode != SetupCheckVerified {
		return TestSignInStart{}, ErrTestSignInUnavailable
	}
	if connection.Enabled {
		return TestSignInStart{}, ErrEnabled
	}

	providerCtx, cancel := context.WithTimeout(ctx, testSignInProviderTimeout)
	discovery := s.checker.discover(providerCtx, connection.Issuer, true)
	cancel()
	if discovery.resultCode != SetupCheckVerified {
		if discovery.resultCode == SetupCheckDiscoveryUnavailable {
			return TestSignInStart{}, ErrTestProviderUnavailable
		}
		return TestSignInStart{}, ErrTestProviderInvalid
	}
	authorizationEndpoint, err := prepareAuthorizationEndpoint(discovery.metadata.authorizationEndpoint)
	if err != nil {
		return TestSignInStart{}, ErrTestProviderInvalid
	}

	initiation, err := s.prepareTestSignIn(ctx, TestSignInInitiationInput{
		ActorUserID:      input.ActorUserID,
		SessionID:        input.SessionID,
		ExpectedRevision: input.ExpectedRevision,
		TokenEndpoint:    discovery.metadata.tokenEndpoint,
		JWKSURI:          discovery.metadata.jwksURI,
		RedirectURI:      input.CallbackURI,
	})
	if err != nil {
		return TestSignInStart{}, err
	}

	values := authorizationEndpoint.Query()
	values.Set("scope", "openid email")
	values.Set("response_type", "code")
	values.Set("response_mode", "query")
	values.Set("client_id", initiation.ClientID)
	values.Set("redirect_uri", input.CallbackURI)
	values.Set("state", initiation.State)
	values.Set("nonce", initiation.Nonce)
	values.Set("code_challenge", initiation.PKCEChallenge)
	values.Set("code_challenge_method", "S256")
	authorizationEndpoint.RawQuery = values.Encode()

	return TestSignInStart{AuthorizationURL: authorizationEndpoint.String()}, nil
}

func prepareAuthorizationEndpoint(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || !validHTTPSProviderURL(endpoint) {
		return nil, ErrTestProviderInvalid
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, ErrTestProviderInvalid
	}
	for _, owned := range []string{
		"scope",
		"response_type",
		"response_mode",
		"client_id",
		"redirect_uri",
		"state",
		"nonce",
		"code_challenge",
		"code_challenge_method",
	} {
		if _, collision := values[owned]; collision {
			return nil, ErrTestProviderInvalid
		}
	}
	parsed.RawQuery = values.Encode()
	return parsed, nil
}

func TestSignInStateFromRawQuery(rawQuery string) (string, bool) {
	if len(rawQuery) > testSignInMaxRawQueryBytes {
		return "", false
	}
	values, valid := knownAuthorizationResponseValues(rawQuery, true)
	if !valid || len(values.state) != 1 || !canonicalTestToken(values.state[0]) {
		return "", false
	}
	return values.state[0], true
}

func (s *Service) CompleteTestSignIn(
	ctx context.Context,
	input TestSignInCallbackInput,
) (TestSignInResultCode, error) {
	// Claim consumption and its audit are one SQLite transaction. Provider work
	// cannot share that transaction, so interruption may truthfully leave a
	// claimed event without a completed event; no terminal result is reported
	// until the separate completion audit commits.
	claim, err := s.claimTestSignIn(ctx, testSignInClaimInput{
		State:     input.State,
		SessionID: input.SessionID,
	})
	if err != nil {
		return "", err
	}

	response, valid := parseAuthorizationResponse(input.RawQuery, input.State)
	result := TestSignInProviderInvalid
	if valid && response.providerError != "" {
		result = providerAuthorizationErrorResult(response.providerError)
	} else if valid {
		result = s.verifyAuthorizationCode(ctx, claim, response.code)
	}

	if err := s.completeTestSignIn(ctx, claim, result); err != nil {
		return "", err
	}
	return result, nil
}

type authorizationResponse struct {
	code          string
	providerError string
}

type knownAuthorizationValues struct {
	state            []string
	code             []string
	providerError    []string
	errorDescription []string
	errorURI         []string
}

func parseAuthorizationResponse(rawQuery, claimedState string) (authorizationResponse, bool) {
	if len(rawQuery) > testSignInMaxRawQueryBytes {
		return authorizationResponse{}, false
	}
	values, valid := knownAuthorizationResponseValues(rawQuery, false)
	if !valid || len(values.state) != 1 || values.state[0] != claimedState ||
		len(values.code) > 1 || len(values.providerError) > 1 ||
		len(values.errorDescription) > 1 || len(values.errorURI) > 1 {
		return authorizationResponse{}, false
	}
	hasCode := len(values.code) == 1 && validAuthorizationValue(values.code[0], testSignInMaxCodeBytes)
	hasError := len(values.providerError) == 1 && validAuthorizationValue(values.providerError[0], testSignInMaxErrorBytes)
	if hasCode == hasError {
		return authorizationResponse{}, false
	}
	if len(values.errorDescription) == 1 && !validAuthorizationValue(values.errorDescription[0], 4096) {
		return authorizationResponse{}, false
	}
	if len(values.errorURI) == 1 && !validAuthorizationValue(values.errorURI[0], 2048) {
		return authorizationResponse{}, false
	}
	if hasCode && (len(values.errorDescription) != 0 || len(values.errorURI) != 0) {
		return authorizationResponse{}, false
	}
	if hasCode {
		return authorizationResponse{code: values.code[0]}, true
	}
	return authorizationResponse{providerError: values.providerError[0]}, true
}

func knownAuthorizationResponseValues(rawQuery string, stateOnly bool) (knownAuthorizationValues, bool) {
	var values knownAuthorizationValues
	for _, field := range strings.Split(rawQuery, "&") {
		rawKey, rawValue, _ := strings.Cut(field, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			continue
		}
		known := key == "state" || key == "code" || key == "error" ||
			key == "error_description" || key == "error_uri"
		if !known {
			continue
		}
		if stateOnly && key != "state" {
			continue
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil || !utf8.ValidString(value) {
			return knownAuthorizationValues{}, false
		}
		switch key {
		case "state":
			values.state = append(values.state, value)
		case "code":
			if !stateOnly {
				values.code = append(values.code, value)
			}
		case "error":
			if !stateOnly {
				values.providerError = append(values.providerError, value)
			}
		case "error_description":
			if !stateOnly {
				values.errorDescription = append(values.errorDescription, value)
			}
		case "error_uri":
			if !stateOnly {
				values.errorURI = append(values.errorURI, value)
			}
		}
	}
	return values, true
}

func validAuthorizationValue(value string, maxBytes int) bool {
	return len(value) > 0 && len(value) <= maxBytes && utf8.ValidString(value) && !containsControlOrLineSeparator(value)
}

func providerAuthorizationErrorResult(providerError string) TestSignInResultCode {
	switch providerError {
	case "access_denied", "interaction_required", "login_required", "account_selection_required", "consent_required":
		return TestSignInProviderDenied
	case "server_error", "temporarily_unavailable":
		return TestSignInProviderUnavailable
	default:
		return TestSignInProviderInvalid
	}
}

func (s *Service) verifyAuthorizationCode(
	ctx context.Context,
	claim testSignInClaim,
	code string,
) TestSignInResultCode {
	_, result := s.verifyAuthorizationCodeGrant(ctx, authorizationCodeVerification{
		issuer:                 claim.issuer,
		clientID:               claim.clientID,
		clientSecretCiphertext: claim.clientSecretCiphertext,
		pkceCiphertext:         claim.pkceCiphertext,
		tokenEndpoint:          claim.tokenEndpoint,
		jwksURI:                claim.jwksURI,
		redirectURI:            claim.redirectURI,
		nonceDigest:            claim.nonceDigest,
		nonceDigestPurpose:     testSignInNonceDigestPurpose,
		createdAt:              claim.createdAt,
		domains:                claim.domains,
	}, code)
	return result
}

// authorizationCodeVerification carries everything needed to redeem an
// authorization code and validate the resulting ID token, independent of
// which transaction flow (Test sign-in, link, login) produced it.
type authorizationCodeVerification struct {
	issuer                 string
	clientID               string
	clientSecretCiphertext []byte
	pkceCiphertext         []byte
	tokenEndpoint          string
	jwksURI                string
	redirectURI            string
	nonceDigest            [sha256.Size]byte
	nonceDigestPurpose     string
	createdAt              time.Time
	domains                []string
}

func (s *Service) verifyAuthorizationCodeGrant(
	ctx context.Context,
	verification authorizationCodeVerification,
	code string,
) (verifiedIDToken, TestSignInResultCode) {
	if s.secrets == nil {
		return verifiedIDToken{}, TestSignInConfigurationUnavailable
	}
	if s.checker == nil {
		return verifiedIDToken{}, TestSignInConfigurationUnavailable
	}
	clientSecret, err := s.secrets.Decrypt(ctx, verification.clientSecretCiphertext)
	if err != nil || !validDecryptedClientSecret(clientSecret) {
		clear(clientSecret)
		return verifiedIDToken{}, TestSignInConfigurationUnavailable
	}
	defer clear(clientSecret)
	verifierBytes, err := s.secrets.Decrypt(ctx, verification.pkceCiphertext)
	if err != nil || !canonicalTestToken(string(verifierBytes)) {
		clear(verifierBytes)
		return verifiedIDToken{}, TestSignInConfigurationUnavailable
	}
	defer clear(verifierBytes)

	providerCtx, cancel := context.WithTimeout(ctx, testSignInProviderTimeout)
	defer cancel()
	idToken, result := s.checker.exchangeAuthorizationCode(
		providerCtx,
		verification.tokenEndpoint,
		verification.clientID,
		clientSecret,
		code,
		verification.redirectURI,
		string(verifierBytes),
	)
	if result != TestSignInVerified {
		return verifiedIDToken{}, result
	}

	keys, status := s.checker.fetchJWKS(providerCtx, verification.jwksURI)
	if status == fetchUnavailable {
		return verifiedIDToken{}, TestSignInProviderUnavailable
	}
	if status == fetchInvalid {
		return verifiedIDToken{}, TestSignInProviderInvalid
	}
	verified, err := (idTokenVerifier{
		issuer:               verification.issuer,
		clientID:             verification.clientID,
		keys:                 keys,
		nonceDigest:          verification.nonceDigest,
		nonceDigestPurpose:   verification.nonceDigestPurpose,
		transactionCreatedAt: verification.createdAt,
		now:                  s.now,
	}).verify(idToken)
	if err != nil {
		return verifiedIDToken{}, TestSignInProviderInvalid
	}
	if !slices.Contains(verification.domains, verified.emailDomain) {
		return verifiedIDToken{}, TestSignInProviderInvalid
	}
	return verified, TestSignInVerified
}

func validDecryptedClientSecret(secret []byte) bool {
	return len(secret) > 0 && len(secret) <= 4096 && utf8.Valid(secret) && bytes.IndexByte(secret, 0) < 0
}

func (c *Checker) exchangeAuthorizationCode(
	ctx context.Context,
	tokenEndpoint string,
	clientID string,
	clientSecret []byte,
	code string,
	redirectURI string,
	verifier string,
) (string, TestSignInResultCode) {
	if c == nil || c.client == nil || !validHTTPSProviderURL(tokenEndpoint) {
		return "", TestSignInProviderUnavailable
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", TestSignInProviderUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", clientSecretBasic(clientID, clientSecret))

	response, err := c.client.Do(request)
	if err != nil {
		return "", TestSignInProviderUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, testSignInMaxTokenBody+1))
	if err != nil || ctx.Err() != nil {
		clear(body)
		return "", TestSignInProviderUnavailable
	}
	defer clear(body)
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	jsonResponse := mediaErr == nil && mediaType == "application/json"
	bodyValid := len(body) <= testSignInMaxTokenBody && utf8.Valid(body)

	if response.StatusCode != http.StatusOK {
		if jsonResponse && bodyValid {
			oauthError, ok := parseOAuthError(body)
			if ok {
				switch oauthError {
				case "invalid_client":
					return "", TestSignInConfigurationUnavailable
				case "server_error", "temporarily_unavailable":
					return "", TestSignInProviderUnavailable
				}
			}
		}
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= http.StatusInternalServerError && response.StatusCode <= 599 {
			return "", TestSignInProviderUnavailable
		}
		return "", TestSignInProviderInvalid
	}
	if !jsonResponse || !bodyValid {
		return "", TestSignInProviderInvalid
	}

	object, ok := decodeJSONObject(body)
	if !ok {
		return "", TestSignInProviderInvalid
	}
	if _, hasOAuthError := object["error"]; hasOAuthError {
		return "", TestSignInProviderInvalid
	}
	accessToken, accessOK := requiredJSONString(object, "access_token")
	tokenType, typeOK := requiredJSONString(object, "token_type")
	idToken, idTokenOK := requiredJSONString(object, "id_token")
	if !accessOK || len(accessToken) == 0 || len(accessToken) > testSignInMaxAccessToken ||
		!typeOK || len(tokenType) == 0 || len(tokenType) > testSignInMaxTokenType || !strings.EqualFold(tokenType, "Bearer") ||
		!idTokenOK || len(idToken) == 0 || len(idToken) > maxCompactIDTokenSize {
		return "", TestSignInProviderInvalid
	}
	return idToken, TestSignInVerified
}

func clientSecretBasic(clientID string, clientSecret []byte) string {
	credentials := []byte(url.QueryEscape(clientID) + ":" + url.QueryEscape(string(clientSecret)))
	header := "Basic " + base64.StdEncoding.EncodeToString(credentials)
	clear(credentials)
	return header
}

func parseOAuthError(body []byte) (string, bool) {
	object, ok := decodeJSONObject(body)
	if !ok {
		return "", false
	}
	value, ok := requiredJSONString(object, "error")
	if !ok || !validAuthorizationValue(value, testSignInMaxErrorBytes) {
		return "", false
	}
	return value, true
}

func (s *Service) completeTestSignIn(
	ctx context.Context,
	claim testSignInClaim,
	result TestSignInResultCode,
) error {
	if !result.Valid() || s == nil || s.db == nil {
		return ErrTestTransactionUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrTestTransactionUnavailable
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, claim.actorUserID); err != nil {
		return ErrTestTransactionUnavailable
	}
	now := s.now().UTC()
	current, err := currentTestSession(ctx, tx, claim.actorUserID, claim.sessionID, now)
	if err != nil || !current {
		return ErrTestTransactionUnavailable
	}
	snapshot, found, err := loadTestSignInSnapshot(ctx, tx)
	if err != nil || !found || !snapshot.ready || snapshot.revision != claim.configRevision ||
		snapshot.issuer != claim.issuer || snapshot.clientID != claim.clientID ||
		!bytes.Equal(snapshot.clientSecretCiphertext, claim.clientSecretCiphertext) {
		return ErrTestTransactionUnavailable
	}
	domains, err := loadTestSignInDomains(ctx, tx)
	if err != nil || !slices.Equal(domains, claim.domains) {
		return ErrTestTransactionUnavailable
	}
	if result == TestSignInVerified {
		if err := replaceTestSignInEvidence(ctx, tx, claim.configRevision, now); err != nil {
			return ErrTestTransactionUnavailable
		}
	}
	if err := recordTestSignInCompleted(ctx, tx, claim.actorUserID, claim.configRevision, result); err != nil {
		return ErrTestTransactionUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrTestTransactionOutcomeUnknown
	}
	return nil
}

func replaceTestSignInEvidence(ctx context.Context, tx *sql.Tx, revision int64, verifiedAt time.Time) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_test_sign_in_evidence(connection_id, config_revision, verified_at)
VALUES (1, ?, ?)
ON CONFLICT(connection_id) DO UPDATE
SET config_revision = excluded.config_revision, verified_at = excluded.verified_at`,
		revision,
		formatCompanyOIDCTime(verifiedAt),
	); err != nil {
		return fmt.Errorf("record company OIDC test sign-in evidence: %w", err)
	}
	return nil
}

func recordTestSignInCompleted(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	revision int64,
	result TestSignInResultCode,
) error {
	details, err := json.Marshal(struct {
		Revision   int64                `json:"revision"`
		ResultCode TestSignInResultCode `json:"result_code"`
	}{
		Revision:   revision,
		ResultCode: result,
	})
	if err != nil {
		return errors.New("encode company OIDC Test sign-in completed audit evidence")
	}
	actor := actorUserID
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      audit.ActionOIDCConnectionTestSignInCompleted,
		SubjectType: audit.SubjectTypeOIDCConnection,
		SubjectID:   strconv.FormatInt(singletonConnectionID, 10),
		DetailsJSON: string(details),
	}); err != nil {
		return fmt.Errorf("record company OIDC Test sign-in completed audit event: %w", err)
	}
	return nil
}

func (s *Service) validTestSignInRedirectURI(value string) bool {
	return s != nil && s.publicURL != "" && value == s.publicURL+TestSignInCallbackPath &&
		validTestSignInRedirectURI(value)
}

func validTestSignInRedirectURI(value string) bool {
	if len(value) == 0 || len(value) > 2048 || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.Path != TestSignInCallbackPath || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}
