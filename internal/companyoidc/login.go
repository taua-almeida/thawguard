package companyoidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	// loginDiscoveryConcurrencyLimit bounds how many anonymous login
	// initiations may hold a provider discovery request at once.
	loginDiscoveryConcurrencyLimit = 4
	// loginMaxLiveTransactions bounds the number of pending anonymous login
	// transactions stored at once.
	loginMaxLiveTransactions = 100

	loginStateDigestPurpose   = "thawguard:company-oidc-login-state:v1"
	loginNonceDigestPurpose   = "thawguard:company-oidc-login-nonce:v1"
	loginBrowserDigestPurpose = "thawguard:company-oidc-login-browser:v1"
)

var ErrLoginOutcomeUnknown = errors.New("the company OIDC login outcome could not be confirmed")

type LoginStartInput struct {
	CallbackURI string
}

type LoginStart struct {
	AuthorizationURL string
	// BrowserToken is the raw one-time browser-binding value the web layer
	// stores in the login cookie; only its digest is persisted.
	BrowserToken string
}

type LoginCallbackInput struct {
	State        string
	BrowserToken string
	RawQuery     string
}

// LoginCompletion identifies the linked user a verified login callback
// resolved to, plus the connection revision and activation generation the
// login transaction was fenced against, for the session-creation recheck.
type LoginCompletion struct {
	UserID               int64
	ConnectionRevision   int64
	ActivationGeneration int64
}

type loginTransactionRecord struct {
	configRevision       int64
	activationGeneration int64
	browserBindingDigest [sha256.Size]byte
	nonceDigest          [sha256.Size]byte
	pkceCiphertext       []byte
	tokenEndpoint        string
	jwksURI              string
	redirectURI          string
	createdAt            time.Time
	expiresAt            time.Time
}

type loginClaim struct {
	issuer                 string
	clientID               string
	clientSecretCiphertext []byte
	pkceCiphertext         []byte
	tokenEndpoint          string
	jwksURI                string
	redirectURI            string
	nonceDigest            [sha256.Size]byte
	configRevision         int64
	activationGeneration   int64
	createdAt              time.Time
	domains                []string
	identityUserID         int64
	identitySubject        string
}

// LoginAvailable reports whether anonymous company sign-in can currently
// succeed: the connection is enabled, the linked identity still matches the
// active configuration, the linked Administrator remains an enabled Admin
// with an unforced local credential, and the stored client secret decrypts
// and validates. It performs no provider network work and never mutates
// state, so a runtime holding the wrong encryption key hides the login
// button without disabling the connection.
func (s *Service) LoginAvailable(ctx context.Context) bool {
	if s == nil || s.db == nil || s.secrets == nil {
		return false
	}
	_, available := s.loginAvailability(ctx)
	return available
}

func (s *Service) loginAvailability(ctx context.Context) (Connection, bool) {
	record, found, err := loadConnectionRecord(ctx, s.db)
	if err != nil || !found || !record.Enabled {
		return Connection{}, false
	}
	connection, err := publicConnection(record)
	if err != nil {
		return Connection{}, false
	}
	if connection.Identity == nil || !connection.Identity.MatchesConnection {
		return Connection{}, false
	}
	eligible, err := linkedAdministratorEligible(ctx, s.db, connection.Identity.UserID)
	if err != nil || !eligible {
		return Connection{}, false
	}
	valid, err := s.storedClientSecretValid(ctx, record.ClientSecretCiphertext)
	if err != nil || !valid {
		return Connection{}, false
	}
	return connection, true
}

// loginCapacityAvailable cleans expired login transactions and checks the
// live cap in a short transaction, so a full store rejects the initiation
// before any provider network work. The authoritative recheck against races
// stays inside prepareLogin's insert transaction; no database transaction is
// held during discovery.
func (s *Service) loginCapacityAvailable(ctx context.Context) bool {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	if err := cleanupExpiredLoginTransactions(ctx, tx, s.now().UTC()); err != nil {
		return false
	}
	var live int64
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM company_oidc_login_transactions`,
	).Scan(&live); err != nil {
		return false
	}
	if err := tx.Commit(); err != nil {
		return false
	}
	return live < loginMaxLiveTransactions
}

// StartLogin begins an anonymous company sign-in. Every failure is reported
// as the generic ErrLoginUnavailable; the anonymous surface never learns why.
func (s *Service) StartLogin(ctx context.Context, input LoginStartInput) (LoginStart, error) {
	if s == nil || s.db == nil || s.secrets == nil || s.checker == nil ||
		!s.validTestSignInRedirectURI(input.CallbackURI) {
		return LoginStart{}, ErrLoginUnavailable
	}

	connection, available := s.loginAvailability(ctx)
	if !available {
		return LoginStart{}, ErrLoginUnavailable
	}
	if !s.loginCapacityAvailable(ctx) {
		return LoginStart{}, ErrLoginUnavailable
	}

	select {
	case s.loginGuard <- struct{}{}:
	default:
		return LoginStart{}, ErrLoginUnavailable
	}
	providerCtx, cancel := context.WithTimeout(ctx, testSignInProviderTimeout)
	discovery := s.checker.discover(providerCtx, connection.Issuer, true)
	cancel()
	<-s.loginGuard
	if discovery.resultCode != SetupCheckVerified {
		return LoginStart{}, ErrLoginUnavailable
	}
	authorizationEndpoint, err := prepareAuthorizationEndpoint(discovery.metadata.authorizationEndpoint)
	if err != nil {
		return LoginStart{}, ErrLoginUnavailable
	}

	initiation, err := s.prepareLogin(ctx, loginInitiationInput{
		expectedRevision:   connection.Revision,
		expectedGeneration: connection.ActivationGeneration,
		expectedIssuer:     connection.Issuer,
		expectedClientID:   connection.ClientID,
		tokenEndpoint:      discovery.metadata.tokenEndpoint,
		jwksURI:            discovery.metadata.jwksURI,
		redirectURI:        input.CallbackURI,
	})
	if err != nil {
		return LoginStart{}, err
	}

	values := authorizationEndpoint.Query()
	values.Set("scope", "openid email")
	values.Set("response_type", "code")
	values.Set("response_mode", "query")
	values.Set("client_id", initiation.clientID)
	values.Set("redirect_uri", input.CallbackURI)
	values.Set("state", loginStatePrefix+initiation.state)
	values.Set("nonce", initiation.nonce)
	values.Set("code_challenge", initiation.pkceChallenge)
	values.Set("code_challenge_method", "S256")
	authorizationEndpoint.RawQuery = values.Encode()

	return LoginStart{
		AuthorizationURL: authorizationEndpoint.String(),
		BrowserToken:     initiation.browserToken,
	}, nil
}

type loginInitiationInput struct {
	expectedRevision   int64
	expectedGeneration int64
	expectedIssuer     string
	expectedClientID   string
	tokenEndpoint      string
	jwksURI            string
	redirectURI        string
}

type loginInitiation struct {
	state         string
	nonce         string
	pkceChallenge string
	browserToken  string
	clientID      string
}

func (s *Service) prepareLogin(ctx context.Context, input loginInitiationInput) (loginInitiation, error) {
	if !validHTTPSProviderURL(input.tokenEndpoint) || !validHTTPSProviderURL(input.jwksURI) ||
		!s.validTestSignInRedirectURI(input.redirectURI) {
		return loginInitiation{}, ErrLoginUnavailable
	}
	material, err := newTestSignInMaterial(s.random)
	if err != nil {
		return loginInitiation{}, ErrLoginUnavailable
	}
	browserToken, err := randomTestToken(s.random)
	if err != nil {
		return loginInitiation{}, ErrLoginUnavailable
	}
	verifierCiphertext, err := encryptTestSignInVerifier(ctx, s.secrets, material.pkceVerifier)
	if err != nil {
		return loginInitiation{}, ErrLoginUnavailable
	}

	stateDigest := testSignInDigest(loginStateDigestPurpose, material.state)
	nonceDigest := testSignInDigest(loginNonceDigestPurpose, material.nonce)
	browserDigest := testSignInDigest(loginBrowserDigestPurpose, browserToken)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return loginInitiation{}, ErrLoginUnavailable
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE company_oidc_connections SET id = id WHERE id = 1`,
	); err != nil {
		return loginInitiation{}, ErrLoginUnavailable
	}
	now := s.now().UTC()
	if err := cleanupExpiredLoginTransactions(ctx, tx, now); err != nil {
		return loginInitiation{}, ErrLoginUnavailable
	}
	var live int64
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM company_oidc_login_transactions`,
	).Scan(&live); err != nil {
		return loginInitiation{}, ErrLoginUnavailable
	}
	if live >= loginMaxLiveTransactions {
		return loginInitiation{}, ErrLoginUnavailable
	}

	snapshot, found, err := loadActivationSnapshot(ctx, tx)
	if err != nil || !found || !snapshot.record.Enabled ||
		snapshot.record.Revision != input.expectedRevision ||
		snapshot.record.ActivationGeneration != input.expectedGeneration ||
		snapshot.record.Issuer != input.expectedIssuer ||
		snapshot.record.ClientID != input.expectedClientID {
		return loginInitiation{}, ErrLoginUnavailable
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_login_transactions(
  state_digest, connection_id, config_revision, activation_generation,
  browser_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
)
VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stateDigest[:],
		snapshot.record.Revision,
		snapshot.record.ActivationGeneration,
		browserDigest[:],
		nonceDigest[:],
		verifierCiphertext,
		input.tokenEndpoint,
		input.jwksURI,
		input.redirectURI,
		formatCompanyOIDCTime(now),
		formatCompanyOIDCTime(now.Add(testSignInTransactionTTL)),
	); err != nil {
		return loginInitiation{}, ErrLoginUnavailable
	}
	if err := tx.Commit(); err != nil {
		return loginInitiation{}, ErrLoginOutcomeUnknown
	}

	return loginInitiation{
		state:         material.state,
		nonce:         material.nonce,
		pkceChallenge: material.pkceChallenge,
		browserToken:  browserToken,
		clientID:      snapshot.record.ClientID,
	}, nil
}

// CompleteLogin consumes the one-time login transaction for the callback,
// redeems the authorization code, and resolves the linked Administrator. It
// never creates a session; the auth layer does that with its own atomic
// authority recheck. Non-verified provider outcomes report a result code.
func (s *Service) CompleteLogin(
	ctx context.Context,
	input LoginCallbackInput,
) (LoginCompletion, TestSignInResultCode, error) {
	token, found := strings.CutPrefix(input.State, loginStatePrefix)
	if !found || !canonicalTestToken(token) {
		return LoginCompletion{}, "", ErrLoginUnavailable
	}
	claim, err := s.claimLogin(ctx, token, input.BrowserToken)
	if err != nil {
		return LoginCompletion{}, "", err
	}

	response, valid := parseAuthorizationResponse(input.RawQuery, input.State)
	result := TestSignInProviderInvalid
	var verified verifiedIDToken
	if valid && response.providerError != "" {
		result = providerAuthorizationErrorResult(response.providerError)
	} else if valid {
		verified, result = s.verifyAuthorizationCodeGrant(ctx, authorizationCodeVerification{
			issuer:                 claim.issuer,
			clientID:               claim.clientID,
			clientSecretCiphertext: claim.clientSecretCiphertext,
			pkceCiphertext:         claim.pkceCiphertext,
			tokenEndpoint:          claim.tokenEndpoint,
			jwksURI:                claim.jwksURI,
			redirectURI:            claim.redirectURI,
			nonceDigest:            claim.nonceDigest,
			nonceDigestPurpose:     loginNonceDigestPurpose,
			createdAt:              claim.createdAt,
			domains:                claim.domains,
		}, response.code)
	}
	if result != TestSignInVerified {
		return LoginCompletion{}, result, nil
	}
	if subtle.ConstantTimeCompare(
		[]byte(verified.subject),
		[]byte(claim.identitySubject),
	) != 1 {
		return LoginCompletion{}, TestSignInProviderInvalid, nil
	}
	return LoginCompletion{
		UserID:               claim.identityUserID,
		ConnectionRevision:   claim.configRevision,
		ActivationGeneration: claim.activationGeneration,
	}, TestSignInVerified, nil
}

func (s *Service) claimLogin(ctx context.Context, token, browserToken string) (loginClaim, error) {
	if s == nil || s.db == nil {
		return loginClaim{}, ErrLoginUnavailable
	}

	stateDigest := testSignInDigest(loginStateDigestPurpose, token)
	browserValid := canonicalTestToken(browserToken)
	var browserDigest [sha256.Size]byte
	if browserValid {
		browserDigest = testSignInDigest(loginBrowserDigestPurpose, browserToken)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return loginClaim{}, ErrLoginUnavailable
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE company_oidc_login_transactions SET state_digest = state_digest WHERE state_digest = ?`,
		stateDigest[:],
	); err != nil {
		return loginClaim{}, ErrLoginUnavailable
	}
	now := s.now().UTC()
	if err := cleanupExpiredLoginTransactions(ctx, tx, now); err != nil {
		return loginClaim{}, ErrLoginUnavailable
	}
	record, found, err := loadLoginTransaction(ctx, tx, stateDigest)
	if err != nil {
		if found {
			return loginClaim{}, consumeLoginTransaction(ctx, tx, stateDigest)
		}
		return loginClaim{}, ErrLoginUnavailable
	}
	if !found {
		if err := tx.Commit(); err != nil {
			return loginClaim{}, ErrLoginOutcomeUnknown
		}
		return loginClaim{}, ErrLoginUnavailable
	}

	if !browserValid || !now.Before(record.expiresAt) || subtle.ConstantTimeCompare(
		browserDigest[:],
		record.browserBindingDigest[:],
	) != 1 {
		return loginClaim{}, consumeLoginTransaction(ctx, tx, stateDigest)
	}
	snapshot, snapshotFound, err := loadActivationSnapshot(ctx, tx)
	if err != nil {
		return loginClaim{}, ErrLoginUnavailable
	}
	if !snapshotFound || !snapshot.record.Enabled ||
		snapshot.record.Revision != record.configRevision ||
		snapshot.record.ActivationGeneration != record.activationGeneration ||
		!snapshot.identityMatchesConnection() {
		return loginClaim{}, consumeLoginTransaction(ctx, tx, stateDigest)
	}
	if err := deleteLoginTransaction(ctx, tx, stateDigest); err != nil {
		return loginClaim{}, ErrLoginUnavailable
	}
	if err := tx.Commit(); err != nil {
		return loginClaim{}, ErrLoginOutcomeUnknown
	}
	return loginClaim{
		issuer:                 snapshot.record.Issuer,
		clientID:               snapshot.record.ClientID,
		clientSecretCiphertext: snapshot.record.ClientSecretCiphertext,
		pkceCiphertext:         record.pkceCiphertext,
		tokenEndpoint:          record.tokenEndpoint,
		jwksURI:                record.jwksURI,
		redirectURI:            record.redirectURI,
		nonceDigest:            record.nonceDigest,
		configRevision:         snapshot.record.Revision,
		activationGeneration:   snapshot.record.ActivationGeneration,
		createdAt:              record.createdAt,
		domains:                slices.Clone(snapshot.record.Domains),
		identityUserID:         snapshot.record.Identity.userID,
		identitySubject:        snapshot.record.Identity.subject,
	}, nil
}

func loadLoginTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) (loginTransactionRecord, bool, error) {
	var record loginTransactionRecord
	var browserDigest, nonceDigest []byte
	var createdAt, expiresAt string
	err := tx.QueryRowContext(ctx, `
SELECT config_revision, activation_generation, browser_binding_digest, nonce_digest,
  pkce_verifier_ciphertext, token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
FROM company_oidc_login_transactions
WHERE state_digest = ?`, stateDigest[:]).Scan(
		&record.configRevision,
		&record.activationGeneration,
		&browserDigest,
		&nonceDigest,
		&record.pkceCiphertext,
		&record.tokenEndpoint,
		&record.jwksURI,
		&record.redirectURI,
		&createdAt,
		&expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return loginTransactionRecord{}, false, nil
	}
	if err != nil {
		return loginTransactionRecord{}, false, err
	}
	if record.configRevision <= 0 || record.activationGeneration <= 0 ||
		len(browserDigest) != sha256.Size || len(nonceDigest) != sha256.Size ||
		len(record.pkceCiphertext) < 1 || len(record.pkceCiphertext) > testSignInMaxCiphertext ||
		!validHTTPSProviderURL(record.tokenEndpoint) || !validHTTPSProviderURL(record.jwksURI) ||
		!validTestSignInRedirectURI(record.redirectURI) {
		return loginTransactionRecord{}, true, errors.New("company OIDC login transaction is malformed")
	}
	copy(record.browserBindingDigest[:], browserDigest)
	copy(record.nonceDigest[:], nonceDigest)
	record.createdAt, err = parseCompanyOIDCTime(createdAt)
	if err != nil {
		return loginTransactionRecord{}, true, errors.New("company OIDC login transaction is malformed")
	}
	record.expiresAt, err = parseCompanyOIDCTime(expiresAt)
	if err != nil || !record.expiresAt.After(record.createdAt) {
		return loginTransactionRecord{}, true, errors.New("company OIDC login transaction is malformed")
	}
	return record, true, nil
}

func cleanupExpiredLoginTransactions(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
DELETE FROM company_oidc_login_transactions
WHERE state_digest IN (
  SELECT state_digest
  FROM company_oidc_login_transactions
  WHERE expires_at <= ?
  ORDER BY expires_at, state_digest
  LIMIT ?
)`, formatCompanyOIDCTime(now), testSignInCleanupLimit)
	return err
}

func consumeLoginTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) error {
	if err := deleteLoginTransaction(ctx, tx, stateDigest); err != nil {
		return ErrLoginUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrLoginOutcomeUnknown
	}
	return ErrLoginUnavailable
}

func deleteLoginTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) error {
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM company_oidc_login_transactions WHERE state_digest = ?`,
		stateDigest[:],
	)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if deleted != 1 {
		return fmt.Errorf("delete company OIDC login transaction affected %d rows", deleted)
	}
	return nil
}
