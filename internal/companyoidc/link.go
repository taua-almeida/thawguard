package companyoidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const (
	linkStatePrefix  = "link."
	loginStatePrefix = "login."

	linkStateDigestPurpose   = "thawguard:company-oidc-link-state:v1"
	linkNonceDigestPurpose   = "thawguard:company-oidc-link-nonce:v1"
	linkSessionDigestPurpose = "thawguard:company-oidc-link-session:v1"
)

var ErrLinkOutcomeUnknown = errors.New("the company OIDC identity-link outcome could not be confirmed")

// CallbackStateKind classifies which flow a shared-callback request belongs
// to, decided purely from the shape of its state value.
type CallbackStateKind int

const (
	CallbackStateInvalid CallbackStateKind = iota
	CallbackStateTest
	CallbackStateLink
	CallbackStateLogin
)

// CallbackStateFromRawQuery parses the callback purpose from the state shape
// alone, before any database access. A bare canonical token is a Test
// sign-in; "link."-prefixed and "login."-prefixed canonical tokens belong to
// the link and login flows. Anything else is invalid for every flow.
func CallbackStateFromRawQuery(rawQuery string) (CallbackStateKind, string) {
	if len(rawQuery) > testSignInMaxRawQueryBytes {
		return CallbackStateInvalid, ""
	}
	values, valid := knownAuthorizationResponseValues(rawQuery, true)
	if !valid || len(values.state) != 1 {
		return CallbackStateInvalid, ""
	}
	state := values.state[0]
	switch {
	case canonicalTestToken(state):
		return CallbackStateTest, state
	case canonicalPrefixedState(state, linkStatePrefix):
		return CallbackStateLink, state
	case canonicalPrefixedState(state, loginStatePrefix):
		return CallbackStateLogin, state
	}
	return CallbackStateInvalid, ""
}

func canonicalPrefixedState(state, prefix string) bool {
	token, found := strings.CutPrefix(state, prefix)
	return found && canonicalTestToken(token)
}

type LinkStartInput struct {
	ActorUserID      int64
	SessionID        string
	ExpectedRevision int64
	CallbackURI      string
}

type LinkStart struct {
	AuthorizationURL string
}

type LinkCallbackInput struct {
	State     string
	SessionID string
	RawQuery  string
}

type linkTransactionRecord struct {
	configRevision       int64
	activationGeneration int64
	actorUserID          int64
	sessionBindingDigest [sha256.Size]byte
	nonceDigest          [sha256.Size]byte
	pkceCiphertext       []byte
	tokenEndpoint        string
	jwksURI              string
	redirectURI          string
	createdAt            time.Time
	expiresAt            time.Time
}

type linkClaim struct {
	actorUserID            int64
	sessionID              string
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
}

// StartLink begins linking the acting Administrator's company identity. The
// caller has already verified the current password; this rechecks actor,
// session, readiness evidence, disabled state, and identity absence, then
// stores a one-time transaction bound to the exact session, revision, and
// activation generation.
func (s *Service) StartLink(ctx context.Context, input LinkStartInput) (LinkStart, error) {
	if s == nil || s.db == nil {
		return LinkStart{}, ErrLinkUnavailable
	}
	if input.ActorUserID <= 0 || input.ExpectedRevision <= 0 || !validTestSessionID(input.SessionID) {
		return LinkStart{}, ErrLinkAuthorization
	}
	if s.secrets == nil {
		return LinkStart{}, ErrConfiguration
	}
	if s.checker == nil || !s.validTestSignInRedirectURI(input.CallbackURI) {
		return LinkStart{}, ErrLinkUnavailable
	}

	connection, found, err := s.Current(ctx)
	if err != nil || !found || connection.Revision != input.ExpectedRevision ||
		connection.Enabled || connection.Identity != nil ||
		connection.SetupCheck == nil || connection.SetupCheck.ResultCode != SetupCheckVerified ||
		connection.TestSignInEvidence == nil {
		return LinkStart{}, ErrLinkUnavailable
	}

	providerCtx, cancel := context.WithTimeout(ctx, testSignInProviderTimeout)
	discovery := s.checker.discover(providerCtx, connection.Issuer, true)
	cancel()
	if discovery.resultCode != SetupCheckVerified {
		if discovery.resultCode == SetupCheckDiscoveryUnavailable {
			return LinkStart{}, ErrTestProviderUnavailable
		}
		return LinkStart{}, ErrTestProviderInvalid
	}
	authorizationEndpoint, err := prepareAuthorizationEndpoint(discovery.metadata.authorizationEndpoint)
	if err != nil {
		return LinkStart{}, ErrTestProviderInvalid
	}

	initiation, err := s.prepareLink(ctx, linkInitiationInput{
		actorUserID:      input.ActorUserID,
		sessionID:        input.SessionID,
		expectedRevision: input.ExpectedRevision,
		tokenEndpoint:    discovery.metadata.tokenEndpoint,
		jwksURI:          discovery.metadata.jwksURI,
		redirectURI:      input.CallbackURI,
	})
	if err != nil {
		return LinkStart{}, err
	}

	values := authorizationEndpoint.Query()
	values.Set("scope", "openid email")
	values.Set("response_type", "code")
	values.Set("response_mode", "query")
	values.Set("client_id", initiation.clientID)
	values.Set("redirect_uri", input.CallbackURI)
	values.Set("state", linkStatePrefix+initiation.state)
	values.Set("nonce", initiation.nonce)
	values.Set("code_challenge", initiation.pkceChallenge)
	values.Set("code_challenge_method", "S256")
	authorizationEndpoint.RawQuery = values.Encode()

	return LinkStart{AuthorizationURL: authorizationEndpoint.String()}, nil
}

type linkInitiationInput struct {
	actorUserID      int64
	sessionID        string
	expectedRevision int64
	tokenEndpoint    string
	jwksURI          string
	redirectURI      string
}

type linkInitiation struct {
	state         string
	nonce         string
	pkceChallenge string
	clientID      string
}

func (s *Service) prepareLink(ctx context.Context, input linkInitiationInput) (linkInitiation, error) {
	if !validHTTPSProviderURL(input.tokenEndpoint) || !validHTTPSProviderURL(input.jwksURI) ||
		!s.validTestSignInRedirectURI(input.redirectURI) {
		return linkInitiation{}, ErrLinkUnavailable
	}
	material, err := newTestSignInMaterial(s.random)
	if err != nil {
		return linkInitiation{}, errors.New("prepare company OIDC link material")
	}
	verifierCiphertext, err := encryptTestSignInVerifier(ctx, s.secrets, material.pkceVerifier)
	if err != nil {
		return linkInitiation{}, err
	}

	sessionDigest := testSignInDigest(linkSessionDigestPurpose, input.sessionID)
	stateDigest := testSignInDigest(linkStateDigestPurpose, material.state)
	nonceDigest := testSignInDigest(linkNonceDigestPurpose, material.nonce)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return linkInitiation{}, errors.New("begin company OIDC link initiation")
	}
	defer tx.Rollback()

	if err := lockEnabledAdminActor(ctx, tx, input.actorUserID); err != nil {
		if errors.Is(err, ErrAuthorization) {
			return linkInitiation{}, ErrLinkAuthorization
		}
		return linkInitiation{}, errors.New("authorize company OIDC link initiation")
	}
	now := s.now().UTC()
	authorized, err := currentCredentialedSession(ctx, tx, input.actorUserID, input.sessionID, now)
	if err != nil {
		return linkInitiation{}, errors.New("authorize company OIDC link session")
	}
	if !authorized {
		return linkInitiation{}, ErrLinkAuthorization
	}
	if err := cleanupExpiredLinkTransactions(ctx, tx, now); err != nil {
		return linkInitiation{}, errors.New("clean expired company OIDC link transactions")
	}

	snapshot, found, err := loadActivationSnapshot(ctx, tx)
	if err != nil {
		return linkInitiation{}, ErrLinkUnavailable
	}
	if !found {
		return linkInitiation{}, ErrNoDraft
	}
	if snapshot.record.Revision != input.expectedRevision || snapshot.record.Enabled ||
		snapshot.record.Identity != nil || !snapshot.readyEvidence() {
		return linkInitiation{}, ErrLinkUnavailable
	}

	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM company_oidc_link_transactions WHERE session_binding_digest = ?`,
		sessionDigest[:],
	); err != nil {
		return linkInitiation{}, errors.New("replace company OIDC link transaction")
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_link_transactions(
  state_digest, connection_id, config_revision, activation_generation,
  actor_user_id, session_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
)
VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stateDigest[:],
		snapshot.record.Revision,
		snapshot.record.ActivationGeneration,
		input.actorUserID,
		sessionDigest[:],
		nonceDigest[:],
		verifierCiphertext,
		input.tokenEndpoint,
		input.jwksURI,
		input.redirectURI,
		formatCompanyOIDCTime(now),
		formatCompanyOIDCTime(now.Add(testSignInTransactionTTL)),
	); err != nil {
		return linkInitiation{}, errors.New("store company OIDC link transaction")
	}
	if err := tx.Commit(); err != nil {
		return linkInitiation{}, ErrLinkOutcomeUnknown
	}

	return linkInitiation{
		state:         material.state,
		nonce:         material.nonce,
		pkceChallenge: material.pkceChallenge,
		clientID:      snapshot.record.ClientID,
	}, nil
}

// CompleteLink consumes the one-time link transaction for the callback,
// redeems the authorization code, and commits the linked identity
// atomically with its audit event. Non-verified provider outcomes report a
// result code without touching the identity table.
func (s *Service) CompleteLink(ctx context.Context, input LinkCallbackInput) (TestSignInResultCode, error) {
	token, found := strings.CutPrefix(input.State, linkStatePrefix)
	if !found || !canonicalTestToken(token) {
		return "", ErrLinkUnavailable
	}
	claim, err := s.claimLink(ctx, token, input.SessionID)
	if err != nil {
		return "", err
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
			nonceDigestPurpose:     linkNonceDigestPurpose,
			createdAt:              claim.createdAt,
			domains:                claim.domains,
		}, response.code)
	}
	if result != TestSignInVerified {
		return result, nil
	}
	if err := s.commitLink(ctx, claim, verified); err != nil {
		return "", err
	}
	return TestSignInVerified, nil
}

func (s *Service) claimLink(ctx context.Context, token, sessionID string) (linkClaim, error) {
	if s == nil || s.db == nil {
		return linkClaim{}, ErrLinkUnavailable
	}

	stateDigest := testSignInDigest(linkStateDigestPurpose, token)
	sessionValid := validTestSessionID(sessionID)
	var sessionDigest [sha256.Size]byte
	if sessionValid {
		sessionDigest = testSignInDigest(linkSessionDigestPurpose, sessionID)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return linkClaim{}, ErrLinkUnavailable
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE company_oidc_link_transactions SET state_digest = state_digest WHERE state_digest = ?`,
		stateDigest[:],
	); err != nil {
		return linkClaim{}, ErrLinkUnavailable
	}
	now := s.now().UTC()
	if err := cleanupExpiredLinkTransactions(ctx, tx, now); err != nil {
		return linkClaim{}, ErrLinkUnavailable
	}
	record, found, err := loadLinkTransaction(ctx, tx, stateDigest)
	if err != nil {
		if found {
			return linkClaim{}, consumeLinkTransaction(ctx, tx, stateDigest)
		}
		return linkClaim{}, ErrLinkUnavailable
	}
	if !found {
		if err := tx.Commit(); err != nil {
			return linkClaim{}, ErrLinkOutcomeUnknown
		}
		return linkClaim{}, ErrLinkUnavailable
	}

	if !sessionValid || !now.Before(record.expiresAt) || subtle.ConstantTimeCompare(
		sessionDigest[:],
		record.sessionBindingDigest[:],
	) != 1 {
		return linkClaim{}, consumeLinkTransaction(ctx, tx, stateDigest)
	}
	if err := lockEnabledAdminActor(ctx, tx, record.actorUserID); err != nil {
		if errors.Is(err, ErrAuthorization) {
			return linkClaim{}, consumeLinkTransaction(ctx, tx, stateDigest)
		}
		return linkClaim{}, ErrLinkUnavailable
	}
	authorized, err := currentCredentialedSession(ctx, tx, record.actorUserID, sessionID, now)
	if err != nil {
		return linkClaim{}, ErrLinkUnavailable
	}
	if !authorized {
		return linkClaim{}, consumeLinkTransaction(ctx, tx, stateDigest)
	}
	snapshot, snapshotFound, err := loadActivationSnapshot(ctx, tx)
	if err != nil {
		return linkClaim{}, ErrLinkUnavailable
	}
	if !snapshotFound || snapshot.record.Enabled || snapshot.record.Identity != nil ||
		snapshot.record.Revision != record.configRevision ||
		snapshot.record.ActivationGeneration != record.activationGeneration ||
		!snapshot.readyEvidence() {
		return linkClaim{}, consumeLinkTransaction(ctx, tx, stateDigest)
	}
	if err := deleteLinkTransaction(ctx, tx, stateDigest); err != nil {
		return linkClaim{}, ErrLinkUnavailable
	}
	if err := tx.Commit(); err != nil {
		return linkClaim{}, ErrLinkOutcomeUnknown
	}
	return linkClaim{
		actorUserID:            record.actorUserID,
		sessionID:              sessionID,
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
	}, nil
}

func (s *Service) commitLink(ctx context.Context, claim linkClaim, verified verifiedIDToken) error {
	if !validOIDCSubject(verified.subject) || !validLinkedIdentityEmail(verified.email) {
		return ErrLinkUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrLinkUnavailable
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, claim.actorUserID); err != nil {
		return ErrLinkUnavailable
	}
	now := s.now().UTC()
	current, err := currentCredentialedSession(ctx, tx, claim.actorUserID, claim.sessionID, now)
	if err != nil || !current {
		return ErrLinkUnavailable
	}
	snapshot, found, err := loadActivationSnapshot(ctx, tx)
	if err != nil || !found || snapshot.record.Enabled || snapshot.record.Identity != nil ||
		snapshot.record.Revision != claim.configRevision ||
		snapshot.record.ActivationGeneration != claim.activationGeneration ||
		snapshot.record.Issuer != claim.issuer || snapshot.record.ClientID != claim.clientID ||
		!bytes.Equal(snapshot.record.ClientSecretCiphertext, claim.clientSecretCiphertext) ||
		!slices.Equal(snapshot.record.Domains, claim.domains) ||
		!snapshot.readyEvidence() {
		return ErrLinkUnavailable
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_identities(
  connection_id, user_id, issuer, client_id, subject, email, config_revision, linked_at
)
VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
		claim.actorUserID,
		snapshot.record.Issuer,
		snapshot.record.ClientID,
		verified.subject,
		verified.email,
		snapshot.record.Revision,
		formatCompanyOIDCTime(now),
	); err != nil {
		return ErrLinkUnavailable
	}
	if err := incrementActivationGeneration(ctx, tx, snapshot.record.ActivationGeneration); err != nil {
		return ErrLinkUnavailable
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_link_transactions`); err != nil {
		return ErrLinkUnavailable
	}
	actor := claim.actorUserID
	if err := recordActivationChange(
		ctx, tx, &actor, audit.ActionOIDCIdentityLinked, snapshot.record.Revision, "",
	); err != nil {
		return ErrLinkUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrLinkOutcomeUnknown
	}
	return nil
}

type UnlinkInput struct {
	ActorUserID      int64
	SessionID        string
	ExpectedRevision int64
}

// Unlink removes the acting Administrator's own linked identity. The
// connection must already be disabled; the caller has already verified the
// current password. Pending link and login transactions are deleted and the
// actor's OIDC-provenance sessions revoked in the same transaction.
func (s *Service) Unlink(ctx context.Context, input UnlinkInput) error {
	if s == nil || s.db == nil {
		return errors.New("company OIDC service has no database")
	}
	if input.ActorUserID <= 0 || !validTestSessionID(input.SessionID) {
		return ErrLinkAuthorization
	}
	if input.ExpectedRevision <= 0 {
		return ErrConflict
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin company OIDC unlink: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, input.ActorUserID); err != nil {
		if errors.Is(err, ErrAuthorization) {
			return ErrLinkAuthorization
		}
		return err
	}
	now := s.now().UTC()
	authorized, err := currentCredentialedSession(ctx, tx, input.ActorUserID, input.SessionID, now)
	if err != nil {
		return fmt.Errorf("authorize company OIDC unlink session: %w", err)
	}
	if !authorized {
		return ErrLinkAuthorization
	}
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return err
	}
	if !found || record.Revision != input.ExpectedRevision {
		return ErrConflict
	}
	if record.Enabled {
		return ErrEnabled
	}
	if record.Identity == nil || record.Identity.userID != input.ActorUserID {
		return ErrConflict
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM company_oidc_identities WHERE connection_id = 1 AND user_id = ?`,
		input.ActorUserID,
	)
	if err != nil {
		return fmt.Errorf("delete company OIDC linked identity: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count deleted company OIDC linked identities: %w", err)
	}
	if deleted != 1 {
		return fmt.Errorf("delete company OIDC linked identity affected %d rows", deleted)
	}
	if err := incrementActivationGeneration(ctx, tx, record.ActivationGeneration); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_link_transactions`); err != nil {
		return fmt.Errorf("delete pending company OIDC link transactions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_login_transactions`); err != nil {
		return fmt.Errorf("delete pending company OIDC login transactions: %w", err)
	}
	if err := revokeUserCompanyOIDCSessions(ctx, tx, input.ActorUserID); err != nil {
		return err
	}
	actor := input.ActorUserID
	if err := recordActivationChange(
		ctx, tx, &actor, audit.ActionOIDCIdentityUnlinked, record.Revision, "administrator",
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

func loadLinkTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) (linkTransactionRecord, bool, error) {
	var record linkTransactionRecord
	var sessionDigest, nonceDigest []byte
	var createdAt, expiresAt string
	err := tx.QueryRowContext(ctx, `
SELECT config_revision, activation_generation, actor_user_id, session_binding_digest,
  nonce_digest, pkce_verifier_ciphertext, token_endpoint, jwks_uri, redirect_uri,
  created_at, expires_at
FROM company_oidc_link_transactions
WHERE state_digest = ?`, stateDigest[:]).Scan(
		&record.configRevision,
		&record.activationGeneration,
		&record.actorUserID,
		&sessionDigest,
		&nonceDigest,
		&record.pkceCiphertext,
		&record.tokenEndpoint,
		&record.jwksURI,
		&record.redirectURI,
		&createdAt,
		&expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return linkTransactionRecord{}, false, nil
	}
	if err != nil {
		return linkTransactionRecord{}, false, err
	}
	if record.configRevision <= 0 || record.activationGeneration <= 0 || record.actorUserID <= 0 ||
		len(sessionDigest) != sha256.Size || len(nonceDigest) != sha256.Size ||
		len(record.pkceCiphertext) < 1 || len(record.pkceCiphertext) > testSignInMaxCiphertext ||
		!validHTTPSProviderURL(record.tokenEndpoint) || !validHTTPSProviderURL(record.jwksURI) ||
		!validTestSignInRedirectURI(record.redirectURI) {
		return linkTransactionRecord{}, true, errors.New("company OIDC link transaction is malformed")
	}
	copy(record.sessionBindingDigest[:], sessionDigest)
	copy(record.nonceDigest[:], nonceDigest)
	record.createdAt, err = parseCompanyOIDCTime(createdAt)
	if err != nil {
		return linkTransactionRecord{}, true, errors.New("company OIDC link transaction is malformed")
	}
	record.expiresAt, err = parseCompanyOIDCTime(expiresAt)
	if err != nil || !record.expiresAt.After(record.createdAt) {
		return linkTransactionRecord{}, true, errors.New("company OIDC link transaction is malformed")
	}
	return record, true, nil
}

func cleanupExpiredLinkTransactions(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
DELETE FROM company_oidc_link_transactions
WHERE state_digest IN (
  SELECT state_digest
  FROM company_oidc_link_transactions
  WHERE expires_at <= ?
  ORDER BY expires_at, state_digest
  LIMIT ?
)`, formatCompanyOIDCTime(now), testSignInCleanupLimit)
	return err
}

func consumeLinkTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) error {
	if err := deleteLinkTransaction(ctx, tx, stateDigest); err != nil {
		return ErrLinkUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrLinkOutcomeUnknown
	}
	return ErrLinkUnavailable
}

func deleteLinkTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) error {
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM company_oidc_link_transactions WHERE state_digest = ?`,
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
		return fmt.Errorf("delete company OIDC link transaction affected %d rows", deleted)
	}
	return nil
}
