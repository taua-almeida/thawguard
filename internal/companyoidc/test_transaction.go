package companyoidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

const (
	testSignInTokenBytes       = 32
	testSignInTransactionTTL   = 10 * time.Minute
	testSignInCleanupLimit     = 100
	testSignInMaxSessionIDSize = 512
	testSignInMaxCiphertext    = 512

	testSignInStateDigestPurpose   = "thawguard:company-oidc-test-state:v1"
	testSignInNonceDigestPurpose   = "thawguard:company-oidc-test-nonce:v1"
	testSignInSessionDigestPurpose = "thawguard:company-oidc-test-session:v1"
)

var (
	ErrTestSignInUnavailable         = errors.New("company OIDC Test sign-in is not available for the saved Draft")
	ErrTestSignInAuthorization       = errors.New("company OIDC Test sign-in requires a current enabled Administrator session")
	ErrTestTransactionUnavailable    = errors.New("company OIDC Test sign-in transaction is unavailable")
	ErrTestTransactionOutcomeUnknown = errors.New("company OIDC Test sign-in transaction outcome could not be confirmed")

	errMalformedTestSignInSnapshot = errors.New("company OIDC Test sign-in snapshot is malformed")
)

type TestSignInInitiationInput struct {
	ActorUserID      int64
	SessionID        string
	ExpectedRevision int64
	TokenEndpoint    string
	JWKSURI          string
	RedirectURI      string
}

type TestSignInInitiation struct {
	State         string
	Nonce         string
	PKCEChallenge string
	Issuer        string
	ClientID      string
}

type testSignInClaimInput struct {
	State     string
	SessionID string
}

type testSignInClaim struct {
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
	createdAt              time.Time
	domains                []string
}

type testSignInMaterial struct {
	state         string
	nonce         string
	pkceVerifier  string
	pkceChallenge string
}

type testSignInSnapshot struct {
	issuer                 string
	clientID               string
	clientSecretCiphertext []byte
	revision               int64
	ready                  bool
}

type testTransactionRecord struct {
	configRevision       int64
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

func (s *Service) prepareTestSignIn(
	ctx context.Context,
	input TestSignInInitiationInput,
) (TestSignInInitiation, error) {
	if s == nil || s.db == nil {
		return TestSignInInitiation{}, errors.New("company OIDC service has no database")
	}
	if s.secrets == nil {
		return TestSignInInitiation{}, ErrConfiguration
	}
	if input.ActorUserID <= 0 || input.ExpectedRevision <= 0 || !validTestSessionID(input.SessionID) {
		return TestSignInInitiation{}, ErrTestSignInAuthorization
	}
	if !validHTTPSProviderURL(input.TokenEndpoint) || !validHTTPSProviderURL(input.JWKSURI) ||
		!s.validTestSignInRedirectURI(input.RedirectURI) {
		return TestSignInInitiation{}, ErrTestSignInUnavailable
	}

	material, err := newTestSignInMaterial(s.random)
	if err != nil {
		return TestSignInInitiation{}, errors.New("prepare company OIDC Test sign-in material")
	}
	verifierCiphertext, err := encryptTestSignInVerifier(ctx, s.secrets, material.pkceVerifier)
	if err != nil {
		return TestSignInInitiation{}, err
	}

	sessionDigest := testSessionBindingDigest(input.SessionID)
	stateDigest := testSignInDigest(testSignInStateDigestPurpose, material.state)
	nonceDigest := testSignInDigest(testSignInNonceDigestPurpose, material.nonce)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TestSignInInitiation{}, errors.New("begin company OIDC Test sign-in initiation")
	}
	defer tx.Rollback()

	if err := lockEnabledAdminActor(ctx, tx, input.ActorUserID); err != nil {
		if errors.Is(err, ErrAuthorization) {
			return TestSignInInitiation{}, ErrTestSignInAuthorization
		}
		return TestSignInInitiation{}, errors.New("authorize company OIDC Test sign-in initiation")
	}
	now := s.now().UTC()
	authorized, err := currentTestSession(ctx, tx, input.ActorUserID, input.SessionID, now)
	if err != nil {
		return TestSignInInitiation{}, errors.New("authorize company OIDC Test sign-in session")
	}
	if !authorized {
		return TestSignInInitiation{}, ErrTestSignInAuthorization
	}
	if err := cleanupExpiredTestTransactions(ctx, tx, now); err != nil {
		return TestSignInInitiation{}, errors.New("clean expired company OIDC Test sign-in transactions")
	}

	snapshot, found, err := loadTestSignInSnapshot(ctx, tx)
	if err != nil {
		return TestSignInInitiation{}, ErrTestSignInUnavailable
	}
	if !found {
		return TestSignInInitiation{}, ErrNoDraft
	}
	if !snapshot.ready || snapshot.revision != input.ExpectedRevision {
		return TestSignInInitiation{}, ErrTestSignInUnavailable
	}

	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM company_oidc_test_transactions WHERE session_binding_digest = ?`,
		sessionDigest[:],
	); err != nil {
		return TestSignInInitiation{}, errors.New("replace company OIDC Test sign-in transaction")
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_test_transactions(
  state_digest, connection_id, config_revision, actor_user_id,
  session_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
)
VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stateDigest[:],
		snapshot.revision,
		input.ActorUserID,
		sessionDigest[:],
		nonceDigest[:],
		verifierCiphertext,
		input.TokenEndpoint,
		input.JWKSURI,
		input.RedirectURI,
		formatCompanyOIDCTime(now),
		formatCompanyOIDCTime(now.Add(testSignInTransactionTTL)),
	); err != nil {
		return TestSignInInitiation{}, errors.New("store company OIDC Test sign-in transaction")
	}
	if err := tx.Commit(); err != nil {
		return TestSignInInitiation{}, ErrTestTransactionOutcomeUnknown
	}

	return TestSignInInitiation{
		State:         material.state,
		Nonce:         material.nonce,
		PKCEChallenge: material.pkceChallenge,
		Issuer:        snapshot.issuer,
		ClientID:      snapshot.clientID,
	}, nil
}

func (s *Service) claimTestSignIn(
	ctx context.Context,
	input testSignInClaimInput,
) (testSignInClaim, error) {
	if s == nil || s.db == nil {
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	if !canonicalTestToken(input.State) {
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}

	stateDigest := testSignInDigest(testSignInStateDigestPurpose, input.State)
	sessionValid := validTestSessionID(input.SessionID)
	var sessionDigest [sha256.Size]byte
	if sessionValid {
		sessionDigest = testSessionBindingDigest(input.SessionID)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE company_oidc_test_transactions SET state_digest = state_digest WHERE state_digest = ?`,
		stateDigest[:],
	); err != nil {
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	now := s.now().UTC()
	if err := cleanupExpiredTestTransactions(ctx, tx, now); err != nil {
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	record, found, err := loadTestTransaction(ctx, tx, stateDigest)
	if err != nil {
		if found {
			return testSignInClaim{}, consumeTestTransaction(ctx, tx, stateDigest)
		}
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	if !found {
		if err := tx.Commit(); err != nil {
			return testSignInClaim{}, ErrTestTransactionOutcomeUnknown
		}
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}

	if !sessionValid || !now.Before(record.expiresAt) || subtle.ConstantTimeCompare(
		sessionDigest[:],
		record.sessionBindingDigest[:],
	) != 1 {
		return testSignInClaim{}, consumeTestTransaction(ctx, tx, stateDigest)
	}
	if err := lockEnabledAdminActor(ctx, tx, record.actorUserID); err != nil {
		if errors.Is(err, ErrAuthorization) {
			return testSignInClaim{}, consumeTestTransaction(ctx, tx, stateDigest)
		}
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	authorized, err := currentTestSession(ctx, tx, record.actorUserID, input.SessionID, now)
	if err != nil {
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	if !authorized {
		return testSignInClaim{}, consumeTestTransaction(ctx, tx, stateDigest)
	}
	snapshot, found, err := loadTestSignInSnapshot(ctx, tx)
	if err != nil {
		if errors.Is(err, errMalformedTestSignInSnapshot) {
			return testSignInClaim{}, consumeTestTransaction(ctx, tx, stateDigest)
		}
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	if !found || !snapshot.ready || snapshot.revision != record.configRevision {
		return testSignInClaim{}, consumeTestTransaction(ctx, tx, stateDigest)
	}
	domains, err := loadTestSignInDomains(ctx, tx)
	if err != nil {
		if errors.Is(err, errMalformedTestSignInSnapshot) {
			return testSignInClaim{}, consumeTestTransaction(ctx, tx, stateDigest)
		}
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	if err := deleteTestTransaction(ctx, tx, stateDigest); err != nil {
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	if err := recordTestSignInClaimed(ctx, tx, record.actorUserID, record.configRevision); err != nil {
		return testSignInClaim{}, ErrTestTransactionUnavailable
	}
	if err := tx.Commit(); err != nil {
		return testSignInClaim{}, ErrTestTransactionOutcomeUnknown
	}
	return testSignInClaim{
		actorUserID:            record.actorUserID,
		sessionID:              input.SessionID,
		issuer:                 snapshot.issuer,
		clientID:               snapshot.clientID,
		clientSecretCiphertext: snapshot.clientSecretCiphertext,
		pkceCiphertext:         record.pkceCiphertext,
		tokenEndpoint:          record.tokenEndpoint,
		jwksURI:                record.jwksURI,
		redirectURI:            record.redirectURI,
		nonceDigest:            record.nonceDigest,
		configRevision:         snapshot.revision,
		createdAt:              record.createdAt,
		domains:                domains,
	}, nil
}

func newTestSignInMaterial(random io.Reader) (testSignInMaterial, error) {
	state, err := randomTestToken(random)
	if err != nil {
		return testSignInMaterial{}, err
	}
	nonce, err := randomTestToken(random)
	if err != nil {
		return testSignInMaterial{}, err
	}
	verifier, err := randomTestToken(random)
	if err != nil {
		return testSignInMaterial{}, err
	}
	return testSignInMaterial{
		state:         state,
		nonce:         nonce,
		pkceVerifier:  verifier,
		pkceChallenge: pkceS256Challenge(verifier),
	}, nil
}

func randomTestToken(random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("company OIDC Test sign-in random source is unavailable")
	}
	value := make([]byte, testSignInTokenBytes)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func canonicalTestToken(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(testSignInTokenBytes) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == testSignInTokenBytes && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func pkceS256Challenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func testSessionBindingDigest(sessionID string) [sha256.Size]byte {
	return testSignInDigest(testSignInSessionDigestPurpose, sessionID)
}

func testSignInDigest(purpose, value string) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(purpose))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(value))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func validTestSessionID(sessionID string) bool {
	return len(sessionID) > 0 && len(sessionID) <= testSignInMaxSessionIDSize
}

func encryptTestSignInVerifier(
	ctx context.Context,
	store secrets.Store,
	verifier string,
) ([]byte, error) {
	plaintext := []byte(verifier)
	defer clear(plaintext)
	ciphertext, err := store.Encrypt(ctx, plaintext)
	if err != nil || len(ciphertext) < 1 || len(ciphertext) > testSignInMaxCiphertext {
		return nil, errors.New("encrypt company OIDC Test sign-in verifier")
	}
	return ciphertext, nil
}

func currentTestSession(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	sessionID string,
	now time.Time,
) (bool, error) {
	var userID int64
	var hasCSRF int
	var expiresAt string
	var mustChangePassword sql.NullInt64
	err := tx.QueryRowContext(ctx, `
SELECT s.user_id, s.csrf_token != '', s.expires_at, lc.must_change_password
FROM sessions s
LEFT JOIN local_credentials lc ON lc.user_id = s.user_id
WHERE s.id = ?`, sessionID).Scan(&userID, &hasCSRF, &expiresAt, &mustChangePassword)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	parsedExpiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return false, nil
	}
	forced := mustChangePassword.Valid && mustChangePassword.Int64 != 0
	return userID == actorUserID && hasCSRF == 1 && now.Before(parsedExpiry.UTC()) && !forced, nil
}

// currentCredentialedSession is currentTestSession restricted to users who
// hold a local credential: the INNER JOIN requires the credential row to
// exist, so a user without a local password never passes.
func currentCredentialedSession(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	sessionID string,
	now time.Time,
) (bool, error) {
	var userID int64
	var hasCSRF int
	var expiresAt string
	var mustChangePassword int64
	err := tx.QueryRowContext(ctx, `
SELECT s.user_id, s.csrf_token != '', s.expires_at, lc.must_change_password
FROM sessions s
JOIN local_credentials lc ON lc.user_id = s.user_id
WHERE s.id = ?`, sessionID).Scan(&userID, &hasCSRF, &expiresAt, &mustChangePassword)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	parsedExpiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return false, nil
	}
	return userID == actorUserID && hasCSRF == 1 && now.Before(parsedExpiry.UTC()) &&
		mustChangePassword == 0, nil
}

func loadTestSignInSnapshot(
	ctx context.Context,
	tx *sql.Tx,
) (testSignInSnapshot, bool, error) {
	var snapshot testSignInSnapshot
	var enabled int64
	var checkRevision sql.NullInt64
	var resultCode sql.NullString
	var observedIssuer, checkedAt sql.NullString
	var candidateCount sql.NullInt64
	err := tx.QueryRowContext(ctx, `
SELECT c.issuer, c.client_id, c.client_secret_ciphertext, c.revision, c.enabled,
  sc.config_revision, sc.result_code, sc.observed_issuer,
  sc.public_key_candidate_count, sc.checked_at
FROM company_oidc_connections c
LEFT JOIN company_oidc_setup_checks sc ON sc.connection_id = c.id
WHERE c.id = 1`).Scan(
		&snapshot.issuer,
		&snapshot.clientID,
		&snapshot.clientSecretCiphertext,
		&snapshot.revision,
		&enabled,
		&checkRevision,
		&resultCode,
		&observedIssuer,
		&candidateCount,
		&checkedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return testSignInSnapshot{}, false, nil
	}
	if err != nil {
		return testSignInSnapshot{}, false, err
	}
	issuer, issuerErr := normalizeIssuer(snapshot.issuer)
	clientID, clientIDErr := normalizeClientID(snapshot.clientID)
	if issuerErr != nil || issuer != snapshot.issuer || clientIDErr != nil || clientID != snapshot.clientID ||
		len(snapshot.clientSecretCiphertext) == 0 || len(snapshot.clientSecretCiphertext) > 8192 ||
		snapshot.revision <= 0 || enabled < 0 || enabled > 1 {
		return testSignInSnapshot{}, true, errMalformedTestSignInSnapshot
	}
	if !checkRevision.Valid && !resultCode.Valid && !observedIssuer.Valid && !candidateCount.Valid && !checkedAt.Valid {
		return snapshot, true, nil
	}
	if !checkRevision.Valid || !resultCode.Valid || !checkedAt.Valid {
		return testSignInSnapshot{}, true, errMalformedTestSignInSnapshot
	}
	checkedTime, err := parseCompanyOIDCTime(checkedAt.String)
	if err != nil {
		return testSignInSnapshot{}, true, errMalformedTestSignInSnapshot
	}
	check := SetupCheck{
		ConfigRevision: checkRevision.Int64,
		ResultCode:     SetupCheckResultCode(resultCode.String),
		CheckedAt:      checkedTime,
	}
	if observedIssuer.Valid {
		check.ObservedIssuer = &observedIssuer.String
	}
	if candidateCount.Valid {
		check.PublicKeyCandidateCount = &candidateCount.Int64
	}
	if err := validateSetupCheck(check, snapshot.issuer, snapshot.revision); err != nil {
		return testSignInSnapshot{}, true, errMalformedTestSignInSnapshot
	}
	snapshot.ready = check.ResultCode == SetupCheckVerified && enabled == 0
	return snapshot, true, nil
}

// loadTestSignInDomains reads the complete allowed-domain policy inside the
// caller's transaction, in deterministic order. The claim keeps this in-memory
// snapshot only; completion reloads and compares it so a same-revision domain
// edit fails the final fence.
func loadTestSignInDomains(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT domain
FROM company_oidc_allowed_domains
WHERE connection_id = 1
ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(domains) < 1 || len(domains) > 20 {
		return nil, errMalformedTestSignInSnapshot
	}
	for i, domain := range domains {
		if validateDomain(domain) != nil || (i > 0 && domains[i-1] >= domain) {
			return nil, errMalformedTestSignInSnapshot
		}
	}
	return domains, nil
}

func loadTestTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) (testTransactionRecord, bool, error) {
	var record testTransactionRecord
	var sessionDigest, nonceDigest []byte
	var createdAt, expiresAt string
	err := tx.QueryRowContext(ctx, `
SELECT config_revision, actor_user_id, session_binding_digest, nonce_digest,
  pkce_verifier_ciphertext, token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
FROM company_oidc_test_transactions
WHERE state_digest = ?`, stateDigest[:]).Scan(
		&record.configRevision,
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
		return testTransactionRecord{}, false, nil
	}
	if err != nil {
		return testTransactionRecord{}, false, err
	}
	if record.configRevision <= 0 || record.actorUserID <= 0 ||
		len(sessionDigest) != sha256.Size || len(nonceDigest) != sha256.Size ||
		len(record.pkceCiphertext) < 1 || len(record.pkceCiphertext) > testSignInMaxCiphertext ||
		!validHTTPSProviderURL(record.tokenEndpoint) || !validHTTPSProviderURL(record.jwksURI) ||
		!validTestSignInRedirectURI(record.redirectURI) {
		return testTransactionRecord{}, true, errors.New("company OIDC Test sign-in transaction is malformed")
	}
	copy(record.sessionBindingDigest[:], sessionDigest)
	copy(record.nonceDigest[:], nonceDigest)
	record.createdAt, err = parseCompanyOIDCTime(createdAt)
	if err != nil {
		return testTransactionRecord{}, true, errors.New("company OIDC Test sign-in transaction is malformed")
	}
	record.expiresAt, err = parseCompanyOIDCTime(expiresAt)
	if err != nil || !record.expiresAt.After(record.createdAt) {
		return testTransactionRecord{}, true, errors.New("company OIDC Test sign-in transaction is malformed")
	}
	return record, true, nil
}

func recordTestSignInClaimed(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	revision int64,
) error {
	details, err := json.Marshal(struct {
		Revision  int64  `json:"revision"`
		Binding   string `json:"binding"`
		Authority string `json:"authority"`
	}{
		Revision:  revision,
		Binding:   "exact_session",
		Authority: "current_administrator",
	})
	if err != nil {
		return errors.New("encode company OIDC Test sign-in claimed audit evidence")
	}
	actor := actorUserID
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      audit.ActionOIDCConnectionTestSignInClaimed,
		SubjectType: audit.SubjectTypeOIDCConnection,
		SubjectID:   fmt.Sprintf("%d", singletonConnectionID),
		DetailsJSON: string(details),
	}); err != nil {
		return errors.New("record company OIDC Test sign-in claimed audit event")
	}
	return nil
}

func cleanupExpiredTestTransactions(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
DELETE FROM company_oidc_test_transactions
WHERE state_digest IN (
  SELECT state_digest
  FROM company_oidc_test_transactions
  WHERE expires_at <= ?
  ORDER BY expires_at, state_digest
  LIMIT ?
)`, formatCompanyOIDCTime(now), testSignInCleanupLimit)
	return err
}

func consumeTestTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) error {
	if err := deleteTestTransaction(ctx, tx, stateDigest); err != nil {
		return ErrTestTransactionUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrTestTransactionOutcomeUnknown
	}
	return ErrTestTransactionUnavailable
}

func deleteTestTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) error {
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM company_oidc_test_transactions WHERE state_digest = ?`,
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
		return fmt.Errorf("delete company OIDC Test sign-in transaction affected %d rows", deleted)
	}
	return nil
}
