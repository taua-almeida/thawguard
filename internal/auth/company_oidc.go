package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

type CreateCompanyOIDCSessionParams struct {
	UserID int64
	// ConnectionRevision and ActivationGeneration are the fences the login
	// transaction was created against; session creation requires the enabled
	// connection to still match both exactly.
	ConnectionRevision   int64
	ActivationGeneration int64
}

// VerifyCurrentPassword checks the given password against the user's local
// credential. It reports the generic authentication failure when the account
// has no credential or the password does not match.
func (s *Service) VerifyCurrentPassword(ctx context.Context, userID int64, password string) error {
	if s == nil || s.db == nil {
		return errors.New("auth service has no database")
	}
	if userID <= 0 || password == "" {
		return AuthenticationError{}
	}
	record, err := s.userByID(ctx, s.db, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthenticationError{}
	}
	if err != nil {
		return fmt.Errorf("load user for password verification: %w", err)
	}
	if !record.HasLocalPassword {
		return AuthenticationError{}
	}
	passwordOK, err := VerifyPassword(password, record.passwordHash)
	if err != nil || !passwordOK {
		return AuthenticationError{}
	}
	return nil
}

// CreateCompanyOIDCSession creates a fresh session with company OIDC
// provenance for the linked Administrator a verified login callback resolved
// to. The guarded insert re-verifies, atomically with session creation, that
// the user is an enabled Administrator holding a local credential without a
// forced change, that the connection is still enabled at the exact revision
// and activation generation, and that the linked identity still belongs to
// this user.
func (s *Service) CreateCompanyOIDCSession(ctx context.Context, params CreateCompanyOIDCSessionParams) (Session, error) {
	if s == nil || s.db == nil {
		return Session{}, errors.New("auth service has no database")
	}
	if params.UserID <= 0 || params.ConnectionRevision <= 0 || params.ActivationGeneration <= 0 {
		return Session{}, AuthenticationError{}
	}
	sessionID, csrfToken, err := sessionTokens()
	if err != nil {
		return Session{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, fmt.Errorf("begin company OIDC session creation: %w", err)
	}
	defer tx.Rollback()

	now := s.now().UTC()
	expiresAt := now.Add(s.sessionTTL)
	result, err := tx.ExecContext(ctx, `
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
SELECT ?, u.id, ?, ?, ?
FROM users u
JOIN local_credentials lc ON lc.user_id = u.id
JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
WHERE u.id = ? AND u.disabled_at IS NULL AND lc.must_change_password = 0
  AND EXISTS (
    SELECT 1 FROM company_oidc_connections c
    WHERE c.id = 1 AND c.enabled = 1 AND c.revision = ? AND c.activation_generation = ?
  )
  AND EXISTS (
    SELECT 1 FROM company_oidc_identities i
    WHERE i.connection_id = 1 AND i.user_id = u.id
  )`,
		sessionID,
		csrfToken,
		expiresAt.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
		params.UserID,
		params.ConnectionRevision,
		params.ActivationGeneration,
	)
	if err != nil {
		return Session{}, fmt.Errorf("create company OIDC session: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return Session{}, fmt.Errorf("count created company OIDC sessions: %w", err)
	}
	if inserted == 0 {
		return Session{}, AuthenticationError{}
	}
	if inserted != 1 {
		return Session{}, fmt.Errorf("create company OIDC session affected %d rows", inserted)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_sessions(session_id, connection_id, user_id)
VALUES (?, 1, ?)`, sessionID, params.UserID); err != nil {
		return Session{}, fmt.Errorf("record company OIDC session provenance: %w", err)
	}
	record, err := s.userByID(ctx, tx, params.UserID)
	if err != nil {
		return Session{}, fmt.Errorf("load company OIDC session user: %w", err)
	}
	grants, err := loadGrants(ctx, tx, record.User)
	if err != nil {
		return Session{}, err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, fmt.Errorf("commit company OIDC session creation: %w", err)
	}
	return Session{
		ID:          sessionID,
		CSRFToken:   csrfToken,
		User:        record.User,
		Grants:      grants,
		CompanyOIDC: true,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
	}, nil
}

// secureCompanyOIDCOnAuthorityLoss shuts company login off inside the
// caller's transaction when the mutated user is the linked company OIDC
// Administrator: demotion, disablement, and a forced password reset each
// remove a login prerequisite, so the enabled connection, pending
// transactions, and OIDC sessions must fall with it atomically. The linked
// identity is retained; re-enabling stays an explicit Administrator action.
// With no linked identity it does nothing, so mutations of every other
// account are untouched by OIDC state.
func secureCompanyOIDCOnAuthorityLoss(ctx context.Context, tx *sql.Tx, actorUserID, userID int64) error {
	var linked int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1 FROM company_oidc_identities WHERE connection_id = 1 AND user_id = ?
)`, userID).Scan(&linked); err != nil {
		return fmt.Errorf("check company OIDC linked identity during authority change: %w", err)
	}
	if linked == 0 {
		return nil
	}

	var enabled, revision, generation int64
	if err := tx.QueryRowContext(ctx, `
SELECT enabled, revision, activation_generation
FROM company_oidc_connections
WHERE id = 1`).Scan(&enabled, &revision, &generation); err != nil {
		return fmt.Errorf("read company OIDC connection during authority change: %w", err)
	}
	if generation == math.MaxInt64 {
		return errors.New("company OIDC activation generation is exhausted")
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE company_oidc_connections
SET enabled = 0, activation_generation = activation_generation + 1
WHERE id = 1`); err != nil {
		return fmt.Errorf("disable company OIDC login during authority change: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_link_transactions`); err != nil {
		return fmt.Errorf("delete company OIDC link transactions during authority change: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_login_transactions`); err != nil {
		return fmt.Errorf("delete company OIDC login transactions during authority change: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM sessions
WHERE id IN (SELECT session_id FROM company_oidc_sessions)`); err != nil {
		return fmt.Errorf("revoke company OIDC sessions during authority change: %w", err)
	}

	if enabled != 1 {
		return nil
	}
	actor := actorUserID
	details := `{"revision":` + strconv.FormatInt(revision, 10) + `,"cause":"authority-loss"}`
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      audit.ActionOIDCConnectionDisabled,
		SubjectType: audit.SubjectTypeOIDCConnection,
		SubjectID:   "1",
		DetailsJSON: details,
	}); err != nil {
		return fmt.Errorf("record company OIDC disable audit event during authority change: %w", err)
	}
	return nil
}

// companyOIDCSessionStillAuthorized re-verifies, on every load of a company
// OIDC session, the prerequisites an account or connection mutation may have
// removed since login: the user must still be an enabled Administrator
// holding an unforced local credential, must still own the linked identity,
// and the connection must still be enabled.
func (s *Service) companyOIDCSessionStillAuthorized(ctx context.Context, userID int64) (bool, error) {
	var authorized int
	if err := s.db.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM users u
  JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
  JOIN local_credentials lc ON lc.user_id = u.id
  JOIN company_oidc_identities i ON i.connection_id = 1 AND i.user_id = u.id
  JOIN company_oidc_connections c ON c.id = 1 AND c.enabled = 1
  WHERE u.id = ? AND u.disabled_at IS NULL AND lc.must_change_password = 0
)`, userID).Scan(&authorized); err != nil {
		return false, fmt.Errorf("check company OIDC session authority: %w", err)
	}
	return authorized == 1, nil
}

// removeCompanyOIDCIdentityForRecovery deletes the recovering user's linked
// company identity, if any, and shuts company login off in the same
// transaction. With no linked identity it does nothing, so recovery for
// every other account is untouched by OIDC state.
func removeCompanyOIDCIdentityForRecovery(ctx context.Context, tx *sql.Tx, userID int64) error {
	result, err := tx.ExecContext(ctx, `
DELETE FROM company_oidc_identities WHERE user_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("delete company OIDC identity during recovery: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count company OIDC identities deleted during recovery: %w", err)
	}
	if deleted == 0 {
		return nil
	}
	if deleted != 1 {
		return fmt.Errorf("delete company OIDC identity during recovery affected %d rows", deleted)
	}

	var enabled, revision, generation int64
	if err := tx.QueryRowContext(ctx, `
SELECT enabled, revision, activation_generation
FROM company_oidc_connections
WHERE id = 1`).Scan(&enabled, &revision, &generation); err != nil {
		return fmt.Errorf("read company OIDC connection during recovery: %w", err)
	}
	if generation == math.MaxInt64 {
		return errors.New("company OIDC activation generation is exhausted")
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE company_oidc_connections
SET enabled = 0, activation_generation = activation_generation + 1
WHERE id = 1`); err != nil {
		return fmt.Errorf("disable company OIDC login during recovery: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_link_transactions`); err != nil {
		return fmt.Errorf("delete company OIDC link transactions during recovery: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_login_transactions`); err != nil {
		return fmt.Errorf("delete company OIDC login transactions during recovery: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM sessions
WHERE id IN (SELECT session_id FROM company_oidc_sessions)`); err != nil {
		return fmt.Errorf("revoke company OIDC sessions during recovery: %w", err)
	}

	store := audit.NewStoreTx(tx)
	details := `{"revision":` + strconv.FormatInt(revision, 10) + `,"cause":"recovery"}`
	if err := store.Record(ctx, audit.Event{
		Action:      audit.ActionOIDCIdentityUnlinked,
		SubjectType: audit.SubjectTypeOIDCConnection,
		SubjectID:   "1",
		DetailsJSON: details,
	}); err != nil {
		return fmt.Errorf("record company OIDC unlink audit event during recovery: %w", err)
	}
	if enabled == 1 {
		if err := store.Record(ctx, audit.Event{
			Action:      audit.ActionOIDCConnectionDisabled,
			SubjectType: audit.SubjectTypeOIDCConnection,
			SubjectID:   "1",
			DetailsJSON: details,
		}); err != nil {
			return fmt.Errorf("record company OIDC disable audit event during recovery: %w", err)
		}
	}
	return nil
}
