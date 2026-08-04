package companyoidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/taua-almeida/thawguard/internal/audit"
)

// activationSnapshot is the fully validated in-transaction view of the
// singleton connection used by link, login, Enable, and Disable fences. The
// public view carries validated setup-check and Test sign-in evidence; the
// record keeps the fields the public view redacts (secret ciphertext and the
// linked identity's issuer, client ID, and subject).
type activationSnapshot struct {
	record     connectionRecord
	connection Connection
}

func loadActivationSnapshot(ctx context.Context, tx *sql.Tx) (activationSnapshot, bool, error) {
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil || !found {
		return activationSnapshot{}, found, err
	}
	connection, err := publicConnection(record)
	if err != nil {
		return activationSnapshot{}, false, err
	}
	return activationSnapshot{record: record, connection: connection}, true, nil
}

// readyEvidence reports whether the snapshot carries a current verified
// setup check and current Test sign-in evidence. publicConnection already
// rejected evidence whose revision differs from the current connection.
func (s activationSnapshot) readyEvidence() bool {
	return s.connection.SetupCheck != nil &&
		s.connection.SetupCheck.ResultCode == SetupCheckVerified &&
		s.connection.TestSignInEvidence != nil
}

// identityMatchesConnection reports whether the linked identity was linked
// against the exact current issuer, client ID, and revision.
func (s activationSnapshot) identityMatchesConnection() bool {
	return s.record.Identity != nil &&
		s.record.Identity.issuer == s.record.Issuer &&
		s.record.Identity.clientID == s.record.ClientID &&
		s.record.Identity.revision == s.record.Revision
}

type EnableInput struct {
	ActorUserID      int64
	ExpectedRevision int64
}

// Enable turns company login on for the singleton connection after
// rechecking every prerequisite inside one writer transaction.
func (s *Service) Enable(ctx context.Context, input EnableInput) error {
	if s == nil || s.db == nil {
		return errors.New("company OIDC service has no database")
	}
	if s.secrets == nil {
		return ErrConfiguration
	}
	if input.ActorUserID <= 0 {
		return ErrAuthorization
	}
	if input.ExpectedRevision <= 0 {
		return ErrConflict
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin company OIDC enable: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, input.ActorUserID); err != nil {
		return err
	}
	snapshot, found, err := loadActivationSnapshot(ctx, tx)
	if err != nil {
		return err
	}
	if !found || snapshot.record.Revision != input.ExpectedRevision || snapshot.record.Enabled {
		return ErrConflict
	}
	if !snapshot.readyEvidence() || !snapshot.identityMatchesConnection() {
		return ErrNotReady
	}
	eligible, err := linkedAdministratorEligible(ctx, tx, snapshot.record.Identity.userID)
	if err != nil {
		return err
	}
	if !eligible {
		return ErrNotReady
	}
	secretValid, err := s.storedClientSecretValid(ctx, snapshot.record.ClientSecretCiphertext)
	if err != nil {
		return ErrConfiguration
	}
	if !secretValid {
		return ErrNotReady
	}
	if err := setConnectionEnabled(ctx, tx, snapshot.record.ActivationGeneration, true); err != nil {
		return err
	}
	actor := input.ActorUserID
	if err := recordActivationChange(
		ctx, tx, &actor, audit.ActionOIDCConnectionEnabled, snapshot.record.Revision, "",
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

// EnableReady reports whether Enable's prerequisites currently hold, without
// provider network work and without mutating state: current verified evidence,
// a linked identity matching the active configuration, an eligible linked
// Administrator, and a stored client secret that decrypts and validates under
// the runtime encryption key. The Authentication page uses it to withhold the
// Enable action when a prerequisite lapsed after linking; Enable itself
// rechecks everything inside its transaction.
func (s *Service) EnableReady(ctx context.Context) bool {
	if s == nil || s.db == nil || s.secrets == nil {
		return false
	}
	record, found, err := loadConnectionRecord(ctx, s.db)
	if err != nil || !found || record.Enabled {
		return false
	}
	connection, err := publicConnection(record)
	if err != nil {
		return false
	}
	snapshot := activationSnapshot{record: record, connection: connection}
	if !snapshot.readyEvidence() || !snapshot.identityMatchesConnection() {
		return false
	}
	eligible, err := linkedAdministratorEligible(ctx, s.db, record.Identity.userID)
	if err != nil || !eligible {
		return false
	}
	valid, err := s.storedClientSecretValid(ctx, record.ClientSecretCiphertext)
	return err == nil && valid
}

// storedClientSecretValid decrypts the stored client secret ciphertext,
// validates the plaintext, and clears the decrypted bytes. A non-nil error
// means decryption failed (for example, the runtime holds the wrong
// encryption key); false with a nil error means the plaintext is unusable.
func (s *Service) storedClientSecretValid(ctx context.Context, ciphertext []byte) (bool, error) {
	secret, err := s.secrets.Decrypt(ctx, ciphertext)
	if err != nil {
		return false, err
	}
	valid := validDecryptedClientSecret(secret)
	clear(secret)
	return valid, nil
}

type DisableInput struct {
	ActorUserID      int64
	ExpectedRevision int64
}

// Disable turns company login off, deletes every pending login transaction,
// and revokes every OIDC-provenance session, atomically.
func (s *Service) Disable(ctx context.Context, input DisableInput) error {
	if s == nil || s.db == nil {
		return errors.New("company OIDC service has no database")
	}
	if input.ActorUserID <= 0 {
		return ErrAuthorization
	}
	if input.ExpectedRevision <= 0 {
		return ErrConflict
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin company OIDC disable: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, input.ActorUserID); err != nil {
		return err
	}
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return err
	}
	if !found || record.Revision != input.ExpectedRevision || !record.Enabled {
		return ErrConflict
	}
	if err := setConnectionEnabled(ctx, tx, record.ActivationGeneration, false); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_login_transactions`); err != nil {
		return fmt.Errorf("delete pending company OIDC login transactions: %w", err)
	}
	if err := revokeCompanyOIDCSessions(ctx, tx); err != nil {
		return err
	}
	actor := input.ActorUserID
	if err := recordActivationChange(
		ctx, tx, &actor, audit.ActionOIDCConnectionDisabled, record.Revision, "administrator",
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

// linkedAdministratorEligible reports whether the linked user is currently an
// enabled Administrator holding a local credential without a forced change.
func linkedAdministratorEligible(ctx context.Context, q queryer, userID int64) (bool, error) {
	var eligible int
	if err := q.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM users u
  JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
  JOIN local_credentials lc ON lc.user_id = u.id
  WHERE u.id = ? AND u.disabled_at IS NULL AND lc.must_change_password = 0
)`, userID).Scan(&eligible); err != nil {
		return false, fmt.Errorf("check company OIDC linked Administrator eligibility: %w", err)
	}
	return eligible == 1, nil
}

func setConnectionEnabled(ctx context.Context, tx *sql.Tx, currentGeneration int64, enable bool) error {
	if currentGeneration == math.MaxInt64 {
		return errors.New("company OIDC activation generation is exhausted")
	}
	target, expected := 1, 0
	if !enable {
		target, expected = 0, 1
	}
	result, err := tx.ExecContext(ctx, `
UPDATE company_oidc_connections
SET enabled = ?, activation_generation = activation_generation + 1
WHERE id = 1 AND enabled = ?`, target, expected)
	if err != nil {
		return fmt.Errorf("update company OIDC enabled state: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count company OIDC enabled-state rows: %w", err)
	}
	if updated != 1 {
		return fmt.Errorf("update company OIDC enabled state affected %d rows", updated)
	}
	return nil
}

// incrementActivationGeneration fences out every in-flight link and login
// callback without touching the enabled flag; link and unlink use it.
func incrementActivationGeneration(ctx context.Context, tx *sql.Tx, currentGeneration int64) error {
	if currentGeneration == math.MaxInt64 {
		return errors.New("company OIDC activation generation is exhausted")
	}
	result, err := tx.ExecContext(ctx, `
UPDATE company_oidc_connections
SET activation_generation = activation_generation + 1
WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("increment company OIDC activation generation: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count company OIDC activation-generation rows: %w", err)
	}
	if updated != 1 {
		return fmt.Errorf("increment company OIDC activation generation affected %d rows", updated)
	}
	return nil
}

func revokeCompanyOIDCSessions(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `
DELETE FROM sessions
WHERE id IN (SELECT session_id FROM company_oidc_sessions)`); err != nil {
		return fmt.Errorf("revoke company OIDC sessions: %w", err)
	}
	return nil
}

func revokeUserCompanyOIDCSessions(ctx context.Context, tx *sql.Tx, userID int64) error {
	if _, err := tx.ExecContext(ctx, `
DELETE FROM sessions
WHERE id IN (SELECT session_id FROM company_oidc_sessions WHERE user_id = ?)`, userID); err != nil {
		return fmt.Errorf("revoke company OIDC sessions for user: %w", err)
	}
	return nil
}

// recordActivationChange writes one of the four activation audit events.
// Details carry only the connection revision and, where the action needs it,
// a fixed cause; never the subject, provider email, or any transaction value.
func recordActivationChange(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID *int64,
	action string,
	revision int64,
	cause string,
) error {
	var details []byte
	var err error
	if cause == "" {
		details, err = json.Marshal(struct {
			Revision int64 `json:"revision"`
		}{Revision: revision})
	} else {
		details, err = json.Marshal(struct {
			Revision int64  `json:"revision"`
			Cause    string `json:"cause"`
		}{Revision: revision, Cause: cause})
	}
	if err != nil {
		return errors.New("encode company OIDC activation audit evidence")
	}
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: actorUserID,
		Action:      action,
		SubjectType: audit.SubjectTypeOIDCConnection,
		SubjectID:   strconv.FormatInt(singletonConnectionID, 10),
		DetailsJSON: string(details),
	}); err != nil {
		return fmt.Errorf("record company OIDC activation audit event: %w", err)
	}
	return nil
}
