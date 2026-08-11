package forgeidentity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/taua-almeida/thawguard/internal/audit"
)

// IdentityForUser returns the user's linked identity, if any. The remote
// numeric id is deliberately absent from the read model.
func (s *Service) IdentityForUser(ctx context.Context, userID int64) (Identity, bool, error) {
	if s == nil || s.db == nil {
		return Identity{}, false, errors.New("forge identity service has no database")
	}
	if userID <= 0 {
		return Identity{}, false, nil
	}
	return loadIdentityForUser(ctx, s.db, userID)
}

func loadIdentityForUser(ctx context.Context, q queryer, userID int64) (Identity, bool, error) {
	var identity Identity
	var linkedAt string
	err := q.QueryRowContext(ctx, `
SELECT id, connection_id, user_id, username_at_link, linked_at
FROM forgejo_identities
WHERE user_id = ?`, userID).Scan(
		&identity.ID,
		&identity.ConnectionID,
		&identity.UserID,
		&identity.UsernameAtLink,
		&linkedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, false, nil
	}
	if err != nil {
		return Identity{}, false, fmt.Errorf("read forge identity: %w", err)
	}
	if identity.ID <= 0 || identity.ConnectionID <= 0 || identity.UserID != userID ||
		!validUsernameAtLink(identity.UsernameAtLink) {
		return Identity{}, false, errors.New("forge identity data is malformed")
	}
	identity.LinkedAt, err = parseForgeIdentityTime(linkedAt)
	if err != nil {
		return Identity{}, false, errors.New("forge identity data is malformed")
	}
	return identity, true, nil
}

// HasIdentities reports whether any linked identity exists. The Forge
// access page uses it to show that a reset is blocked.
func (s *Service) HasIdentities(ctx context.Context) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("forge identity service has no database")
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM forgejo_identities)`).Scan(&exists); err != nil {
		return false, fmt.Errorf("check linked forge identities: %w", err)
	}
	return exists == 1, nil
}

// AccountForUser assembles the /account card state for one user. Every
// configuration shortfall collapses into the single unavailable status.
func (s *Service) AccountForUser(ctx context.Context, userID int64) (AccountView, error) {
	if s == nil || s.db == nil {
		return AccountView{Status: AccountUnavailable}, errors.New("forge identity service has no database")
	}
	if userID <= 0 {
		return AccountView{Status: AccountUnavailable}, nil
	}
	identity, linked, err := loadIdentityForUser(ctx, s.db, userID)
	if err != nil {
		return AccountView{}, err
	}
	if linked {
		return AccountView{Status: AccountLinked, Identity: &identity}, nil
	}
	connection, found, err := loadConnectionSnapshot(ctx, s.db)
	if err != nil {
		return AccountView{}, err
	}
	if !found {
		return AccountView{Status: AccountUnavailable}, nil
	}
	oauth, configured, err := loadOAuthClientRecord(ctx, s.db, connection.ID)
	if err != nil {
		return AccountView{}, err
	}
	if !configured || !oauth.Enabled || oauth.BoundBaseURL != connection.BaseURL || s.secrets == nil {
		return AccountView{Status: AccountUnavailable}, nil
	}
	view := AccountView{
		Status:             AccountReady,
		ConnectionID:       connection.ID,
		ConnectionRevision: connection.Revision,
		OAuthRevision:      oauth.Revision,
	}
	var live int
	if err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(
  SELECT 1 FROM forgejo_identity_link_transactions
  WHERE connection_id = ? AND user_id = ? AND expires_at > ?
)`, connection.ID, userID, formatForgeIdentityTime(s.now().UTC())).Scan(&live); err != nil {
		return AccountView{}, fmt.Errorf("check live forge identity link transaction: %w", err)
	}
	if live == 1 {
		view.Status = AccountInProgress
	}
	return view, nil
}

// Unlink removes the acting user's own identity by its exact never-reused
// row id. The identity delete runs first and must remove exactly one row;
// only then are the user's ceremonies deleted and the audit event written.
// A stale unlink deletes no ceremony and writes no audit.
func (s *Service) Unlink(ctx context.Context, input UnlinkInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge identity service has no database")
	}
	if input.ActorUserID <= 0 || !validSessionID(input.SessionID) {
		return ErrAuthorization
	}
	if input.IdentityID <= 0 {
		return ErrIdentityStale
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forge identity unlink: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledCredentialedActor(ctx, tx, input.ActorUserID); err != nil {
		return err
	}
	now := s.now().UTC()
	authorized, err := currentCredentialedSession(ctx, tx, input.ActorUserID, input.SessionID, now)
	if err != nil {
		return fmt.Errorf("authorize forge identity unlink session: %w", err)
	}
	if !authorized {
		return ErrAuthorization
	}
	var connectionID int64
	err = tx.QueryRowContext(ctx, `
SELECT connection_id FROM forgejo_identities WHERE id = ? AND user_id = ?`,
		input.IdentityID, input.ActorUserID).Scan(&connectionID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIdentityStale
	}
	if err != nil {
		return fmt.Errorf("read forge identity for unlink: %w", err)
	}
	deleted, err := execExpectingOneRow(ctx, tx, `
DELETE FROM forgejo_identities WHERE id = ? AND user_id = ? AND connection_id = ?`,
		input.IdentityID, input.ActorUserID, connectionID)
	if err != nil {
		return fmt.Errorf("delete forge identity: %w", err)
	}
	if !deleted {
		return ErrIdentityStale
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM forgejo_identity_link_transactions WHERE connection_id = ? AND user_id = ?`,
		connectionID, input.ActorUserID); err != nil {
		return fmt.Errorf("delete forge identity link transactions: %w", err)
	}
	if err := recordIdentityEvent(ctx, tx, input.ActorUserID, audit.ActionForgeIdentityUnlinked, input.IdentityID, connectionID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

// Purge removes a disabled user's identity on Administrator authority. The
// transaction re-proves Administrator authority, the Administrator's own
// session, and that the target remains disabled before deleting the exact
// identity row, its owner's ceremonies, and writing the audit event
// atomically. An enabled owner is never purged.
func (s *Service) Purge(ctx context.Context, input PurgeInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge identity service has no database")
	}
	if input.ActorUserID <= 0 || !validSessionID(input.SessionID) {
		return ErrAdminOnly
	}
	if input.TargetUserID <= 0 || input.IdentityID <= 0 {
		return ErrIdentityStale
	}
	if !input.ConfirmPurge {
		return ValidationError{Message: "confirm the purge before removing the identity"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forge identity purge: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, input.ActorUserID); err != nil {
		return err
	}
	now := s.now().UTC()
	authorized, err := currentCredentialedSession(ctx, tx, input.ActorUserID, input.SessionID, now)
	if err != nil {
		return fmt.Errorf("authorize forge identity purge session: %w", err)
	}
	if !authorized {
		return ErrAdminOnly
	}
	var targetDisabled int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND disabled_at IS NOT NULL)`,
		input.TargetUserID).Scan(&targetDisabled); err != nil {
		return fmt.Errorf("check forge identity purge target: %w", err)
	}
	if targetDisabled != 1 {
		return ErrIdentityStale
	}
	var connectionID int64
	err = tx.QueryRowContext(ctx, `
SELECT connection_id FROM forgejo_identities WHERE id = ? AND user_id = ?`,
		input.IdentityID, input.TargetUserID).Scan(&connectionID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIdentityStale
	}
	if err != nil {
		return fmt.Errorf("read forge identity for purge: %w", err)
	}
	deleted, err := execExpectingOneRow(ctx, tx, `
DELETE FROM forgejo_identities WHERE id = ? AND user_id = ? AND connection_id = ?`,
		input.IdentityID, input.TargetUserID, connectionID)
	if err != nil {
		return fmt.Errorf("delete forge identity for purge: %w", err)
	}
	if !deleted {
		return ErrIdentityStale
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM forgejo_identity_link_transactions WHERE connection_id = ? AND user_id = ?`,
		connectionID, input.TargetUserID); err != nil {
		return fmt.Errorf("delete forge identity link transactions for purge: %w", err)
	}
	if err := recordIdentityEvent(ctx, tx, input.ActorUserID, audit.ActionForgeIdentityPurged, input.IdentityID, connectionID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}
