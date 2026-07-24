package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const DefaultPasswordRecoveryTTL = 60 * time.Minute

type IssuePasswordRecoveryParams struct {
	ActorUserID int64
	UserID      int64
}

type PasswordRecoveryToken struct {
	Token     string
	ExpiresAt time.Time
}

type CompletePasswordRecoveryParams struct {
	Token       string
	NewPassword string
}

type InvalidPasswordRecoveryTokenError struct{}

func (InvalidPasswordRecoveryTokenError) Error() string {
	return "password recovery token is invalid or expired"
}

func IsInvalidPasswordRecoveryToken(err error) bool {
	var tokenErr InvalidPasswordRecoveryTokenError
	return errors.As(err, &tokenErr)
}

func (s *Service) IssuePasswordRecoveryToken(ctx context.Context, params IssuePasswordRecoveryParams) (PasswordRecoveryToken, error) {
	if s == nil || s.db == nil {
		return PasswordRecoveryToken{}, errors.New("auth service has no database")
	}
	token, err := randomToken(32)
	if err != nil {
		return PasswordRecoveryToken{}, err
	}
	digest := sha256.Sum256([]byte(token))
	now := s.now().UTC()
	expiresAt := now.Add(DefaultPasswordRecoveryTTL)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PasswordRecoveryToken{}, fmt.Errorf("begin password recovery issuance: %w", err)
	}
	defer tx.Rollback()

	if err := s.requireEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return PasswordRecoveryToken{}, err
	}
	if params.ActorUserID == params.UserID {
		return PasswordRecoveryToken{}, ValidationError{Message: "an admin cannot issue a password recovery token for their own account"}
	}
	target, err := s.userByID(ctx, tx, params.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PasswordRecoveryToken{}, ValidationError{Message: "user was not found"}
		}
		return PasswordRecoveryToken{}, err
	}
	if target.Disabled() {
		return PasswordRecoveryToken{}, ValidationError{Message: "password recovery requires an enabled user"}
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO password_recovery_tokens(user_id, token_digest, expires_at)
VALUES (?, ?, ?)
ON CONFLICT(user_id) DO UPDATE SET
  token_digest = excluded.token_digest,
  expires_at = excluded.expires_at`, target.ID, digest[:], expiresAt.UnixNano()); err != nil {
		return PasswordRecoveryToken{}, fmt.Errorf("store password recovery token: %w", err)
	}
	event := userAuditEvent(
		audit.ActionUserPasswordRecoveryIssued,
		params.ActorUserID,
		target.ID,
		map[string]string{"expires_at": expiresAt.Format(time.RFC3339Nano)},
	)
	if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
		return PasswordRecoveryToken{}, fmt.Errorf("record password recovery issuance audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return PasswordRecoveryToken{}, fmt.Errorf("commit password recovery issuance: %w", err)
	}
	return PasswordRecoveryToken{Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Service) CompletePasswordRecovery(ctx context.Context, params CompletePasswordRecoveryParams) error {
	if s == nil || s.db == nil {
		return errors.New("auth service has no database")
	}
	digest, ok := passwordRecoveryTokenDigest(params.Token)
	if !ok {
		return InvalidPasswordRecoveryTokenError{}
	}
	userID, err := s.preflightPasswordRecovery(ctx, digest, s.now().UTC())
	if err != nil {
		return err
	}
	if err := validatePassword(params.NewPassword); err != nil {
		return err
	}
	passwordHash, err := HashPassword(params.NewPassword)
	if err != nil {
		return err
	}
	return s.commitPasswordRecovery(ctx, userID, digest, passwordHash)
}

func (s *Service) commitPasswordRecovery(
	ctx context.Context,
	userID int64,
	digest [sha256.Size]byte,
	passwordHash string,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin password recovery completion: %w", err)
	}
	defer tx.Rollback()

	// SQLite deferred transactions do not reserve the writer lock at BeginTx.
	// This digest CAS acquires it before expiry is sampled, so lock contention
	// cannot make a token valid past its boundary.
	result, err := tx.ExecContext(ctx, `
UPDATE password_recovery_tokens
SET expires_at = expires_at
WHERE user_id = ?
  AND token_digest = ?
  AND EXISTS (
    SELECT 1
    FROM users u
    WHERE u.id = password_recovery_tokens.user_id
      AND u.disabled_at IS NULL
  )`, userID, digest[:])
	if err != nil {
		return fmt.Errorf("lock password recovery token: %w", err)
	}
	locked, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count locked password recovery tokens: %w", err)
	}
	if locked == 0 {
		return InvalidPasswordRecoveryTokenError{}
	}
	if locked != 1 {
		return fmt.Errorf("lock password recovery token affected %d rows", locked)
	}

	now := s.now().UTC()
	result, err = tx.ExecContext(ctx, `
DELETE FROM password_recovery_tokens
WHERE user_id = ?
  AND token_digest = ?
  AND expires_at > ?
  AND EXISTS (
    SELECT 1
    FROM users u
    WHERE u.id = password_recovery_tokens.user_id
      AND u.disabled_at IS NULL
  )`, userID, digest[:], now.UnixNano())
	if err != nil {
		return fmt.Errorf("claim password recovery token: %w", err)
	}
	claimed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count claimed password recovery tokens: %w", err)
	}
	if claimed == 0 {
		return InvalidPasswordRecoveryTokenError{}
	}
	if claimed != 1 {
		return fmt.Errorf("claim password recovery token affected %d rows", claimed)
	}

	result, err = tx.ExecContext(ctx, `
UPDATE users
SET password_hash = ?, must_change_password = 0, updated_at = ?
WHERE id = ? AND disabled_at IS NULL`, passwordHash, now.Format(time.RFC3339Nano), userID)
	if err != nil {
		return fmt.Errorf("update recovered password: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count recovered password updates: %w", err)
	}
	if updated == 0 {
		return InvalidPasswordRecoveryTokenError{}
	}
	if updated != 1 {
		return fmt.Errorf("update recovered password affected %d rows", updated)
	}
	if err := deleteUserSessions(ctx, tx, userID); err != nil {
		return err
	}
	event := audit.Event{
		Action:      audit.ActionUserPasswordRecoveryCompleted,
		SubjectType: audit.SubjectTypeUser,
		SubjectID:   strconv.FormatInt(userID, 10),
		DetailsJSON: `{"actor_kind":"` + audit.ActorKindPasswordRecoveryLink + `"}`,
	}
	if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
		return fmt.Errorf("record password recovery completion audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit password recovery completion: %w", err)
	}
	return nil
}

func (s *Service) preflightPasswordRecovery(ctx context.Context, digest [sha256.Size]byte, now time.Time) (int64, error) {
	var userID int64
	err := s.db.QueryRowContext(ctx, `
SELECT tokens.user_id
FROM password_recovery_tokens tokens
JOIN users u ON u.id = tokens.user_id
WHERE tokens.token_digest = ?
  AND tokens.expires_at > ?
  AND u.disabled_at IS NULL`, digest[:], now.UnixNano()).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, InvalidPasswordRecoveryTokenError{}
	}
	if err != nil {
		return 0, fmt.Errorf("find password recovery token: %w", err)
	}
	return userID, nil
}

func passwordRecoveryTokenDigest(token string) ([sha256.Size]byte, bool) {
	if len(token) != base64.RawURLEncoding.EncodedLen(32) {
		return [sha256.Size]byte{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
}
