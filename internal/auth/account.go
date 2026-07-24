package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

type SetUserAdminParams struct {
	ActorUserID int64
	UserID      int64
	Admin       bool
}

type ChangePasswordParams struct {
	UserID          int64
	CurrentPassword string
	NewPassword     string
}

type ResetPasswordParams struct {
	ActorUserID       int64
	UserID            int64
	TemporaryPassword string
}

// SetUserAdmin changes only the one live global authority row. Repository
// grants are preserved.
func (s *Service) SetUserAdmin(ctx context.Context, params SetUserAdminParams) (User, error) {
	if s == nil || s.db == nil {
		return User{}, errors.New("auth service has no database")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin admin update: %w", err)
	}
	defer tx.Rollback()

	if err := s.requireEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return User{}, err
	}
	record, err := s.userByID(ctx, tx, params.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ValidationError{Message: "user was not found"}
		}
		return User{}, err
	}
	before := record.IsAdmin

	now := s.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	if params.Admin {
		if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO user_roles(user_id, role, created_at)
VALUES (?, ?, ?)`, record.ID, RoleAdmin, nowText); err != nil {
			return User{}, fmt.Errorf("grant user admin: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ? AND role = ?`, record.ID, RoleAdmin); err != nil {
			return User{}, fmt.Errorf("remove user admin: %w", err)
		}
		if err := s.ensureEnabledAdminRemains(ctx, tx, "the final enabled admin must keep the admin role"); err != nil {
			return User{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET updated_at = ? WHERE id = ?`, nowText, record.ID); err != nil {
		return User{}, fmt.Errorf("update user after Admin change: %w", err)
	}
	if before != params.Admin {
		beforeLabel, afterLabel := "none", "none"
		if before {
			beforeLabel = string(RoleAdmin)
		}
		if params.Admin {
			afterLabel = string(RoleAdmin)
		}
		event := userAuditEvent(audit.ActionUserRolesUpdated, params.ActorUserID, record.ID, map[string]string{
			"roles_before": beforeLabel,
			"roles_after":  afterLabel,
		})
		if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
			return User{}, fmt.Errorf("record admin update audit event: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit admin update: %w", err)
	}
	user := record.User
	user.IsAdmin = params.Admin
	user.UpdatedAt = now
	return user, nil
}

// DisableUser atomically marks a user disabled, revokes every session for
// that user, and refuses to disable the final enabled admin.
func (s *Service) DisableUser(ctx context.Context, actorUserID int64, userID int64) (User, error) {
	if s == nil || s.db == nil {
		return User{}, errors.New("auth service has no database")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin user disable: %w", err)
	}
	defer tx.Rollback()
	if err := s.requireEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return User{}, err
	}

	record, err := s.userByID(ctx, tx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ValidationError{Message: "user was not found"}
		}
		return User{}, err
	}
	if record.Disabled() {
		return User{}, ValidationError{Message: "user is already disabled"}
	}

	now := s.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = ?, updated_at = ? WHERE id = ?`, nowText, nowText, record.ID); err != nil {
		return User{}, fmt.Errorf("disable user: %w", err)
	}
	if err := s.ensureEnabledAdminRemains(ctx, tx, "the final enabled admin cannot be disabled"); err != nil {
		return User{}, err
	}
	if err := deleteUserSessions(ctx, tx, record.ID); err != nil {
		return User{}, err
	}
	if err := deleteUserPasswordRecoveryToken(ctx, tx, record.ID); err != nil {
		return User{}, err
	}
	event := userAuditEvent(audit.ActionUserDisabled, actorUserID, record.ID, map[string]string{"enabled": "false"})
	if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
		return User{}, fmt.Errorf("record user disable audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit user disable: %w", err)
	}
	user := record.User
	user.DisabledAt = &now
	user.UpdatedAt = now
	return user, nil
}

// EnableUser atomically re-enables a disabled user. It does not create or
// restore any session.
func (s *Service) EnableUser(ctx context.Context, actorUserID int64, userID int64) (User, error) {
	if s == nil || s.db == nil {
		return User{}, errors.New("auth service has no database")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin user enable: %w", err)
	}
	defer tx.Rollback()
	if err := s.requireEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return User{}, err
	}

	record, err := s.userByID(ctx, tx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ValidationError{Message: "user was not found"}
		}
		return User{}, err
	}
	if !record.Disabled() {
		return User{}, ValidationError{Message: "user is not disabled"}
	}

	now := s.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = NULL, updated_at = ? WHERE id = ?`, nowText, record.ID); err != nil {
		return User{}, fmt.Errorf("enable user: %w", err)
	}
	event := userAuditEvent(audit.ActionUserEnabled, actorUserID, record.ID, map[string]string{"enabled": "true"})
	if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
		return User{}, fmt.Errorf("record user enable audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit user enable: %w", err)
	}
	user := record.User
	user.DisabledAt = nil
	user.UpdatedAt = now
	return user, nil
}

// ChangePassword verifies the current password, replaces the hash, clears any
// forced-password flag, revokes every session for the user, and returns a
// freshly rotated session.
func (s *Service) ChangePassword(ctx context.Context, params ChangePasswordParams) (Session, error) {
	if s == nil || s.db == nil {
		return Session{}, errors.New("auth service has no database")
	}
	if err := validatePassword(params.NewPassword); err != nil {
		return Session{}, err
	}
	record, err := s.userByID(ctx, s.db, params.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ValidationError{Message: "user was not found"}
		}
		return Session{}, err
	}
	currentOK, err := VerifyPassword(params.CurrentPassword, record.passwordHash)
	if err != nil || !currentOK {
		return Session{}, ValidationError{Message: "current password is incorrect"}
	}
	reused, err := VerifyPassword(params.NewPassword, record.passwordHash)
	if err == nil && reused {
		return Session{}, ValidationError{Message: "new password must be different from the current password"}
	}
	passwordHash, err := HashPassword(params.NewPassword)
	if err != nil {
		return Session{}, err
	}
	sessionID, csrfToken, err := sessionTokens()
	if err != nil {
		return Session{}, err
	}
	return s.commitPasswordChange(ctx, record, passwordHash, sessionID, csrfToken)
}

func (s *Service) commitPasswordChange(
	ctx context.Context,
	record userRecord,
	passwordHash string,
	sessionID string,
	csrfToken string,
) (Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, fmt.Errorf("begin password change: %w", err)
	}
	defer tx.Rollback()

	now := s.now().UTC()
	result, err := tx.ExecContext(ctx, `
UPDATE users
SET password_hash = ?, must_change_password = 0, updated_at = ?
WHERE id = ? AND password_hash = ? AND disabled_at IS NULL`,
		passwordHash,
		now.Format(time.RFC3339Nano),
		record.ID,
		record.passwordHash,
	)
	if err != nil {
		return Session{}, fmt.Errorf("update user password: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return Session{}, fmt.Errorf("count updated user passwords: %w", err)
	}
	if updated == 0 {
		return Session{}, ValidationError{Message: "current password is incorrect"}
	}
	if updated != 1 {
		return Session{}, fmt.Errorf("update user password affected %d rows", updated)
	}
	if err := deleteUserSessions(ctx, tx, record.ID); err != nil {
		return Session{}, err
	}
	if err := deleteUserPasswordRecoveryToken(ctx, tx, record.ID); err != nil {
		return Session{}, err
	}
	user := record.User
	user.MustChangePassword = false
	user.UpdatedAt = now
	session, err := s.insertSession(ctx, tx, user, passwordHash, sessionID, csrfToken)
	if err != nil {
		return Session{}, err
	}
	event := userAuditEvent(audit.ActionUserPasswordChanged, record.ID, record.ID, nil)
	if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
		return Session{}, fmt.Errorf("record password change audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Session{}, fmt.Errorf("commit password change: %w", err)
	}
	return session, nil
}

// ResetPassword sets an admin-entered temporary password on another user,
// forces a password change on next login, and revokes every session for that
// user. Enabled/disabled state and roles are preserved.
func (s *Service) ResetPassword(ctx context.Context, params ResetPasswordParams) error {
	if s == nil || s.db == nil {
		return errors.New("auth service has no database")
	}
	if params.ActorUserID == params.UserID {
		return ValidationError{Message: "use the change password form for your own account"}
	}
	if err := validatePassword(params.TemporaryPassword); err != nil {
		return err
	}
	passwordHash, err := HashPassword(params.TemporaryPassword)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin password reset: %w", err)
	}
	defer tx.Rollback()
	if err := s.requireEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return err
	}

	record, err := s.userByID(ctx, tx, params.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ValidationError{Message: "user was not found"}
		}
		return err
	}
	nowText := s.now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, must_change_password = 1, updated_at = ? WHERE id = ?`, passwordHash, nowText, record.ID); err != nil {
		return fmt.Errorf("reset user password: %w", err)
	}
	if err := deleteUserSessions(ctx, tx, record.ID); err != nil {
		return err
	}
	if err := deleteUserPasswordRecoveryToken(ctx, tx, record.ID); err != nil {
		return err
	}
	event := userAuditEvent(audit.ActionUserPasswordReset, params.ActorUserID, record.ID, nil)
	if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
		return fmt.Errorf("record password reset audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit password reset: %w", err)
	}
	return nil
}

// ensureEnabledAdminRemains enforces the final enabled admin invariant after
// a mutation inside the same transaction, so a violating change rolls back.
func (s *Service) ensureEnabledAdminRemains(ctx context.Context, q queryer, message string) error {
	var count int
	if err := q.QueryRowContext(ctx, `
SELECT count(*)
FROM users u
JOIN user_roles ur ON ur.user_id = u.id AND ur.role = ?
WHERE u.disabled_at IS NULL`, RoleAdmin).Scan(&count); err != nil {
		return fmt.Errorf("count enabled admins: %w", err)
	}
	if count == 0 {
		return ValidationError{Message: message}
	}
	return nil
}

func deleteUserSessions(ctx context.Context, q queryer, userID int64) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}
	return nil
}

func deleteUserPasswordRecoveryToken(ctx context.Context, q queryer, userID int64) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM password_recovery_tokens WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete user password recovery token: %w", err)
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 12 {
		return ValidationError{Message: "password must be at least 12 characters"}
	}
	if len(password) > 1024 {
		return ValidationError{Message: "password is too long"}
	}
	return nil
}

func userAuditEvent(action string, actorUserID int64, subjectUserID int64, details map[string]string) audit.Event {
	if details == nil {
		details = map[string]string{}
	}
	details["actor_kind"] = "user"
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	actor := actorUserID
	return audit.Event{
		ActorUserID: &actor,
		Action:      action,
		SubjectType: audit.SubjectTypeUser,
		SubjectID:   strconv.FormatInt(subjectUserID, 10),
		DetailsJSON: string(detailsJSON),
	}
}
