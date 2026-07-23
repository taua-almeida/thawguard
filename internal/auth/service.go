package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const DefaultSessionTTL = 12 * time.Hour

type User struct {
	ID                 int64
	Email              string
	DisplayName        string
	IsAdmin            bool
	DisabledAt         *time.Time
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (u User) Disabled() bool { return u.DisabledAt != nil }

type Session struct {
	ID        string
	CSRFToken string
	User      User
	// Grants is the repository-aware capability set current as of when this
	// Session value was produced. For live requests only the fresh SessionByID
	// result is authoritative.
	Grants    Grants
	ExpiresAt time.Time
	CreatedAt time.Time
}

type CreateFirstAdminParams struct {
	Email       string
	DisplayName string
	Password    string
}

type LoginParams struct {
	Email    string
	Password string
}

type CreateUserParams struct {
	ActorUserID int64
	Email       string
	DisplayName string
	Password    string
}

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func IsValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

type AuthenticationError struct{}

func (AuthenticationError) Error() string { return "invalid email or password" }

func IsAuthenticationError(err error) bool {
	var authErr AuthenticationError
	return errors.As(err, &authErr)
}

type Service struct {
	db         *sql.DB
	now        func() time.Time
	sessionTTL time.Duration
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db, now: func() time.Time { return time.Now().UTC() }, sessionTTL: DefaultSessionTTL}
}

func (s *Service) HasUsers(ctx context.Context) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("auth service has no database")
	}
	count, err := s.userCount(ctx, s.db)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Service) CreateFirstAdmin(ctx context.Context, params CreateFirstAdminParams) (Session, error) {
	if s == nil || s.db == nil {
		return Session{}, errors.New("auth service has no database")
	}
	createParams := CreateUserParams{Email: params.Email, DisplayName: params.DisplayName, Password: params.Password}
	createParams = normalizeCreateUserParams(createParams)
	if err := validateLocalUserParams(createParams); err != nil {
		return Session{}, err
	}
	passwordHash, err := HashPassword(createParams.Password)
	if err != nil {
		return Session{}, err
	}
	sessionID, csrfToken, err := sessionTokens()
	if err != nil {
		return Session{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, fmt.Errorf("begin first admin setup: %w", err)
	}
	defer tx.Rollback()

	count, err := s.userCount(ctx, tx)
	if err != nil {
		return Session{}, err
	}
	if count > 0 {
		return Session{}, ValidationError{Message: "first admin is already configured"}
	}
	user, err := s.insertUser(ctx, tx, createParams, passwordHash, false, true)
	if err != nil {
		return Session{}, err
	}
	session, err := s.insertSession(ctx, tx, user, sessionID, csrfToken)
	if err != nil {
		return Session{}, err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, fmt.Errorf("commit first admin setup: %w", err)
	}
	return session, nil
}

func (s *Service) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	if s == nil || s.db == nil {
		return User{}, errors.New("auth service has no database")
	}
	params = normalizeCreateUserParams(params)
	if err := validateLocalUserParams(params); err != nil {
		return User{}, err
	}
	passwordHash, err := HashPassword(params.Password)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin create user: %w", err)
	}
	defer tx.Rollback()
	if err := s.requireEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return User{}, err
	}
	user, err := s.insertUser(ctx, tx, params, passwordHash, true, false)
	if err != nil {
		return User{}, err
	}
	if err := auditUserCreated(ctx, tx, params.ActorUserID, user.ID); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit create user: %w", err)
	}
	return user, nil
}

func (s *Service) Login(ctx context.Context, params LoginParams) (Session, error) {
	if s == nil || s.db == nil {
		return Session{}, errors.New("auth service has no database")
	}
	params.Email = normalizeEmail(params.Email)
	if params.Email == "" || params.Password == "" {
		return Session{}, AuthenticationError{}
	}
	record, err := s.userByEmail(ctx, params.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, AuthenticationError{}
		}
		return Session{}, err
	}
	passwordOK, err := VerifyPassword(params.Password, record.passwordHash)
	if err != nil || !passwordOK {
		return Session{}, AuthenticationError{}
	}
	if record.Disabled() {
		return Session{}, AuthenticationError{}
	}
	sessionID, csrfToken, err := sessionTokens()
	if err != nil {
		return Session{}, err
	}
	return s.insertSession(ctx, s.db, record.User, sessionID, csrfToken)
}

func (s *Service) SessionByID(ctx context.Context, id string) (Session, bool, error) {
	if s == nil || s.db == nil {
		return Session{}, false, errors.New("auth service has no database")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Session{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
SELECT s.id, s.csrf_token, s.expires_at, s.created_at,
  u.id, u.email, u.display_name,
  EXISTS (SELECT 1 FROM user_roles admin_role WHERE admin_role.user_id = u.id AND admin_role.role = 'admin'),
  u.disabled_at, u.must_change_password, u.created_at, u.updated_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.id = ?`, id)
	session, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, false, nil
		}
		return Session{}, false, err
	}
	if session.CSRFToken == "" {
		if err := s.Logout(ctx, id); err != nil {
			return Session{}, false, err
		}
		return Session{}, false, nil
	}
	if !s.now().UTC().Before(session.ExpiresAt) {
		if err := s.Logout(ctx, id); err != nil {
			return Session{}, false, err
		}
		return Session{}, false, nil
	}
	if session.User.Disabled() {
		if err := s.Logout(ctx, id); err != nil {
			return Session{}, false, err
		}
		return Session{}, false, nil
	}
	grants, err := loadGrants(ctx, s.db, session.User)
	if err != nil {
		return Session{}, false, err
	}
	session.Grants = grants
	return session, true, nil
}

func (s *Service) Logout(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("auth service has no database")
	}
	if strings.TrimSpace(id) == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("auth service has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT u.id, u.email, u.display_name,
  EXISTS (SELECT 1 FROM user_roles admin_role WHERE admin_role.user_id = u.id AND admin_role.role = 'admin'),
  u.disabled_at, u.must_change_password, u.created_at, u.updated_at
FROM users u
ORDER BY u.created_at ASC, u.id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users rows: %w", err)
	}
	return users, nil
}

type queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface {
	Scan(dest ...any) error
}

type userRecord struct {
	User
	passwordHash string
}

func (s *Service) userCount(ctx context.Context, q queryer) (int, error) {
	if s == nil || q == nil {
		return 0, errors.New("auth service has no database")
	}
	var count int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

func (s *Service) userByEmail(ctx context.Context, email string) (userRecord, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT u.id, u.email, u.display_name, u.password_hash,
  EXISTS (SELECT 1 FROM user_roles admin_role WHERE admin_role.user_id = u.id AND admin_role.role = 'admin'),
  u.disabled_at, u.must_change_password, u.created_at, u.updated_at
FROM users u
WHERE u.email = ?`, email)
	record, err := scanUserRecord(row)
	if err != nil {
		return userRecord{}, err
	}
	return record, nil
}

func (s *Service) userByID(ctx context.Context, q queryer, id int64) (userRecord, error) {
	row := q.QueryRowContext(ctx, `
SELECT u.id, u.email, u.display_name, u.password_hash,
  EXISTS (SELECT 1 FROM user_roles admin_role WHERE admin_role.user_id = u.id AND admin_role.role = 'admin'),
  u.disabled_at, u.must_change_password, u.created_at, u.updated_at
FROM users u
WHERE u.id = ?`, id)
	record, err := scanUserRecord(row)
	if err != nil {
		return userRecord{}, err
	}
	return record, nil
}

func (s *Service) insertUser(ctx context.Context, q queryer, params CreateUserParams, passwordHash string, mustChangePassword bool, isAdmin bool) (User, error) {
	now := s.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	result, err := q.ExecContext(ctx, `
INSERT INTO users(email, display_name, password_hash, must_change_password, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`, params.Email, params.DisplayName, passwordHash, boolInt(mustChangePassword), nowText, nowText)
	if err != nil {
		return User{}, createUserError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("created user id: %w", err)
	}
	if isAdmin {
		if _, err := q.ExecContext(ctx, `
INSERT INTO user_roles(user_id, role, created_at)
VALUES (?, 'admin', ?)`, id, nowText); err != nil {
			return User{}, fmt.Errorf("create user Admin row: %w", err)
		}
	}
	return User{ID: id, Email: params.Email, DisplayName: params.DisplayName, IsAdmin: isAdmin, MustChangePassword: mustChangePassword, CreatedAt: now, UpdatedAt: now}, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *Service) insertSession(ctx context.Context, q queryer, user User, sessionID string, csrfToken string) (Session, error) {
	grants, err := loadGrants(ctx, q, user)
	if err != nil {
		return Session{}, err
	}
	now := s.now().UTC()
	expiresAt := now.Add(s.sessionTTL)
	_, err = q.ExecContext(ctx, `
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)`, sessionID, user.ID, csrfToken, expiresAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return Session{ID: sessionID, CSRFToken: csrfToken, User: user, Grants: grants, ExpiresAt: expiresAt, CreatedAt: now}, nil
}

func scanUser(row scanner) (User, error) {
	var user User
	var isAdmin int
	var disabledAt sql.NullString
	var mustChangePassword int
	var createdAt string
	var updatedAt string
	if err := row.Scan(&user.ID, &user.Email, &user.DisplayName, &isAdmin, &disabledAt, &mustChangePassword, &createdAt, &updatedAt); err != nil {
		return User{}, err
	}
	parsedCreatedAt, err := parseTime(createdAt)
	if err != nil {
		return User{}, fmt.Errorf("parse user created_at: %w", err)
	}
	parsedUpdatedAt, err := parseTime(updatedAt)
	if err != nil {
		return User{}, fmt.Errorf("parse user updated_at: %w", err)
	}
	parsedDisabledAt, err := parseOptionalTime(disabledAt)
	if err != nil {
		return User{}, fmt.Errorf("parse user disabled_at: %w", err)
	}
	user.IsAdmin = isAdmin != 0
	user.DisabledAt = parsedDisabledAt
	user.MustChangePassword = mustChangePassword != 0
	user.CreatedAt = parsedCreatedAt
	user.UpdatedAt = parsedUpdatedAt
	return user, nil
}

func scanUserRecord(row scanner) (userRecord, error) {
	var record userRecord
	var isAdmin int
	var disabledAt sql.NullString
	var mustChangePassword int
	var createdAt string
	var updatedAt string
	if err := row.Scan(&record.ID, &record.Email, &record.DisplayName, &record.passwordHash, &isAdmin, &disabledAt, &mustChangePassword, &createdAt, &updatedAt); err != nil {
		return userRecord{}, err
	}
	parsedCreatedAt, err := parseTime(createdAt)
	if err != nil {
		return userRecord{}, fmt.Errorf("parse user created_at: %w", err)
	}
	parsedUpdatedAt, err := parseTime(updatedAt)
	if err != nil {
		return userRecord{}, fmt.Errorf("parse user updated_at: %w", err)
	}
	parsedDisabledAt, err := parseOptionalTime(disabledAt)
	if err != nil {
		return userRecord{}, fmt.Errorf("parse user disabled_at: %w", err)
	}
	record.IsAdmin = isAdmin != 0
	record.DisabledAt = parsedDisabledAt
	record.MustChangePassword = mustChangePassword != 0
	record.CreatedAt = parsedCreatedAt
	record.UpdatedAt = parsedUpdatedAt
	return record, nil
}

func scanSession(row scanner) (Session, error) {
	var session Session
	var isAdmin int
	var expiresAt string
	var sessionCreatedAt string
	var disabledAt sql.NullString
	var mustChangePassword int
	var userCreatedAt string
	var userUpdatedAt string
	if err := row.Scan(&session.ID, &session.CSRFToken, &expiresAt, &sessionCreatedAt, &session.User.ID, &session.User.Email, &session.User.DisplayName, &isAdmin, &disabledAt, &mustChangePassword, &userCreatedAt, &userUpdatedAt); err != nil {
		return Session{}, err
	}
	parsedExpiresAt, err := parseTime(expiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session expires_at: %w", err)
	}
	parsedSessionCreatedAt, err := parseTime(sessionCreatedAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session created_at: %w", err)
	}
	parsedUserCreatedAt, err := parseTime(userCreatedAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session user created_at: %w", err)
	}
	parsedUserUpdatedAt, err := parseTime(userUpdatedAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session user updated_at: %w", err)
	}
	parsedDisabledAt, err := parseOptionalTime(disabledAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session user disabled_at: %w", err)
	}
	session.ExpiresAt = parsedExpiresAt
	session.CreatedAt = parsedSessionCreatedAt
	session.User.IsAdmin = isAdmin != 0
	session.User.DisabledAt = parsedDisabledAt
	session.User.MustChangePassword = mustChangePassword != 0
	session.User.CreatedAt = parsedUserCreatedAt
	session.User.UpdatedAt = parsedUserUpdatedAt
	return session, nil
}

func parseTime(raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func parseOptionalTime(raw sql.NullString) (*time.Time, error) {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil, nil
	}
	parsed, err := parseTime(raw.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func normalizeCreateUserParams(params CreateUserParams) CreateUserParams {
	params.Email = normalizeEmail(params.Email)
	params.DisplayName = strings.TrimSpace(params.DisplayName)
	return params
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateLocalUserParams(params CreateUserParams) error {
	if params.Email == "" {
		return ValidationError{Message: "email is required"}
	}
	if len(params.Email) > 254 || !strings.Contains(params.Email, "@") {
		return ValidationError{Message: "email must be valid"}
	}
	if params.DisplayName == "" {
		return ValidationError{Message: "display name is required"}
	}
	if len(params.DisplayName) > 120 {
		return ValidationError{Message: "display name is too long"}
	}
	if err := validatePassword(params.Password); err != nil {
		return err
	}
	return nil
}

func auditUserCreated(ctx context.Context, tx *sql.Tx, actorUserID, userID int64) error {
	if err := audit.NewStoreTx(tx).Record(ctx, userAuditEvent(audit.ActionUserCreated, actorUserID, userID, map[string]string{"access": "none", "sign_in": "password"})); err != nil {
		return fmt.Errorf("record user creation audit event: %w", err)
	}
	return nil
}

func createUserError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed: users.email") {
		return ValidationError{Message: "user email already exists"}
	}
	return fmt.Errorf("create user: %w", err)
}

func sessionTokens() (string, string, error) {
	sessionID, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	return sessionID, csrfToken, nil
}

func randomToken(byteLength int) (string, error) {
	buf := make([]byte, byteLength)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
