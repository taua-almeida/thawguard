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
)

const DefaultSessionTTL = 12 * time.Hour

type User struct {
	ID                 int64
	Email              string
	DisplayName        string
	Role               Role
	Roles              RoleSet
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
	Email       string
	DisplayName string
	Password    string
	Roles       []Role
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
	createParams := CreateUserParams{Email: params.Email, DisplayName: params.DisplayName, Password: params.Password, Roles: Roles()}
	createParams = normalizeCreateUserParams(createParams)
	if err := validateCreateUserParams(createParams); err != nil {
		return Session{}, err
	}
	roles, _ := NormalizeRoleSet(createParams.Roles)
	createParams.Roles = []Role(roles)
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
	user, err := s.insertUser(ctx, tx, createParams, passwordHash)
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
	if err := validateCreateUserParams(params); err != nil {
		return User{}, err
	}
	roles, _ := NormalizeRoleSet(params.Roles)
	params.Roles = []Role(roles)
	passwordHash, err := HashPassword(params.Password)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin create user: %w", err)
	}
	defer tx.Rollback()
	user, err := s.insertUser(ctx, tx, params, passwordHash)
	if err != nil {
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
  u.id, u.email, u.display_name, u.role, u.disabled_at, u.must_change_password, u.created_at, u.updated_at
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
	user, err := s.hydrateUserRoles(ctx, s.db, session.User)
	if err != nil {
		return Session{}, false, err
	}
	session.User = user
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
SELECT id, email, display_name, role, disabled_at, must_change_password, created_at, updated_at
FROM users
ORDER BY created_at ASC, id ASC`)
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
		user, err = s.hydrateUserRoles(ctx, s.db, user)
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
SELECT id, email, display_name, password_hash, role, disabled_at, must_change_password, created_at, updated_at
FROM users
WHERE email = ?`, email)
	record, err := scanUserRecord(row)
	if err != nil {
		return userRecord{}, err
	}
	user, err := s.hydrateUserRoles(ctx, s.db, record.User)
	if err != nil {
		return userRecord{}, err
	}
	record.User = user
	return record, nil
}

func (s *Service) userByID(ctx context.Context, q queryer, id int64) (userRecord, error) {
	row := q.QueryRowContext(ctx, `
SELECT id, email, display_name, password_hash, role, disabled_at, must_change_password, created_at, updated_at
FROM users
WHERE id = ?`, id)
	record, err := scanUserRecord(row)
	if err != nil {
		return userRecord{}, err
	}
	user, err := s.hydrateUserRoles(ctx, q, record.User)
	if err != nil {
		return userRecord{}, err
	}
	record.User = user
	return record, nil
}

func (s *Service) insertUser(ctx context.Context, q queryer, params CreateUserParams, passwordHash string) (User, error) {
	now := s.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	roles := RoleSet(params.Roles)
	primaryRole := roles.Primary()
	result, err := q.ExecContext(ctx, `
INSERT INTO users(email, display_name, password_hash, role, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`, params.Email, params.DisplayName, passwordHash, primaryRole, nowText, nowText)
	if err != nil {
		return User{}, createUserError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("created user id: %w", err)
	}
	if err := s.insertUserRoles(ctx, q, id, roles, nowText); err != nil {
		return User{}, err
	}
	return User{ID: id, Email: params.Email, DisplayName: params.DisplayName, Role: primaryRole, Roles: roles, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Service) insertUserRoles(ctx context.Context, q queryer, userID int64, roles RoleSet, createdAt string) error {
	for _, role := range roles {
		if _, err := q.ExecContext(ctx, `
INSERT INTO user_roles(user_id, role, created_at)
VALUES (?, ?, ?)`, userID, role, createdAt); err != nil {
			return fmt.Errorf("create user role: %w", err)
		}
	}
	return nil
}

func (s *Service) hydrateUserRoles(ctx context.Context, q queryer, user User) (User, error) {
	roles, err := s.rolesForUser(ctx, q, user.ID)
	if err != nil {
		return User{}, err
	}
	if len(roles) == 0 && user.Role.Valid() {
		roles = RoleSet{user.Role}
	}
	user.Roles = roles
	user.Role = roles.Primary()
	return user, nil
}

func (s *Service) rolesForUser(ctx context.Context, q queryer, userID int64) (RoleSet, error) {
	rows, err := q.QueryContext(ctx, `SELECT role FROM user_roles WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	defer rows.Close()
	raw := make([]Role, 0)
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scan user role: %w", err)
		}
		raw = append(raw, Role(role))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user roles rows: %w", err)
	}
	roles, valid := NormalizeRoleSet(raw)
	if !valid {
		return nil, errors.New("stored user role is invalid")
	}
	return roles, nil
}

func (s *Service) insertSession(ctx context.Context, q queryer, user User, sessionID string, csrfToken string) (Session, error) {
	now := s.now().UTC()
	expiresAt := now.Add(s.sessionTTL)
	_, err := q.ExecContext(ctx, `
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)`, sessionID, user.ID, csrfToken, expiresAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return Session{ID: sessionID, CSRFToken: csrfToken, User: user, ExpiresAt: expiresAt, CreatedAt: now}, nil
}

func scanUser(row scanner) (User, error) {
	var user User
	var role string
	var disabledAt sql.NullString
	var mustChangePassword int
	var createdAt string
	var updatedAt string
	if err := row.Scan(&user.ID, &user.Email, &user.DisplayName, &role, &disabledAt, &mustChangePassword, &createdAt, &updatedAt); err != nil {
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
	user.Role = Role(role)
	if user.Role.Valid() {
		user.Roles = RoleSet{user.Role}
	}
	user.DisabledAt = parsedDisabledAt
	user.MustChangePassword = mustChangePassword != 0
	user.CreatedAt = parsedCreatedAt
	user.UpdatedAt = parsedUpdatedAt
	return user, nil
}

func scanUserRecord(row scanner) (userRecord, error) {
	var record userRecord
	var role string
	var disabledAt sql.NullString
	var mustChangePassword int
	var createdAt string
	var updatedAt string
	if err := row.Scan(&record.ID, &record.Email, &record.DisplayName, &record.passwordHash, &role, &disabledAt, &mustChangePassword, &createdAt, &updatedAt); err != nil {
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
	record.Role = Role(role)
	if record.Role.Valid() {
		record.Roles = RoleSet{record.Role}
	}
	record.DisabledAt = parsedDisabledAt
	record.MustChangePassword = mustChangePassword != 0
	record.CreatedAt = parsedCreatedAt
	record.UpdatedAt = parsedUpdatedAt
	return record, nil
}

func scanSession(row scanner) (Session, error) {
	var session Session
	var role string
	var expiresAt string
	var sessionCreatedAt string
	var disabledAt sql.NullString
	var mustChangePassword int
	var userCreatedAt string
	var userUpdatedAt string
	if err := row.Scan(&session.ID, &session.CSRFToken, &expiresAt, &sessionCreatedAt, &session.User.ID, &session.User.Email, &session.User.DisplayName, &role, &disabledAt, &mustChangePassword, &userCreatedAt, &userUpdatedAt); err != nil {
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
	session.User.Role = Role(role)
	if session.User.Role.Valid() {
		session.User.Roles = RoleSet{session.User.Role}
	}
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
	for i, role := range params.Roles {
		params.Roles[i] = Role(strings.TrimSpace(string(role)))
	}
	return params
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateCreateUserParams(params CreateUserParams) error {
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
	roles, valid := NormalizeRoleSet(params.Roles)
	if !valid {
		return ValidationError{Message: "role is invalid"}
	}
	if len(roles) == 0 {
		return ValidationError{Message: "at least one role is required"}
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
