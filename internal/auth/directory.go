package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const UserDirectorySearchMaxLength = 120

type UserDirectoryQuery struct {
	Search       string
	RepositoryID int64
}

type UserDirectoryEntry struct {
	User
	IsAdmin         bool
	RepositoryCount int
	HasViewer       bool
	HasFreezer      bool
	HasThawApprover bool
}

// GetUser loads one account with only explicit Admin as live global authority.
// Retained repository grants are loaded separately by the detail page.
func (s *Service) GetUser(ctx context.Context, userID int64) (User, error) {
	if s == nil || s.db == nil {
		return User{}, errors.New("auth service has no database")
	}
	record, err := s.userByID(ctx, s.db, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ValidationError{Message: "user was not found"}
	}
	if err != nil {
		return User{}, err
	}
	return record.User, nil
}

// ListUsersDirectory applies search and repository membership inside SQL and
// returns one stable, unpaginated directory. Admins match every existing
// repository filter; non-Admins match only an exact repository grant.
func (s *Service) ListUsersDirectory(ctx context.Context, query UserDirectoryQuery) ([]UserDirectoryEntry, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("auth service has no database")
	}
	query.Search = strings.TrimSpace(query.Search)
	if len(query.Search) > UserDirectorySearchMaxLength {
		return nil, ValidationError{Message: "search is too long"}
	}
	if query.RepositoryID < 0 {
		return nil, ValidationError{Message: "repository filter is invalid"}
	}
	if query.RepositoryID > 0 {
		if err := ensureRepositoryExists(ctx, s.db, query.RepositoryID); err != nil {
			return nil, err
		}
	}
	pattern := "%" + escapeLike(strings.ToLower(query.Search)) + "%"
	rows, err := s.db.QueryContext(ctx, `
SELECT
  u.id,
  u.email,
  u.display_name,
  u.role,
  u.disabled_at,
  u.must_change_password,
  u.created_at,
  u.updated_at,
  EXISTS (
    SELECT 1 FROM user_roles admin_role
    WHERE admin_role.user_id = u.id AND admin_role.role = 'admin'
  ) AS is_admin,
  (SELECT count(DISTINCT grants.repository_id) FROM repository_grants grants WHERE grants.user_id = u.id) AS repository_count,
  EXISTS (SELECT 1 FROM repository_grants grants WHERE grants.user_id = u.id AND grants.role = 'viewer') AS has_viewer,
  EXISTS (SELECT 1 FROM repository_grants grants WHERE grants.user_id = u.id AND grants.role = 'freezer') AS has_freezer,
  EXISTS (SELECT 1 FROM repository_grants grants WHERE grants.user_id = u.id AND grants.role = 'thaw_approver') AS has_thaw_approver
FROM users u
WHERE (
    ? = ''
    OR lower(u.display_name) LIKE ? ESCAPE '\'
    OR lower(u.email) LIKE ? ESCAPE '\'
  )
  AND (
    ? = 0
    OR EXISTS (
      SELECT 1 FROM user_roles admin_role
      WHERE admin_role.user_id = u.id AND admin_role.role = 'admin'
    )
    OR EXISTS (
      SELECT 1 FROM repository_grants grants
      WHERE grants.user_id = u.id AND grants.repository_id = ?
    )
  )
ORDER BY lower(trim(u.display_name)), lower(u.email), u.id`, query.Search, pattern, pattern, query.RepositoryID, query.RepositoryID)
	if err != nil {
		return nil, fmt.Errorf("list users directory: %w", err)
	}
	defer rows.Close()
	entries := make([]UserDirectoryEntry, 0)
	for rows.Next() {
		var entry UserDirectoryEntry
		var isAdmin, hasViewer, hasFreezer, hasThaw int
		if err := scanDirectoryEntry(rows, &entry, &isAdmin, &hasViewer, &hasFreezer, &hasThaw); err != nil {
			return nil, err
		}
		entry.IsAdmin = isAdmin != 0
		entry.HasViewer = hasViewer != 0
		entry.HasFreezer = hasFreezer != 0
		entry.HasThawApprover = hasThaw != 0
		if entry.IsAdmin {
			entry.Roles = RoleSet{RoleAdmin}
			entry.Role = RoleAdmin
		} else {
			entry.Roles = nil
			entry.Role = ""
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users directory rows: %w", err)
	}
	return entries, nil
}

func scanDirectoryEntry(row scanner, entry *UserDirectoryEntry, isAdmin, hasViewer, hasFreezer, hasThaw *int) error {
	var storedRole string
	var disabledAt sql.NullString
	var mustChange int
	var createdAt, updatedAt string
	if err := row.Scan(
		&entry.ID,
		&entry.Email,
		&entry.DisplayName,
		&storedRole,
		&disabledAt,
		&mustChange,
		&createdAt,
		&updatedAt,
		isAdmin,
		&entry.RepositoryCount,
		hasViewer,
		hasFreezer,
		hasThaw,
	); err != nil {
		return fmt.Errorf("scan users directory entry: %w", err)
	}
	parsedCreatedAt, err := parseTime(createdAt)
	if err != nil {
		return fmt.Errorf("parse directory user created_at: %w", err)
	}
	parsedUpdatedAt, err := parseTime(updatedAt)
	if err != nil {
		return fmt.Errorf("parse directory user updated_at: %w", err)
	}
	parsedDisabledAt, err := parseOptionalTime(disabledAt)
	if err != nil {
		return fmt.Errorf("parse directory user disabled_at: %w", err)
	}
	entry.DisabledAt = parsedDisabledAt
	entry.MustChangePassword = mustChange != 0
	entry.CreatedAt = parsedCreatedAt
	entry.UpdatedAt = parsedUpdatedAt
	return nil
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}
