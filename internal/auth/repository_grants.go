package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

// RepositoryGrant is one repository-scoped role held by a user.
// GrantedByUserID is the live "added by" attribution and is nil when the
// granting account was later deleted.
type RepositoryGrant struct {
	RepositoryID    int64
	UserID          int64
	Role            Role
	GrantedByUserID *int64
	GrantedAt       time.Time
}

type GrantRepositoryRoleParams struct {
	ActorUserID  int64
	RepositoryID int64
	UserID       int64
	Role         Role
}

type RevokeRepositoryRoleParams struct {
	ActorUserID  int64
	RepositoryID int64
	UserID       int64
	Role         Role
}

type SetUserRepositoryRolesParams struct {
	ActorUserID  int64
	RepositoryID int64
	UserID       int64
	Roles        []Role
}

// RepositoryGrantDetail adds the attribution needed by Users & Access without
// changing repository_grants storage. Migrated is proven from the matching
// migration audit evidence; a null granter without that evidence is presented
// as deleted/unavailable attribution instead of being guessed as migration.
type RepositoryGrantDetail struct {
	RepositoryGrant
	GranterDisplayName string
	Migrated           bool
}

// GrantsForUser loads the repository-aware authorization model for one
// user. It is an administrative state lookup, not an authentication
// gateway: it returns retained grants even for a disabled user so their
// access stays visible and manageable. Live request authorization must
// start from a valid enabled session, which SessionByID already enforces.
// Nothing consumes it on a live path yet; HTTP wiring happens at cutover.
func (s *Service) GrantsForUser(ctx context.Context, userID int64) (Grants, error) {
	if s == nil || s.db == nil {
		return Grants{}, errors.New("auth service has no database")
	}
	record, err := s.userByID(ctx, s.db, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Grants{}, ValidationError{Message: "user was not found"}
		}
		return Grants{}, err
	}
	return loadGrants(ctx, s.db, record.User)
}

// loadGrants builds the current repository-aware Grants for an
// already-hydrated user: the legacy role set filtered by NewGrants plus the
// live repository_grants rows read through q, so a transaction sees its own
// writes.
func loadGrants(ctx context.Context, q queryer, user User) (Grants, error) {
	scoped, err := scopedGrantsForUser(ctx, q, user.ID)
	if err != nil {
		return Grants{}, err
	}
	return NewGrants(user.Roles, scoped), nil
}

// GrantRepositoryRole atomically adds one repository-scoped role and its
// audit event; an audit persistence failure rolls the grant back. Only an
// enabled global Admin may grant, checked inside the transaction as
// defense in depth ahead of any handler-level authorization. The target
// may be disabled: their access stays administratively manageable while
// disabled-session rejection keeps them out of live requests.
func (s *Service) GrantRepositoryRole(ctx context.Context, params GrantRepositoryRoleParams) error {
	if s == nil || s.db == nil {
		return errors.New("auth service has no database")
	}
	if !params.Role.ValidForRepository() {
		return ValidationError{Message: "role cannot be granted on a repository"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin repository grant: %w", err)
	}
	defer tx.Rollback()

	if err := s.requireEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return err
	}
	if err := ensureRepositoryExists(ctx, tx, params.RepositoryID); err != nil {
		return err
	}
	if _, err := s.userByID(ctx, tx, params.UserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ValidationError{Message: "user was not found"}
		}
		return err
	}

	result, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (?, ?, ?, ?, ?)`, params.RepositoryID, params.UserID, params.Role, params.ActorUserID, s.now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("create repository grant: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("created repository grant rows: %w", err)
	}
	if inserted == 0 {
		return ValidationError{Message: "user already holds this role for the repository"}
	}

	event := repositoryGrantAuditEvent(audit.ActionRepositoryGrantAdded, params.ActorUserID, params.RepositoryID, params.UserID, params.Role)
	if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
		return fmt.Errorf("record repository grant audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit repository grant: %w", err)
	}
	return nil
}

// RevokeRepositoryRole atomically removes one repository-scoped role and
// its audit event; an audit persistence failure rolls the revoke back.
// Only an enabled global Admin may revoke, checked inside the transaction
// as defense in depth ahead of any handler-level authorization.
func (s *Service) RevokeRepositoryRole(ctx context.Context, params RevokeRepositoryRoleParams) error {
	if s == nil || s.db == nil {
		return errors.New("auth service has no database")
	}
	if !params.Role.ValidForRepository() {
		return ValidationError{Message: "role cannot be granted on a repository"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin repository grant revoke: %w", err)
	}
	defer tx.Rollback()

	if err := s.requireEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
DELETE FROM repository_grants
WHERE repository_id = ? AND user_id = ? AND role = ?`, params.RepositoryID, params.UserID, params.Role)
	if err != nil {
		return fmt.Errorf("revoke repository grant: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoked repository grant rows: %w", err)
	}
	if removed == 0 {
		return ValidationError{Message: "grant was not found"}
	}

	event := repositoryGrantAuditEvent(audit.ActionRepositoryGrantRevoked, params.ActorUserID, params.RepositoryID, params.UserID, params.Role)
	if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
		return fmt.Errorf("record repository grant revoke audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit repository grant revoke: %w", err)
	}
	return nil
}

// SetUserRepositoryRoles atomically replaces the desired scoped role set for
// one user and repository. Unchanged rows keep their attribution and timestamp;
// only actual additions/removals are audited.
func (s *Service) SetUserRepositoryRoles(ctx context.Context, params SetUserRepositoryRolesParams) error {
	if s == nil || s.db == nil {
		return errors.New("auth service has no database")
	}
	desired, err := normalizeRepositoryRoleSet(params.Roles)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin repository role set: %w", err)
	}
	defer tx.Rollback()

	if err := s.requireEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return err
	}
	if err := ensureRepositoryExists(ctx, tx, params.RepositoryID); err != nil {
		return err
	}
	if _, err := s.userByID(ctx, tx, params.UserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ValidationError{Message: "user was not found"}
		}
		return err
	}

	rows, err := tx.QueryContext(ctx, `
SELECT role
FROM repository_grants
WHERE repository_id = ? AND user_id = ?`, params.RepositoryID, params.UserID)
	if err != nil {
		return fmt.Errorf("list current repository roles: %w", err)
	}
	current := RoleSet{}
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role); err != nil {
			rows.Close()
			return fmt.Errorf("scan current repository role: %w", err)
		}
		current = append(current, role)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close current repository roles: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list current repository role rows: %w", err)
	}

	nowText := s.now().UTC().Format(time.RFC3339Nano)
	for _, role := range RepositoryRoles() {
		wasPresent := current.Contains(role)
		wantPresent := desired.Contains(role)
		switch {
		case !wasPresent && wantPresent:
			if _, err := tx.ExecContext(ctx, `
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (?, ?, ?, ?, ?)`, params.RepositoryID, params.UserID, role, params.ActorUserID, nowText); err != nil {
				return fmt.Errorf("add repository role: %w", err)
			}
			if err := audit.NewStoreTx(tx).Record(ctx, repositoryGrantAuditEvent(audit.ActionRepositoryGrantAdded, params.ActorUserID, params.RepositoryID, params.UserID, role)); err != nil {
				return fmt.Errorf("record repository role addition: %w", err)
			}
		case wasPresent && !wantPresent:
			if _, err := tx.ExecContext(ctx, `
DELETE FROM repository_grants
WHERE repository_id = ? AND user_id = ? AND role = ?`, params.RepositoryID, params.UserID, role); err != nil {
				return fmt.Errorf("remove repository role: %w", err)
			}
			if err := audit.NewStoreTx(tx).Record(ctx, repositoryGrantAuditEvent(audit.ActionRepositoryGrantRevoked, params.ActorUserID, params.RepositoryID, params.UserID, role)); err != nil {
				return fmt.Errorf("record repository role removal: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit repository role set: %w", err)
	}
	return nil
}

func normalizeRepositoryRoleSet(raw []Role) (RoleSet, error) {
	seen := make(map[Role]bool, len(raw))
	for _, role := range raw {
		role = Role(strings.TrimSpace(string(role)))
		if role == "" {
			continue
		}
		if !role.ValidForRepository() {
			return nil, ValidationError{Message: "repository role is invalid"}
		}
		seen[role] = true
	}
	roles := make(RoleSet, 0, len(seen))
	for _, role := range RepositoryRoles() {
		if seen[role] {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

// ListRepositoryGrants returns every grant on one repository.
func (s *Service) ListRepositoryGrants(ctx context.Context, repositoryID int64) ([]RepositoryGrant, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("auth service has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT repository_id, user_id, role, granted_by_user_id, granted_at
FROM repository_grants
WHERE repository_id = ?
ORDER BY user_id, role`, repositoryID)
	if err != nil {
		return nil, fmt.Errorf("list repository grants: %w", err)
	}
	defer rows.Close()

	grants := make([]RepositoryGrant, 0)
	for rows.Next() {
		var grant RepositoryGrant
		var role string
		var grantedBy sql.NullInt64
		var grantedAt string
		if err := rows.Scan(&grant.RepositoryID, &grant.UserID, &role, &grantedBy, &grantedAt); err != nil {
			return nil, fmt.Errorf("scan repository grant: %w", err)
		}
		grant.Role = Role(role)
		if grantedBy.Valid {
			id := grantedBy.Int64
			grant.GrantedByUserID = &id
		}
		parsedGrantedAt, err := time.Parse(time.RFC3339Nano, grantedAt)
		if err != nil {
			return nil, fmt.Errorf("parse repository grant granted_at: %w", err)
		}
		grant.GrantedAt = parsedGrantedAt
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list repository grants rows: %w", err)
	}
	return grants, nil
}

// ListUserRepositoryGrants returns retained grants and honest attribution for
// one user, including disabled users.
func (s *Service) ListUserRepositoryGrants(ctx context.Context, userID int64) ([]RepositoryGrantDetail, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("auth service has no database")
	}
	if _, err := s.userByID(ctx, s.db, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ValidationError{Message: "user was not found"}
		}
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT
  rg.repository_id,
  rg.user_id,
  rg.role,
  rg.granted_by_user_id,
  rg.granted_at,
  COALESCE(granter.display_name, ''),
  CASE WHEN rg.granted_by_user_id IS NULL AND EXISTS (
    SELECT 1
    FROM audit_events event
    WHERE event.action = 'repository_grant.added'
      AND event.subject_type = 'repository'
      AND event.subject_id = CAST(rg.repository_id AS TEXT)
      AND event.actor_user_id IS NULL
      AND event.created_at = rg.granted_at
      AND CASE WHEN json_valid(event.details_json)
        THEN json_extract(event.details_json, '$.provenance')
        ELSE NULL END = 'legacy_authorization_cutover'
      AND CASE WHEN json_valid(event.details_json)
        THEN json_extract(event.details_json, '$.user_id')
        ELSE NULL END = CAST(rg.user_id AS TEXT)
      AND CASE WHEN json_valid(event.details_json)
        THEN json_extract(event.details_json, '$.role')
        ELSE NULL END = rg.role
  ) THEN 1 ELSE 0 END
FROM repository_grants rg
LEFT JOIN users granter ON granter.id = rg.granted_by_user_id
WHERE rg.user_id = ?
ORDER BY rg.repository_id, rg.role`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user repository grants: %w", err)
	}
	defer rows.Close()
	details := make([]RepositoryGrantDetail, 0)
	for rows.Next() {
		var detail RepositoryGrantDetail
		var role string
		var grantedBy sql.NullInt64
		var grantedAt string
		var migrated int
		if err := rows.Scan(&detail.RepositoryID, &detail.UserID, &role, &grantedBy, &grantedAt, &detail.GranterDisplayName, &migrated); err != nil {
			return nil, fmt.Errorf("scan user repository grant: %w", err)
		}
		detail.Role = Role(role)
		if grantedBy.Valid {
			id := grantedBy.Int64
			detail.GrantedByUserID = &id
		}
		parsed, err := time.Parse(time.RFC3339Nano, grantedAt)
		if err != nil {
			return nil, fmt.Errorf("parse user repository grant granted_at: %w", err)
		}
		detail.GrantedAt = parsed
		detail.Migrated = migrated != 0
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user repository grant rows: %w", err)
	}
	return details, nil
}

// requireEnabledAdminActor guards manual access mutations: the actor must
// exist, be enabled, and hold the global Admin role in user_roles. A future
// system-owned provisioning path must get its own operation rather than
// impersonate an Admin here. Callers run it inside their transaction before
// mutating, so a rejected actor leaves no grant row and no audit event.
func (s *Service) requireEnabledAdminActor(ctx context.Context, q queryer, actorUserID int64) error {
	denied := ValidationError{Message: "only an enabled admin can change repository access"}
	if actorUserID <= 0 {
		return denied
	}
	record, err := s.userByID(ctx, q, actorUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return denied
		}
		return err
	}
	if record.Disabled() || !record.Roles.Contains(RoleAdmin) {
		return denied
	}
	return nil
}

// scopedGrantsForUser loads a user's repository-scoped roles. It is a plain
// query with no audit side effect.
func scopedGrantsForUser(ctx context.Context, q queryer, userID int64) (map[int64]RoleSet, error) {
	rows, err := q.QueryContext(ctx, `
SELECT repository_id, role
FROM repository_grants
WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user repository grants: %w", err)
	}
	defer rows.Close()

	scoped := make(map[int64]RoleSet)
	for rows.Next() {
		var repositoryID int64
		var role string
		if err := rows.Scan(&repositoryID, &role); err != nil {
			return nil, fmt.Errorf("scan user repository grant: %w", err)
		}
		scoped[repositoryID] = append(scoped[repositoryID], Role(role))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user repository grants rows: %w", err)
	}
	return scoped, nil
}

func ensureRepositoryExists(ctx context.Context, q queryer, repositoryID int64) error {
	if repositoryID <= 0 {
		return ValidationError{Message: "repository was not found"}
	}
	var id int64
	err := q.QueryRowContext(ctx, `SELECT id FROM repositories WHERE id = ?`, repositoryID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ValidationError{Message: "repository was not found"}
	}
	if err != nil {
		return fmt.Errorf("find repository: %w", err)
	}
	return nil
}

func repositoryGrantAuditEvent(action string, actorUserID int64, repositoryID int64, userID int64, role Role) audit.Event {
	details := map[string]string{
		"actor_kind": "user",
		"user_id":    strconv.FormatInt(userID, 10),
		"role":       string(role),
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	actor := actorUserID
	return audit.Event{
		ActorUserID: &actor,
		Action:      action,
		SubjectType: audit.SubjectTypeRepository,
		SubjectID:   strconv.FormatInt(repositoryID, 10),
		DetailsJSON: string(detailsJSON),
	}
}
