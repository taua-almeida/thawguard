package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const DefaultInvitationTTL = 7 * 24 * time.Hour

const (
	invitationIDPrefix        = "inv_"
	invitationIDRandomBytes   = 16
	invitationBearerBytes     = 32
	invitationStatusPending   = "pending"
	invitationStatusReissue   = "needs_reissue"
	invitationStatusAccepted  = "accepted"
	invitationStatusCancelled = "cancelled"

	invitationRevocationAuthorizerDisabled = "authorizer_disabled"
	invitationRevocationAdminRemoved       = "authorizer_admin_removed"
)

type InvitationRepositoryGrant struct {
	RepositoryID int64
	Role         Role
}

type CreateInvitationParams struct {
	ActorUserID      int64
	Email            string
	DisplayName      string
	IsAdmin          bool
	RepositoryGrants []InvitationRepositoryGrant
}

type ReissueInvitationParams struct {
	ActorUserID      int64
	InvitationID     string
	IsAdmin          bool
	RepositoryGrants []InvitationRepositoryGrant
}

type CancelInvitationParams struct {
	ActorUserID  int64
	InvitationID string
}

type InvitationCredential struct {
	InvitationID string
	Token        string
	ExpiresAt    time.Time
}

// ValidInvitationID reports whether id is the canonical inv_ encoding of
// exactly 16 bytes.
func ValidInvitationID(id string) bool {
	if len(id) != len(invitationIDPrefix)+base64.RawURLEncoding.EncodedLen(invitationIDRandomBytes) ||
		!strings.HasPrefix(id, invitationIDPrefix) {
		return false
	}
	suffix := id[len(invitationIDPrefix):]
	raw, err := base64.RawURLEncoding.DecodeString(suffix)
	if err != nil || len(raw) != invitationIDRandomBytes {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(raw) == suffix
}

func (s *Service) CreateInvitation(ctx context.Context, params CreateInvitationParams) (InvitationCredential, error) {
	if s == nil || s.db == nil {
		return InvitationCredential{}, errors.New("auth service has no database")
	}
	normalized, err := normalizeCreateInvitationParams(params)
	if err != nil {
		return InvitationCredential{}, err
	}
	invitationID, err := newInvitationID()
	if err != nil {
		return InvitationCredential{}, err
	}
	token, err := randomToken(invitationBearerBytes)
	if err != nil {
		return InvitationCredential{}, err
	}
	digest := sha256.Sum256([]byte(token))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return InvitationCredential{}, fmt.Errorf("begin invitation creation: %w", err)
	}
	defer tx.Rollback()
	if err := s.lockEnabledAdminActor(ctx, tx, normalized.ActorUserID); err != nil {
		return InvitationCredential{}, err
	}
	if err := rejectInvitationUserCollision(ctx, tx, normalized.Email); err != nil {
		return InvitationCredential{}, err
	}
	reserved, err := activeInvitationEmailExists(ctx, tx, normalized.Email)
	if err != nil {
		return InvitationCredential{}, err
	}
	if reserved {
		return InvitationCredential{}, ValidationError{Message: "an active invitation already exists for this email"}
	}
	if err := validateInvitationRepositories(ctx, tx, normalized.RepositoryGrants); err != nil {
		return InvitationCredential{}, err
	}

	now := s.now().UTC()
	expiresAt := persistedInvitationExpiry(now)
	nowText := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO invitations(
  id,
  status,
  canonical_email,
  display_name,
  token_digest,
  expires_at,
  is_admin,
  authorized_by_user_id,
  expected_repository_grant_count,
  created_at,
  updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invitationID,
		invitationStatusPending,
		normalized.Email,
		normalized.DisplayName,
		digest[:],
		expiresAt.UnixNano(),
		boolInt(normalized.IsAdmin),
		normalized.ActorUserID,
		len(normalized.RepositoryGrants),
		nowText,
		nowText,
	); err != nil {
		return InvitationCredential{}, fmt.Errorf("create invitation: %w", err)
	}
	if err := insertInvitationRepositoryGrants(ctx, tx, invitationID, normalized.RepositoryGrants); err != nil {
		return InvitationCredential{}, err
	}
	if err := recordInvitationAudit(ctx, tx, audit.ActionInvitationCreated, normalized.ActorUserID, invitationID, map[string]string{
		"expires_at":             expiresAt.Format(time.RFC3339Nano),
		"administrator":          strconv.FormatBool(normalized.IsAdmin),
		"repository_grant_count": strconv.Itoa(len(normalized.RepositoryGrants)),
	}); err != nil {
		return InvitationCredential{}, fmt.Errorf("record invitation creation audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return InvitationCredential{}, fmt.Errorf("commit invitation creation: %w", err)
	}
	return InvitationCredential{InvitationID: invitationID, Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Service) ReissueInvitation(ctx context.Context, params ReissueInvitationParams) (InvitationCredential, error) {
	if s == nil || s.db == nil {
		return InvitationCredential{}, errors.New("auth service has no database")
	}
	normalized, err := normalizeReissueInvitationParams(params)
	if err != nil {
		return InvitationCredential{}, err
	}
	token, err := randomToken(invitationBearerBytes)
	if err != nil {
		return InvitationCredential{}, err
	}
	digest := sha256.Sum256([]byte(token))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return InvitationCredential{}, fmt.Errorf("begin invitation reissue: %w", err)
	}
	defer tx.Rollback()
	if err := s.lockEnabledAdminActor(ctx, tx, normalized.ActorUserID); err != nil {
		return InvitationCredential{}, err
	}
	invitation, err := loadManagedInvitation(ctx, tx, normalized.InvitationID)
	if err != nil {
		return InvitationCredential{}, err
	}
	switch invitation.Status {
	case invitationStatusPending, invitationStatusReissue:
	case invitationStatusAccepted, invitationStatusCancelled:
		return InvitationCredential{}, ValidationError{Message: "invitation cannot be reissued"}
	default:
		return InvitationCredential{}, fmt.Errorf("invitation %q has unsupported status %q", normalized.InvitationID, invitation.Status)
	}
	if !invitation.CanonicalEmail.Valid || !invitation.IsAdmin.Valid || !invitation.ExpectedGrantCount.Valid {
		return InvitationCredential{}, errors.New("active invitation row is malformed")
	}
	if err := rejectInvitationUserCollision(ctx, tx, invitation.CanonicalEmail.String); err != nil {
		return InvitationCredential{}, err
	}
	if err := validateInvitationRepositories(ctx, tx, normalized.RepositoryGrants); err != nil {
		return InvitationCredential{}, err
	}
	var actualBefore int64
	if err := tx.QueryRowContext(ctx, `
SELECT count(*)
FROM invitation_repository_grants
WHERE invitation_id = ?`, normalized.InvitationID).Scan(&actualBefore); err != nil {
		return InvitationCredential{}, fmt.Errorf("count staged invitation repository grants: %w", err)
	}

	now := s.now().UTC()
	expiresAt := persistedInvitationExpiry(now)
	if _, err := tx.ExecContext(ctx, `DELETE FROM invitation_repository_grants WHERE invitation_id = ?`, normalized.InvitationID); err != nil {
		return InvitationCredential{}, fmt.Errorf("replace staged invitation repository grants: %w", err)
	}
	if err := insertInvitationRepositoryGrants(ctx, tx, normalized.InvitationID, normalized.RepositoryGrants); err != nil {
		return InvitationCredential{}, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE invitations
SET status = ?,
    token_digest = ?,
    expires_at = ?,
    is_admin = ?,
    authorized_by_user_id = ?,
    expected_repository_grant_count = ?,
    updated_at = ?
WHERE id = ?
  AND status IN (?, ?)`,
		invitationStatusPending,
		digest[:],
		expiresAt.UnixNano(),
		boolInt(normalized.IsAdmin),
		normalized.ActorUserID,
		len(normalized.RepositoryGrants),
		now.Format(time.RFC3339Nano),
		normalized.InvitationID,
		invitationStatusPending,
		invitationStatusReissue,
	)
	if err != nil {
		return InvitationCredential{}, fmt.Errorf("reissue invitation: %w", err)
	}
	if err := requireOneAffectedRow(result, "reissue invitation"); err != nil {
		return InvitationCredential{}, err
	}
	if err := recordInvitationAudit(ctx, tx, audit.ActionInvitationReissued, normalized.ActorUserID, normalized.InvitationID, map[string]string{
		"expires_at":                             expiresAt.Format(time.RFC3339Nano),
		"administrator_before":                   strconv.FormatBool(invitation.IsAdmin.Int64 != 0),
		"administrator_after":                    strconv.FormatBool(normalized.IsAdmin),
		"repository_grant_count_before_expected": strconv.FormatInt(invitation.ExpectedGrantCount.Int64, 10),
		"repository_grant_count_before_actual":   strconv.FormatInt(actualBefore, 10),
		"repository_grant_count_after":           strconv.Itoa(len(normalized.RepositoryGrants)),
	}); err != nil {
		return InvitationCredential{}, fmt.Errorf("record invitation reissue audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return InvitationCredential{}, fmt.Errorf("commit invitation reissue: %w", err)
	}
	return InvitationCredential{InvitationID: normalized.InvitationID, Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Service) CancelInvitation(ctx context.Context, params CancelInvitationParams) error {
	if s == nil || s.db == nil {
		return errors.New("auth service has no database")
	}
	if !ValidInvitationID(params.InvitationID) {
		return ValidationError{Message: "invitation was not found"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin invitation cancellation: %w", err)
	}
	defer tx.Rollback()
	if err := s.lockEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return err
	}
	invitation, err := loadManagedInvitation(ctx, tx, params.InvitationID)
	if err != nil {
		return err
	}
	switch invitation.Status {
	case invitationStatusPending, invitationStatusReissue:
	case invitationStatusAccepted, invitationStatusCancelled:
		return ValidationError{Message: "invitation cannot be cancelled"}
	default:
		return fmt.Errorf("invitation %q has unsupported status %q", params.InvitationID, invitation.Status)
	}

	nowText := s.now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `DELETE FROM invitation_repository_grants WHERE invitation_id = ?`, params.InvitationID); err != nil {
		return fmt.Errorf("delete staged invitation repository grants: %w", err)
	}
	if err := recordInvitationAudit(ctx, tx, audit.ActionInvitationCancelled, params.ActorUserID, params.InvitationID, nil); err != nil {
		return fmt.Errorf("record invitation cancellation audit event: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE invitations
SET status = ?,
    canonical_email = NULL,
    display_name = NULL,
    token_digest = NULL,
    expires_at = NULL,
    is_admin = NULL,
    authorized_by_user_id = NULL,
    expected_repository_grant_count = NULL,
    updated_at = ?
WHERE id = ?
  AND status IN (?, ?)`,
		invitationStatusCancelled,
		nowText,
		params.InvitationID,
		invitationStatusPending,
		invitationStatusReissue,
	)
	if err != nil {
		return fmt.Errorf("cancel invitation: %w", err)
	}
	if err := requireOneAffectedRow(result, "cancel invitation"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit invitation cancellation: %w", err)
	}
	return nil
}

type managedInvitation struct {
	Status             string
	CanonicalEmail     sql.NullString
	IsAdmin            sql.NullInt64
	ExpectedGrantCount sql.NullInt64
}

func loadManagedInvitation(ctx context.Context, q queryer, invitationID string) (managedInvitation, error) {
	var invitation managedInvitation
	err := q.QueryRowContext(ctx, `
SELECT status, canonical_email, is_admin, expected_repository_grant_count
FROM invitations
WHERE id = ?`, invitationID).Scan(
		&invitation.Status,
		&invitation.CanonicalEmail,
		&invitation.IsAdmin,
		&invitation.ExpectedGrantCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return managedInvitation{}, ValidationError{Message: "invitation was not found"}
	}
	if err != nil {
		return managedInvitation{}, fmt.Errorf("load invitation: %w", err)
	}
	return invitation, nil
}

func normalizeCreateInvitationParams(params CreateInvitationParams) (CreateInvitationParams, error) {
	params.Email = normalizeEmail(params.Email)
	params.DisplayName = strings.TrimSpace(params.DisplayName)
	if err := validateLocalIdentity(params.Email, params.DisplayName); err != nil {
		return CreateInvitationParams{}, err
	}
	grants, err := normalizeInvitationRepositoryGrants(params.RepositoryGrants)
	if err != nil {
		return CreateInvitationParams{}, err
	}
	params.RepositoryGrants = grants
	return params, nil
}

func normalizeReissueInvitationParams(params ReissueInvitationParams) (ReissueInvitationParams, error) {
	if !ValidInvitationID(params.InvitationID) {
		return ReissueInvitationParams{}, ValidationError{Message: "invitation was not found"}
	}
	grants, err := normalizeInvitationRepositoryGrants(params.RepositoryGrants)
	if err != nil {
		return ReissueInvitationParams{}, err
	}
	params.RepositoryGrants = grants
	return params, nil
}

func normalizeInvitationRepositoryGrants(raw []InvitationRepositoryGrant) ([]InvitationRepositoryGrant, error) {
	cloned := append([]InvitationRepositoryGrant(nil), raw...)
	seen := make(map[InvitationRepositoryGrant]struct{}, len(cloned))
	normalized := make([]InvitationRepositoryGrant, 0, len(cloned))
	for _, grant := range cloned {
		grant.Role = Role(strings.TrimSpace(string(grant.Role)))
		if grant.RepositoryID <= 0 {
			return nil, ValidationError{Message: "repository was not found"}
		}
		if !grant.Role.ValidForRepository() {
			return nil, ValidationError{Message: "repository role is invalid"}
		}
		if _, exists := seen[grant]; exists {
			continue
		}
		seen[grant] = struct{}{}
		normalized = append(normalized, grant)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].RepositoryID != normalized[j].RepositoryID {
			return normalized[i].RepositoryID < normalized[j].RepositoryID
		}
		return normalized[i].Role < normalized[j].Role
	})
	return normalized, nil
}

func validateInvitationRepositories(ctx context.Context, q queryer, grants []InvitationRepositoryGrant) error {
	var previousID int64
	for _, grant := range grants {
		if grant.RepositoryID == previousID {
			continue
		}
		if err := ensureRepositoryExists(ctx, q, grant.RepositoryID); err != nil {
			return err
		}
		previousID = grant.RepositoryID
	}
	return nil
}

func insertInvitationRepositoryGrants(
	ctx context.Context,
	tx *sql.Tx,
	invitationID string,
	grants []InvitationRepositoryGrant,
) error {
	for _, grant := range grants {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO invitation_repository_grants(invitation_id, repository_id, role)
VALUES (?, ?, ?)`, invitationID, grant.RepositoryID, grant.Role); err != nil {
			return fmt.Errorf("stage invitation repository grant: %w", err)
		}
	}
	return nil
}

func rejectInvitationUserCollision(ctx context.Context, q queryer, canonicalEmail string) error {
	var exists int
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)`, canonicalEmail).Scan(&exists); err != nil {
		return fmt.Errorf("check invitation user collision: %w", err)
	}
	if exists != 0 {
		return ValidationError{Message: "user email already exists"}
	}
	return nil
}

func activeInvitationEmailExists(ctx context.Context, q queryer, canonicalEmail string) (bool, error) {
	var exists int
	if err := q.QueryRowContext(ctx, `
SELECT EXISTS(
  SELECT 1
  FROM invitations
  WHERE canonical_email = ?
    AND status IN (?, ?)
)`, canonicalEmail, invitationStatusPending, invitationStatusReissue).Scan(&exists); err != nil {
		return false, fmt.Errorf("check active invitation email: %w", err)
	}
	return exists != 0, nil
}

func newInvitationID() (string, error) {
	suffix, err := randomToken(invitationIDRandomBytes)
	if err != nil {
		return "", err
	}
	return invitationIDPrefix + suffix, nil
}

func persistedInvitationExpiry(now time.Time) time.Time {
	return time.Unix(0, now.UTC().Add(DefaultInvitationTTL).UnixNano()).UTC()
}

func recordInvitationAudit(
	ctx context.Context,
	tx *sql.Tx,
	action string,
	actorUserID int64,
	invitationID string,
	details map[string]string,
) error {
	if details == nil {
		details = make(map[string]string, 1)
	}
	details["actor_kind"] = "user"
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode invitation audit details: %w", err)
	}
	actor := actorUserID
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      action,
		SubjectType: audit.SubjectTypeInvitation,
		SubjectID:   invitationID,
		DetailsJSON: string(detailsJSON),
	}); err != nil {
		return err
	}
	return nil
}

func invalidateInvitationsAuthorizedBy(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	authorizerUserID int64,
	reason string,
	updatedAt time.Time,
) error {
	switch reason {
	case invitationRevocationAuthorizerDisabled, invitationRevocationAdminRemoved:
	default:
		return fmt.Errorf("unsupported invitation authorization revocation reason %q", reason)
	}
	rows, err := tx.QueryContext(ctx, `
SELECT id
FROM invitations
WHERE status = ?
  AND authorized_by_user_id = ?
ORDER BY id`, invitationStatusPending, authorizerUserID)
	if err != nil {
		return fmt.Errorf("list invitations authorized by user: %w", err)
	}
	invitationIDs := make([]string, 0)
	for rows.Next() {
		var invitationID string
		if err := rows.Scan(&invitationID); err != nil {
			rows.Close()
			return fmt.Errorf("scan invitation authorized by user: %w", err)
		}
		invitationIDs = append(invitationIDs, invitationID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("list invitations authorized by user rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close invitations authorized by user rows: %w", err)
	}
	if len(invitationIDs) == 0 {
		return nil
	}

	result, err := tx.ExecContext(ctx, `
UPDATE invitations
SET status = ?,
    token_digest = NULL,
    expires_at = NULL,
    authorized_by_user_id = NULL,
    updated_at = ?
WHERE status = ?
  AND authorized_by_user_id = ?`,
		invitationStatusReissue,
		updatedAt.UTC().Format(time.RFC3339Nano),
		invitationStatusPending,
		authorizerUserID,
	)
	if err != nil {
		return fmt.Errorf("invalidate invitation credentials: %w", err)
	}
	invalidated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count invalidated invitation credentials: %w", err)
	}
	if invalidated != int64(len(invitationIDs)) {
		return fmt.Errorf("invalidate invitation credentials affected %d rows, expected %d", invalidated, len(invitationIDs))
	}
	for _, invitationID := range invitationIDs {
		if err := recordInvitationAudit(
			ctx,
			tx,
			audit.ActionInvitationAuthorizationRevoked,
			actorUserID,
			invitationID,
			map[string]string{"reason": reason},
		); err != nil {
			return fmt.Errorf("record invitation authorization revocation audit event: %w", err)
		}
	}
	return nil
}

func requireOneAffectedRow(result sql.Result, operation string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count %s rows: %w", operation, err)
	}
	if rows != 1 {
		return fmt.Errorf("%s affected %d rows", operation, rows)
	}
	return nil
}
