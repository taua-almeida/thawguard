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

// ReplaceInvitationLinkParams carries no authority fields on purpose:
// replacement preserves whatever the retired invitation already stages, so a
// caller cannot smuggle an Admin flag or a repository grant through it.
type ReplaceInvitationLinkParams struct {
	ActorUserID  int64
	InvitationID string
}

// InvitationLinkReplacement describes the invitation that took over from
// ReplacedInvitationID. Token is the only copy of the new bearer that will ever
// exist; the row keeps a digest.
type InvitationLinkReplacement struct {
	ReplacedInvitationID string
	InvitationID         string
	Email                string
	DisplayName          string
	IsAdmin              bool
	RepositoryGrants     []InvitationRepositoryGrant
	Token                string
	ExpiresAt            time.Time
}

type InvitationCredential struct {
	InvitationID string
	Token        string
	ExpiresAt    time.Time
}

// InvalidInvitationError hides whether an invitation bearer or its current
// lifecycle state caused an expected acceptance rejection.
type InvalidInvitationError struct{}

func (InvalidInvitationError) Error() string {
	return "invitation is invalid or expired"
}

// IsInvalidInvitation reports whether acceptance failed through the generic
// invitation rejection contract.
func IsInvalidInvitation(err error) bool {
	var invitationErr InvalidInvitationError
	return errors.As(err, &invitationErr)
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

// ReplaceInvitationLink retires one active invitation and issues a brand-new
// invitation carrying the retired invitation's email, display name, Admin
// flag, and the staged repository grants whose repositories still exist when
// the transaction owns SQLite's writer slot.
//
// The retired invitation ID is the replay fence. Once it is tombstoned, a
// refresh, a double submit, or a replayed POST against the same ID finds
// nothing to replace and cannot rotate the link that was just handed out. That
// is why this is one transaction and not a Cancel followed by a Create: the
// email reservation must move between the two rows without ever being free,
// and any later failure must roll both sides back.
func (s *Service) ReplaceInvitationLink(ctx context.Context, params ReplaceInvitationLinkParams) (InvitationLinkReplacement, error) {
	if s == nil || s.db == nil {
		return InvitationLinkReplacement{}, errors.New("auth service has no database")
	}
	if !ValidInvitationID(params.InvitationID) {
		return InvitationLinkReplacement{}, ValidationError{Message: "invitation was not found"}
	}
	invitationID, err := newInvitationID()
	if err != nil {
		return InvitationLinkReplacement{}, err
	}
	token, err := randomToken(invitationBearerBytes)
	if err != nil {
		return InvitationLinkReplacement{}, err
	}
	digest := sha256.Sum256([]byte(token))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return InvitationLinkReplacement{}, fmt.Errorf("begin invitation link replacement: %w", err)
	}
	defer tx.Rollback()

	// BeginTx is deferred in SQLite, so this actor lock is the first write and
	// every authoritative read plus the clock sample below happen after this
	// transaction owns the writer slot.
	if err := s.lockEnabledAdminActor(ctx, tx, params.ActorUserID); err != nil {
		return InvitationLinkReplacement{}, err
	}
	replaced, err := loadReplaceableInvitation(ctx, tx, params.InvitationID)
	if err != nil {
		return InvitationLinkReplacement{}, err
	}
	switch replaced.Status {
	// Expired and drifted invitations are ordinary pending rows, so an Admin
	// can recover from either without restaging identity.
	case invitationStatusPending, invitationStatusReissue:
	case invitationStatusAccepted, invitationStatusCancelled:
		return InvitationLinkReplacement{}, ValidationError{Message: "invitation link cannot be replaced"}
	default:
		return InvitationLinkReplacement{}, fmt.Errorf("invitation %q has unsupported status %q", params.InvitationID, replaced.Status)
	}
	if !replaced.CanonicalEmail.Valid || !replaced.DisplayName.Valid || !replaced.IsAdmin.Valid || !replaced.ExpectedGrantCount.Valid {
		return InvitationLinkReplacement{}, errors.New("active invitation row is malformed")
	}
	email := replaced.CanonicalEmail.String
	displayName := replaced.DisplayName.String
	if email != normalizeEmail(email) ||
		displayName != strings.TrimSpace(displayName) ||
		validateLocalIdentity(email, displayName) != nil ||
		(replaced.IsAdmin.Int64 != 0 && replaced.IsAdmin.Int64 != 1) ||
		replaced.ExpectedGrantCount.Int64 < 0 {
		return InvitationLinkReplacement{}, errors.New("active invitation row is malformed")
	}
	isAdmin := replaced.IsAdmin.Int64 != 0
	if err := rejectInvitationUserCollision(ctx, tx, email); err != nil {
		return InvitationLinkReplacement{}, err
	}
	var actualBefore int64
	if err := tx.QueryRowContext(ctx, `
SELECT count(*)
FROM invitation_repository_grants
WHERE invitation_id = ?`, params.InvitationID).Scan(&actualBefore); err != nil {
		return InvitationLinkReplacement{}, fmt.Errorf("count staged invitation repository grants: %w", err)
	}
	grants, err := loadSurvivingInvitationRepositoryGrants(ctx, tx, params.InvitationID)
	if err != nil {
		return InvitationLinkReplacement{}, err
	}

	now := s.now().UTC()
	expiresAt := persistedInvitationExpiry(now)
	nowText := now.Format(time.RFC3339Nano)

	if _, err := tx.ExecContext(ctx, `DELETE FROM invitation_repository_grants WHERE invitation_id = ?`, params.InvitationID); err != nil {
		return InvitationLinkReplacement{}, fmt.Errorf("delete replaced invitation repository grants: %w", err)
	}
	// Redacting the retired row first releases the active-email reservation so
	// the new row can claim it inside this same transaction.
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
		return InvitationLinkReplacement{}, fmt.Errorf("retire replaced invitation: %w", err)
	}
	if err := requireOneAffectedRow(result, "retire replaced invitation"); err != nil {
		return InvitationLinkReplacement{}, err
	}
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
		email,
		displayName,
		digest[:],
		expiresAt.UnixNano(),
		boolInt(isAdmin),
		params.ActorUserID,
		len(grants),
		nowText,
		nowText,
	); err != nil {
		return InvitationLinkReplacement{}, fmt.Errorf("create replacement invitation: %w", err)
	}
	if err := insertInvitationRepositoryGrants(ctx, tx, invitationID, grants); err != nil {
		return InvitationLinkReplacement{}, err
	}
	if err := recordInvitationAudit(ctx, tx, audit.ActionInvitationReplaced, params.ActorUserID, invitationID, map[string]string{
		"replaced_invitation_id":                 params.InvitationID,
		"expires_at":                             expiresAt.Format(time.RFC3339Nano),
		"administrator":                          strconv.FormatBool(isAdmin),
		"repository_grant_count_before_expected": strconv.FormatInt(replaced.ExpectedGrantCount.Int64, 10),
		"repository_grant_count_before_actual":   strconv.FormatInt(actualBefore, 10),
		"repository_grant_count_after":           strconv.Itoa(len(grants)),
	}); err != nil {
		return InvitationLinkReplacement{}, fmt.Errorf("record invitation link replacement audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return InvitationLinkReplacement{}, fmt.Errorf("commit invitation link replacement: %w", err)
	}
	return InvitationLinkReplacement{
		ReplacedInvitationID: params.InvitationID,
		InvitationID:         invitationID,
		Email:                email,
		DisplayName:          displayName,
		IsAdmin:              isAdmin,
		RepositoryGrants:     grants,
		Token:                token,
		ExpiresAt:            expiresAt,
	}, nil
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

// AcceptInvitation atomically creates a local-password user and materializes
// the identity and authority staged on a currently valid invitation. It does
// not create a session.
func (s *Service) AcceptInvitation(ctx context.Context, token, password string) (User, error) {
	if s == nil || s.db == nil {
		return User{}, errors.New("auth service has no database")
	}
	digest, ok := invitationBearerDigest(token)
	if !ok {
		return User{}, InvalidInvitationError{}
	}
	if err := s.preflightInvitationAcceptance(ctx, digest, s.now().UTC()); err != nil {
		return User{}, err
	}
	if err := validatePassword(password); err != nil {
		return User{}, err
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return User{}, fmt.Errorf("hash invitation password: %w", err)
	}
	return s.commitInvitationAcceptance(ctx, digest, passwordHash)
}

type acceptanceInvitation struct {
	ID                 string
	CanonicalEmail     string
	DisplayName        string
	ExpiresAt          int64
	IsAdmin            int64
	AuthorizedBy       sql.NullInt64
	ExpectedGrantCount int64
}

func (s *Service) preflightInvitationAcceptance(
	ctx context.Context,
	digest [sha256.Size]byte,
	now time.Time,
) error {
	invitation, err := loadAcceptanceInvitation(ctx, s.db, digest)
	if err != nil {
		return err
	}
	_, err = validateAcceptanceInvitation(ctx, s.db, invitation, now)
	return err
}

func (s *Service) commitInvitationAcceptance(
	ctx context.Context,
	digest [sha256.Size]byte,
	passwordHash string,
) (User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin invitation acceptance: %w", err)
	}
	defer tx.Rollback()

	// BeginTx is deferred in SQLite. This digest-guarded no-op is deliberately
	// the first write so every final read and the final clock sample happen
	// after this transaction owns the writer slot.
	result, err := tx.ExecContext(ctx, `
UPDATE invitations
SET status = status
WHERE token_digest = ?
  AND status = ?`, digest[:], invitationStatusPending)
	if err != nil {
		return User{}, fmt.Errorf("claim invitation for acceptance: %w", err)
	}
	claimed, err := result.RowsAffected()
	if err != nil {
		return User{}, fmt.Errorf("count claimed invitations: %w", err)
	}
	if claimed == 0 {
		return User{}, InvalidInvitationError{}
	}
	if claimed != 1 {
		return User{}, fmt.Errorf("claim invitation affected %d rows", claimed)
	}

	now := s.now().UTC()
	invitation, err := loadAcceptanceInvitation(ctx, tx, digest)
	if err != nil {
		return User{}, err
	}
	grants, err := validateAcceptanceInvitation(ctx, tx, invitation, now)
	if err != nil {
		return User{}, err
	}

	user, err := s.insertUser(ctx, tx, CreateUserParams{
		Email:       invitation.CanonicalEmail,
		DisplayName: invitation.DisplayName,
	}, passwordHash, false, invitation.IsAdmin != 0)
	if err != nil {
		if IsValidationError(err) {
			return User{}, InvalidInvitationError{}
		}
		return User{}, fmt.Errorf("create invited user: %w", err)
	}
	if err := insertAcceptedRepositoryGrants(ctx, tx, user.ID, invitation.AuthorizedBy.Int64, grants, now); err != nil {
		return User{}, err
	}

	result, err = tx.ExecContext(ctx, `
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
  AND token_digest = ?
  AND status = ?`,
		invitationStatusAccepted,
		now.Format(time.RFC3339Nano),
		invitation.ID,
		digest[:],
		invitationStatusPending,
	)
	if err != nil {
		return User{}, fmt.Errorf("redact accepted invitation: %w", err)
	}
	transitioned, err := result.RowsAffected()
	if err != nil {
		return User{}, fmt.Errorf("count accepted invitation transitions: %w", err)
	}
	if transitioned == 0 {
		return User{}, InvalidInvitationError{}
	}
	if transitioned != 1 {
		return User{}, fmt.Errorf("accept invitation affected %d rows", transitioned)
	}

	result, err = tx.ExecContext(ctx, `DELETE FROM invitation_repository_grants WHERE invitation_id = ?`, invitation.ID)
	if err != nil {
		return User{}, fmt.Errorf("delete accepted invitation repository grants: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return User{}, fmt.Errorf("count deleted invitation repository grants: %w", err)
	}
	if deleted != int64(len(grants)) {
		return User{}, InvalidInvitationError{}
	}
	if err := recordInvitationAcceptanceAudits(ctx, tx, invitation, user, grants); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit invitation acceptance: %w", err)
	}
	return user, nil
}

func loadAcceptanceInvitation(
	ctx context.Context,
	q queryer,
	digest [sha256.Size]byte,
) (acceptanceInvitation, error) {
	var invitation acceptanceInvitation
	err := q.QueryRowContext(ctx, `
SELECT
  id,
  canonical_email,
  display_name,
  expires_at,
  is_admin,
  authorized_by_user_id,
  expected_repository_grant_count
FROM invitations
WHERE token_digest = ?
  AND status = ?`, digest[:], invitationStatusPending).Scan(
		&invitation.ID,
		&invitation.CanonicalEmail,
		&invitation.DisplayName,
		&invitation.ExpiresAt,
		&invitation.IsAdmin,
		&invitation.AuthorizedBy,
		&invitation.ExpectedGrantCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return acceptanceInvitation{}, InvalidInvitationError{}
	}
	if err != nil {
		return acceptanceInvitation{}, fmt.Errorf("load invitation for acceptance: %w", err)
	}
	return invitation, nil
}

func validateAcceptanceInvitation(
	ctx context.Context,
	q queryer,
	invitation acceptanceInvitation,
	now time.Time,
) ([]InvitationRepositoryGrant, error) {
	if !ValidInvitationID(invitation.ID) ||
		invitation.CanonicalEmail != normalizeEmail(invitation.CanonicalEmail) ||
		invitation.DisplayName != strings.TrimSpace(invitation.DisplayName) ||
		validateLocalIdentity(invitation.CanonicalEmail, invitation.DisplayName) != nil ||
		invitation.ExpiresAt <= now.UTC().UnixNano() ||
		(invitation.IsAdmin != 0 && invitation.IsAdmin != 1) ||
		!invitation.AuthorizedBy.Valid || invitation.AuthorizedBy.Int64 <= 0 ||
		invitation.ExpectedGrantCount < 0 {
		return nil, InvalidInvitationError{}
	}

	var authorizerEligible int
	if err := q.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM users u
  JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
  WHERE u.id = ?
    AND u.disabled_at IS NULL
)`, invitation.AuthorizedBy.Int64).Scan(&authorizerEligible); err != nil {
		return nil, fmt.Errorf("check invitation authorizer: %w", err)
	}
	if authorizerEligible == 0 {
		return nil, InvalidInvitationError{}
	}

	var emailCollision int
	if err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE email = ?)`, invitation.CanonicalEmail).Scan(&emailCollision); err != nil {
		return nil, fmt.Errorf("check invited user collision: %w", err)
	}
	if emailCollision != 0 {
		return nil, InvalidInvitationError{}
	}

	grants, err := loadAcceptanceRepositoryGrants(ctx, q, invitation.ID)
	if err != nil {
		return nil, err
	}
	if int64(len(grants)) != invitation.ExpectedGrantCount {
		return nil, InvalidInvitationError{}
	}
	return grants, nil
}

func loadAcceptanceRepositoryGrants(
	ctx context.Context,
	q queryer,
	invitationID string,
) ([]InvitationRepositoryGrant, error) {
	rows, err := q.QueryContext(ctx, `
SELECT staged.repository_id, staged.role, repositories.id
FROM invitation_repository_grants staged
LEFT JOIN repositories ON repositories.id = staged.repository_id
WHERE staged.invitation_id = ?
ORDER BY staged.repository_id, staged.role`, invitationID)
	if err != nil {
		return nil, fmt.Errorf("load invitation repository grants for acceptance: %w", err)
	}
	defer rows.Close()

	grants := make([]InvitationRepositoryGrant, 0)
	for rows.Next() {
		var grant InvitationRepositoryGrant
		var repositoryID sql.NullInt64
		if err := rows.Scan(&grant.RepositoryID, &grant.Role, &repositoryID); err != nil {
			return nil, fmt.Errorf("scan invitation repository grant for acceptance: %w", err)
		}
		if !repositoryID.Valid || repositoryID.Int64 != grant.RepositoryID || !grant.Role.ValidForRepository() {
			return nil, InvalidInvitationError{}
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load invitation repository grant rows for acceptance: %w", err)
	}
	return grants, nil
}

func insertAcceptedRepositoryGrants(
	ctx context.Context,
	tx *sql.Tx,
	userID int64,
	authorizerUserID int64,
	grants []InvitationRepositoryGrant,
	grantedAt time.Time,
) error {
	for _, grant := range grants {
		result, err := tx.ExecContext(ctx, `
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (?, ?, ?, ?, ?)`,
			grant.RepositoryID,
			userID,
			grant.Role,
			authorizerUserID,
			grantedAt.UTC().Format(time.RFC3339Nano),
		)
		if err != nil {
			return fmt.Errorf("materialize invitation repository grant: %w", err)
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count materialized invitation repository grants: %w", err)
		}
		if inserted != 1 {
			return InvalidInvitationError{}
		}
	}
	return nil
}

func recordInvitationAcceptanceAudits(
	ctx context.Context,
	tx *sql.Tx,
	invitation acceptanceInvitation,
	user User,
	grants []InvitationRepositoryGrant,
) error {
	store := audit.NewStoreTx(tx)
	userID := strconv.FormatInt(user.ID, 10)
	acceptedDetails, err := json.Marshal(map[string]string{
		"accepted_user_id": userID,
		"actor_kind":       audit.ActorKindInvitationLink,
	})
	if err != nil {
		return fmt.Errorf("encode invitation acceptance audit details: %w", err)
	}
	if err := store.Record(ctx, audit.Event{
		Action:      audit.ActionInvitationAccepted,
		SubjectType: audit.SubjectTypeInvitation,
		SubjectID:   invitation.ID,
		DetailsJSON: string(acceptedDetails),
	}); err != nil {
		return fmt.Errorf("record invitation acceptance audit event: %w", err)
	}

	createdDetails, err := json.Marshal(map[string]string{
		"actor_kind": audit.ActorKindInvitationLink,
		"onboarding": "invitation",
		"sign_in":    "password",
	})
	if err != nil {
		return fmt.Errorf("encode invited user creation audit details: %w", err)
	}
	if err := store.Record(ctx, audit.Event{
		Action:      audit.ActionUserCreated,
		SubjectType: audit.SubjectTypeUser,
		SubjectID:   userID,
		DetailsJSON: string(createdDetails),
	}); err != nil {
		return fmt.Errorf("record invited user creation audit event: %w", err)
	}

	authorizerUserID := invitation.AuthorizedBy.Int64
	if invitation.IsAdmin != 0 {
		event := userAuditEvent(audit.ActionUserRolesUpdated, authorizerUserID, user.ID, map[string]string{
			"provenance":   "invitation_acceptance",
			"roles_after":  "admin",
			"roles_before": "none",
		})
		if err := store.Record(ctx, event); err != nil {
			return fmt.Errorf("record accepted Admin audit event: %w", err)
		}
	}

	for _, grant := range grants {
		grantDetails, err := json.Marshal(map[string]string{
			"actor_kind": "user",
			"provenance": "invitation_acceptance",
			"role":       string(grant.Role),
			"user_id":    userID,
		})
		if err != nil {
			return fmt.Errorf("encode accepted repository grant audit details: %w", err)
		}
		actor := authorizerUserID
		if err := store.Record(ctx, audit.Event{
			ActorUserID: &actor,
			Action:      audit.ActionRepositoryGrantAdded,
			SubjectType: audit.SubjectTypeRepository,
			SubjectID:   strconv.FormatInt(grant.RepositoryID, 10),
			DetailsJSON: string(grantDetails),
		}); err != nil {
			return fmt.Errorf("record accepted repository grant audit event: %w", err)
		}
	}
	return nil
}

func invitationBearerDigest(token string) ([sha256.Size]byte, bool) {
	if len(token) != base64.RawURLEncoding.EncodedLen(invitationBearerBytes) {
		return [sha256.Size]byte{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != invitationBearerBytes || base64.RawURLEncoding.EncodeToString(raw) != token {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
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

// replaceableInvitation is the managed shape plus the display name, because
// replacement copies the staged identity forward instead of restaging it.
type replaceableInvitation struct {
	Status             string
	CanonicalEmail     sql.NullString
	DisplayName        sql.NullString
	IsAdmin            sql.NullInt64
	ExpectedGrantCount sql.NullInt64
}

func loadReplaceableInvitation(ctx context.Context, q queryer, invitationID string) (replaceableInvitation, error) {
	var invitation replaceableInvitation
	err := q.QueryRowContext(ctx, `
SELECT status, canonical_email, display_name, is_admin, expected_repository_grant_count
FROM invitations
WHERE id = ?`, invitationID).Scan(
		&invitation.Status,
		&invitation.CanonicalEmail,
		&invitation.DisplayName,
		&invitation.IsAdmin,
		&invitation.ExpectedGrantCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return replaceableInvitation{}, ValidationError{Message: "invitation was not found"}
	}
	if err != nil {
		return replaceableInvitation{}, fmt.Errorf("load invitation: %w", err)
	}
	return invitation, nil
}

// loadSurvivingInvitationRepositoryGrants returns the staged grants whose
// repository still exists, in the same canonical order acceptance uses. Grants
// pointing at a deleted repository are dropped rather than copied: they can
// never be materialized, and carrying them forward would leave the replacement
// permanently drifted.
func loadSurvivingInvitationRepositoryGrants(
	ctx context.Context,
	q queryer,
	invitationID string,
) ([]InvitationRepositoryGrant, error) {
	rows, err := q.QueryContext(ctx, `
SELECT staged.repository_id, staged.role
FROM invitation_repository_grants staged
JOIN repositories ON repositories.id = staged.repository_id
WHERE staged.invitation_id = ?
ORDER BY staged.repository_id, staged.role`, invitationID)
	if err != nil {
		return nil, fmt.Errorf("load surviving invitation repository grants: %w", err)
	}
	defer rows.Close()

	grants := make([]InvitationRepositoryGrant, 0)
	for rows.Next() {
		var grant InvitationRepositoryGrant
		if err := rows.Scan(&grant.RepositoryID, &grant.Role); err != nil {
			return nil, fmt.Errorf("scan surviving invitation repository grant: %w", err)
		}
		if grant.RepositoryID <= 0 || !grant.Role.ValidForRepository() {
			return nil, errors.New("staged invitation repository grant is malformed")
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load surviving invitation repository grant rows: %w", err)
	}
	return grants, nil
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
