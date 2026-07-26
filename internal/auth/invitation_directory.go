package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// InvitationLifecycle is the management view of an active invitation's
// acceptance state, derived from the persisted status and the service clock.
type InvitationLifecycle string

const (
	// InvitationLifecyclePending marks a pending invitation whose expiry is
	// still in the future.
	InvitationLifecyclePending InvitationLifecycle = "pending"
	// InvitationLifecycleExpired marks a pending invitation whose expiry has
	// passed. The row still reserves its email until an Admin cancels it.
	InvitationLifecycleExpired InvitationLifecycle = "expired"
	// InvitationLifecycleNeedsReplacement marks a needs_reissue row whose
	// credential was invalidated when its authorizing Admin lost authority.
	InvitationLifecycleNeedsReplacement InvitationLifecycle = "needs_replacement"
)

// ActiveInvitation is the read model behind the Users & Access Active
// invitations region. It never carries token digests or bearer material.
type ActiveInvitation struct {
	ID          string
	Email       string
	DisplayName string
	Lifecycle   InvitationLifecycle
	// ExpiresAt is nil for needs-replacement rows, whose persisted expiry was
	// cleared together with the invalidated credential.
	ExpiresAt *time.Time
	IsAdmin   bool
	// RepositoryGrants are the surviving staged grants in canonical
	// (repository, role) order. Repository deletion cascades staged grants
	// away, so this list can be shorter than what the Admin staged.
	RepositoryGrants   []InvitationRepositoryGrant
	ExpectedGrantCount int
	ActualGrantCount   int
}

// AccessDrift reports whether staged repository access no longer matches what
// the authorizing Admin staged.
func (i ActiveInvitation) AccessDrift() bool {
	return i.ActualGrantCount != i.ExpectedGrantCount
}

// Usable reports whether the invitation link can still be accepted exactly as
// staged: pending, unexpired, and without access drift.
func (i ActiveInvitation) Usable() bool {
	return i.Lifecycle == InvitationLifecyclePending && !i.AccessDrift()
}

type activeInvitationRow struct {
	ID            string
	Status        string
	Email         sql.NullString
	DisplayName   sql.NullString
	ExpiresAt     sql.NullInt64
	IsAdmin       sql.NullInt64
	ExpectedCount sql.NullInt64
	CreatedAt     string
	RepositoryID  sql.NullInt64
	Role          sql.NullString
}

// ListActiveInvitations returns every pending and needs_reissue invitation for
// the management UI, newest first. Accepted and cancelled tombstones stay out;
// expired pending rows stay in because they still reserve their email. Any
// malformed active row fails the whole listing so the UI never hides a
// reservation it cannot represent.
func (s *Service) ListActiveInvitations(ctx context.Context) ([]ActiveInvitation, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("auth service has no database")
	}
	now := s.now().UTC()
	rows, err := s.db.QueryContext(ctx, `
SELECT
  i.id,
  i.status,
  i.canonical_email,
  i.display_name,
  i.expires_at,
  i.is_admin,
  i.expected_repository_grant_count,
  i.created_at,
  g.repository_id,
  g.role
FROM invitations i
LEFT JOIN invitation_repository_grants g ON g.invitation_id = i.id
WHERE i.status IN (?, ?)`,
		invitationStatusPending,
		invitationStatusReissue,
	)
	if err != nil {
		return nil, fmt.Errorf("list active invitations: %w", err)
	}
	defer rows.Close()

	type activeEntry struct {
		invitation ActiveInvitation
		createdAt  time.Time
	}
	entries := make([]*activeEntry, 0)
	byID := make(map[string]*activeEntry)
	for rows.Next() {
		var row activeInvitationRow
		if err := rows.Scan(
			&row.ID,
			&row.Status,
			&row.Email,
			&row.DisplayName,
			&row.ExpiresAt,
			&row.IsAdmin,
			&row.ExpectedCount,
			&row.CreatedAt,
			&row.RepositoryID,
			&row.Role,
		); err != nil {
			return nil, fmt.Errorf("scan active invitation: %w", err)
		}
		entry, seen := byID[row.ID]
		if !seen {
			invitation, createdAt, err := buildActiveInvitation(row, now)
			if err != nil {
				return nil, err
			}
			entry = &activeEntry{invitation: invitation, createdAt: createdAt}
			byID[row.ID] = entry
			entries = append(entries, entry)
		}
		if !row.RepositoryID.Valid && !row.Role.Valid {
			continue
		}
		if !row.RepositoryID.Valid || !row.Role.Valid ||
			row.RepositoryID.Int64 <= 0 || !Role(row.Role.String).ValidForRepository() {
			return nil, fmt.Errorf("active invitation %q has a malformed staged repository grant", row.ID)
		}
		entry.invitation.RepositoryGrants = append(entry.invitation.RepositoryGrants, InvitationRepositoryGrant{
			RepositoryID: row.RepositoryID.Int64,
			Role:         Role(row.Role.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active invitations rows: %w", err)
	}

	for _, entry := range entries {
		grants := entry.invitation.RepositoryGrants
		sort.Slice(grants, func(a, b int) bool {
			if grants[a].RepositoryID != grants[b].RepositoryID {
				return grants[a].RepositoryID < grants[b].RepositoryID
			}
			return grants[a].Role < grants[b].Role
		})
		entry.invitation.ActualGrantCount = len(grants)
	}
	// SQLite text timestamps order lexically, which misorders mixed fractional
	// precision ("...:00.5Z" sorts before "...:00Z"), so ordering uses the
	// parsed instants and falls back to the ID only for equal instants.
	sort.Slice(entries, func(a, b int) bool {
		if !entries[a].createdAt.Equal(entries[b].createdAt) {
			return entries[a].createdAt.After(entries[b].createdAt)
		}
		return entries[a].invitation.ID > entries[b].invitation.ID
	})
	invitations := make([]ActiveInvitation, 0, len(entries))
	for _, entry := range entries {
		invitations = append(invitations, entry.invitation)
	}
	return invitations, nil
}

func buildActiveInvitation(row activeInvitationRow, now time.Time) (ActiveInvitation, time.Time, error) {
	malformed := func() (ActiveInvitation, time.Time, error) {
		return ActiveInvitation{}, time.Time{}, fmt.Errorf("active invitation %q row is malformed", row.ID)
	}
	if !ValidInvitationID(row.ID) {
		return malformed()
	}
	if !row.Email.Valid || row.Email.String == "" || !row.DisplayName.Valid || row.DisplayName.String == "" {
		return malformed()
	}
	if !row.IsAdmin.Valid || (row.IsAdmin.Int64 != 0 && row.IsAdmin.Int64 != 1) {
		return malformed()
	}
	if !row.ExpectedCount.Valid || row.ExpectedCount.Int64 < 0 {
		return malformed()
	}
	createdAt, err := parseTime(row.CreatedAt)
	if err != nil {
		return malformed()
	}
	invitation := ActiveInvitation{
		ID:                 row.ID,
		Email:              row.Email.String,
		DisplayName:        row.DisplayName.String,
		IsAdmin:            row.IsAdmin.Int64 != 0,
		RepositoryGrants:   make([]InvitationRepositoryGrant, 0),
		ExpectedGrantCount: int(row.ExpectedCount.Int64),
	}
	switch row.Status {
	case invitationStatusPending:
		if !row.ExpiresAt.Valid || row.ExpiresAt.Int64 <= 0 {
			return malformed()
		}
		expiry := time.Unix(0, row.ExpiresAt.Int64).UTC()
		invitation.ExpiresAt = &expiry
		if expiry.After(now) {
			invitation.Lifecycle = InvitationLifecyclePending
		} else {
			invitation.Lifecycle = InvitationLifecycleExpired
		}
	case invitationStatusReissue:
		if row.ExpiresAt.Valid {
			return malformed()
		}
		invitation.Lifecycle = InvitationLifecycleNeedsReplacement
	default:
		return ActiveInvitation{}, time.Time{}, fmt.Errorf(
			"active invitation %q has unsupported status %q",
			row.ID,
			row.Status,
		)
	}
	return invitation, createdAt, nil
}
