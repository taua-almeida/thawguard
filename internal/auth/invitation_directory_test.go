package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestListActiveInvitationsOrdersChronologicallyAndExcludesTombstones(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 24, 9, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryA := mustCreateTestRepository(t, ctx, database, "acme", "api")
	repositoryB := mustCreateTestRepository(t, ctx, database, "acme", "web")

	empty, err := service.ListActiveInvitations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("expected an initialized empty active list, got %#v", empty)
	}

	createAt := func(instant time.Time, email string, isAdmin bool, grants []InvitationRepositoryGrant) InvitationCredential {
		t.Helper()
		now = instant
		credential, err := service.CreateInvitation(ctx, CreateInvitationParams{
			ActorUserID:      admin.User.ID,
			Email:            email,
			DisplayName:      "Invitee " + email,
			IsAdmin:          isAdmin,
			RepositoryGrants: grants,
		})
		if err != nil {
			t.Fatal(err)
		}
		return credential
	}

	// The whole-second and half-second instants order lexically as
	// "...:00.5Z" < "...:00Z" in SQLite text comparison; chronological
	// ordering must invert that.
	oldest := createAt(time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC), "oldest@example.test", false, []InvitationRepositoryGrant{
		{RepositoryID: repositoryB, Role: RoleViewer},
		{RepositoryID: repositoryA, Role: RoleThawApprover},
		{RepositoryID: repositoryA, Role: RoleFreezer},
	})
	fractional := createAt(time.Date(2026, 7, 24, 10, 0, 0, 500000000, time.UTC), "fractional@example.test", true, nil)
	tied := time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)
	tiedFirst := createAt(tied, "tied-first@example.test", false, nil)
	tiedSecond := createAt(tied, "tied-second@example.test", false, nil)

	cancelled := createAt(time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC), "cancelled@example.test", false, nil)
	if err := service.CancelInvitation(ctx, CancelInvitationParams{ActorUserID: admin.User.ID, InvitationID: cancelled.InvitationID}); err != nil {
		t.Fatal(err)
	}
	accepted := createAt(time.Date(2026, 7, 24, 12, 30, 0, 0, time.UTC), "accepted@example.test", false, nil)
	if _, err := service.AcceptInvitation(ctx, accepted.Token, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}

	now = time.Date(2026, 7, 24, 13, 0, 0, 0, time.UTC)
	invitations, err := service.ListActiveInvitations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(invitations) != 4 {
		t.Fatalf("expected 4 active invitations, got %d: %+v", len(invitations), invitations)
	}
	tiedIDs := map[string]bool{tiedFirst.InvitationID: true, tiedSecond.InvitationID: true}
	if !tiedIDs[invitations[0].ID] || !tiedIDs[invitations[1].ID] || invitations[0].ID <= invitations[1].ID {
		t.Fatalf("expected equal-instant invitations first with IDs descending, got %q then %q", invitations[0].ID, invitations[1].ID)
	}
	if invitations[2].ID != fractional.InvitationID || invitations[3].ID != oldest.InvitationID {
		t.Fatalf(
			"expected chronological newest-first ordering [tied, tied, fractional, oldest], got %q then %q",
			invitations[2].ID,
			invitations[3].ID,
		)
	}

	first := invitations[3]
	if first.Email != "oldest@example.test" || first.DisplayName != "Invitee oldest@example.test" || first.IsAdmin {
		t.Fatalf("unexpected staged identity: %+v", first)
	}
	if first.Lifecycle != InvitationLifecyclePending || first.ExpiresAt == nil || !first.ExpiresAt.Equal(oldest.ExpiresAt) {
		t.Fatalf("expected pending lifecycle with expiry %s, got %+v", oldest.ExpiresAt, first)
	}
	assertInvitationGrantsEqual(t, first.RepositoryGrants, []InvitationRepositoryGrant{
		{RepositoryID: repositoryA, Role: RoleFreezer},
		{RepositoryID: repositoryA, Role: RoleThawApprover},
		{RepositoryID: repositoryB, Role: RoleViewer},
	})
	if first.ExpectedGrantCount != 3 || first.ActualGrantCount != 3 || first.AccessDrift() || !first.Usable() {
		t.Fatalf("expected a usable fully-staged invitation, got %+v", first)
	}

	adminStaged := invitations[2]
	if !adminStaged.IsAdmin || adminStaged.ExpectedGrantCount != 0 || adminStaged.ActualGrantCount != 0 ||
		len(adminStaged.RepositoryGrants) != 0 || adminStaged.AccessDrift() || !adminStaged.Usable() {
		t.Fatalf("expected a usable zero-access Admin invitation, got %+v", adminStaged)
	}

	serialized, err := json.Marshal(invitations)
	if err != nil {
		t.Fatal(err)
	}
	body := string(serialized)
	for _, credential := range []InvitationCredential{oldest, fractional, tiedFirst, tiedSecond, cancelled, accepted} {
		digest := sha256.Sum256([]byte(credential.Token))
		for _, secret := range []string{
			credential.Token,
			hex.EncodeToString(digest[:]),
			base64.RawURLEncoding.EncodeToString(digest[:]),
		} {
			if strings.Contains(body, secret) {
				t.Fatalf("active invitation list exposes bearer material %q", secret)
			}
		}
	}
}

func TestListActiveInvitationsLifecycleBoundaryAndAccessDrift(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	created := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	now := created
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryA := mustCreateTestRepository(t, ctx, database, "acme", "api")
	repositoryB := mustCreateTestRepository(t, ctx, database, "acme", "web")
	repositoryC := mustCreateTestRepository(t, ctx, database, "acme", "ops")

	create := func(email string, grants []InvitationRepositoryGrant) InvitationCredential {
		t.Helper()
		credential, err := service.CreateInvitation(ctx, CreateInvitationParams{
			ActorUserID:      admin.User.ID,
			Email:            email,
			DisplayName:      "Invitee " + email,
			RepositoryGrants: grants,
		})
		if err != nil {
			t.Fatal(err)
		}
		return credential
	}
	boundary := create("boundary@example.test", nil)
	drifted := create("drifted@example.test", []InvitationRepositoryGrant{
		{RepositoryID: repositoryA, Role: RoleViewer},
		{RepositoryID: repositoryB, Role: RoleFreezer},
	})
	replacement := create("replacement@example.test", []InvitationRepositoryGrant{
		{RepositoryID: repositoryA, Role: RoleViewer},
	})
	replacementDrifted := create("replacement-drifted@example.test", []InvitationRepositoryGrant{
		{RepositoryID: repositoryC, Role: RoleViewer},
	})

	for _, repositoryID := range []int64{repositoryB, repositoryC} {
		if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, repositoryID); err != nil {
			t.Fatal(err)
		}
	}
	for _, invitationID := range []string{replacement.InvitationID, replacementDrifted.InvitationID} {
		if _, err := database.ExecContext(ctx, `
UPDATE invitations
SET status = 'needs_reissue', token_digest = NULL, expires_at = NULL, authorized_by_user_id = NULL
WHERE id = ?`, invitationID); err != nil {
			t.Fatal(err)
		}
	}

	listByID := func() map[string]ActiveInvitation {
		t.Helper()
		invitations, err := service.ListActiveInvitations(ctx)
		if err != nil {
			t.Fatal(err)
		}
		byID := make(map[string]ActiveInvitation, len(invitations))
		for _, invitation := range invitations {
			byID[invitation.ID] = invitation
		}
		if len(byID) != 4 {
			t.Fatalf("expected all 4 active invitations listed, got %+v", invitations)
		}
		return byID
	}

	now = boundary.ExpiresAt.Add(-time.Nanosecond)
	beforeExpiry := listByID()
	if got := beforeExpiry[boundary.InvitationID]; got.Lifecycle != InvitationLifecyclePending || !got.Usable() {
		t.Fatalf("expected a usable pending invitation just before expiry, got %+v", got)
	}
	got := beforeExpiry[drifted.InvitationID]
	if got.Lifecycle != InvitationLifecyclePending || !got.AccessDrift() || got.Usable() ||
		got.ExpectedGrantCount != 2 || got.ActualGrantCount != 1 {
		t.Fatalf("expected pending invitation with access drift, got %+v", got)
	}
	assertInvitationGrantsEqual(t, got.RepositoryGrants, []InvitationRepositoryGrant{
		{RepositoryID: repositoryA, Role: RoleViewer},
	})
	got = beforeExpiry[replacement.InvitationID]
	if got.Lifecycle != InvitationLifecycleNeedsReplacement || got.ExpiresAt != nil ||
		got.AccessDrift() || got.Usable() || got.ExpectedGrantCount != 1 || got.ActualGrantCount != 1 {
		t.Fatalf("expected needs-replacement invitation without drift, got %+v", got)
	}
	got = beforeExpiry[replacementDrifted.InvitationID]
	if got.Lifecycle != InvitationLifecycleNeedsReplacement || got.ExpiresAt != nil ||
		!got.AccessDrift() || got.Usable() || got.ExpectedGrantCount != 1 || got.ActualGrantCount != 0 {
		t.Fatalf("expected needs-replacement invitation with drift, got %+v", got)
	}

	now = boundary.ExpiresAt
	atExpiry := listByID()
	if got := atExpiry[boundary.InvitationID]; got.Lifecycle != InvitationLifecycleExpired || got.Usable() {
		t.Fatalf("expected expiry to be exclusive at the exact boundary, got %+v", got)
	}
	got = atExpiry[drifted.InvitationID]
	if got.Lifecycle != InvitationLifecycleExpired || !got.AccessDrift() || got.Usable() {
		t.Fatalf("expected expired invitation with access drift, got %+v", got)
	}
}

func TestListActiveInvitationsFailsClosedOnMalformedActiveRows(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name                string
		ignoreChecks        bool
		withoutStagedGrants bool
		corrupt             string
	}{
		{
			name:                "noncanonical invitation id",
			ignoreChecks:        true,
			withoutStagedGrants: true,
			corrupt:             `UPDATE invitations SET id = 'not-canonical' WHERE id = ?`,
		},
		{
			name:    "unparseable created_at",
			corrupt: `UPDATE invitations SET created_at = 'yesterday-ish' WHERE id = ?`,
		},
		{
			name:         "pending row without expiry",
			ignoreChecks: true,
			corrupt:      `UPDATE invitations SET expires_at = NULL WHERE id = ?`,
		},
		{
			name:         "needs_reissue row with expiry",
			ignoreChecks: true,
			corrupt: `
UPDATE invitations
SET status = 'needs_reissue', token_digest = NULL, authorized_by_user_id = NULL
WHERE id = ?`,
		},
		{
			name:         "missing staged identity",
			ignoreChecks: true,
			corrupt:      `UPDATE invitations SET canonical_email = NULL WHERE id = ?`,
		},
		{
			name:         "staged grant with invalid role",
			ignoreChecks: true,
			corrupt:      `UPDATE invitation_repository_grants SET role = 'admin' WHERE invitation_id = ?`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			now := time.Date(2026, 7, 24, 9, 0, 0, 0, time.UTC)
			service.now = func() time.Time { return now }
			admin := mustCreateFirstAdmin(t, ctx, service)
			repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "api")
			grants := []InvitationRepositoryGrant{{RepositoryID: repositoryID, Role: RoleViewer}}
			if tc.withoutStagedGrants {
				grants = nil
			}
			credential, err := service.CreateInvitation(ctx, CreateInvitationParams{
				ActorUserID:      admin.User.ID,
				Email:            "malformed@example.test",
				DisplayName:      "Malformed Row",
				RepositoryGrants: grants,
			})
			if err != nil {
				t.Fatal(err)
			}

			if tc.ignoreChecks {
				execIgnoringCheckConstraints(t, ctx, database, tc.corrupt, credential.InvitationID)
			} else if _, err := database.ExecContext(ctx, tc.corrupt, credential.InvitationID); err != nil {
				t.Fatal(err)
			}

			invitations, err := service.ListActiveInvitations(ctx)
			if err == nil {
				t.Fatalf("expected malformed active row to fail the listing, got %+v", invitations)
			}
			if invitations != nil {
				t.Fatalf("expected no partial listing on malformed rows, got %+v", invitations)
			}
		})
	}
}

// execIgnoringCheckConstraints pins one connection so the corruption statement
// runs under PRAGMA ignore_check_constraints; tests use it to fabricate rows
// the schema CHECKs would otherwise reject.
func execIgnoringCheckConstraints(t *testing.T, ctx context.Context, database *sql.DB, query string, args ...any) {
	t.Helper()
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA ignore_check_constraints = ON`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.ExecContext(ctx, `PRAGMA ignore_check_constraints = OFF`); err != nil {
			t.Error(err)
		}
	}()
	if _, err := conn.ExecContext(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}
