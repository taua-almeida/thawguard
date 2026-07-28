package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

type invitationReplacementResult struct {
	replacement InvitationLinkReplacement
	err         error
}

func TestInvitationReplacementPreservesIdentityAuthorityAndRotatesInvitationID(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 26, 9, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryA := mustCreateTestRepository(t, ctx, database, "acme", "api")
	repositoryB := mustCreateTestRepository(t, ctx, database, "acme", "web")
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "replace@example.test",
		DisplayName: "Replace Target",
		IsAdmin:     true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: repositoryA, Role: RoleFreezer},
			{RepositoryID: repositoryB, Role: RoleViewer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	createdRow := loadStoredInvitation(t, ctx, database, created.InvitationID)

	// Past the seven-day window: an expired invitation is still an ordinary
	// pending row, so replacement must recover it without restaging identity.
	now = now.Add(8 * 24 * time.Hour)
	replacement, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ReplacedInvitationID != created.InvitationID ||
		!ValidInvitationID(replacement.InvitationID) ||
		replacement.InvitationID == created.InvitationID {
		t.Fatalf("expected a new canonical invitation ID fencing %q, got %+v", created.InvitationID, replacement)
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(replacement.Token)
	if err != nil || len(rawToken) != invitationBearerBytes || replacement.Token == created.Token {
		t.Fatalf("expected a fresh canonical 32-byte bearer, bytes=%d err=%v", len(rawToken), err)
	}
	wantExpiry := time.Unix(0, now.UTC().Add(DefaultInvitationTTL).UnixNano()).UTC()
	if !replacement.ExpiresAt.Equal(wantExpiry) || replacement.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expected a fresh UTC expiry %s, got %s", wantExpiry, replacement.ExpiresAt)
	}
	if replacement.Email != "replace@example.test" || replacement.DisplayName != "Replace Target" || !replacement.IsAdmin {
		t.Fatalf("expected preserved identity and Admin flag, got %+v", replacement)
	}
	assertInvitationGrantsEqual(t, replacement.RepositoryGrants, []InvitationRepositoryGrant{
		{RepositoryID: repositoryA, Role: RoleFreezer},
		{RepositoryID: repositoryB, Role: RoleViewer},
	})

	stored := loadStoredInvitation(t, ctx, database, replacement.InvitationID)
	digest := sha256.Sum256([]byte(replacement.Token))
	if stored.Status != invitationStatusPending || stored.Email.String != "replace@example.test" ||
		stored.DisplayName.String != "Replace Target" || stored.IsAdmin.Int64 != 1 ||
		stored.AuthorizedBy.Int64 != admin.User.ID || stored.ExpectedGrantCount.Int64 != 2 ||
		!bytes.Equal(stored.TokenDigest, digest[:]) || stored.ExpiresAt.Int64 != wantExpiry.UnixNano() {
		t.Fatalf("unexpected replacement invitation row: %+v", stored)
	}
	nowText := now.UTC().Format(time.RFC3339Nano)
	if stored.CreatedAt != nowText || stored.UpdatedAt != nowText {
		t.Fatalf("expected replacement timestamps %s, got created=%s updated=%s", nowText, stored.CreatedAt, stored.UpdatedAt)
	}
	assertInvitationGrantsEqual(t, loadStoredInvitationGrants(t, ctx, database, replacement.InvitationID), replacement.RepositoryGrants)

	retired := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if retired.Status != invitationStatusCancelled || retired.Email.Valid || retired.DisplayName.Valid ||
		retired.TokenDigest != nil || retired.ExpiresAt.Valid || retired.IsAdmin.Valid ||
		retired.AuthorizedBy.Valid || retired.ExpectedGrantCount.Valid ||
		retired.CreatedAt != createdRow.CreatedAt || retired.UpdatedAt != nowText {
		t.Fatalf("expected the retired invitation to reuse the cancelled tombstone, got %+v", retired)
	}
	if len(loadStoredInvitationGrants(t, ctx, database, created.InvitationID)) != 0 {
		t.Fatal("expected replacement to delete every grant staged on the retired invitation")
	}
	var active int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM invitations
WHERE canonical_email = 'replace@example.test' AND status IN ('pending', 'needs_reissue')`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("expected exactly one active email reservation, got %d", active)
	}

	details := loadInvitationAuditDetails(t, ctx, database, audit.ActionInvitationReplaced, replacement.InvitationID)
	assertInvitationAuditKeys(t, details,
		"actor_kind",
		"replaced_invitation_id",
		"expires_at",
		"administrator",
		"repository_grant_count_before_expected",
		"repository_grant_count_before_actual",
		"repository_grant_count_after",
	)
	if details["actor_kind"] != "user" || details["replaced_invitation_id"] != created.InvitationID ||
		details["administrator"] != "true" || details["expires_at"] != wantExpiry.Format(time.RFC3339Nano) ||
		details["repository_grant_count_before_expected"] != "2" ||
		details["repository_grant_count_before_actual"] != "2" ||
		details["repository_grant_count_after"] != "2" {
		t.Fatalf("unexpected invitation replacement audit details: %v", details)
	}
	assertInvitationAuditSecretsAbsent(t, details,
		"replace@example.test", "Replace Target", replacement.Token, created.Token)

	// A pending, unexpired invitation replaces just as well, and the retired ID
	// is a spent fence rather than a reusable handle.
	second, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: replacement.InvitationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.InvitationID == replacement.InvitationID || second.Token == replacement.Token {
		t.Fatalf("expected the second replacement to rotate both ID and bearer, got %+v", second)
	}
	replayed, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: replacement.InvitationID,
	})
	if !IsValidationError(err) || replayed.Token != "" || replayed.InvitationID != "" {
		t.Fatalf("expected the retired ID to reject a replay with a zero result, got %+v err=%v", replayed, err)
	}
}

func TestInvitationReplacementRecoversNeedsReplacementStateAndCopiesSurvivingGrants(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	authorizer := mustCreateUser(t, ctx, service, "authorizer@example.test", false)
	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: authorizer.ID, Admin: true}); err != nil {
		t.Fatal(err)
	}
	survivingRepository := mustCreateTestRepository(t, ctx, database, "acme", "surviving")
	deletedRepository := mustCreateTestRepository(t, ctx, database, "acme", "deleted")
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: authorizer.ID,
		Email:       "recover@example.test",
		DisplayName: "Recovered Invitee",
		IsAdmin:     true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: survivingRepository, Role: RoleThawApprover},
			{RepositoryID: deletedRepository, Role: RoleFreezer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, deletedRepository); err != nil {
		t.Fatal(err)
	}
	// Demoting the authorizing Admin drives the invitation into
	// needs_reissue and strips its credential, which is the lost-authority
	// state an Admin must be able to recover from.
	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: authorizer.ID, Admin: false}); err != nil {
		t.Fatal(err)
	}
	drifted := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if drifted.Status != invitationStatusReissue || drifted.TokenDigest != nil ||
		drifted.ExpectedGrantCount.Int64 != 2 || len(loadStoredInvitationGrants(t, ctx, database, created.InvitationID)) != 1 {
		t.Fatalf("expected an invalidated, drifted invitation, got %+v", drifted)
	}

	now = now.Add(time.Hour)
	replacement, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertInvitationGrantsEqual(t, replacement.RepositoryGrants, []InvitationRepositoryGrant{
		{RepositoryID: survivingRepository, Role: RoleThawApprover},
	})
	if !replacement.IsAdmin || replacement.Email != "recover@example.test" || replacement.DisplayName != "Recovered Invitee" {
		t.Fatalf("expected recovery to preserve staged identity and authority, got %+v", replacement)
	}
	stored := loadStoredInvitation(t, ctx, database, replacement.InvitationID)
	if stored.Status != invitationStatusPending || stored.ExpectedGrantCount.Int64 != 1 ||
		stored.AuthorizedBy.Int64 != admin.User.ID {
		t.Fatalf("expected drift to be repaired against the replacing Admin, got %+v", stored)
	}
	assertInvitationGrantsEqual(t, loadStoredInvitationGrants(t, ctx, database, replacement.InvitationID), replacement.RepositoryGrants)

	details := loadInvitationAuditDetails(t, ctx, database, audit.ActionInvitationReplaced, replacement.InvitationID)
	if details["repository_grant_count_before_expected"] != "2" ||
		details["repository_grant_count_before_actual"] != "1" ||
		details["repository_grant_count_after"] != "1" {
		t.Fatalf("expected the audit event to retain pre-replacement drift evidence, got %v", details)
	}

	// The recovered credential accepts, proving the repaired expected count
	// matches what is actually staged.
	user, err := service.AcceptInvitation(ctx, replacement.Token, invitationAcceptanceTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "recover@example.test" || !user.IsAdmin {
		t.Fatalf("unexpected accepted identity: %+v", user)
	}
}

func TestInvitationReplacementInvalidatesTheOldBearerAndStaysFailClosedOnLaterDrift(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 26, 11, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "api")
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "bearer-swap@example.test",
		DisplayName: "Bearer Swap",
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: repositoryID, Role: RoleViewer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptInvitation(ctx, created.Token, invitationAcceptanceTestPassword); !IsInvalidInvitation(err) {
		t.Fatalf("expected the retired bearer to be rejected, got %v", err)
	}
	assertNoUserWithEmail(t, ctx, database, "bearer-swap@example.test")

	// Deleting the repository after replacement drifts the fresh invitation,
	// which must fail closed at acceptance exactly like any other drift.
	if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, repositoryID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptInvitation(ctx, replacement.Token, invitationAcceptanceTestPassword); !IsInvalidInvitation(err) {
		t.Fatalf("expected post-replacement drift to fail closed, got %v", err)
	}
	assertNoUserWithEmail(t, ctx, database, "bearer-swap@example.test")

	// Replacing again drops the dead grant, and only then does the bearer work.
	repaired, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: replacement.InvitationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(repaired.RepositoryGrants) != 0 {
		t.Fatalf("expected the deleted repository grant to be dropped, got %+v", repaired.RepositoryGrants)
	}
	if _, err := service.AcceptInvitation(ctx, repaired.Token, invitationAcceptanceTestPassword); err != nil {
		t.Fatal(err)
	}
}

func TestInvitationReplacementRejectsTerminalStatesCollisionsAndActorAuthorityLoss(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)

	for _, malformed := range []string{"", "inv_", "invitation", "inv_" + strings.Repeat("A", 22)} {
		if _, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
			ActorUserID:  admin.User.ID,
			InvitationID: malformed,
		}); !IsValidationError(err) {
			t.Fatalf("expected malformed invitation ID %q to be rejected, got %v", malformed, err)
		}
	}
	missing, err := newInvitationID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: missing,
	}); !IsValidationError(err) {
		t.Fatalf("expected an unknown invitation to be rejected, got %v", err)
	}

	cancelled, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "cancelled@example.test",
		DisplayName: "Cancelled Invitee",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CancelInvitation(ctx, CancelInvitationParams{ActorUserID: admin.User.ID, InvitationID: cancelled.InvitationID}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: cancelled.InvitationID,
	}); !IsValidationError(err) {
		t.Fatalf("expected a cancelled invitation to be rejected, got %v", err)
	}

	accepted, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "accepted@example.test",
		DisplayName: "Accepted Invitee",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptInvitation(ctx, accepted.Token, invitationAcceptanceTestPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: accepted.InvitationID,
	}); !IsValidationError(err) {
		t.Fatalf("expected an accepted invitation to be rejected, got %v", err)
	}

	// A user created for the staged email after the invitation went out makes
	// the invitation unusable; replacement must not hand out a link that can
	// never be accepted.
	colliding, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "collision@example.test",
		DisplayName: "Collision Invitee",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(email, display_name, created_at, updated_at)
VALUES ('collision@example.test', 'Collision User', '2026-07-26T12:00:00Z', '2026-07-26T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: colliding.InvitationID,
	}); !IsValidationError(err) {
		t.Fatalf("expected a colliding invitation to be rejected, got %v", err)
	}
	if loadStoredInvitation(t, ctx, database, colliding.InvitationID).Status != invitationStatusPending {
		t.Fatal("expected a rejected replacement to leave the invitation untouched")
	}

	// The replacing Admin's own authority is checked under the writer lock.
	demoted := mustCreateUser(t, ctx, service, "demoted@example.test", false)
	live, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "authority@example.test",
		DisplayName: "Authority Invitee",
	})
	if err != nil {
		t.Fatal(err)
	}
	before := loadStoredInvitation(t, ctx, database, live.InvitationID)
	if _, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  demoted.ID,
		InvitationID: live.InvitationID,
	}); !IsValidationError(err) {
		t.Fatalf("expected a non-Admin actor to be rejected, got %v", err)
	}
	after := loadStoredInvitation(t, ctx, database, live.InvitationID)
	assertStoredInvitationCredentialEqual(t, after, before)
	if after.Status != invitationStatusPending || after.UpdatedAt != before.UpdatedAt {
		t.Fatalf("expected a rejected replacement to change nothing, before=%+v after=%+v", before, after)
	}
}

func TestInvitationReplacementCredentialFollowsLaterAuthorizerLoss(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 26, 13, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	replacer := mustCreateUser(t, ctx, service, "replacer@example.test", false)
	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: replacer.ID, Admin: true}); err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "follows-authorizer@example.test",
		DisplayName: "Follows Authorizer",
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  replacer.ID,
		InvitationID: created.InvitationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DisableUser(ctx, admin.User.ID, replacer.ID); err != nil {
		t.Fatal(err)
	}
	stored := loadStoredInvitation(t, ctx, database, replacement.InvitationID)
	if stored.Status != invitationStatusReissue || stored.TokenDigest != nil || stored.AuthorizedBy.Valid {
		t.Fatalf("expected the replacement credential to be invalidated with its authorizer, got %+v", stored)
	}
	if _, err := service.AcceptInvitation(ctx, replacement.Token, invitationAcceptanceTestPassword); !IsInvalidInvitation(err) {
		t.Fatalf("expected the orphaned replacement bearer to be rejected, got %v", err)
	}
	assertNoUserWithEmail(t, ctx, database, "follows-authorizer@example.test")
}

func TestInvitationReplacementRollsBackAuditAndLateFailures(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 26, 14, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "api")
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "rollback@example.test",
		DisplayName: "Rollback Invitee",
		IsAdmin:     true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: repositoryID, Role: RoleFreezer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := loadStoredInvitation(t, ctx, database, created.InvitationID)

	assertReplacementRolledBack := func(t *testing.T, replacement InvitationLinkReplacement, err error) {
		t.Helper()
		if err == nil || IsValidationError(err) {
			t.Fatalf("expected an operational replacement failure, got %v", err)
		}
		if replacement.Token != "" || replacement.InvitationID != "" || replacement.Email != "" ||
			replacement.DisplayName != "" || replacement.RepositoryGrants != nil {
			t.Fatalf("expected a zero replacement result on failure, got %+v", replacement)
		}
		message := err.Error()
		for _, secret := range []string{created.Token, "rollback@example.test", "Rollback Invitee"} {
			if strings.Contains(message, secret) {
				t.Fatalf("replacement error leaked %q in %q", secret, message)
			}
		}
		after := loadStoredInvitation(t, ctx, database, created.InvitationID)
		assertStoredInvitationCredentialEqual(t, after, before)
		if after.Status != invitationStatusPending || after.Email.String != before.Email.String ||
			after.DisplayName.String != before.DisplayName.String || after.IsAdmin.Int64 != before.IsAdmin.Int64 ||
			after.ExpectedGrantCount.Int64 != before.ExpectedGrantCount.Int64 || after.UpdatedAt != before.UpdatedAt {
			t.Fatalf("expected a full rollback, before=%+v after=%+v", before, after)
		}
		assertInvitationGrantsEqual(t, loadStoredInvitationGrants(t, ctx, database, created.InvitationID), []InvitationRepositoryGrant{
			{RepositoryID: repositoryID, Role: RoleFreezer},
		})
		var replacements int
		if err := database.QueryRowContext(ctx, `
SELECT count(*) FROM invitations WHERE id != ?`, created.InvitationID).Scan(&replacements); err != nil {
			t.Fatal(err)
		}
		if replacements != 0 {
			t.Fatalf("expected no replacement row to survive, got %d", replacements)
		}
	}

	// A failure after the tombstone update and the new insert must roll both
	// sides back, not leave the email reserved by a half-built replacement.
	rejectInvitationInserts(t, ctx, database)
	replacement, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
	})
	assertReplacementRolledBack(t, replacement, err)
	allowInvitationInserts(t, ctx, database)

	breakAuditTable(t, ctx, database)
	replacement, err = service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
	})
	assertReplacementRolledBack(t, replacement, err)
}

func TestInvitationReplacementRacingReplacementHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 26, 15, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "replace-race@example.test",
		DisplayName: "Replace Race",
	})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan invitationReplacementResult, 2)
	for range 2 {
		go func() {
			<-start
			replacement, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
				ActorUserID:  admin.User.ID,
				InvitationID: created.InvitationID,
			})
			results <- invitationReplacementResult{replacement: replacement, err: err}
		}()
	}
	close(start)

	var winner InvitationLinkReplacement
	var successes, validationFailures int
	for range 2 {
		outcome := <-results
		switch {
		case outcome.err == nil:
			successes++
			winner = outcome.replacement
		case IsValidationError(outcome.err):
			validationFailures++
			if outcome.replacement.Token != "" {
				t.Fatalf("expected the losing replacement to reveal no bearer, got %+v", outcome.replacement)
			}
		default:
			t.Fatalf("expected a domain race result, got operational error %v", outcome.err)
		}
	}
	if successes != 1 || validationFailures != 1 {
		t.Fatalf("expected one replacement winner and one validation loser, success=%d validation=%d", successes, validationFailures)
	}
	var active int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM invitations
WHERE canonical_email = 'replace-race@example.test' AND status IN ('pending', 'needs_reissue')`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("expected exactly one active invitation after the race, got %d", active)
	}
	if _, err := service.AcceptInvitation(ctx, winner.Token, invitationAcceptanceTestPassword); err != nil {
		t.Fatalf("expected the winning bearer to remain usable: %v", err)
	}
}

func TestInvitationReplacementRacingAcceptanceHasOneOldInvitationWinner(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 26, 16, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "replace-accept-race@example.test",
		DisplayName: "Replace Accept Race",
	})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	accepted := make(chan error, 1)
	replaced := make(chan invitationReplacementResult, 1)
	go func() {
		<-start
		_, err := service.AcceptInvitation(ctx, created.Token, invitationAcceptanceTestPassword)
		accepted <- err
	}()
	go func() {
		<-start
		replacement, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
			ActorUserID:  admin.User.ID,
			InvitationID: created.InvitationID,
		})
		replaced <- invitationReplacementResult{replacement: replacement, err: err}
	}()
	close(start)
	acceptErr := <-accepted
	replaceOutcome := <-replaced

	switch {
	case acceptErr == nil:
		if !IsValidationError(replaceOutcome.err) || replaceOutcome.replacement.Token != "" {
			t.Fatalf("acceptance-first replacement must fail without a bearer, got %+v", replaceOutcome)
		}
		assertAcceptedInvitationTombstone(t, loadStoredInvitation(t, ctx, database, created.InvitationID), service.now())
	case replaceOutcome.err == nil:
		assertInvalidInvitation(t, acceptErr)
		assertNoUserWithEmail(t, ctx, database, "replace-accept-race@example.test")
		retired := loadStoredInvitation(t, ctx, database, created.InvitationID)
		if retired.Status != invitationStatusCancelled || retired.Email.Valid || retired.TokenDigest != nil {
			t.Fatalf("replacement-first race left the wrong tombstone: %+v", retired)
		}
		if _, err := service.AcceptInvitation(ctx, replaceOutcome.replacement.Token, invitationAcceptanceTestPassword); err != nil {
			t.Fatalf("expected the replacement bearer to remain usable: %v", err)
		}
	default:
		t.Fatalf("expected exactly one lifecycle winner, accept=%v replace=%v", acceptErr, replaceOutcome.err)
	}
}

func TestInvitationReplacementRacingCancellationHasOneOldInvitationWinner(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 26, 17, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "replace-cancel-race@example.test",
		DisplayName: "Replace Cancel Race",
	})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	cancelled := make(chan error, 1)
	replaced := make(chan invitationReplacementResult, 1)
	go func() {
		<-start
		cancelled <- service.CancelInvitation(ctx, CancelInvitationParams{
			ActorUserID:  admin.User.ID,
			InvitationID: created.InvitationID,
		})
	}()
	go func() {
		<-start
		replacement, err := service.ReplaceInvitationLink(ctx, ReplaceInvitationLinkParams{
			ActorUserID:  admin.User.ID,
			InvitationID: created.InvitationID,
		})
		replaced <- invitationReplacementResult{replacement: replacement, err: err}
	}()
	close(start)
	cancelErr := <-cancelled
	replaceOutcome := <-replaced

	var active int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM invitations
WHERE canonical_email = 'replace-cancel-race@example.test' AND status IN ('pending', 'needs_reissue')`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	switch {
	case cancelErr == nil:
		if !IsValidationError(replaceOutcome.err) || replaceOutcome.replacement.Token != "" {
			t.Fatalf("cancellation-first replacement must fail without a bearer, got %+v", replaceOutcome)
		}
		if active != 0 {
			t.Fatalf("expected cancellation to release the email reservation, got %d active invitations", active)
		}
	case replaceOutcome.err == nil:
		if !IsValidationError(cancelErr) {
			t.Fatalf("replacement-first cancellation must fail, got %v", cancelErr)
		}
		if active != 1 {
			t.Fatalf("expected exactly one active invitation after the race, got %d", active)
		}
		if _, err := service.AcceptInvitation(ctx, replaceOutcome.replacement.Token, invitationAcceptanceTestPassword); err != nil {
			t.Fatalf("expected the replacement bearer to remain usable: %v", err)
		}
	default:
		t.Fatalf("expected exactly one lifecycle winner, cancel=%v replace=%v", cancelErr, replaceOutcome.err)
	}
}

// rejectInvitationInserts fails every new invitation row so a replacement dies
// after it has already retired the old row, exercising two-sided rollback.
func rejectInvitationInserts(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `
CREATE TRIGGER reject_invitation_inserts
BEFORE INSERT ON invitations
BEGIN
  SELECT RAISE(ABORT, 'invitation insert rejected');
END`); err != nil {
		t.Fatal(err)
	}
}

func allowInvitationInserts(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `DROP TRIGGER reject_invitation_inserts`); err != nil {
		t.Fatal(err)
	}
}
