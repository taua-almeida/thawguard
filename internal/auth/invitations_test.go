package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

type invitationCredentialResult struct {
	credential InvitationCredential
	err        error
}

func TestInvitationCreateNormalizesIdentityStagesAuthorityAndStoresOnlyDigest(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	local := time.FixedZone("test-local", -3*60*60)
	now := time.Date(2026, 7, 24, 9, 10, 11, 123456789, local)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryA := mustCreateTestRepository(t, ctx, database, "acme", "api")
	repositoryB := mustCreateTestRepository(t, ctx, database, "acme", "web")
	grants := []InvitationRepositoryGrant{
		{RepositoryID: repositoryB, Role: RoleViewer},
		{RepositoryID: repositoryA, Role: RoleThawApprover},
		{RepositoryID: repositoryA, Role: Role(" freezer ")},
		{RepositoryID: repositoryA, Role: RoleFreezer},
	}

	credential, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID:      admin.User.ID,
		Email:            "  LEAD@Example.Test ",
		DisplayName:      "  Release Lead  ",
		IsAdmin:          true,
		RepositoryGrants: grants,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidInvitationID(credential.InvitationID) {
		t.Fatalf("expected canonical invitation ID, got %q", credential.InvitationID)
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(credential.Token)
	if err != nil || len(rawToken) != invitationBearerBytes || base64.RawURLEncoding.EncodeToString(rawToken) != credential.Token {
		t.Fatalf("expected canonical 32-byte bearer, bytes=%d err=%v", len(rawToken), err)
	}
	wantNow := now.UTC()
	wantExpiry := time.Unix(0, wantNow.Add(DefaultInvitationTTL).UnixNano()).UTC()
	if !credential.ExpiresAt.Equal(wantExpiry) || credential.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expected exact UTC expiry %s, got %s", wantExpiry, credential.ExpiresAt)
	}

	stored := loadStoredInvitation(t, ctx, database, credential.InvitationID)
	if stored.Status != invitationStatusPending || stored.Email.String != "lead@example.test" ||
		stored.DisplayName.String != "Release Lead" || stored.IsAdmin.Int64 != 1 ||
		stored.AuthorizedBy.Int64 != admin.User.ID || stored.ExpectedGrantCount.Int64 != 3 {
		t.Fatalf("unexpected stored invitation: %+v", stored)
	}
	digest := sha256.Sum256([]byte(credential.Token))
	if !bytes.Equal(stored.TokenDigest, digest[:]) || stored.ExpiresAt.Int64 != credential.ExpiresAt.UnixNano() {
		t.Fatalf("expected digest-only credential persistence, digest=%x expiry=%d", stored.TokenDigest, stored.ExpiresAt.Int64)
	}
	createdAt, err := parseTime(stored.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	updatedAt, err := parseTime(stored.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !createdAt.Equal(wantNow) || !updatedAt.Equal(wantNow) {
		t.Fatalf("expected creation timestamps %s, got created=%s updated=%s", wantNow, createdAt, updatedAt)
	}

	wantGrants := []InvitationRepositoryGrant{
		{RepositoryID: repositoryA, Role: RoleFreezer},
		{RepositoryID: repositoryA, Role: RoleThawApprover},
		{RepositoryID: repositoryB, Role: RoleViewer},
	}
	gotGrants := loadStoredInvitationGrants(t, ctx, database, credential.InvitationID)
	assertInvitationGrantsEqual(t, gotGrants, wantGrants)
	if grants[2].Role != Role(" freezer ") || len(grants) != 4 {
		t.Fatalf("expected caller-owned grants to remain untouched, got %+v", grants)
	}

	var invitedUsers int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE email = 'lead@example.test'`).Scan(&invitedUsers); err != nil {
		t.Fatal(err)
	}
	if invitedUsers != 0 {
		t.Fatalf("expected invitation identity to remain separate from users, got %d user rows", invitedUsers)
	}
	details := loadInvitationAuditDetails(t, ctx, database, audit.ActionInvitationCreated, credential.InvitationID)
	assertInvitationAuditKeys(t, details, "actor_kind", "expires_at", "administrator", "repository_grant_count")
	if details["actor_kind"] != "user" || details["administrator"] != "true" || details["repository_grant_count"] != "3" || details["expires_at"] != wantExpiry.Format(time.RFC3339Nano) {
		t.Fatalf("unexpected invitation creation audit details: %v", details)
	}
	assertInvitationAuditSecretsAbsent(t, details, "lead@example.test", "Release Lead", credential.Token, fmt.Sprintf("%x", digest))

	zero, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "zero@example.test",
		DisplayName: "Zero Authority",
	})
	if err != nil {
		t.Fatal(err)
	}
	zeroStored := loadStoredInvitation(t, ctx, database, zero.InvitationID)
	if zeroStored.IsAdmin.Int64 != 0 || zeroStored.ExpectedGrantCount.Int64 != 0 || len(loadStoredInvitationGrants(t, ctx, database, zero.InvitationID)) != 0 {
		t.Fatalf("expected zero staged authority to be valid, got %+v", zeroStored)
	}
}

func TestInvitationCreateRejectsUsersReservationsAndInvalidAuthority(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	enabled := mustCreateUser(t, ctx, service, "enabled@example.test", false)
	disabled := mustCreateUser(t, ctx, service, "disabled@example.test", false)
	if _, err := service.DisableUser(ctx, admin.User.ID, disabled.ID); err != nil {
		t.Fatal(err)
	}
	repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "api")

	for _, email := range []string{enabled.Email, " DISABLED@EXAMPLE.TEST "} {
		if _, err := service.CreateInvitation(ctx, CreateInvitationParams{
			ActorUserID: admin.User.ID,
			Email:       email,
			DisplayName: "Collision",
		}); !IsValidationError(err) {
			t.Fatalf("expected current-user collision for %q, got %v", email, err)
		}
	}

	pending, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "Reserved@Example.Test",
		DisplayName: "Reserved",
	})
	if err != nil {
		t.Fatal(err)
	}
	now = pending.ExpiresAt.Add(time.Hour)
	if _, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       " reserved@example.test ",
		DisplayName: "Duplicate",
	}); !IsValidationError(err) {
		t.Fatalf("expected expired pending invitation to reserve its email, got %v", err)
	}
	if _, err := service.CreateUser(ctx, CreateUserParams{
		ActorUserID: admin.User.ID,
		Email:       "reserved@example.test",
		DisplayName: "Temporary bridge",
		Password:    accountTestPassword,
	}); !IsValidationError(err) {
		t.Fatalf("expected expired pending invitation to block CreateUser, got %v", err)
	}

	needsReissue, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "reissue@example.test",
		DisplayName: "Needs Reissue",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE invitations
SET status = 'needs_reissue', token_digest = NULL, expires_at = NULL, authorized_by_user_id = NULL
WHERE id = ?`, needsReissue.InvitationID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "REISSUE@example.test",
		DisplayName: "Duplicate",
	}); !IsValidationError(err) {
		t.Fatalf("expected needs_reissue invitation to reserve its email, got %v", err)
	}
	if _, err := service.CreateUser(ctx, CreateUserParams{
		ActorUserID: admin.User.ID,
		Email:       "reissue@example.test",
		DisplayName: "Temporary bridge",
		Password:    accountTestPassword,
	}); !IsValidationError(err) {
		t.Fatalf("expected needs_reissue invitation to block CreateUser, got %v", err)
	}

	invalidCases := []struct {
		name   string
		params CreateInvitationParams
	}{
		{name: "email", params: CreateInvitationParams{ActorUserID: admin.User.ID, Email: "not-an-email", DisplayName: "Invalid"}},
		{name: "display name", params: CreateInvitationParams{ActorUserID: admin.User.ID, Email: "blank@example.test", DisplayName: "  "}},
		{name: "repository ID", params: CreateInvitationParams{ActorUserID: admin.User.ID, Email: "repo-id@example.test", DisplayName: "Invalid", RepositoryGrants: []InvitationRepositoryGrant{{RepositoryID: 0, Role: RoleViewer}}}},
		{name: "Administrator repository role", params: CreateInvitationParams{ActorUserID: admin.User.ID, Email: "admin-role@example.test", DisplayName: "Invalid", RepositoryGrants: []InvitationRepositoryGrant{{RepositoryID: repositoryID, Role: RoleAdmin}}}},
		{name: "unknown repository role", params: CreateInvitationParams{ActorUserID: admin.User.ID, Email: "unknown-role@example.test", DisplayName: "Invalid", RepositoryGrants: []InvitationRepositoryGrant{{RepositoryID: repositoryID, Role: Role("owner")}}}},
		{name: "missing repository", params: CreateInvitationParams{ActorUserID: admin.User.ID, Email: "missing-repo@example.test", DisplayName: "Invalid", RepositoryGrants: []InvitationRepositoryGrant{{RepositoryID: repositoryID + 999, Role: RoleViewer}}}},
	}
	for _, testCase := range invalidCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := service.CreateInvitation(ctx, testCase.params); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}

	ordinary := mustCreateUser(t, ctx, service, "ordinary@example.test", false)
	if _, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: ordinary.ID,
		Email:       "denied@example.test",
		DisplayName: "Denied",
	}); !IsValidationError(err) {
		t.Fatalf("expected non-Administrator actor rejection, got %v", err)
	}
	disabledAdmin := mustCreateUser(t, ctx, service, "disabled-admin@example.test", true)
	if _, err := service.DisableUser(ctx, admin.User.ID, disabledAdmin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: disabledAdmin.ID,
		Email:       "disabled-actor@example.test",
		DisplayName: "Disabled Actor",
	}); !IsValidationError(err) {
		t.Fatalf("expected disabled Administrator actor rejection, got %v", err)
	}
}

func TestInvitationReissuePreservesIdentityRotatesCredentialAndReplacesAuthority(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 24, 13, 0, 0, 111, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	secondAdmin := mustCreateUser(t, ctx, service, "second-admin@example.test", true)
	repositoryA := mustCreateTestRepository(t, ctx, database, "acme", "api")
	repositoryB := mustCreateTestRepository(t, ctx, database, "acme", "web")
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "lead@example.test",
		DisplayName: "Release Lead",
		IsAdmin:     true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: repositoryA, Role: RoleViewer},
			{RepositoryID: repositoryA, Role: RoleFreezer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := loadStoredInvitation(t, ctx, database, created.InvitationID)
	oldDigest := append([]byte(nil), before.TokenDigest...)

	now = created.ExpiresAt.Add(time.Hour)
	reissued, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
		ActorUserID:  secondAdmin.ID,
		InvitationID: created.InvitationID,
		IsAdmin:      false,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: repositoryB, Role: RoleThawApprover},
			{RepositoryID: repositoryB, Role: RoleViewer},
			{RepositoryID: repositoryB, Role: RoleViewer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reissued.InvitationID != created.InvitationID || reissued.Token == created.Token || !reissued.ExpiresAt.Equal(persistedInvitationExpiry(now)) {
		t.Fatalf("unexpected reissued credential: before=%+v after=%+v", created, reissued)
	}
	after := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if after.Status != invitationStatusPending || after.Email.String != before.Email.String ||
		after.DisplayName.String != before.DisplayName.String || after.CreatedAt != before.CreatedAt ||
		after.IsAdmin.Int64 != 0 || after.AuthorizedBy.Int64 != secondAdmin.ID ||
		after.ExpectedGrantCount.Int64 != 2 || after.UpdatedAt == before.UpdatedAt {
		t.Fatalf("unexpected invitation after reissue: before=%+v after=%+v", before, after)
	}
	newDigest := sha256.Sum256([]byte(reissued.Token))
	if bytes.Equal(after.TokenDigest, oldDigest) || !bytes.Equal(after.TokenDigest, newDigest[:]) || after.ExpiresAt.Int64 != reissued.ExpiresAt.UnixNano() {
		t.Fatalf("expected rotated digest and exact expiry, got digest=%x expiry=%d", after.TokenDigest, after.ExpiresAt.Int64)
	}
	assertInvitationGrantsEqual(t, loadStoredInvitationGrants(t, ctx, database, created.InvitationID), []InvitationRepositoryGrant{
		{RepositoryID: repositoryB, Role: RoleThawApprover},
		{RepositoryID: repositoryB, Role: RoleViewer},
	})

	details := loadInvitationAuditDetails(t, ctx, database, audit.ActionInvitationReissued, created.InvitationID)
	assertInvitationAuditKeys(
		t,
		details,
		"actor_kind",
		"expires_at",
		"administrator_before",
		"administrator_after",
		"repository_grant_count_before_expected",
		"repository_grant_count_before_actual",
		"repository_grant_count_after",
	)
	if details["administrator_before"] != "true" || details["administrator_after"] != "false" ||
		details["repository_grant_count_before_expected"] != "2" ||
		details["repository_grant_count_before_actual"] != "2" ||
		details["repository_grant_count_after"] != "2" {
		t.Fatalf("unexpected invitation reissue audit details: %v", details)
	}
	assertInvitationAuditSecretsAbsent(t, details, after.Email.String, after.DisplayName.String, created.Token, reissued.Token, fmt.Sprintf("%x", newDigest))
}

func TestInvitationReissueRepairsDriftAndMissingReplacementPreservesOldState(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 24, 14, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	deletedRepository := mustCreateTestRepository(t, ctx, database, "acme", "deleted")
	replacementRepository := mustCreateTestRepository(t, ctx, database, "acme", "replacement")
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "drift@example.test",
		DisplayName: "Drifted",
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: deletedRepository, Role: RoleFreezer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, deletedRepository); err != nil {
		t.Fatal(err)
	}
	before := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if before.ExpectedGrantCount.Int64 != 1 || len(loadStoredInvitationGrants(t, ctx, database, created.InvitationID)) != 0 {
		t.Fatalf("expected durable staged-authority drift, got %+v", before)
	}

	now = now.Add(time.Hour)
	if _, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
		IsAdmin:      true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: deletedRepository, Role: RoleViewer},
		},
	}); !IsValidationError(err) {
		t.Fatalf("expected missing replacement repository rejection, got %v", err)
	}
	failed := loadStoredInvitation(t, ctx, database, created.InvitationID)
	assertStoredInvitationCredentialEqual(t, failed, before)
	if failed.IsAdmin.Int64 != before.IsAdmin.Int64 || failed.UpdatedAt != before.UpdatedAt || len(loadStoredInvitationGrants(t, ctx, database, created.InvitationID)) != 0 {
		t.Fatalf("expected rejected replacement to preserve drifted state, before=%+v after=%+v", before, failed)
	}

	reissued, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
		IsAdmin:      true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: replacementRepository, Role: RoleViewer},
			{RepositoryID: replacementRepository, Role: RoleFreezer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	after := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if bytes.Equal(after.TokenDigest, before.TokenDigest) || after.ExpectedGrantCount.Int64 != 2 || after.IsAdmin.Int64 != 1 {
		t.Fatalf("expected valid replacement to rotate and reset authority, got %+v", after)
	}
	if reissued.Token == created.Token {
		t.Fatal("expected valid post-drift replacement to return a new bearer")
	}
	details := loadInvitationAuditDetails(t, ctx, database, audit.ActionInvitationReissued, created.InvitationID)
	if details["repository_grant_count_before_expected"] != "1" || details["repository_grant_count_before_actual"] != "0" || details["repository_grant_count_after"] != "2" {
		t.Fatalf("expected reissue audit to retain pre-repair drift evidence, got %v", details)
	}
}

func TestInvitationCancelRedactsTerminalStateAndReleasesEmail(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 24, 15, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "api")
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "cancel@example.test",
		DisplayName: "Cancelled User",
		IsAdmin:     true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: repositoryID, Role: RoleFreezer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := loadStoredInvitation(t, ctx, database, created.InvitationID)
	now = now.Add(time.Hour)
	if err := service.CancelInvitation(ctx, CancelInvitationParams{ActorUserID: admin.User.ID, InvitationID: created.InvitationID}); err != nil {
		t.Fatal(err)
	}
	after := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if after.Status != invitationStatusCancelled || after.Email.Valid || after.DisplayName.Valid ||
		after.TokenDigest != nil || after.ExpiresAt.Valid || after.IsAdmin.Valid ||
		after.AuthorizedBy.Valid || after.ExpectedGrantCount.Valid || after.CreatedAt != before.CreatedAt ||
		after.UpdatedAt != now.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("expected terminal cancellation redaction, before=%+v after=%+v", before, after)
	}
	if len(loadStoredInvitationGrants(t, ctx, database, created.InvitationID)) != 0 {
		t.Fatal("expected cancellation to delete every staged repository grant")
	}
	details := loadInvitationAuditDetails(t, ctx, database, audit.ActionInvitationCancelled, created.InvitationID)
	assertInvitationAuditKeys(t, details, "actor_kind")
	assertInvitationAuditSecretsAbsent(t, details, "cancel@example.test", "Cancelled User", created.Token)

	if err := service.CancelInvitation(ctx, CancelInvitationParams{ActorUserID: admin.User.ID, InvitationID: created.InvitationID}); !IsValidationError(err) {
		t.Fatalf("expected terminal cancellation rejection, got %v", err)
	}
	if _, err := service.ReissueInvitation(ctx, ReissueInvitationParams{ActorUserID: admin.User.ID, InvitationID: created.InvitationID}); !IsValidationError(err) {
		t.Fatalf("expected cancelled invitation reissue rejection, got %v", err)
	}
	user, err := service.CreateUser(ctx, CreateUserParams{
		ActorUserID: admin.User.ID,
		Email:       "cancel@example.test",
		DisplayName: "Bridge User",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatalf("expected cancellation to release CreateUser email reservation: %v", err)
	}
	if !user.MustChangePassword {
		t.Fatalf("expected temporary CreateUser bridge behavior preserved, got %+v", user)
	}
}

func TestInvitationAcceptedStateIsReservedForLaterLifecycle(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "accepted@example.test",
		DisplayName: "Accepted Later",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE invitations
SET status = 'accepted',
    canonical_email = NULL,
    display_name = NULL,
    token_digest = NULL,
    expires_at = NULL,
    is_admin = NULL,
    authorized_by_user_id = NULL,
    expected_repository_grant_count = NULL
WHERE id = ?`, created.InvitationID); err != nil {
		t.Fatal(err)
	}
	before := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if _, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
	}); !IsValidationError(err) {
		t.Fatalf("expected accepted invitation reissue rejection, got %v", err)
	}
	if err := service.CancelInvitation(ctx, CancelInvitationParams{
		ActorUserID:  admin.User.ID,
		InvitationID: created.InvitationID,
	}); !IsValidationError(err) {
		t.Fatalf("expected accepted invitation cancellation rejection, got %v", err)
	}
	after := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if after.Status != invitationStatusAccepted || after.UpdatedAt != before.UpdatedAt ||
		after.Email.Valid || after.DisplayName.Valid || after.TokenDigest != nil || after.ExpiresAt.Valid ||
		after.IsAdmin.Valid || after.AuthorizedBy.Valid || after.ExpectedGrantCount.Valid {
		t.Fatalf("expected invitation management methods to leave accepted tombstone unchanged, before=%+v after=%+v", before, after)
	}
}

func TestInvitationLifecycleRollsBackWhenAuditPersistenceFails(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		ctx := context.Background()
		database := newAuthTestDB(t, ctx)
		service := NewService(database)
		admin := mustCreateFirstAdmin(t, ctx, service)
		breakAuditTable(t, ctx, database)

		if _, err := service.CreateInvitation(ctx, CreateInvitationParams{
			ActorUserID: admin.User.ID,
			Email:       "rollback-create@example.test",
			DisplayName: "Rollback",
		}); err == nil || IsValidationError(err) {
			t.Fatalf("expected operational audit failure, got %v", err)
		}
		var invitations int
		if err := database.QueryRowContext(ctx, `SELECT count(*) FROM invitations`).Scan(&invitations); err != nil {
			t.Fatal(err)
		}
		if invitations != 0 {
			t.Fatalf("expected failed creation to roll back, got %d invitations", invitations)
		}
	})

	for _, operation := range []string{"reissue", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin := mustCreateFirstAdmin(t, ctx, service)
			repositoryA := mustCreateTestRepository(t, ctx, database, "acme", "api")
			repositoryB := mustCreateTestRepository(t, ctx, database, "acme", "web")
			created, err := service.CreateInvitation(ctx, CreateInvitationParams{
				ActorUserID: admin.User.ID,
				Email:       "rollback@example.test",
				DisplayName: "Rollback",
				IsAdmin:     true,
				RepositoryGrants: []InvitationRepositoryGrant{
					{RepositoryID: repositoryA, Role: RoleFreezer},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			before := loadStoredInvitation(t, ctx, database, created.InvitationID)
			beforeGrants := loadStoredInvitationGrants(t, ctx, database, created.InvitationID)
			breakAuditTable(t, ctx, database)

			switch operation {
			case "reissue":
				_, err = service.ReissueInvitation(ctx, ReissueInvitationParams{
					ActorUserID:  admin.User.ID,
					InvitationID: created.InvitationID,
					RepositoryGrants: []InvitationRepositoryGrant{
						{RepositoryID: repositoryB, Role: RoleViewer},
					},
				})
			case "cancel":
				err = service.CancelInvitation(ctx, CancelInvitationParams{ActorUserID: admin.User.ID, InvitationID: created.InvitationID})
			}
			if err == nil || IsValidationError(err) {
				t.Fatalf("expected operational audit failure, got %v", err)
			}
			after := loadStoredInvitation(t, ctx, database, created.InvitationID)
			assertStoredInvitationCredentialEqual(t, after, before)
			if after.Status != before.Status || after.Email != before.Email || after.DisplayName != before.DisplayName ||
				after.IsAdmin != before.IsAdmin || after.AuthorizedBy != before.AuthorizedBy ||
				after.ExpectedGrantCount != before.ExpectedGrantCount || after.CreatedAt != before.CreatedAt || after.UpdatedAt != before.UpdatedAt {
				t.Fatalf("expected failed %s to preserve parent row, before=%+v after=%+v", operation, before, after)
			}
			assertInvitationGrantsEqual(t, loadStoredInvitationGrants(t, ctx, database, created.InvitationID), beforeGrants)
		})
	}
}

func TestInvitationAuthorizerDemotionAndDisablementInvalidateEveryCredential(t *testing.T) {
	for _, operation := range []struct {
		name   string
		reason string
		mutate func(context.Context, *Service, int64, int64) error
	}{
		{
			name:   "demotion",
			reason: invitationRevocationAdminRemoved,
			mutate: func(ctx context.Context, service *Service, actorID, targetID int64) error {
				_, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actorID, UserID: targetID, Admin: false})
				return err
			},
		},
		{
			name:   "disablement",
			reason: invitationRevocationAuthorizerDisabled,
			mutate: func(ctx context.Context, service *Service, actorID, targetID int64) error {
				_, err := service.DisableUser(ctx, actorID, targetID)
				return err
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			now := time.Date(2026, 7, 24, 16, 0, 0, 0, time.UTC)
			service.now = func() time.Time { return now }
			admin := mustCreateFirstAdmin(t, ctx, service)
			authorizer := mustCreateUser(t, ctx, service, "authorizer@example.test", true)
			unrelatedAuthorizer := mustCreateUser(t, ctx, service, "other-admin@example.test", true)
			repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "api")
			first, err := service.CreateInvitation(ctx, CreateInvitationParams{
				ActorUserID: authorizer.ID,
				Email:       "first@example.test",
				DisplayName: "First",
				IsAdmin:     true,
				RepositoryGrants: []InvitationRepositoryGrant{
					{RepositoryID: repositoryID, Role: RoleFreezer},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			second, err := service.CreateInvitation(ctx, CreateInvitationParams{
				ActorUserID: authorizer.ID,
				Email:       "second@example.test",
				DisplayName: "Second",
			})
			if err != nil {
				t.Fatal(err)
			}
			unrelated, err := service.CreateInvitation(ctx, CreateInvitationParams{
				ActorUserID: unrelatedAuthorizer.ID,
				Email:       "unrelated@example.test",
				DisplayName: "Unrelated",
			})
			if err != nil {
				t.Fatal(err)
			}
			before := map[string]storedInvitation{
				first.InvitationID:     loadStoredInvitation(t, ctx, database, first.InvitationID),
				second.InvitationID:    loadStoredInvitation(t, ctx, database, second.InvitationID),
				unrelated.InvitationID: loadStoredInvitation(t, ctx, database, unrelated.InvitationID),
			}
			firstGrants := loadStoredInvitationGrants(t, ctx, database, first.InvitationID)

			now = first.ExpiresAt.Add(time.Hour)
			if err := operation.mutate(ctx, service, admin.User.ID, authorizer.ID); err != nil {
				t.Fatal(err)
			}
			for _, invitationID := range []string{first.InvitationID, second.InvitationID} {
				after := loadStoredInvitation(t, ctx, database, invitationID)
				prior := before[invitationID]
				if after.Status != invitationStatusReissue || after.TokenDigest != nil || after.ExpiresAt.Valid || after.AuthorizedBy.Valid {
					t.Fatalf("expected %s to invalidate invitation %s, got %+v", operation.name, invitationID, after)
				}
				if after.Email != prior.Email || after.DisplayName != prior.DisplayName || after.IsAdmin != prior.IsAdmin ||
					after.ExpectedGrantCount != prior.ExpectedGrantCount || after.CreatedAt != prior.CreatedAt ||
					after.UpdatedAt != now.UTC().Format(time.RFC3339Nano) {
					t.Fatalf("expected %s to retain staged identity and authority, before=%+v after=%+v", operation.name, prior, after)
				}
				details := loadInvitationAuditDetails(t, ctx, database, audit.ActionInvitationAuthorizationRevoked, invitationID)
				assertInvitationAuditKeys(t, details, "actor_kind", "reason")
				if details["reason"] != operation.reason || details["actor_kind"] != "user" {
					t.Fatalf("unexpected revocation audit details: %v", details)
				}
				assertInvitationAuditSecretsAbsent(t, details, prior.Email.String, prior.DisplayName.String)
			}
			assertInvitationGrantsEqual(t, loadStoredInvitationGrants(t, ctx, database, first.InvitationID), firstGrants)

			unrelatedAfter := loadStoredInvitation(t, ctx, database, unrelated.InvitationID)
			assertStoredInvitationCredentialEqual(t, unrelatedAfter, before[unrelated.InvitationID])
			if unrelatedAfter.Status != invitationStatusPending || unrelatedAfter.UpdatedAt != before[unrelated.InvitationID].UpdatedAt {
				t.Fatalf("expected unrelated authorizer invitation unchanged, got %+v", unrelatedAfter)
			}
			var userUpdatedAt string
			if err := database.QueryRowContext(ctx, `SELECT updated_at FROM users WHERE id = ?`, authorizer.ID).Scan(&userUpdatedAt); err != nil {
				t.Fatal(err)
			}
			if userUpdatedAt != now.UTC().Format(time.RFC3339Nano) {
				t.Fatalf("expected account and invitations to share post-lock timestamp, user=%q invitations=%q", userUpdatedAt, now.UTC().Format(time.RFC3339Nano))
			}
			var revoked int
			if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM audit_events
WHERE action = ? AND subject_type = ?`, audit.ActionInvitationAuthorizationRevoked, audit.SubjectTypeInvitation).Scan(&revoked); err != nil {
				t.Fatal(err)
			}
			if revoked != 2 {
				t.Fatalf("expected one authorization-revoked event per invalidated invitation, got %d", revoked)
			}
		})
	}
}

func TestInvitationAuthorizerFinalAdminAndAuditFailuresRollBackEverything(t *testing.T) {
	for _, operation := range []struct {
		name   string
		mutate func(context.Context, *Service, int64, int64) error
	}{
		{
			name: "demotion",
			mutate: func(ctx context.Context, service *Service, actorID, targetID int64) error {
				_, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actorID, UserID: targetID, Admin: false})
				return err
			},
		},
		{
			name: "disablement",
			mutate: func(ctx context.Context, service *Service, actorID, targetID int64) error {
				_, err := service.DisableUser(ctx, actorID, targetID)
				return err
			},
		},
	} {
		t.Run(operation.name+" final Administrator", func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin := mustCreateFirstAdmin(t, ctx, service)
			created, err := service.CreateInvitation(ctx, CreateInvitationParams{
				ActorUserID: admin.User.ID,
				Email:       "protected@example.test",
				DisplayName: "Protected",
			})
			if err != nil {
				t.Fatal(err)
			}
			before := loadStoredInvitation(t, ctx, database, created.InvitationID)
			if err := operation.mutate(ctx, service, admin.User.ID, admin.User.ID); !IsValidationError(err) {
				t.Fatalf("expected final-Administrator rejection, got %v", err)
			}
			after := loadStoredInvitation(t, ctx, database, created.InvitationID)
			assertStoredInvitationCredentialEqual(t, after, before)
			if after.Status != invitationStatusPending || after.UpdatedAt != before.UpdatedAt {
				t.Fatalf("expected final-Administrator rejection to preserve invitation, got %+v", after)
			}
			loaded, err := service.userByID(ctx, database, admin.User.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !loaded.IsAdmin || loaded.Disabled() {
				t.Fatalf("expected final Administrator account preserved, got %+v", loaded.User)
			}
			var revoked int
			if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = ?`, audit.ActionInvitationAuthorizationRevoked).Scan(&revoked); err != nil {
				t.Fatal(err)
			}
			if revoked != 0 {
				t.Fatalf("expected no revocation audit after rejected account mutation, got %d", revoked)
			}
		})

		t.Run(operation.name+" audit failure", func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin := mustCreateFirstAdmin(t, ctx, service)
			authorizer := mustCreateUser(t, ctx, service, "authorizer@example.test", true)
			created, err := service.CreateInvitation(ctx, CreateInvitationParams{
				ActorUserID: authorizer.ID,
				Email:       "rollback-authorizer@example.test",
				DisplayName: "Rollback",
			})
			if err != nil {
				t.Fatal(err)
			}
			before := loadStoredInvitation(t, ctx, database, created.InvitationID)
			breakAuditTable(t, ctx, database)
			if err := operation.mutate(ctx, service, admin.User.ID, authorizer.ID); err == nil || IsValidationError(err) {
				t.Fatalf("expected operational audit failure, got %v", err)
			}
			after := loadStoredInvitation(t, ctx, database, created.InvitationID)
			assertStoredInvitationCredentialEqual(t, after, before)
			if after.Status != invitationStatusPending || after.UpdatedAt != before.UpdatedAt {
				t.Fatalf("expected audit failure to preserve invitation, got %+v", after)
			}
			loaded, err := service.userByID(ctx, database, authorizer.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !loaded.IsAdmin || loaded.Disabled() {
				t.Fatalf("expected audit failure to roll back account mutation, got %+v", loaded.User)
			}
		})
	}
}

func TestInvitationAuthorizerRestorationNeverRevivesOldCredential(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 24, 17, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	authorizer := mustCreateUser(t, ctx, service, "authorizer@example.test", true)
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: authorizer.ID,
		Email:       "restore@example.test",
		DisplayName: "Restore",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: authorizer.ID, Admin: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: admin.User.ID, UserID: authorizer.ID, Admin: true}); err != nil {
		t.Fatal(err)
	}
	afterPromotion := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if afterPromotion.Status != invitationStatusReissue || afterPromotion.TokenDigest != nil || afterPromotion.ExpiresAt.Valid || afterPromotion.AuthorizedBy.Valid {
		t.Fatalf("expected re-promotion not to restore invitation credential, got %+v", afterPromotion)
	}
	now = now.Add(time.Hour)
	afterRepromotion, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
		ActorUserID:  authorizer.ID,
		InvitationID: created.InvitationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if afterRepromotion.Token == created.Token {
		t.Fatal("expected explicit reissue after re-promotion to rotate the credential")
	}

	if _, err := service.DisableUser(ctx, admin.User.ID, authorizer.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnableUser(ctx, admin.User.ID, authorizer.ID); err != nil {
		t.Fatal(err)
	}
	afterEnable := loadStoredInvitation(t, ctx, database, created.InvitationID)
	if afterEnable.Status != invitationStatusReissue || afterEnable.TokenDigest != nil || afterEnable.ExpiresAt.Valid || afterEnable.AuthorizedBy.Valid {
		t.Fatalf("expected re-enable not to restore invitation credential, got %+v", afterEnable)
	}
	now = now.Add(time.Hour)
	afterReenable, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
		ActorUserID:  authorizer.ID,
		InvitationID: created.InvitationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if afterReenable.Token == created.Token || afterReenable.Token == afterRepromotion.Token {
		t.Fatal("expected explicit reissue after re-enable to create a third credential")
	}
}

func TestConcurrentInvitationCreationHasOneDomainWinner(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)

	start := make(chan struct{})
	results := make(chan error, 2)
	for i := range 2 {
		go func(i int) {
			<-start
			_, err := service.CreateInvitation(ctx, CreateInvitationParams{
				ActorUserID: admin.User.ID,
				Email:       " Race@Example.Test ",
				DisplayName: fmt.Sprintf("Racer %d", i),
			})
			results <- err
		}(i)
	}
	close(start)

	var successes, validationFailures int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case IsValidationError(err):
			validationFailures++
		default:
			t.Fatalf("expected domain race result, got operational error %v", err)
		}
	}
	if successes != 1 || validationFailures != 1 {
		t.Fatalf("expected one invitation winner and one validation loser, success=%d validation=%d", successes, validationFailures)
	}
	var rows int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM invitations
WHERE canonical_email = 'race@example.test' AND status = 'pending'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("expected exactly one active invitation, got %d", rows)
	}
}

func TestInvitationCreationRacingCreateUserHasOneDomainWinner(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, err := service.CreateInvitation(ctx, CreateInvitationParams{
			ActorUserID: admin.User.ID,
			Email:       "identity-race@example.test",
			DisplayName: "Invitation Racer",
		})
		results <- err
	}()
	go func() {
		<-start
		_, err := service.CreateUser(ctx, CreateUserParams{
			ActorUserID: admin.User.ID,
			Email:       "IDENTITY-RACE@example.test",
			DisplayName: "User Racer",
			Password:    accountTestPassword,
		})
		results <- err
	}()
	close(start)

	var successes, validationFailures int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case IsValidationError(err):
			validationFailures++
		default:
			t.Fatalf("expected domain race result, got operational error %v", err)
		}
	}
	if successes != 1 || validationFailures != 1 {
		t.Fatalf("expected one identity winner and one validation loser, success=%d validation=%d", successes, validationFailures)
	}
	var users, invitations int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE email = 'identity-race@example.test'`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM invitations WHERE canonical_email = 'identity-race@example.test' AND status IN ('pending', 'needs_reissue')`).Scan(&invitations); err != nil {
		t.Fatal(err)
	}
	if users+invitations != 1 {
		t.Fatalf("expected one canonical identity owner, users=%d invitations=%d", users, invitations)
	}
}

func TestInvitationCreateAndReissueRacingAuthorizerLossLeaveNoActiveCredential(t *testing.T) {
	for _, authorityLoss := range []struct {
		name   string
		mutate func(context.Context, *Service, int64, int64) error
	}{
		{
			name: "disable",
			mutate: func(ctx context.Context, service *Service, actorID, targetID int64) error {
				_, err := service.DisableUser(ctx, actorID, targetID)
				return err
			},
		},
		{
			name: "demote",
			mutate: func(ctx context.Context, service *Service, actorID, targetID int64) error {
				_, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actorID, UserID: targetID, Admin: false})
				return err
			},
		},
	} {
		for _, lifecycle := range []string{"create", "reissue"} {
			t.Run(lifecycle+" versus "+authorityLoss.name, func(t *testing.T) {
				ctx := context.Background()
				database := newAuthTestDB(t, ctx)
				service := NewService(database)
				admin := mustCreateFirstAdmin(t, ctx, service)
				authorizer := mustCreateUser(t, ctx, service, "racing-authorizer@example.test", true)
				var invitationID string
				if lifecycle == "reissue" {
					created, err := service.CreateInvitation(ctx, CreateInvitationParams{
						ActorUserID: authorizer.ID,
						Email:       "reissue-race@example.test",
						DisplayName: "Reissue Race",
					})
					if err != nil {
						t.Fatal(err)
					}
					invitationID = created.InvitationID
				}

				start := make(chan struct{})
				credentialResult := make(chan invitationCredentialResult, 1)
				mutationResult := make(chan error, 1)
				go func() {
					<-start
					var credential InvitationCredential
					var err error
					if lifecycle == "create" {
						credential, err = service.CreateInvitation(ctx, CreateInvitationParams{
							ActorUserID: authorizer.ID,
							Email:       "create-race@example.test",
							DisplayName: "Create Race",
						})
					} else {
						credential, err = service.ReissueInvitation(ctx, ReissueInvitationParams{
							ActorUserID:  authorizer.ID,
							InvitationID: invitationID,
						})
					}
					credentialResult <- invitationCredentialResult{credential: credential, err: err}
				}()
				go func() {
					<-start
					mutationResult <- authorityLoss.mutate(ctx, service, admin.User.ID, authorizer.ID)
				}()
				close(start)

				credentialOutcome := <-credentialResult
				if credentialOutcome.err != nil && !IsValidationError(credentialOutcome.err) {
					t.Fatalf("expected credential operation to succeed or lose by validation, got %v", credentialOutcome.err)
				}
				if err := <-mutationResult; err != nil {
					t.Fatalf("expected authority loss to succeed, got %v", err)
				}
				var active int
				if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM invitations
WHERE status = 'pending'
  AND authorized_by_user_id = ?
  AND token_digest IS NOT NULL
  AND expires_at IS NOT NULL`, authorizer.ID).Scan(&active); err != nil {
					t.Fatal(err)
				}
				if active != 0 {
					t.Fatalf("%s racing %s left %d active credentials for an ineligible authorizer", lifecycle, authorityLoss.name, active)
				}
				if lifecycle == "reissue" {
					stored := loadStoredInvitation(t, ctx, database, invitationID)
					if stored.Status != invitationStatusReissue || stored.TokenDigest != nil || stored.ExpiresAt.Valid || stored.AuthorizedBy.Valid {
						t.Fatalf("expected raced reissue credential to remain permanently invalid, got %+v", stored)
					}
				}
			})
		}
	}
}

func TestInvitationReissueRacingRepositoryDeletionIsRejectedOrLeavesDrift(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	retainedRepository := mustCreateTestRepository(t, ctx, database, "acme", "retained")
	racingRepository := mustCreateTestRepository(t, ctx, database, "acme", "racing")
	created, err := service.CreateInvitation(ctx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "repository-race@example.test",
		DisplayName: "Repository Race",
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: retainedRepository, Role: RoleViewer},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := loadStoredInvitation(t, ctx, database, created.InvitationID)
	beforeGrants := loadStoredInvitationGrants(t, ctx, database, created.InvitationID)

	start := make(chan struct{})
	reissueResult := make(chan invitationCredentialResult, 1)
	deleteResult := make(chan error, 1)
	go func() {
		<-start
		credential, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
			ActorUserID:  admin.User.ID,
			InvitationID: created.InvitationID,
			RepositoryGrants: []InvitationRepositoryGrant{
				{RepositoryID: retainedRepository, Role: RoleViewer},
				{RepositoryID: racingRepository, Role: RoleFreezer},
			},
		})
		reissueResult <- invitationCredentialResult{credential: credential, err: err}
	}()
	go func() {
		<-start
		_, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, racingRepository)
		deleteResult <- err
	}()
	close(start)
	outcome := <-reissueResult
	if err := <-deleteResult; err != nil {
		t.Fatalf("delete racing repository: %v", err)
	}

	after := loadStoredInvitation(t, ctx, database, created.InvitationID)
	grants := loadStoredInvitationGrants(t, ctx, database, created.InvitationID)
	if outcome.err != nil {
		if !IsValidationError(outcome.err) {
			t.Fatalf("expected missing-repository validation rejection, got %v", outcome.err)
		}
		assertStoredInvitationCredentialEqual(t, after, before)
		if after.Status != before.Status || after.ExpectedGrantCount != before.ExpectedGrantCount || after.UpdatedAt != before.UpdatedAt {
			t.Fatalf("expected rejected reissue to preserve parent state, before=%+v after=%+v", before, after)
		}
		assertInvitationGrantsEqual(t, grants, beforeGrants)
		return
	}
	if outcome.credential.Token == created.Token || after.ExpectedGrantCount.Int64 != 2 || len(grants) != 1 || grants[0].RepositoryID != retainedRepository {
		t.Fatalf("expected completed reissue followed by durable expected/actual mismatch, credential=%+v invitation=%+v grants=%+v", outcome.credential, after, grants)
	}
}

func TestInvitationCreateAndReissueSampleClockAfterWriterContention(t *testing.T) {
	for _, operation := range []string{"create", "reissue"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin := mustCreateFirstAdmin(t, ctx, service)
			var invitationID string
			if operation == "reissue" {
				service.now = func() time.Time { return time.Date(2026, 7, 24, 18, 0, 0, 0, time.UTC) }
				created, err := service.CreateInvitation(ctx, CreateInvitationParams{
					ActorUserID: admin.User.ID,
					Email:       "clock-reissue@example.test",
					DisplayName: "Clock Reissue",
				})
				if err != nil {
					t.Fatal(err)
				}
				invitationID = created.InvitationID
			}

			blocker, err := database.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			if _, err := blocker.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, admin.User.ID); err != nil {
				t.Fatal(err)
			}

			beforeLock := time.Date(2026, 7, 24, 19, 0, 0, 0, time.UTC)
			afterLock := beforeLock.Add(time.Minute)
			var clockNanos atomic.Int64
			clockNanos.Store(beforeLock.UnixNano())
			clockRead := make(chan struct{}, 1)
			service.now = func() time.Time {
				select {
				case clockRead <- struct{}{}:
				default:
				}
				return time.Unix(0, clockNanos.Load()).UTC()
			}
			result := make(chan invitationCredentialResult, 1)
			go func() {
				var credential InvitationCredential
				var err error
				if operation == "create" {
					credential, err = service.CreateInvitation(ctx, CreateInvitationParams{
						ActorUserID: admin.User.ID,
						Email:       "clock-create@example.test",
						DisplayName: "Clock Create",
					})
				} else {
					credential, err = service.ReissueInvitation(ctx, ReissueInvitationParams{
						ActorUserID:  admin.User.ID,
						InvitationID: invitationID,
					})
				}
				result <- invitationCredentialResult{credential: credential, err: err}
			}()

			select {
			case <-clockRead:
				t.Fatalf("%s sampled time before SQLite writer ownership", operation)
			case outcome := <-result:
				t.Fatalf("%s returned before controlled writer release: %v", operation, outcome.err)
			case <-time.After(200 * time.Millisecond):
			}
			clockNanos.Store(afterLock.UnixNano())
			if err := blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case outcome := <-result:
				if outcome.err != nil {
					t.Fatalf("expected %s to continue after writer release: %v", operation, outcome.err)
				}
				if !outcome.credential.ExpiresAt.Equal(persistedInvitationExpiry(afterLock)) {
					t.Fatalf("expected post-lock expiry %s, got %s", persistedInvitationExpiry(afterLock), outcome.credential.ExpiresAt)
				}
				stored := loadStoredInvitation(t, ctx, database, outcome.credential.InvitationID)
				if stored.UpdatedAt != afterLock.Format(time.RFC3339Nano) {
					t.Fatalf("expected post-lock updated_at %s, got %s", afterLock, stored.UpdatedAt)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("timed out waiting for %s after writer release", operation)
			}
		})
	}
}

func TestInvitationWriterTimeoutRemainsOperationalAndRollsBack(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	blocker, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, admin.User.ID); err != nil {
		t.Fatal(err)
	}

	timedCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err = service.CreateInvitation(timedCtx, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "timeout@example.test",
		DisplayName: "Timeout",
	})
	if err == nil || IsValidationError(err) {
		t.Fatalf("expected context/lock timeout to remain operational, got %v", err)
	}
	var rows int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM invitations WHERE canonical_email = 'timeout@example.test'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("expected timed-out invitation creation to leave no partial row, got %d", rows)
	}
}

type storedInvitation struct {
	ID                 string
	Status             string
	Email              sql.NullString
	DisplayName        sql.NullString
	TokenDigest        []byte
	ExpiresAt          sql.NullInt64
	IsAdmin            sql.NullInt64
	AuthorizedBy       sql.NullInt64
	ExpectedGrantCount sql.NullInt64
	CreatedAt          string
	UpdatedAt          string
}

func loadStoredInvitation(t *testing.T, ctx context.Context, database *sql.DB, invitationID string) storedInvitation {
	t.Helper()
	var invitation storedInvitation
	if err := database.QueryRowContext(ctx, `
SELECT
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
FROM invitations
WHERE id = ?`, invitationID).Scan(
		&invitation.ID,
		&invitation.Status,
		&invitation.Email,
		&invitation.DisplayName,
		&invitation.TokenDigest,
		&invitation.ExpiresAt,
		&invitation.IsAdmin,
		&invitation.AuthorizedBy,
		&invitation.ExpectedGrantCount,
		&invitation.CreatedAt,
		&invitation.UpdatedAt,
	); err != nil {
		t.Fatal(err)
	}
	return invitation
}

func loadStoredInvitationGrants(t *testing.T, ctx context.Context, database *sql.DB, invitationID string) []InvitationRepositoryGrant {
	t.Helper()
	rows, err := database.QueryContext(ctx, `
SELECT repository_id, role
FROM invitation_repository_grants
WHERE invitation_id = ?
ORDER BY repository_id, role`, invitationID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	grants := make([]InvitationRepositoryGrant, 0)
	for rows.Next() {
		var grant InvitationRepositoryGrant
		if err := rows.Scan(&grant.RepositoryID, &grant.Role); err != nil {
			t.Fatal(err)
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return grants
}

func assertInvitationGrantsEqual(t *testing.T, got, want []InvitationRepositoryGrant) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("unexpected staged grants: got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected staged grants: got %+v, want %+v", got, want)
		}
	}
}

func loadInvitationAuditDetails(t *testing.T, ctx context.Context, database *sql.DB, action, invitationID string) map[string]string {
	t.Helper()
	var subjectType string
	var detailsJSON string
	if err := database.QueryRowContext(ctx, `
SELECT subject_type, details_json
FROM audit_events
WHERE action = ? AND subject_id = ?
ORDER BY id DESC
LIMIT 1`, action, invitationID).Scan(&subjectType, &detailsJSON); err != nil {
		t.Fatal(err)
	}
	if subjectType != audit.SubjectTypeInvitation {
		t.Fatalf("expected invitation audit subject, got %q", subjectType)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(detailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	return details
}

func assertInvitationAuditKeys(t *testing.T, details map[string]string, want ...string) {
	t.Helper()
	if len(details) != len(want) {
		t.Fatalf("unexpected invitation audit keys: got %v want %v", details, want)
	}
	for _, key := range want {
		if _, ok := details[key]; !ok {
			t.Fatalf("missing invitation audit key %q in %v", key, details)
		}
	}
}

func assertInvitationAuditSecretsAbsent(t *testing.T, details map[string]string, secrets ...string) {
	t.Helper()
	encoded, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	visible := string(encoded)
	for _, secret := range append(secrets, "password", "password_hash", "token_digest") {
		if secret != "" && strings.Contains(visible, secret) {
			t.Fatalf("invitation audit leaked %q in %s", secret, visible)
		}
	}
}

func assertStoredInvitationCredentialEqual(t *testing.T, got, want storedInvitation) {
	t.Helper()
	if !bytes.Equal(got.TokenDigest, want.TokenDigest) || got.ExpiresAt != want.ExpiresAt || got.AuthorizedBy != want.AuthorizedBy {
		t.Fatalf("invitation credential changed: got %+v want %+v", got, want)
	}
}

func breakAuditTable(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `ALTER TABLE audit_events_broken RENAME TO audit_events`)
	})
}
