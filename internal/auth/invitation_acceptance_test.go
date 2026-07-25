package auth

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const invitationAcceptanceTestPassword = "an accepted local password"

func TestAcceptInvitationRejectsNoncanonicalBearersBeforePasswordValidation(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "bearer@example.test",
		DisplayName: "Bearer Test",
	})

	unknown := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, invitationBearerBytes))
	noncanonical := noncanonicalInvitationBearer(t, credential.Token)
	alternate := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, invitationBearerBytes))
	cases := []struct {
		name  string
		token string
	}{
		{name: "malformed", token: "not-a-token"},
		{name: "padded", token: credential.Token + "="},
		{name: "leading whitespace", token: " " + credential.Token},
		{name: "trailing whitespace", token: credential.Token + "\n"},
		{name: "embedded whitespace", token: credential.Token[:10] + "\t" + credential.Token[10:]},
		{name: "short", token: base64.RawURLEncoding.EncodeToString(make([]byte, invitationBearerBytes-1))},
		{name: "long", token: base64.RawURLEncoding.EncodeToString(make([]byte, invitationBearerBytes+1))},
		{name: "alternate alphabet", token: alternate},
		{name: "non URL-safe", token: "*" + credential.Token[1:]},
		{name: "noncanonical trailing bits", token: noncanonical},
		{name: "unknown canonical bearer", token: unknown},
	}
	var genericMessage string
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := service.AcceptInvitation(ctx, testCase.token, "short")
			assertInvalidInvitation(t, err)
			if genericMessage == "" {
				genericMessage = err.Error()
			}
			if err.Error() != genericMessage {
				t.Fatalf("expected one generic invitation error, got %q and %q", genericMessage, err)
			}
			if strings.Contains(err.Error(), testCase.token) || strings.Contains(err.Error(), "short") {
				t.Fatalf("invitation rejection exposed credential material: %v", err)
			}
		})
	}

	before := loadStoredInvitation(t, ctx, database, credential.InvitationID)
	_, err := service.AcceptInvitation(ctx, credential.Token, "short")
	if !IsValidationError(err) || IsInvalidInvitation(err) {
		t.Fatalf("expected valid invitation to reach password policy, got %v", err)
	}
	after := loadStoredInvitation(t, ctx, database, credential.InvitationID)
	assertStoredInvitationUnchanged(t, after, before)

	accepted, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Email != "bearer@example.test" {
		t.Fatalf("expected canonical bearer acceptance, got %+v", accepted)
	}
	_, err = service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
	assertInvalidInvitation(t, err)
}

func TestAcceptInvitationMaterializesStagedIdentityAuthorityAndExactAudits(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 25, 10, 0, 0, 987654321, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryA := mustCreateTestRepository(t, ctx, database, "acme", "api")
	repositoryB := mustCreateTestRepository(t, ctx, database, "acme", "web")
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       " Accepted@Example.Test ",
		DisplayName: " Accepted Release Lead ",
		IsAdmin:     true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: repositoryA, Role: RoleViewer},
			{RepositoryID: repositoryA, Role: RoleFreezer},
			{RepositoryID: repositoryB, Role: RoleThawApprover},
		},
	})
	digest := sha256.Sum256([]byte(credential.Token))

	user, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID <= 0 || user.Email != "accepted@example.test" || user.DisplayName != "Accepted Release Lead" ||
		!user.IsAdmin || user.Disabled() || user.MustChangePassword {
		t.Fatalf("unexpected accepted user: %+v", user)
	}
	if sessions := countUserSessions(t, ctx, database, user.ID); sessions != 0 {
		t.Fatalf("expected acceptance to create no session, got %d", sessions)
	}

	grants, err := service.ListUserRepositoryGrants(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantGrants := []InvitationRepositoryGrant{
		{RepositoryID: repositoryA, Role: RoleFreezer},
		{RepositoryID: repositoryA, Role: RoleViewer},
		{RepositoryID: repositoryB, Role: RoleThawApprover},
	}
	if len(grants) != len(wantGrants) {
		t.Fatalf("expected %d accepted grants, got %+v", len(wantGrants), grants)
	}
	for i, want := range wantGrants {
		got := grants[i]
		if got.RepositoryID != want.RepositoryID || got.Role != want.Role || got.UserID != user.ID ||
			got.GrantedByUserID == nil || *got.GrantedByUserID != admin.User.ID || !got.GrantedAt.Equal(now) {
			t.Fatalf("unexpected accepted repository grant %d: %+v", i, got)
		}
	}

	tombstone := loadStoredInvitation(t, ctx, database, credential.InvitationID)
	assertAcceptedInvitationTombstone(t, tombstone, now)
	if staged := loadStoredInvitationGrants(t, ctx, database, credential.InvitationID); len(staged) != 0 {
		t.Fatalf("expected accepted invitation stages removed, got %+v", staged)
	}

	userID := strconv.FormatInt(user.ID, 10)
	assertAcceptanceAuditEvent(t, ctx, database, audit.ActionInvitationAccepted, audit.SubjectTypeInvitation, credential.InvitationID, "", nil, map[string]string{
		"accepted_user_id": userID,
		"actor_kind":       audit.ActorKindInvitationLink,
	})
	assertAcceptanceAuditEvent(t, ctx, database, audit.ActionUserCreated, audit.SubjectTypeUser, userID, "", nil, map[string]string{
		"actor_kind": audit.ActorKindInvitationLink,
		"onboarding": "invitation",
		"sign_in":    "password",
	})
	assertAcceptanceAuditEvent(t, ctx, database, audit.ActionUserRolesUpdated, audit.SubjectTypeUser, userID, "", &admin.User.ID, map[string]string{
		"actor_kind":   "user",
		"provenance":   "invitation_acceptance",
		"roles_after":  "admin",
		"roles_before": "none",
	})
	for _, grant := range wantGrants {
		assertAcceptanceAuditEvent(
			t,
			ctx,
			database,
			audit.ActionRepositoryGrantAdded,
			audit.SubjectTypeRepository,
			strconv.FormatInt(grant.RepositoryID, 10),
			string(grant.Role),
			&admin.User.ID,
			map[string]string{
				"actor_kind": "user",
				"provenance": "invitation_acceptance",
				"role":       string(grant.Role),
				"user_id":    userID,
			},
		)
	}
	assertAcceptanceAuditCount(t, ctx, database, user.ID, credential.InvitationID, 6)

	var passwordHash string
	if err := database.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, user.ID).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	assertInvitationAcceptanceSecretsAbsent(
		t,
		ctx,
		database,
		credential.Token,
		"https://thawguard.example.test/invitations/accept?token="+credential.Token,
		hex.EncodeToString(digest[:]),
		invitationAcceptanceTestPassword,
		passwordHash,
		user.Email,
		user.DisplayName,
	)

	_, err = service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
	assertInvalidInvitation(t, err)
	for _, secret := range []string{credential.Token, invitationAcceptanceTestPassword, user.Email, user.DisplayName} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("second acceptance error exposed %q", secret)
		}
	}
	acceptedBeforeLifecycleProbes := loadStoredInvitation(t, ctx, database, credential.InvitationID)
	if _, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
		ActorUserID:  admin.User.ID,
		InvitationID: credential.InvitationID,
	}); !IsValidationError(err) {
		t.Fatalf("expected reissue not to alter an accepted tombstone, got %v", err)
	}
	if err := service.CancelInvitation(ctx, CancelInvitationParams{
		ActorUserID:  admin.User.ID,
		InvitationID: credential.InvitationID,
	}); !IsValidationError(err) {
		t.Fatalf("expected cancellation not to alter an accepted tombstone, got %v", err)
	}
	assertStoredInvitationUnchanged(
		t,
		loadStoredInvitation(t, ctx, database, credential.InvitationID),
		acceptedBeforeLifecycleProbes,
	)
	if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, repositoryA); err != nil {
		t.Fatal(err)
	}
	var retainedGrants, deletedGrants, adminRows int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id = ? AND repository_id = ?`, user.ID, repositoryB).Scan(&retainedGrants); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id = ? AND repository_id = ?`, user.ID, repositoryA).Scan(&deletedGrants); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id = ? AND role = 'admin'`, user.ID).Scan(&adminRows); err != nil {
		t.Fatal(err)
	}
	if retainedGrants != 1 || deletedGrants != 0 || adminRows != 1 {
		t.Fatalf("later repository deletion changed unrelated accepted authority: retained=%d deleted=%d admin=%d", retainedGrants, deletedGrants, adminRows)
	}
	assertAcceptanceAuditCount(t, ctx, database, user.ID, credential.InvitationID, 6)
	assertStoredInvitationUnchanged(
		t,
		loadStoredInvitation(t, ctx, database, credential.InvitationID),
		acceptedBeforeLifecycleProbes,
	)

	session, err := service.Login(ctx, LoginParams{Email: user.Email, Password: invitationAcceptanceTestPassword})
	if err != nil {
		t.Fatalf("expected ordinary later login to work: %v", err)
	}
	if session.User.MustChangePassword || session.User.ID != user.ID || !session.Grants.CanManageInstallation() ||
		!session.Grants.CanThawRepository(repositoryB) || session.Grants.CanFreezeRepository(repositoryA) {
		t.Fatalf("expected accepted password login without forced change, got %+v", session.User)
	}
}

func TestAcceptInvitationWithoutStagedAuthorityCreatesPlainUser(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "plain@example.test",
		DisplayName: "Plain Invitee",
	})

	user, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if user.IsAdmin || user.MustChangePassword || user.Disabled() {
		t.Fatalf("expected enabled plain invited user, got %+v", user)
	}
	var adminRows, grantRows, sessionRows, authorityAudits int
	queries := []struct {
		destination *int
		query       string
		args        []any
	}{
		{destination: &adminRows, query: `SELECT count(*) FROM user_roles WHERE user_id = ?`, args: []any{user.ID}},
		{destination: &grantRows, query: `SELECT count(*) FROM repository_grants WHERE user_id = ?`, args: []any{user.ID}},
		{destination: &sessionRows, query: `SELECT count(*) FROM sessions WHERE user_id = ?`, args: []any{user.ID}},
		{destination: &authorityAudits, query: `SELECT count(*) FROM audit_events WHERE (action = ? AND subject_type = ? AND subject_id = ?) OR (action = ? AND json_extract(details_json, '$.user_id') = ?)`, args: []any{audit.ActionUserRolesUpdated, audit.SubjectTypeUser, user.ID, audit.ActionRepositoryGrantAdded, strconv.FormatInt(user.ID, 10)}},
	}
	for _, check := range queries {
		if err := database.QueryRowContext(ctx, check.query, check.args...).Scan(check.destination); err != nil {
			t.Fatal(err)
		}
	}
	if adminRows != 0 || grantRows != 0 || sessionRows != 0 || authorityAudits != 0 {
		t.Fatalf("plain acceptance created authority or session: admins=%d grants=%d sessions=%d audits=%d", adminRows, grantRows, sessionRows, authorityAudits)
	}
	assertAcceptanceAuditCount(t, ctx, database, user.ID, credential.InvitationID, 2)
}

func TestAcceptedAuthoritySurvivesLaterAuthorizerLoss(t *testing.T) {
	operations := []struct {
		name   string
		mutate func(context.Context, *Service, int64, int64) error
	}{
		{
			name: "demotion",
			mutate: func(ctx context.Context, service *Service, actorID, authorizerID int64) error {
				_, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actorID, UserID: authorizerID, Admin: false})
				return err
			},
		},
		{
			name: "disablement",
			mutate: func(ctx context.Context, service *Service, actorID, authorizerID int64) error {
				_, err := service.DisableUser(ctx, actorID, authorizerID)
				return err
			},
		},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			rootAdmin := mustCreateFirstAdmin(t, ctx, service)
			authorizer := mustCreateUser(t, ctx, service, "later-loss-authorizer@example.test", true)
			repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "later-authorizer-"+operation.name)
			credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
				ActorUserID: authorizer.ID,
				Email:       "accepted-before-" + operation.name + "@example.test",
				DisplayName: "Accepted Before Loss",
				IsAdmin:     true,
				RepositoryGrants: []InvitationRepositoryGrant{
					{RepositoryID: repositoryID, Role: RoleViewer},
				},
			})
			accepted, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
			if err != nil {
				t.Fatal(err)
			}
			tombstone := loadStoredInvitation(t, ctx, database, credential.InvitationID)

			if err := operation.mutate(ctx, service, rootAdmin.User.ID, authorizer.ID); err != nil {
				t.Fatalf("later authorizer %s: %v", operation.name, err)
			}
			var adminRows, grantRows int
			if err := database.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id = ? AND role = 'admin'`, accepted.ID).Scan(&adminRows); err != nil {
				t.Fatal(err)
			}
			if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id = ? AND repository_id = ? AND role = 'viewer'`, accepted.ID, repositoryID).Scan(&grantRows); err != nil {
				t.Fatal(err)
			}
			if adminRows != 1 || grantRows != 1 {
				t.Fatalf("later authorizer %s unwound accepted authority: admin=%d grant=%d", operation.name, adminRows, grantRows)
			}
			assertStoredInvitationUnchanged(t, loadStoredInvitation(t, ctx, database, credential.InvitationID), tombstone)
			assertAcceptanceAuditCount(t, ctx, database, accepted.ID, credential.InvitationID, 4)
		})
	}
}

func TestAcceptInvitationExpectedInvalidStatesShareOneErrorAndLeaveNoPartialState(t *testing.T) {
	type invalidSetup func(*testing.T, context.Context, *sql.DB, *Service, Session, InvitationCredential)
	cases := []struct {
		name   string
		params func(*testing.T, context.Context, *sql.DB, Session) CreateInvitationParams
		setup  invalidSetup
	}{
		{
			name: "noncanonical staged email",
			params: func(_ *testing.T, _ context.Context, _ *sql.DB, admin Session) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: "identity-drift@example.test", DisplayName: "Identity Drift"}
			},
			setup: func(t *testing.T, ctx context.Context, database *sql.DB, _ *Service, _ Session, credential InvitationCredential) {
				if _, err := database.ExecContext(ctx, `UPDATE invitations SET canonical_email = 'Identity-Drift@Example.Test' WHERE id = ?`, credential.InvitationID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "noncanonical staged display name",
			params: func(_ *testing.T, _ context.Context, _ *sql.DB, admin Session) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: "display-drift@example.test", DisplayName: "Display Drift"}
			},
			setup: func(t *testing.T, ctx context.Context, database *sql.DB, _ *Service, _ Session, credential InvitationCredential) {
				if _, err := database.ExecContext(ctx, `UPDATE invitations SET display_name = ' Display Drift ' WHERE id = ?`, credential.InvitationID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "expired",
			params: func(_ *testing.T, _ context.Context, _ *sql.DB, admin Session) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: "expired@example.test", DisplayName: "Expired"}
			},
			setup: func(_ *testing.T, _ context.Context, _ *sql.DB, service *Service, _ Session, credential InvitationCredential) {
				service.now = func() time.Time { return credential.ExpiresAt }
			},
		},
		{
			name: "missing authorizer",
			params: func(_ *testing.T, _ context.Context, _ *sql.DB, admin Session) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: "missing-authorizer@example.test", DisplayName: "Missing Authorizer"}
			},
			setup: func(t *testing.T, ctx context.Context, database *sql.DB, _ *Service, _ Session, credential InvitationCredential) {
				if _, err := database.ExecContext(ctx, `UPDATE invitations SET authorized_by_user_id = NULL WHERE id = ?`, credential.InvitationID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "disabled authorizer",
			params: func(t *testing.T, ctx context.Context, _ *sql.DB, admin Session) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: acceptanceCaseEmail(t), DisplayName: "Disabled Authorizer"}
			},
			setup: func(t *testing.T, ctx context.Context, _ *sql.DB, service *Service, admin Session, _ InvitationCredential) {
				secondAdmin := mustCreateUser(t, ctx, service, "second-disabled-admin@example.test", true)
				if _, err := service.DisableUser(ctx, secondAdmin.ID, admin.User.ID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "demoted authorizer",
			params: func(t *testing.T, ctx context.Context, _ *sql.DB, admin Session) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: acceptanceCaseEmail(t), DisplayName: "Demoted Authorizer"}
			},
			setup: func(t *testing.T, ctx context.Context, _ *sql.DB, service *Service, admin Session, _ InvitationCredential) {
				secondAdmin := mustCreateUser(t, ctx, service, "second-demotion-admin@example.test", true)
				if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: secondAdmin.ID, UserID: admin.User.ID, Admin: false}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "canonical email collision",
			params: func(_ *testing.T, _ context.Context, _ *sql.DB, admin Session) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: "collision@example.test", DisplayName: "Collision"}
			},
			setup: func(t *testing.T, ctx context.Context, database *sql.DB, _ *Service, _ Session, _ InvitationCredential) {
				now := time.Now().UTC().Format(time.RFC3339Nano)
				if _, err := database.ExecContext(ctx, `
INSERT INTO users(email, display_name, password_hash, must_change_password, created_at, updated_at)
VALUES ('collision@example.test', 'Existing Collision', 'hash', 0, ?, ?)`, now, now); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "staged count drift",
			params: func(t *testing.T, ctx context.Context, database *sql.DB, admin Session) CreateInvitationParams {
				repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "count-drift")
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: "count-drift@example.test", DisplayName: "Count Drift", RepositoryGrants: []InvitationRepositoryGrant{{RepositoryID: repositoryID, Role: RoleViewer}}}
			},
			setup: func(t *testing.T, ctx context.Context, database *sql.DB, _ *Service, _ Session, credential InvitationCredential) {
				if _, err := database.ExecContext(ctx, `UPDATE invitations SET expected_repository_grant_count = 2 WHERE id = ?`, credential.InvitationID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "deleted repository drift",
			params: func(t *testing.T, ctx context.Context, database *sql.DB, admin Session) CreateInvitationParams {
				repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "deleted-drift")
				return CreateInvitationParams{ActorUserID: admin.User.ID, Email: "deleted-drift@example.test", DisplayName: "Deleted Drift", RepositoryGrants: []InvitationRepositoryGrant{{RepositoryID: repositoryID, Role: RoleFreezer}}}
			},
			setup: func(t *testing.T, ctx context.Context, database *sql.DB, _ *Service, _ Session, credential InvitationCredential) {
				grants := loadStoredInvitationGrants(t, ctx, database, credential.InvitationID)
				if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, grants[0].RepositoryID); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	var genericMessage string
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin := mustCreateFirstAdmin(t, ctx, service)
			credential := mustCreateAcceptanceInvitation(t, ctx, service, testCase.params(t, ctx, database, admin))
			testCase.setup(t, ctx, database, service, admin, credential)
			before := acceptanceStateSnapshot(t, ctx, database, credential.InvitationID)

			_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
			assertInvalidInvitation(t, err)
			if genericMessage == "" {
				genericMessage = err.Error()
			}
			if err.Error() != genericMessage {
				t.Fatalf("expected generic invitation error %q, got %q", genericMessage, err)
			}
			after := acceptanceStateSnapshot(t, ctx, database, credential.InvitationID)
			if after != before {
				t.Fatalf("rejected acceptance changed state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestAcceptInvitationSamplesExpiryAfterWriterAcquisition(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	issuedAt := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return issuedAt }
	admin := mustCreateFirstAdmin(t, ctx, service)
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "contention-expiry@example.test",
		DisplayName: "Contention Expiry",
	})

	blocker, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, admin.User.ID); err != nil {
		t.Fatal(err)
	}

	var clockCalls atomic.Int64
	var clockNanos atomic.Int64
	clockNanos.Store(credential.ExpiresAt.Add(-time.Nanosecond).UnixNano())
	postLockClockRead := make(chan struct{}, 1)
	service.now = func() time.Time {
		call := clockCalls.Add(1)
		if call > 1 {
			select {
			case postLockClockRead <- struct{}{}:
			default:
			}
		}
		return time.Unix(0, clockNanos.Load()).UTC()
	}
	result := make(chan error, 1)
	go func() {
		_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
		result <- err
	}()

	select {
	case <-postLockClockRead:
		t.Fatal("acceptance sampled final expiry before obtaining the SQLite writer")
	case err := <-result:
		t.Fatalf("acceptance returned before controlled writer release: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	clockNanos.Store(credential.ExpiresAt.UnixNano())
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		assertInvalidInvitation(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for acceptance after writer release")
	}
	stored := loadStoredInvitation(t, ctx, database, credential.InvitationID)
	if stored.Status != invitationStatusPending || !stored.Email.Valid {
		t.Fatalf("expiry rejection mutated invitation: %+v", stored)
	}
	var users int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE email = 'contention-expiry@example.test'`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Fatalf("expected no account after post-lock expiry, got %d", users)
	}
}

func TestAcceptInvitationPasswordHashFailureIsOperationalAndSafe(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "hash-failure@example.test",
		DisplayName: "Hash Failure Invitee",
	})
	before := acceptanceStateSnapshot(t, ctx, database, credential.InvitationID)

	originalReader := cryptorand.Reader
	cryptorand.Reader = iotest.ErrReader(errors.New("forced random failure"))
	t.Cleanup(func() { cryptorand.Reader = originalReader })
	_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
	if err == nil || IsInvalidInvitation(err) || IsValidationError(err) {
		t.Fatalf("expected operational password-hash failure, got %v", err)
	}
	for _, secret := range []string{credential.Token, invitationAcceptanceTestPassword, "hash-failure@example.test", "Hash Failure Invitee"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("password-hash failure exposed %q: %v", secret, err)
		}
	}
	after := acceptanceStateSnapshot(t, ctx, database, credential.InvitationID)
	if after != before {
		t.Fatalf("password-hash failure changed state: before=%+v after=%+v", before, after)
	}
}

func TestAcceptInvitationDatabaseFailureIsOperationalAndSafe(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "database-failure@example.test",
		DisplayName: "Database Failure Invitee",
	})
	if _, err := database.ExecContext(ctx, `ALTER TABLE invitations RENAME TO invitations_unavailable`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `ALTER TABLE invitations_unavailable RENAME TO invitations`)
	})

	_, err := service.AcceptInvitation(ctx, credential.Token, "short")
	if err == nil || IsInvalidInvitation(err) || IsValidationError(err) {
		t.Fatalf("expected operational invitation database failure, got %v", err)
	}
	for _, secret := range []string{credential.Token, "short", "database-failure@example.test", "Database Failure Invitee"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("database failure exposed %q: %v", secret, err)
		}
	}
}

func TestAcceptInvitationRollsBackRepresentativeLateFailures(t *testing.T) {
	cases := []struct {
		name       string
		invitation func(int64, int64) CreateInvitationParams
		trigger    string
	}{
		{
			name: "after user insertion",
			invitation: func(adminID, _ int64) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: adminID, Email: "rollback-admin@example.test", DisplayName: "Rollback Admin", IsAdmin: true}
			},
			trigger: `CREATE TRIGGER fail_accepted_admin BEFORE INSERT ON user_roles
WHEN NEW.role = 'admin' AND NEW.user_id > 1
BEGIN SELECT RAISE(ABORT, 'accepted admin insertion failed'); END`,
		},
		{
			name: "after authority insertion",
			invitation: func(adminID, repositoryID int64) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: adminID, Email: "rollback-grant@example.test", DisplayName: "Rollback Grant", IsAdmin: true, RepositoryGrants: []InvitationRepositoryGrant{{RepositoryID: repositoryID, Role: RoleFreezer}}}
			},
			trigger: `CREATE TRIGGER fail_accepted_repository_grant BEFORE INSERT ON repository_grants
BEGIN SELECT RAISE(ABORT, 'accepted repository grant insertion failed'); END`,
		},
		{
			name: "after audit insertion",
			invitation: func(adminID, repositoryID int64) CreateInvitationParams {
				return CreateInvitationParams{ActorUserID: adminID, Email: "rollback-audit@example.test", DisplayName: "Rollback Audit", IsAdmin: true, RepositoryGrants: []InvitationRepositoryGrant{{RepositoryID: repositoryID, Role: RoleViewer}}}
			},
			trigger: `CREATE TRIGGER fail_accepted_user_audit BEFORE INSERT ON audit_events
WHEN NEW.action = 'user.created' AND json_extract(NEW.details_json, '$.onboarding') = 'invitation'
BEGIN SELECT RAISE(ABORT, 'accepted user audit insertion failed'); END`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin := mustCreateFirstAdmin(t, ctx, service)
			repositoryID := mustCreateTestRepository(t, ctx, database, "acme", strings.ReplaceAll(testCase.name, " ", "-"))
			credential := mustCreateAcceptanceInvitation(t, ctx, service, testCase.invitation(admin.User.ID, repositoryID))
			before := acceptanceStateSnapshot(t, ctx, database, credential.InvitationID)
			storedBefore := loadStoredInvitation(t, ctx, database, credential.InvitationID)
			stagesBefore := loadStoredInvitationGrants(t, ctx, database, credential.InvitationID)
			if _, err := database.ExecContext(ctx, testCase.trigger); err != nil {
				t.Fatal(err)
			}

			_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
			if err == nil || IsInvalidInvitation(err) || IsValidationError(err) {
				t.Fatalf("expected operational rollback failure, got %v", err)
			}
			after := acceptanceStateSnapshot(t, ctx, database, credential.InvitationID)
			if after != before {
				t.Fatalf("late failure left partial state: before=%+v after=%+v", before, after)
			}
			storedAfter := loadStoredInvitation(t, ctx, database, credential.InvitationID)
			assertStoredInvitationUnchanged(t, storedAfter, storedBefore)
			assertInvitationGrantsEqual(t, loadStoredInvitationGrants(t, ctx, database, credential.InvitationID), stagesBefore)
		})
	}
}

func TestConcurrentAcceptInvitationHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "accept-race")
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "accept-race@example.test",
		DisplayName: "Accept Race",
		IsAdmin:     true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: repositoryID, Role: RoleFreezer},
		},
	})

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
			results <- err
		}()
	}
	close(start)
	winners, losers := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			winners++
		case IsInvalidInvitation(err):
			losers++
		default:
			t.Fatalf("unexpected concurrent acceptance result: %v", err)
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("expected one acceptance winner and one generic loser, winners=%d losers=%d", winners, losers)
	}
	assertAcceptedIdentityCounts(t, ctx, database, credential.InvitationID, "accept-race@example.test", 1, 1, 1, 4)
}

func TestConcurrentAcceptInvitationAlwaysWinsAgainstCreateUserReservation(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "accept-create-race@example.test",
		DisplayName: "Invitation Winner",
	})

	start := make(chan struct{})
	acceptResult := make(chan error, 1)
	createResult := make(chan error, 1)
	go func() {
		<-start
		_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
		acceptResult <- err
	}()
	go func() {
		<-start
		_, err := service.CreateUser(ctx, CreateUserParams{
			ActorUserID: admin.User.ID,
			Email:       " ACCEPT-CREATE-RACE@example.test ",
			DisplayName: "Competing Admin Creation",
			Password:    accountTestPassword,
		})
		createResult <- err
	}()
	close(start)
	if err := <-acceptResult; err != nil {
		t.Fatalf("finally valid invitation acceptance must win: %v", err)
	}
	if err := <-createResult; !IsValidationError(err) {
		t.Fatalf("expected competing CreateUser to lose by validation, got %v", err)
	}
	var displayName string
	if err := database.QueryRowContext(ctx, `SELECT display_name FROM users WHERE email = 'accept-create-race@example.test'`).Scan(&displayName); err != nil {
		t.Fatal(err)
	}
	if displayName != "Invitation Winner" {
		t.Fatalf("competing CreateUser supplied identity data: %q", displayName)
	}
}

func TestConcurrentAcceptInvitationLinearizesReissue(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 25, 13, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "accept-reissue-race@example.test",
		DisplayName: "Accept Reissue Race",
	})

	type acceptResult struct {
		user User
		err  error
	}
	start := make(chan struct{})
	accepted := make(chan acceptResult, 1)
	reissued := make(chan invitationCredentialResult, 1)
	go func() {
		<-start
		user, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
		accepted <- acceptResult{user: user, err: err}
	}()
	go func() {
		<-start
		replacement, err := service.ReissueInvitation(ctx, ReissueInvitationParams{
			ActorUserID:  admin.User.ID,
			InvitationID: credential.InvitationID,
		})
		reissued <- invitationCredentialResult{credential: replacement, err: err}
	}()
	close(start)
	acceptOutcome := <-accepted
	reissueOutcome := <-reissued

	switch {
	case acceptOutcome.err == nil:
		if !IsValidationError(reissueOutcome.err) || reissueOutcome.credential.Token != "" {
			t.Fatalf("acceptance-first reissue must fail without replacement material, got %+v", reissueOutcome)
		}
		assertAcceptedInvitationTombstone(t, loadStoredInvitation(t, ctx, database, credential.InvitationID), service.now())
		if acceptOutcome.user.Email != "accept-reissue-race@example.test" {
			t.Fatalf("unexpected accepted identity: %+v", acceptOutcome.user)
		}
	case reissueOutcome.err == nil:
		assertInvalidInvitation(t, acceptOutcome.err)
		if reissueOutcome.credential.Token == "" || reissueOutcome.credential.Token == credential.Token {
			t.Fatalf("reissue-first race returned invalid replacement: %+v", reissueOutcome.credential)
		}
		stored := loadStoredInvitation(t, ctx, database, credential.InvitationID)
		if stored.Status != invitationStatusPending {
			t.Fatalf("reissue-first race did not preserve replacement invitation: %+v", stored)
		}
		_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
		assertInvalidInvitation(t, err)
		assertNoUserWithEmail(t, ctx, database, "accept-reissue-race@example.test")
	default:
		t.Fatalf("expected exactly one lifecycle winner, accept=%v reissue=%v", acceptOutcome.err, reissueOutcome.err)
	}
}

func TestConcurrentAcceptInvitationLinearizesCancellation(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 25, 14, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "accept-cancel-race@example.test",
		DisplayName: "Accept Cancel Race",
	})

	start := make(chan struct{})
	acceptResult := make(chan error, 1)
	cancelResult := make(chan error, 1)
	go func() {
		<-start
		_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
		acceptResult <- err
	}()
	go func() {
		<-start
		cancelResult <- service.CancelInvitation(ctx, CancelInvitationParams{
			ActorUserID:  admin.User.ID,
			InvitationID: credential.InvitationID,
		})
	}()
	close(start)
	acceptErr := <-acceptResult
	cancelErr := <-cancelResult

	switch {
	case acceptErr == nil:
		if !IsValidationError(cancelErr) {
			t.Fatalf("acceptance-first cancellation must fail, got %v", cancelErr)
		}
		assertAcceptedInvitationTombstone(t, loadStoredInvitation(t, ctx, database, credential.InvitationID), service.now())
	case cancelErr == nil:
		assertInvalidInvitation(t, acceptErr)
		stored := loadStoredInvitation(t, ctx, database, credential.InvitationID)
		if stored.Status != invitationStatusCancelled || stored.Email.Valid || stored.TokenDigest != nil {
			t.Fatalf("cancel-first race left wrong tombstone: %+v", stored)
		}
		assertNoUserWithEmail(t, ctx, database, "accept-cancel-race@example.test")
	default:
		t.Fatalf("expected exactly one lifecycle winner, accept=%v cancel=%v", acceptErr, cancelErr)
	}
}

func TestConcurrentAcceptInvitationLinearizesAuthorizerLoss(t *testing.T) {
	operations := []struct {
		name   string
		mutate func(context.Context, *Service, int64, int64) error
	}{
		{
			name: "demotion",
			mutate: func(ctx context.Context, service *Service, actorID, authorizerID int64) error {
				_, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actorID, UserID: authorizerID, Admin: false})
				return err
			},
		},
		{
			name: "disablement",
			mutate: func(ctx context.Context, service *Service, actorID, authorizerID int64) error {
				_, err := service.DisableUser(ctx, actorID, authorizerID)
				return err
			},
		},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			service.now = func() time.Time { return time.Date(2026, 7, 25, 15, 0, 0, 0, time.UTC) }
			rootAdmin := mustCreateFirstAdmin(t, ctx, service)
			authorizer := mustCreateUser(t, ctx, service, "racing-authorizer@example.test", true)
			repositoryID := mustCreateTestRepository(t, ctx, database, "acme", "authorizer-"+operation.name)
			email := "accepted-after-" + operation.name + "@example.test"
			credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
				ActorUserID: authorizer.ID,
				Email:       email,
				DisplayName: "Accepted Authority",
				IsAdmin:     true,
				RepositoryGrants: []InvitationRepositoryGrant{
					{RepositoryID: repositoryID, Role: RoleThawApprover},
				},
			})

			start := make(chan struct{})
			acceptResult := make(chan error, 1)
			mutationResult := make(chan error, 1)
			go func() {
				<-start
				_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
				acceptResult <- err
			}()
			go func() {
				<-start
				mutationResult <- operation.mutate(ctx, service, rootAdmin.User.ID, authorizer.ID)
			}()
			close(start)
			acceptErr := <-acceptResult
			if err := <-mutationResult; err != nil {
				t.Fatalf("authorizer %s failed: %v", operation.name, err)
			}

			stored := loadStoredInvitation(t, ctx, database, credential.InvitationID)
			if acceptErr == nil {
				if stored.Status != invitationStatusAccepted {
					t.Fatalf("acceptance-first race lost its tombstone: %+v", stored)
				}
				var acceptedUserID int64
				if err := database.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, email).Scan(&acceptedUserID); err != nil {
					t.Fatal(err)
				}
				var adminRows, grantRows int
				if err := database.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id = ? AND role = 'admin'`, acceptedUserID).Scan(&adminRows); err != nil {
					t.Fatal(err)
				}
				if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id = ? AND repository_id = ? AND role = 'thaw_approver'`, acceptedUserID, repositoryID).Scan(&grantRows); err != nil {
					t.Fatal(err)
				}
				if adminRows != 1 || grantRows != 1 {
					t.Fatalf("later authorizer loss unwound accepted authority: admin=%d grant=%d", adminRows, grantRows)
				}
				return
			}
			assertInvalidInvitation(t, acceptErr)
			if stored.Status != invitationStatusReissue || stored.TokenDigest != nil || stored.AuthorizedBy.Valid {
				t.Fatalf("authorizer-loss-first race did not invalidate invitation: %+v", stored)
			}
			assertNoUserWithEmail(t, ctx, database, email)
		})
	}
}

func TestConcurrentAcceptInvitationLinearizesRepositoryDeletion(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	service.now = func() time.Time { return time.Date(2026, 7, 25, 16, 0, 0, 0, time.UTC) }
	admin := mustCreateFirstAdmin(t, ctx, service)
	retainedRepository := mustCreateTestRepository(t, ctx, database, "acme", "retained-after-acceptance")
	deletedRepository := mustCreateTestRepository(t, ctx, database, "acme", "deleted-during-acceptance")
	credential := mustCreateAcceptanceInvitation(t, ctx, service, CreateInvitationParams{
		ActorUserID: admin.User.ID,
		Email:       "accept-delete-race@example.test",
		DisplayName: "Accept Delete Race",
		IsAdmin:     true,
		RepositoryGrants: []InvitationRepositoryGrant{
			{RepositoryID: retainedRepository, Role: RoleViewer},
			{RepositoryID: deletedRepository, Role: RoleFreezer},
		},
	})

	start := make(chan struct{})
	acceptResult := make(chan error, 1)
	deleteResult := make(chan error, 1)
	go func() {
		<-start
		_, err := service.AcceptInvitation(ctx, credential.Token, invitationAcceptanceTestPassword)
		acceptResult <- err
	}()
	go func() {
		<-start
		_, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, deletedRepository)
		deleteResult <- err
	}()
	close(start)
	acceptErr := <-acceptResult
	if err := <-deleteResult; err != nil {
		t.Fatalf("delete racing repository: %v", err)
	}

	stored := loadStoredInvitation(t, ctx, database, credential.InvitationID)
	if acceptErr == nil {
		if stored.Status != invitationStatusAccepted {
			t.Fatalf("acceptance-first repository race lost tombstone: %+v", stored)
		}
		var userID int64
		if err := database.QueryRowContext(ctx, `SELECT id FROM users WHERE email = 'accept-delete-race@example.test'`).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		var admins, retained, deleted, audits int
		if err := database.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id = ? AND role = 'admin'`, userID).Scan(&admins); err != nil {
			t.Fatal(err)
		}
		if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id = ? AND repository_id = ? AND role = 'viewer'`, userID, retainedRepository).Scan(&retained); err != nil {
			t.Fatal(err)
		}
		if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id = ? AND repository_id = ?`, userID, deletedRepository).Scan(&deleted); err != nil {
			t.Fatal(err)
		}
		if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE json_extract(details_json, '$.provenance') = 'invitation_acceptance' OR json_extract(details_json, '$.onboarding') = 'invitation' OR (action = ? AND subject_id = ?)`, audit.ActionInvitationAccepted, credential.InvitationID).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if admins != 1 || retained != 1 || deleted != 0 || audits != 5 {
			t.Fatalf("post-acceptance repository cascade changed unrelated state: admin=%d retained=%d deleted=%d audits=%d", admins, retained, deleted, audits)
		}
		return
	}
	assertInvalidInvitation(t, acceptErr)
	if stored.Status != invitationStatusPending || stored.ExpectedGrantCount.Int64 != 2 {
		t.Fatalf("delete-first race changed pending parent unexpectedly: %+v", stored)
	}
	staged := loadStoredInvitationGrants(t, ctx, database, credential.InvitationID)
	if len(staged) != 1 || staged[0].RepositoryID != retainedRepository || staged[0].Role != RoleViewer {
		t.Fatalf("expected durable staged-count drift after delete-first race, got %+v", staged)
	}
	assertNoUserWithEmail(t, ctx, database, "accept-delete-race@example.test")
}

type acceptanceSnapshot struct {
	Users       int
	AdminRoles  int
	Grants      int
	Sessions    int
	Stages      int
	Audits      int
	Status      string
	EmailValid  bool
	DigestValid bool
}

func acceptanceStateSnapshot(t *testing.T, ctx context.Context, database *sql.DB, invitationID string) acceptanceSnapshot {
	t.Helper()
	var snapshot acceptanceSnapshot
	for _, check := range []struct {
		destination *int
		query       string
	}{
		{destination: &snapshot.Users, query: `SELECT count(*) FROM users`},
		{destination: &snapshot.AdminRoles, query: `SELECT count(*) FROM user_roles`},
		{destination: &snapshot.Grants, query: `SELECT count(*) FROM repository_grants`},
		{destination: &snapshot.Sessions, query: `SELECT count(*) FROM sessions`},
		{destination: &snapshot.Stages, query: `SELECT count(*) FROM invitation_repository_grants`},
		{destination: &snapshot.Audits, query: `SELECT count(*) FROM audit_events`},
	} {
		if err := database.QueryRowContext(ctx, check.query).Scan(check.destination); err != nil {
			t.Fatal(err)
		}
	}
	var email sql.NullString
	var digest []byte
	if err := database.QueryRowContext(ctx, `SELECT status, canonical_email, token_digest FROM invitations WHERE id = ?`, invitationID).Scan(&snapshot.Status, &email, &digest); err != nil {
		t.Fatal(err)
	}
	snapshot.EmailValid = email.Valid
	snapshot.DigestValid = len(digest) != 0
	return snapshot
}

func mustCreateAcceptanceInvitation(t *testing.T, ctx context.Context, service *Service, params CreateInvitationParams) InvitationCredential {
	t.Helper()
	credential, err := service.CreateInvitation(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func noncanonicalInvitationBearer(t *testing.T, canonical string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	index := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	if index < 0 || index%4 != 0 {
		t.Fatalf("unexpected canonical bearer suffix %q", canonical[len(canonical)-1:])
	}
	return canonical[:len(canonical)-1] + string(alphabet[index+1])
}

func assertInvalidInvitation(t *testing.T, err error) {
	t.Helper()
	if !IsInvalidInvitation(err) {
		t.Fatalf("expected generic invalid invitation error, got %v", err)
	}
	var typed InvalidInvitationError
	if !errors.As(err, &typed) {
		t.Fatalf("expected inspectable InvalidInvitationError, got %T", err)
	}
}

func assertStoredInvitationUnchanged(t *testing.T, got, want storedInvitation) {
	t.Helper()
	if got.ID != want.ID || got.Status != want.Status || got.Email != want.Email || got.DisplayName != want.DisplayName ||
		!bytes.Equal(got.TokenDigest, want.TokenDigest) || got.ExpiresAt != want.ExpiresAt || got.IsAdmin != want.IsAdmin ||
		got.AuthorizedBy != want.AuthorizedBy || got.ExpectedGrantCount != want.ExpectedGrantCount ||
		got.CreatedAt != want.CreatedAt || got.UpdatedAt != want.UpdatedAt {
		t.Fatalf("invitation changed: got %+v want %+v", got, want)
	}
}

func assertAcceptedInvitationTombstone(t *testing.T, invitation storedInvitation, acceptedAt time.Time) {
	t.Helper()
	if invitation.Status != invitationStatusAccepted || invitation.Email.Valid || invitation.DisplayName.Valid ||
		invitation.TokenDigest != nil || invitation.ExpiresAt.Valid || invitation.IsAdmin.Valid ||
		invitation.AuthorizedBy.Valid || invitation.ExpectedGrantCount.Valid ||
		invitation.UpdatedAt != acceptedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("expected fully redacted accepted tombstone, got %+v", invitation)
	}
}

func assertAcceptanceAuditEvent(
	t *testing.T,
	ctx context.Context,
	database *sql.DB,
	action string,
	subjectType string,
	subjectID string,
	role string,
	wantActor *int64,
	wantDetails map[string]string,
) {
	t.Helper()
	query := `
SELECT actor_user_id, subject_type, details_json
FROM audit_events
WHERE action = ? AND subject_id = ?`
	args := []any{action, subjectID}
	if role != "" {
		query += ` AND json_extract(details_json, '$.role') = ?`
		args = append(args, role)
	}
	query += ` ORDER BY id DESC LIMIT 1`
	var actor sql.NullInt64
	var gotSubjectType, detailsJSON string
	if err := database.QueryRowContext(ctx, query, args...).Scan(&actor, &gotSubjectType, &detailsJSON); err != nil {
		t.Fatal(err)
	}
	if gotSubjectType != subjectType {
		t.Fatalf("audit %s has subject type %q, want %q", action, gotSubjectType, subjectType)
	}
	if wantActor == nil {
		if actor.Valid {
			t.Fatalf("audit %s has actor %d, want null", action, actor.Int64)
		}
	} else if !actor.Valid || actor.Int64 != *wantActor {
		t.Fatalf("audit %s has actor %+v, want %d", action, actor, *wantActor)
	}
	var gotDetails map[string]string
	if err := json.Unmarshal([]byte(detailsJSON), &gotDetails); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(gotDetails, wantDetails) {
		t.Fatalf("audit %s details=%v, want exact %v", action, gotDetails, wantDetails)
	}
}

func assertAcceptanceAuditCount(t *testing.T, ctx context.Context, database *sql.DB, userID int64, invitationID string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM audit_events
WHERE (action = ? AND subject_type = ? AND subject_id = ?)
   OR (subject_type = ? AND subject_id = ? AND (
     (action = ? AND json_extract(details_json, '$.onboarding') = 'invitation') OR
     (action = ? AND json_extract(details_json, '$.provenance') = 'invitation_acceptance')
   ))
   OR (action = ? AND json_extract(details_json, '$.user_id') = ? AND json_extract(details_json, '$.provenance') = 'invitation_acceptance')`,
		audit.ActionInvitationAccepted,
		audit.SubjectTypeInvitation,
		invitationID,
		audit.SubjectTypeUser,
		strconv.FormatInt(userID, 10),
		audit.ActionUserCreated,
		audit.ActionUserRolesUpdated,
		audit.ActionRepositoryGrantAdded,
		strconv.FormatInt(userID, 10),
	).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("expected %d invitation-acceptance audits, got %d", want, got)
	}
}

func assertInvitationAcceptanceSecretsAbsent(t *testing.T, ctx context.Context, database *sql.DB, secrets ...string) {
	t.Helper()
	rows, err := database.QueryContext(ctx, `
SELECT details_json
FROM audit_events
WHERE action IN (?, ?, ?, ?)`,
		audit.ActionInvitationAccepted,
		audit.ActionUserCreated,
		audit.ActionUserRolesUpdated,
		audit.ActionRepositoryGrantAdded,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var details string
		if err := rows.Scan(&details); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"token", "digest", "password_hash", "email", "display_name"} {
			if strings.Contains(details, forbidden) {
				t.Fatalf("acceptance audit contains forbidden field %q in %s", forbidden, details)
			}
		}
		for _, secret := range secrets {
			if secret != "" && strings.Contains(details, secret) {
				t.Fatalf("acceptance audit exposed secret or invitee identity material")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func assertNoUserWithEmail(t *testing.T, ctx context.Context, database *sql.DB, email string) {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE email = ?`, email).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected no user with email %q, got %d", email, count)
	}
}

func acceptanceCaseEmail(t *testing.T) string {
	t.Helper()
	return strings.ReplaceAll(t.Name(), "/", "-") + "@example.test"
}

func assertAcceptedIdentityCounts(
	t *testing.T,
	ctx context.Context,
	database *sql.DB,
	invitationID string,
	email string,
	wantUsers int,
	wantAdmins int,
	wantGrants int,
	wantAcceptanceAudits int,
) {
	t.Helper()
	var users, admins, grants, tombstones int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE email = ?`, email).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE email = ?)`, email).Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id IN (SELECT id FROM users WHERE email = ?)`, email).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM invitations WHERE id = ? AND status = 'accepted' AND canonical_email IS NULL AND token_digest IS NULL`, invitationID).Scan(&tombstones); err != nil {
		t.Fatal(err)
	}
	if users != wantUsers || admins != wantAdmins || grants != wantGrants || tombstones != 1 {
		t.Fatalf("unexpected surviving acceptance state: users=%d admins=%d grants=%d tombstones=%d", users, admins, grants, tombstones)
	}
	var userID int64
	if err := database.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	assertAcceptanceAuditCount(t, ctx, database, userID, invitationID, wantAcceptanceAudits)
}
