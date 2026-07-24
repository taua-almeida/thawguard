package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const recoveredAccountTestPassword = "a recovered local password"

func TestIssuePasswordRecoveryTokenRequiresEnabledAdminAndEnabledTarget(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 23, 10, 0, 0, 123, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	target := mustCreateUser(t, ctx, service, "target@example.test", false)
	ordinary := mustCreateUser(t, ctx, service, "ordinary@example.test", false)

	for _, test := range []struct {
		name   string
		params IssuePasswordRecoveryParams
	}{
		{name: "non-admin actor", params: IssuePasswordRecoveryParams{ActorUserID: ordinary.ID, UserID: target.ID}},
		{name: "missing actor", params: IssuePasswordRecoveryParams{ActorUserID: 9999, UserID: target.ID}},
		{name: "self issuance", params: IssuePasswordRecoveryParams{ActorUserID: admin.User.ID, UserID: admin.User.ID}},
		{name: "missing target", params: IssuePasswordRecoveryParams{ActorUserID: admin.User.ID, UserID: 9999}},
	} {
		t.Run(test.name, func(t *testing.T) {
			issued, err := service.IssuePasswordRecoveryToken(ctx, test.params)
			if !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
			if issued.Token != "" || !issued.ExpiresAt.IsZero() {
				t.Fatal("expected rejected issuance to return no recovery material")
			}
		})
	}
	if countPasswordRecoveryTokens(t, ctx, database, target.ID) != 0 {
		t.Fatal("expected rejected issuances to persist no token")
	}

	issued := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)
	if issued.Token == "" || !issued.ExpiresAt.Equal(now.Add(DefaultPasswordRecoveryTTL)) {
		t.Fatalf("unexpected recovery expiry: %s", issued.ExpiresAt)
	}
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryIssued) != 1 {
		t.Fatal("expected exactly one issuance audit after the successful request")
	}

	disabledAdmin := mustCreateUser(t, ctx, service, "disabled-admin@example.test", true)
	if _, err := service.DisableUser(ctx, admin.User.ID, disabledAdmin.ID); err != nil {
		t.Fatal(err)
	}
	if issued, err := service.IssuePasswordRecoveryToken(ctx, IssuePasswordRecoveryParams{ActorUserID: disabledAdmin.ID, UserID: target.ID}); !IsValidationError(err) || issued.Token != "" {
		t.Fatalf("expected disabled Admin rejection without recovery material, got %v", err)
	}

	if _, err := service.DisableUser(ctx, admin.User.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	if issued, err := service.IssuePasswordRecoveryToken(ctx, IssuePasswordRecoveryParams{ActorUserID: admin.User.ID, UserID: target.ID}); !IsValidationError(err) || issued.Token != "" {
		t.Fatalf("expected disabled target rejection without recovery material, got %v", err)
	}
	if countPasswordRecoveryTokens(t, ctx, database, target.ID) != 0 {
		t.Fatal("expected disabling the target to revoke its recovery token")
	}
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryIssued) != 1 {
		t.Fatal("expected rejected issuances to produce no audit events")
	}
}

func TestIssuePasswordRecoveryTokenStoresOnlyDigestAndReplacesPriorToken(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 23, 11, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	target := mustCreateUser(t, ctx, service, "target@example.test", false)

	first := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)
	firstDigest := assertStoredPasswordRecoveryToken(t, ctx, database, target.ID, first)
	if bytes.Equal(firstDigest, []byte(first.Token)) {
		t.Fatal("expected persisted recovery material to differ from the raw token")
	}

	now = now.Add(time.Minute)
	second := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)
	secondDigest := assertStoredPasswordRecoveryToken(t, ctx, database, target.ID, second)
	if first.Token == second.Token || bytes.Equal(firstDigest, secondDigest) {
		t.Fatal("expected reissuance to replace the prior recovery credential")
	}

	err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{
		Token:       first.Token,
		NewPassword: recoveredAccountTestPassword,
	})
	assertInvalidPasswordRecoveryToken(t, err)
	if strings.Contains(err.Error(), first.Token) {
		t.Fatal("invalid-token error exposed raw recovery material")
	}
	assertStoredPasswordRecoveryToken(t, ctx, database, target.ID, second)
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryIssued) != 2 {
		t.Fatal("expected reissuance to retain both sanitized audit events")
	}
	var issuanceActors int
	if err := database.QueryRowContext(ctx, `
SELECT count(*)
FROM audit_events
WHERE action = ? AND subject_type = ? AND subject_id = ? AND actor_user_id = ?`,
		audit.ActionUserPasswordRecoveryIssued,
		audit.SubjectTypeUser,
		target.ID,
		admin.User.ID,
	).Scan(&issuanceActors); err != nil {
		t.Fatal(err)
	}
	if issuanceActors != 2 {
		t.Fatalf("expected both issuance audits attributed to the Admin, got %d", issuanceActors)
	}
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryCompleted) != 0 {
		t.Fatal("expected replaced-token probe to produce no completion audit")
	}
	assertRecoveryAuditSecretsAbsent(
		t,
		ctx,
		database,
		first.Token,
		second.Token,
		hex.EncodeToString(firstDigest),
		hex.EncodeToString(secondDigest),
	)
}

func TestCompletePasswordRecoveryRejectsInvalidTokensBeforePasswordValidation(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	target := mustCreateUser(t, ctx, service, "target@example.test", false)
	issued := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)

	malformedErr := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{Token: "not-a-token", NewPassword: "short"})
	unknown := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	unknownErr := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{Token: unknown, NewPassword: recoveredAccountTestPassword})
	assertInvalidPasswordRecoveryToken(t, malformedErr)
	assertInvalidPasswordRecoveryToken(t, unknownErr)
	if malformedErr.Error() != unknownErr.Error() {
		t.Fatalf("expected malformed and unknown tokens to share one error, got %q and %q", malformedErr, unknownErr)
	}

	err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{Token: issued.Token, NewPassword: "short"})
	if !IsValidationError(err) {
		t.Fatalf("expected valid token with invalid password to use password validation, got %v", err)
	}
	assertStoredPasswordRecoveryToken(t, ctx, database, target.ID, issued)
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryCompleted) != 0 {
		t.Fatal("expected invalid probes to produce no completion audit")
	}
}

func TestPasswordRecoveryExpiryBoundary(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 23, 12, 0, 0, 500, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	beforeBoundaryUser := mustCreateUser(t, ctx, service, "before@example.test", false)
	atBoundaryUser := mustCreateUser(t, ctx, service, "boundary@example.test", false)
	beforeBoundary := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, beforeBoundaryUser.ID)
	atBoundary := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, atBoundaryUser.ID)

	now = beforeBoundary.ExpiresAt.Add(-time.Nanosecond)
	if err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{Token: beforeBoundary.Token, NewPassword: recoveredAccountTestPassword}); err != nil {
		t.Fatalf("expected token to remain valid immediately before expiry, got %v", err)
	}
	now = atBoundary.ExpiresAt
	err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{Token: atBoundary.Token, NewPassword: recoveredAccountTestPassword})
	assertInvalidPasswordRecoveryToken(t, err)
	assertStoredPasswordRecoveryToken(t, ctx, database, atBoundaryUser.ID, atBoundary)
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryCompleted) != 1 {
		t.Fatal("expected only the pre-boundary recovery to be audited")
	}
}

func TestPasswordRecoverySamplesExpiryAfterSQLiteWriterContention(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	issuedAt := time.Date(2026, 7, 23, 12, 30, 0, 0, time.UTC)
	service.now = func() time.Time { return issuedAt }
	admin := mustCreateFirstAdmin(t, ctx, service)
	target := mustCreateUser(t, ctx, service, "contention@example.test", false)
	issued := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)
	digest, ok := passwordRecoveryTokenDigest(issued.Token)
	if !ok {
		t.Fatal("expected issued recovery token to use the canonical format")
	}
	userID, err := service.preflightPasswordRecovery(ctx, digest, issued.ExpiresAt.Add(-time.Nanosecond))
	if err != nil || userID != target.ID {
		t.Fatalf("expected token to pass preflight before expiry, user=%d err=%v", userID, err)
	}
	record, err := service.userByID(ctx, database, target.ID)
	if err != nil {
		t.Fatal(err)
	}

	blocker, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, admin.User.ID); err != nil {
		t.Fatal(err)
	}

	var clockNanos atomic.Int64
	clockNanos.Store(issued.ExpiresAt.Add(-time.Nanosecond).UnixNano())
	clockRead := make(chan struct{}, 1)
	service.now = func() time.Time {
		select {
		case clockRead <- struct{}{}:
		default:
		}
		return time.Unix(0, clockNanos.Load()).UTC()
	}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		result <- service.commitPasswordRecovery(ctx, target.ID, digest, record.passwordHash)
	}()
	<-started

	sampledBeforeWriterLock := false
	select {
	case <-clockRead:
		sampledBeforeWriterLock = true
	case err := <-result:
		t.Fatalf("expected recovery claim to wait for the SQLite writer, got %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	clockNanos.Store(issued.ExpiresAt.UnixNano())
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	err = <-result
	if sampledBeforeWriterLock {
		t.Fatal("password recovery sampled expiry before acquiring the SQLite writer lock")
	}
	assertInvalidPasswordRecoveryToken(t, err)
	assertStoredPasswordRecoveryToken(t, ctx, database, target.ID, issued)
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryCompleted) != 0 {
		t.Fatal("expected expiry during writer contention to produce no audit event")
	}
}

func TestCompletePasswordRecoveryChangesCredentialsAndRevokesSessionsWithoutCreatingOne(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	target := mustCreateUser(t, ctx, service, "target@example.test", false)
	repositoryID := mustCreateTestRepository(t, ctx, database, "taua-almeida", "thawguard")
	if err := service.GrantRepositoryRole(ctx, GrantRepositoryRoleParams{
		ActorUserID:  admin.User.ID,
		RepositoryID: repositoryID,
		UserID:       target.ID,
		Role:         RoleFreezer,
	}); err != nil {
		t.Fatal(err)
	}
	firstSession, err := service.Login(ctx, LoginParams{Email: target.Email, Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	secondSession, err := service.Login(ctx, LoginParams{Email: target.Email, Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	issued := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)

	if err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{
		Token:       issued.Token,
		NewPassword: recoveredAccountTestPassword,
	}); err != nil {
		t.Fatal(err)
	}
	if sessions := countUserSessions(t, ctx, database, target.ID); sessions != 0 {
		t.Fatalf("expected recovery to revoke all sessions and create none, got %d", sessions)
	}
	if countPasswordRecoveryTokens(t, ctx, database, target.ID) != 0 {
		t.Fatal("expected successful recovery to consume its token")
	}
	record, err := service.userByID(ctx, database, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.MustChangePassword || record.Disabled() || record.IsAdmin {
		t.Fatalf("expected recovery to clear only forced-change state, got %+v", record.User)
	}
	newPasswordOK, err := VerifyPassword(recoveredAccountTestPassword, record.passwordHash)
	if err != nil || !newPasswordOK {
		t.Fatalf("expected recovered password hash to verify, ok=%v err=%v", newPasswordOK, err)
	}
	oldPasswordOK, err := VerifyPassword(accountTestPassword, record.passwordHash)
	if err != nil || oldPasswordOK {
		t.Fatalf("expected old password not to verify, ok=%v err=%v", oldPasswordOK, err)
	}
	grants, err := service.GrantsForUser(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !grants.CanFreezeRepository(repositoryID) {
		t.Fatalf("expected recovery to preserve repository grants, got %+v", grants)
	}

	var actor sql.NullInt64
	var details string
	if err := database.QueryRowContext(ctx, `
SELECT actor_user_id, details_json
FROM audit_events
WHERE action = ? AND subject_type = ? AND subject_id = ?`,
		audit.ActionUserPasswordRecoveryCompleted,
		audit.SubjectTypeUser,
		target.ID,
	).Scan(&actor, &details); err != nil {
		t.Fatal(err)
	}
	if actor.Valid || details != `{"actor_kind":"recovery_link"}` {
		t.Fatalf("unexpected recovery completion attribution: actor=%+v details=%q", actor, details)
	}

	err = service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{Token: issued.Token, NewPassword: "another recovered password"})
	assertInvalidPasswordRecoveryToken(t, err)
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryCompleted) != 1 {
		t.Fatal("expected consumed-token probe to produce no second audit")
	}
	if _, err := service.Login(ctx, LoginParams{Email: target.Email, Password: accountTestPassword}); !IsAuthenticationError(err) {
		t.Fatalf("expected old login credential rejection, got %v", err)
	}
	if _, err := service.Login(ctx, LoginParams{Email: target.Email, Password: recoveredAccountTestPassword}); err != nil {
		t.Fatalf("expected recovered credential to log in, got %v", err)
	}
	assertRecoveryAuditSecretsAbsent(
		t,
		ctx,
		database,
		issued.Token,
		recoveredAccountTestPassword,
		record.passwordHash,
		firstSession.ID,
		secondSession.ID,
	)
}

func TestConcurrentPasswordRecoveryHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	now := time.Date(2026, 7, 23, 13, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	admin := mustCreateFirstAdmin(t, ctx, service)
	target := mustCreateUser(t, ctx, service, "target@example.test", false)
	issued := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{
				Token:       issued.Token,
				NewPassword: recoveredAccountTestPassword,
			})
		}()
	}
	close(start)

	winners := 0
	losers := 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			winners++
		case IsInvalidPasswordRecoveryToken(err):
			losers++
		default:
			t.Fatalf("unexpected concurrent recovery result: %v", err)
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("expected one winner and one generic loser, got winners=%d losers=%d", winners, losers)
	}
	if countPasswordRecoveryTokens(t, ctx, database, target.ID) != 0 {
		t.Fatal("expected winning recovery to consume the token")
	}
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryCompleted) != 1 {
		t.Fatal("expected exactly one completion audit")
	}
	if sessions := countUserSessions(t, ctx, database, target.ID); sessions != 0 {
		t.Fatalf("expected concurrent recovery to create no session, got %d", sessions)
	}
}

func TestCredentialMutationsInvalidatePasswordRecoveryTokens(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	changeTarget := mustCreateUser(t, ctx, service, "change@example.test", false)
	resetTarget := mustCreateUser(t, ctx, service, "reset@example.test", false)
	disableTarget := mustCreateUser(t, ctx, service, "disable@example.test", false)
	changeToken := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, changeTarget.ID)
	resetToken := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, resetTarget.ID)
	disableToken := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, disableTarget.ID)

	if _, err := service.ChangePassword(ctx, ChangePasswordParams{
		UserID:          changeTarget.ID,
		CurrentPassword: accountTestPassword,
		NewPassword:     "changed by the account owner",
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.ResetPassword(ctx, ResetPasswordParams{
		ActorUserID:       admin.User.ID,
		UserID:            resetTarget.ID,
		TemporaryPassword: "temporary password bridge",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DisableUser(ctx, admin.User.ID, disableTarget.ID); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		userID int64
		token  string
	}{
		{name: "self change", userID: changeTarget.ID, token: changeToken.Token},
		{name: "admin reset", userID: resetTarget.ID, token: resetToken.Token},
		{name: "disable", userID: disableTarget.ID, token: disableToken.Token},
	} {
		t.Run(test.name, func(t *testing.T) {
			if countPasswordRecoveryTokens(t, ctx, database, test.userID) != 0 {
				t.Fatal("expected credential mutation to revoke recovery token")
			}
			err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{
				Token:       test.token,
				NewPassword: recoveredAccountTestPassword,
			})
			assertInvalidPasswordRecoveryToken(t, err)
		})
	}
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryCompleted) != 0 {
		t.Fatal("expected invalidated-token probes to produce no audit events")
	}
}

func TestPasswordRecoveryAuditFailureRollsBackLifecycle(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	target := mustCreateUser(t, ctx, service, "target@example.test", false)
	oldSession, err := service.Login(ctx, LoginParams{Email: target.Email, Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}

	auditBroken := false
	breakAudit := func() {
		t.Helper()
		if _, err := database.ExecContext(ctx, `ALTER TABLE audit_events RENAME TO audit_events_broken`); err != nil {
			t.Fatal(err)
		}
		auditBroken = true
	}
	restoreAudit := func() {
		t.Helper()
		if _, err := database.ExecContext(ctx, `ALTER TABLE audit_events_broken RENAME TO audit_events`); err != nil {
			t.Fatal(err)
		}
		auditBroken = false
	}
	t.Cleanup(func() {
		if auditBroken {
			_, _ = database.ExecContext(ctx, `ALTER TABLE audit_events_broken RENAME TO audit_events`)
		}
	})

	breakAudit()
	issued, err := service.IssuePasswordRecoveryToken(ctx, IssuePasswordRecoveryParams{ActorUserID: admin.User.ID, UserID: target.ID})
	if err == nil || IsValidationError(err) {
		t.Fatalf("expected issuance audit failure, got %v", err)
	}
	if issued.Token != "" || countPasswordRecoveryTokens(t, ctx, database, target.ID) != 0 {
		t.Fatal("expected failed issuance to return and persist no recovery material")
	}
	restoreAudit()

	issued = mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)
	before, err := service.userByID(ctx, database, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	breakAudit()
	replacement, err := service.IssuePasswordRecoveryToken(ctx, IssuePasswordRecoveryParams{ActorUserID: admin.User.ID, UserID: target.ID})
	if err == nil || IsValidationError(err) {
		t.Fatalf("expected reissuance audit failure, got %v", err)
	}
	if replacement.Token != "" || !replacement.ExpiresAt.IsZero() {
		t.Fatal("expected failed reissuance to return no recovery material")
	}
	assertStoredPasswordRecoveryToken(t, ctx, database, target.ID, issued)
	restoreAudit()

	breakAudit()
	err = service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{
		Token:       issued.Token,
		NewPassword: recoveredAccountTestPassword,
	})
	if err == nil || IsInvalidPasswordRecoveryToken(err) || IsValidationError(err) {
		t.Fatalf("expected internal completion audit failure, got %v", err)
	}
	for _, secret := range []string{issued.Token, recoveredAccountTestPassword, before.passwordHash, oldSession.ID} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("password recovery error exposed secret material")
		}
	}
	assertStoredPasswordRecoveryToken(t, ctx, database, target.ID, issued)
	after, err := service.userByID(ctx, database, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.passwordHash != before.passwordHash || after.MustChangePassword != before.MustChangePassword {
		t.Fatal("expected password mutation and forced-change clearing to roll back")
	}
	if _, found, err := service.SessionByID(ctx, oldSession.ID); err != nil || !found {
		t.Fatalf("expected session revocation to roll back, found=%v err=%v", found, err)
	}
	restoreAudit()
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordRecoveryCompleted) != 0 {
		t.Fatal("expected failed completion to leave no audit event")
	}
}

func TestLoginSessionCASRejectsStaleHashAndDisabledUser(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	stale, err := service.userByEmail(ctx, admin.User.Email)
	if err != nil {
		t.Fatal(err)
	}
	replacementHash, err := HashPassword(recoveredAccountTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, replacementHash, admin.User.ID); err != nil {
		t.Fatal(err)
	}
	_, err = service.insertSession(ctx, database, stale.User, stale.passwordHash, "stale-login-session", "stale-login-csrf")
	if !IsAuthenticationError(err) {
		t.Fatalf("expected stale verified hash to lose the login CAS, got %v", err)
	}
	assertSessionDoesNotExist(t, ctx, database, "stale-login-session")

	current, err := service.userByEmail(ctx, admin.User.Email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), admin.User.ID); err != nil {
		t.Fatal(err)
	}
	_, err = service.insertSession(ctx, database, current.User, current.passwordHash, "disabled-login-session", "disabled-login-csrf")
	if !IsAuthenticationError(err) {
		t.Fatalf("expected disabled user to lose the login CAS, got %v", err)
	}
	assertSessionDoesNotExist(t, ctx, database, "disabled-login-session")
}

func TestCommitPasswordChangeCASLeavesStateUntouchedAfterCredentialReplacement(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin := mustCreateFirstAdmin(t, ctx, service)
	target := mustCreateUser(t, ctx, service, "target@example.test", false)
	oldSession, err := service.Login(ctx, LoginParams{Email: target.Email, Password: accountTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	issued := mustIssuePasswordRecoveryToken(t, ctx, service, admin.User.ID, target.ID)
	stale, err := service.userByID(ctx, database, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacementHash, err := HashPassword(recoveredAccountTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?`, replacementHash, target.ID); err != nil {
		t.Fatal(err)
	}
	staleNewHash, err := HashPassword("stale self-service password")
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.commitPasswordChange(ctx, stale, staleNewHash, "stale-change-session", "stale-change-csrf")
	if !IsValidationError(err) {
		t.Fatalf("expected stale self-change to lose the password CAS, got %v", err)
	}
	current, err := service.userByID(ctx, database, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.passwordHash != replacementHash {
		t.Fatal("expected stale self-change not to overwrite the replacement credential")
	}
	assertStoredPasswordRecoveryToken(t, ctx, database, target.ID, issued)
	if _, found, err := service.SessionByID(ctx, oldSession.ID); err != nil || !found {
		t.Fatalf("expected stale self-change not to revoke sessions, found=%v err=%v", found, err)
	}
	assertSessionDoesNotExist(t, ctx, database, "stale-change-session")
	if countAuditActions(t, ctx, database, audit.ActionUserPasswordChanged) != 0 {
		t.Fatal("expected stale self-change to record no audit event")
	}
}

func mustIssuePasswordRecoveryToken(t *testing.T, ctx context.Context, service *Service, actorUserID int64, userID int64) PasswordRecoveryToken {
	t.Helper()
	issued, err := service.IssuePasswordRecoveryToken(ctx, IssuePasswordRecoveryParams{ActorUserID: actorUserID, UserID: userID})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token == "" || issued.ExpiresAt.IsZero() {
		t.Fatal("expected successful issuance to return recovery material")
	}
	return issued
}

func assertStoredPasswordRecoveryToken(t *testing.T, ctx context.Context, database *sql.DB, userID int64, issued PasswordRecoveryToken) []byte {
	t.Helper()
	var digest []byte
	var digestType string
	var expiresAt int64
	if err := database.QueryRowContext(ctx, `
SELECT token_digest, typeof(token_digest), expires_at
FROM password_recovery_tokens
WHERE user_id = ?`, userID).Scan(&digest, &digestType, &expiresAt); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(issued.Token))
	if digestType != "blob" || len(digest) != sha256.Size || !bytes.Equal(digest, expected[:]) {
		t.Fatalf("unexpected persisted recovery digest: type=%q length=%d", digestType, len(digest))
	}
	if expiresAt != issued.ExpiresAt.UnixNano() {
		t.Fatalf("unexpected persisted recovery expiry: want %d got %d", issued.ExpiresAt.UnixNano(), expiresAt)
	}
	return digest
}

func assertInvalidPasswordRecoveryToken(t *testing.T, err error) {
	t.Helper()
	if !IsInvalidPasswordRecoveryToken(err) {
		t.Fatalf("expected generic invalid password recovery token error, got %v", err)
	}
}

func countPasswordRecoveryTokens(t *testing.T, ctx context.Context, database *sql.DB, userID int64) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM password_recovery_tokens WHERE user_id = ?`, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countUserSessions(t *testing.T, ctx context.Context, database *sql.DB, userID int64) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id = ?`, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countAuditActions(t *testing.T, ctx context.Context, database *sql.DB, action string) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = ?`, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func assertSessionDoesNotExist(t *testing.T, ctx context.Context, database *sql.DB, sessionID string) {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id = ?`, sessionID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("expected rejected credential CAS to create no session")
	}
}

func assertRecoveryAuditSecretsAbsent(t *testing.T, ctx context.Context, database *sql.DB, secrets ...string) {
	t.Helper()
	rows, err := database.QueryContext(ctx, `
SELECT details_json
FROM audit_events
WHERE action IN (?, ?)`, audit.ActionUserPasswordRecoveryIssued, audit.ActionUserPasswordRecoveryCompleted)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var details string
		if err := rows.Scan(&details); err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(details)
		for _, forbidden := range []string{"token", "password", "hash", "session"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("recovery audit details contain forbidden field or value %q", forbidden)
			}
		}
		for _, secret := range secrets {
			if secret != "" && strings.Contains(details, secret) {
				t.Fatal("recovery audit details exposed secret material")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
