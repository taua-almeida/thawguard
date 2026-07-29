package companyoidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

func TestCheckPersistsEveryTypedResultAgainstTheSavedRevision(t *testing.T) {
	tests := []struct {
		code       SetupCheckResultCode
		observed   string
		candidates int64
	}{
		{code: SetupCheckVerified, candidates: 2},
		{code: SetupCheckDiscoveryUnavailable, candidates: -1},
		{code: SetupCheckDiscoveryInvalid, candidates: -1},
		{code: SetupCheckIssuerInvalid, candidates: -1},
		{code: SetupCheckIssuerMismatch, observed: "https://other.example.test", candidates: -1},
		{code: SetupCheckMetadataIncompatible, candidates: -1},
		{code: SetupCheckJWKSUnavailable, candidates: -1},
		{code: SetupCheckJWKSInvalid, candidates: -1},
		{code: SetupCheckJWKSNoCandidate, candidates: 0},
	}
	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			fixture := newServiceFixture(t)
			if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
				t.Fatal(err)
			}
			checkedAt := time.Date(2026, 7, 28, 14, 30, 0, 123, time.UTC)
			fixture.service.now = func() time.Time { return checkedAt }
			var calls atomic.Int64
			fixture.service.check = func(_ context.Context, issuer string) SetupCheckReport {
				calls.Add(1)
				if issuer != "https://id.example.test/tenant" || strings.Contains(issuer, testClientSecret) {
					t.Errorf("checker received unexpected saved input %q", issuer)
				}
				return setupCheckReport(tc.code, tc.observed, tc.candidates)
			}

			check, err := fixture.service.Check(fixture.ctx, fixture.adminID)
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 || check.ConfigRevision != 1 || check.ResultCode != tc.code || !check.CheckedAt.Equal(checkedAt) {
				t.Fatalf("persisted check = %+v, calls=%d", check, calls.Load())
			}
			connection, found, err := fixture.service.Current(fixture.ctx)
			if err != nil || !found || connection.SetupCheck == nil {
				t.Fatalf("read current evidence: found=%v connection=%+v err=%v", found, connection, err)
			}
			if connection.SetupCheck.ResultCode != tc.code || connection.SetupCheck.ConfigRevision != connection.Revision {
				t.Fatalf("current evidence = %+v for revision %d", connection.SetupCheck, connection.Revision)
			}
			var storedCheckedAt string
			if err := fixture.database.QueryRow(`SELECT checked_at FROM company_oidc_setup_checks WHERE connection_id = 1`).Scan(&storedCheckedAt); err != nil {
				t.Fatal(err)
			}
			if storedCheckedAt != "2026-07-28T14:30:00.000000123Z" {
				t.Fatalf("stored checked_at = %q", storedCheckedAt)
			}
			assertMetadataCheckedAudit(t, fixture.database, 1, tc.code)
		})
	}
}

func TestCheckRequiresSavedDraftEncryptionAndConfiguredCheckerBeforeOutboundWork(t *testing.T) {
	fixture := newServiceFixture(t)
	var calls atomic.Int64
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		calls.Add(1)
		return setupCheckReport(SetupCheckVerified, "", 1)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); !errors.Is(err, ErrNoDraft) {
		t.Fatalf("check without Draft = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("check without a saved Draft made an outbound call")
	}

	withoutEncryption := NewService(fixture.database, nil, fixture.service.check)
	if _, err := withoutEncryption.Check(fixture.ctx, fixture.adminID); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("check without encryption = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("encryption-unavailable check made an outbound call")
	}

	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	withoutChecker := NewService(fixture.database, fixture.secretStore, nil)
	if _, err := withoutChecker.Check(fixture.ctx, fixture.adminID); err == nil {
		t.Fatal("check without a configured checker succeeded")
	}
}

func TestEveryActualEditInvalidatesEvidenceWhileNormalizedNoOpPreservesIt(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		return setupCheckReport(SetupCheckVerified, "", 1)
	}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, EditInput{
		ProviderLabel:    " Example IdP ",
		Issuer:           " https://id.example.test/tenant ",
		ClientID:         " client-id ",
		Domains:          []string{"EXAMPLE.TEST", "example.test"},
		ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	assertCurrentCheckCode(t, fixture.service, SetupCheckVerified)
	assertMetadataAuditCount(t, fixture.database, 1)

	edits := []func(EditInput) EditInput{
		func(input EditInput) EditInput { input.ProviderLabel = "Renamed IdP"; return input },
		func(input EditInput) EditInput { input.Issuer = "https://other.example.test"; return input },
		func(input EditInput) EditInput { input.ClientID = "other-client"; return input },
		func(input EditInput) EditInput { input.Domains = []string{"other.example"}; return input },
		func(input EditInput) EditInput { input.ReplacementClientSecret = "replacement secret"; return input },
	}
	for i, edit := range edits {
		current, found, err := fixture.service.Current(fixture.ctx)
		if err != nil || !found {
			t.Fatalf("read before edit %d: found=%v err=%v", i, found, err)
		}
		input := EditInput{
			ProviderLabel:    current.ProviderLabel,
			Issuer:           current.Issuer,
			ClientID:         current.ClientID,
			Domains:          current.Domains,
			ExpectedRevision: current.Revision,
		}
		if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit(input)); err != nil {
			t.Fatalf("actual edit %d: %v", i, err)
		}
		current, found, err = fixture.service.Current(fixture.ctx)
		if err != nil || !found || current.SetupCheck != nil {
			t.Fatalf("edit %d did not invalidate evidence: found=%v connection=%+v err=%v", i, found, current, err)
		}
		if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err != nil {
			t.Fatalf("recheck after edit %d: %v", i, err)
		}
	}
}

func TestCurrentRejectsEvidenceThatDoesNotMatchSavedData(t *testing.T) {
	tests := []struct {
		name     string
		revision int64
		observed string
	}{
		{name: "stale revision", revision: 2, observed: "https://other.example.test"},
		{name: "mismatch equals saved issuer", revision: 1, observed: "https://id.example.test/tenant"},
		{name: "observed issuer is not exact", revision: 1, observed: " https://other.example.test"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.database.Exec(`
INSERT INTO company_oidc_setup_checks(
  connection_id, config_revision, result_code, observed_issuer, public_key_candidate_count, checked_at
)
VALUES (1, ?, 'issuer_mismatch', ?, NULL, '2026-07-28T10:00:00.000000000Z')`, tc.revision, tc.observed); err != nil {
				t.Fatal(err)
			}
			if _, _, err := fixture.service.Current(fixture.ctx); err == nil || !strings.Contains(err.Error(), "evidence is malformed") {
				t.Fatalf("Current accepted malformed evidence: %v", err)
			}
		})
	}
}

func TestCheckRejectsMalformedInjectedEvidenceWithoutPersistenceOrAudit(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		issuer := "https://id.example.test/tenant"
		return SetupCheckReport{ResultCode: SetupCheckIssuerMismatch, ObservedIssuer: &issuer}
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err == nil {
		t.Fatal("malformed checker report was accepted")
	}
	assertNoCurrentEvidence(t, fixture.database)
	assertMetadataAuditCount(t, fixture.database, 0)
}

func TestCheckCommitsSnapshotBeforeNetworkAndDiscardsStaleRevision(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		if _, err := fixture.database.ExecContext(fixture.ctx, `UPDATE users SET display_name = 'Network stage write' WHERE id = ?`, fixture.adminID); err != nil {
			t.Errorf("network stage could not write after snapshot transaction: %v", err)
		}
		close(started)
		<-release
		return setupCheckReport(SetupCheckVerified, "", 1)
	}
	result := make(chan error, 1)
	go func() {
		_, err := fixture.service.Check(fixture.ctx, fixture.adminID)
		result <- err
	}()
	<-started
	edit := validEditInput(1)
	edit.ProviderLabel = "Changed while checking"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrCheckStale) {
		t.Fatalf("stale check result = %v", err)
	}
	assertNoCurrentEvidence(t, fixture.database)
	assertMetadataAuditCount(t, fixture.database, 0)
}

func TestCheckUsesWriterFirstAdministratorAuthorityAtBothBoundaries(t *testing.T) {
	t.Run("snapshot boundary", func(t *testing.T) {
		fixture := newServiceFixture(t)
		if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
			t.Fatal(err)
		}
		var calls atomic.Int64
		fixture.service.check = func(context.Context, string) SetupCheckReport {
			calls.Add(1)
			return setupCheckReport(SetupCheckVerified, "", 1)
		}
		blocker := beginAdminDemotion(t, fixture)
		result := make(chan error, 1)
		go func() {
			_, err := fixture.service.Check(fixture.ctx, fixture.adminID)
			result <- err
		}()
		time.Sleep(20 * time.Millisecond)
		if err := blocker.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, ErrAuthorization) {
			t.Fatalf("snapshot authority result = %v", err)
		}
		if calls.Load() != 0 {
			t.Fatal("lost snapshot authority still made an outbound request")
		}
	})

	t.Run("persistence boundary", func(t *testing.T) {
		fixture := newServiceFixture(t)
		if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		release := make(chan struct{})
		fixture.service.check = func(context.Context, string) SetupCheckReport {
			close(started)
			<-release
			return setupCheckReport(SetupCheckVerified, "", 1)
		}
		result := make(chan error, 1)
		go func() {
			_, err := fixture.service.Check(fixture.ctx, fixture.adminID)
			result <- err
		}()
		<-started
		blocker := beginAdminDemotion(t, fixture)
		close(release)
		time.Sleep(20 * time.Millisecond)
		if err := blocker.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, ErrAuthorization) {
			t.Fatalf("persistence authority result = %v", err)
		}
		assertNoCurrentEvidence(t, fixture.database)
		assertMetadataAuditCount(t, fixture.database, 0)
	})
}

func TestConcurrentSameRevisionChecksPersistLastCompletedResult(t *testing.T) {
	fixture := newServiceFixture(t)
	secondAdminID := fixture.insertAdmin(t, "second-checker@example.test")
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	started := []chan struct{}{make(chan struct{}), make(chan struct{})}
	release := []chan struct{}{make(chan struct{}), make(chan struct{})}
	var calls atomic.Int64
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		call := int(calls.Add(1) - 1)
		close(started[call])
		<-release[call]
		return setupCheckReport(SetupCheckVerified, "", int64(call+1))
	}
	results := make(chan error, 2)
	go func() { _, err := fixture.service.Check(fixture.ctx, fixture.adminID); results <- err }()
	<-started[0]
	go func() { _, err := fixture.service.Check(fixture.ctx, secondAdminID); results <- err }()
	<-started[1]
	close(release[0])
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	close(release[1])
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.SetupCheck == nil || connection.SetupCheck.PublicKeyCandidateCount == nil {
		t.Fatalf("read concurrent result: found=%v connection=%+v err=%v", found, connection, err)
	}
	if got := *connection.SetupCheck.PublicKeyCandidateCount; got != 2 {
		t.Fatalf("current candidate count = %d, want last-completed result 2", got)
	}
	assertMetadataAuditCount(t, fixture.database, 2)
}

func TestSetupCheckEvidenceAndAuditRollBackTogether(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		return setupCheckReport(SetupCheckVerified, "", 1)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TRIGGER reject_oidc_metadata_audit
BEFORE INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.metadata_checked'
BEGIN
  SELECT RAISE(ABORT, 'test audit rejection');
END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err == nil {
		t.Fatal("expected metadata audit failure")
	}
	assertNoCurrentEvidence(t, fixture.database)
	assertMetadataAuditCount(t, fixture.database, 0)
}

func TestSetupCheckCommitFailureReportsUnknownOutcome(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		return setupCheckReport(SetupCheckVerified, "", 1)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TABLE oidc_check_commit_parent (id INTEGER PRIMARY KEY);
CREATE TABLE oidc_check_commit_child (
  id INTEGER PRIMARY KEY,
  parent_id INTEGER NOT NULL REFERENCES oidc_check_commit_parent(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER fail_oidc_check_commit
AFTER INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.metadata_checked'
BEGIN
  INSERT INTO oidc_check_commit_child(parent_id) VALUES (999);
END;`); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.service.Check(fixture.ctx, fixture.adminID)
	if !errors.Is(err, ErrCheckOutcomeUnknown) {
		t.Fatalf("commit failure result = %v", err)
	}
}

func setupCheckReport(code SetupCheckResultCode, observed string, candidates int64) SetupCheckReport {
	report := SetupCheckReport{ResultCode: code}
	if observed != "" {
		report.ObservedIssuer = new(observed)
	}
	if candidates >= 0 {
		report.PublicKeyCandidateCount = new(candidates)
	}
	return report
}

func assertCurrentCheckCode(t *testing.T, service *Service, want SetupCheckResultCode) {
	t.Helper()
	connection, found, err := service.Current(context.Background())
	if err != nil || !found || connection.SetupCheck == nil || connection.SetupCheck.ResultCode != want {
		t.Fatalf("current check: found=%v connection=%+v err=%v", found, connection, err)
	}
}

func assertNoCurrentEvidence(t *testing.T, database *sql.DB) {
	t.Helper()
	var count int
	if err := database.QueryRow(`SELECT count(*) FROM company_oidc_setup_checks`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("current evidence rows = %d, want 0", count)
	}
}

func assertMetadataAuditCount(t *testing.T, database *sql.DB, want int) {
	t.Helper()
	var count int
	if err := database.QueryRow(`SELECT count(*) FROM audit_events WHERE action = ?`, audit.ActionOIDCConnectionMetadataChecked).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("metadata-check audit count = %d, want %d", count, want)
	}
}

func assertMetadataCheckedAudit(
	t *testing.T,
	database *sql.DB,
	revision int64,
	code SetupCheckResultCode,
) {
	t.Helper()
	var actorUserID int64
	var subjectType, subjectID, detailsJSON string
	if err := database.QueryRow(`
SELECT actor_user_id, subject_type, subject_id, details_json
FROM audit_events
WHERE action = ?`, audit.ActionOIDCConnectionMetadataChecked).Scan(
		&actorUserID,
		&subjectType,
		&subjectID,
		&detailsJSON,
	); err != nil {
		t.Fatal(err)
	}
	if actorUserID <= 0 || subjectType != audit.SubjectTypeOIDCConnection || subjectID != "1" {
		t.Fatalf("unexpected metadata audit identity: actor=%d subject=%s/%s", actorUserID, subjectType, subjectID)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(detailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if len(details) != 2 || details["revision"] != float64(revision) || details["result_code"] != string(code) {
		t.Fatalf("unexpected metadata audit details: %s", detailsJSON)
	}
	for _, forbidden := range []string{"Example IdP", "https://", "client-id", "example.test", "secret", "response", "error"} {
		if strings.Contains(strings.ToLower(detailsJSON), strings.ToLower(forbidden)) {
			t.Fatalf("metadata audit contains forbidden value %q: %s", forbidden, detailsJSON)
		}
	}
}

func beginAdminDemotion(t *testing.T, fixture *serviceFixture) *sql.Tx {
	t.Helper()
	tx, err := fixture.database.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(fixture.ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, fixture.adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(fixture.ctx, `DELETE FROM user_roles WHERE user_id = ? AND role = 'admin'`, fixture.adminID); err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestCheckSnapshotQuerySelectsOnlyIssuerAndRevision(t *testing.T) {
	query := strings.Join(strings.Fields(checkSnapshotQuery), " ")
	if want := "SELECT issuer, revision FROM company_oidc_connections WHERE id = 1"; query != want {
		t.Fatalf("check snapshot query = %q, want %q", query, want)
	}
	if strings.Contains(strings.ToLower(query), "client_secret_ciphertext") {
		t.Fatal("check snapshot query selects client-secret ciphertext")
	}
}

func TestCheckSnapshotValidationFailsBeforeOutboundWork(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExecContext(
		fixture.ctx,
		`UPDATE company_oidc_connections SET issuer = 'https://id.example.test/tenant ' WHERE id = 1`,
	); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		calls.Add(1)
		return setupCheckReport(SetupCheckVerified, "", 1)
	}

	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err == nil {
		t.Fatal("check accepted a malformed saved issuer")
	}
	if calls.Load() != 0 {
		t.Fatal("snapshot validation failure made an outbound call")
	}
	assertNoCurrentEvidence(t, fixture.database)
	assertMetadataAuditCount(t, fixture.database, 0)
}

func TestCheckDoesNotUseClientSecretStoreDecryption(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	fixture.service.secrets = panicDecryptStore{}
	fixture.service.check = func(_ context.Context, issuer string) SetupCheckReport {
		if strings.Contains(issuer, testClientSecret) {
			t.Fatal("checker received client-secret material")
		}
		return setupCheckReport(SetupCheckVerified, "", 1)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err != nil {
		t.Fatal(err)
	}
}

type panicDecryptStore struct{}

func (panicDecryptStore) Encrypt(context.Context, []byte) ([]byte, error) {
	return nil, fmt.Errorf("unexpected encryption")
}

func (panicDecryptStore) Decrypt(context.Context, []byte) ([]byte, error) {
	panic("client secret was decrypted during metadata check")
}
