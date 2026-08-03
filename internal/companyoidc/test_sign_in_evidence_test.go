package companyoidc

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

func TestVerifiedTestSignInPersistsEvidenceForExactDraftRevision(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	start := startProtocolTestSignIn(t, fixture)
	authorizationURL := mustParseURL(t, start.AuthorizationURL)
	state, nonce := authorizationURL.Query().Get("state"), authorizationURL.Query().Get("nonce")
	provider.setNonceAndRotate(nonce)

	result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
	if err != nil || result != TestSignInVerified {
		t.Fatalf("complete Test sign-in: result=%q err=%v", result, err)
	}

	var revision int64
	var verifiedAt string
	if err := fixture.database.QueryRow(`
SELECT config_revision, verified_at FROM company_oidc_test_sign_in_evidence WHERE connection_id = 1`).Scan(&revision, &verifiedAt); err != nil {
		t.Fatalf("read persisted evidence: %v", err)
	}
	if revision != 1 || verifiedAt != formatCompanyOIDCTime(testSignInNow) {
		t.Fatalf("evidence revision=%d verified_at=%q, want revision 1 at writer-owned time", revision, verifiedAt)
	}
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 1)

	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection: found=%v err=%v", found, err)
	}
	if connection.TestSignInEvidence == nil ||
		connection.TestSignInEvidence.ConfigRevision != connection.Revision ||
		!connection.TestSignInEvidence.VerifiedAt.Equal(testSignInNow) {
		t.Fatalf("public evidence = %+v, want revision %d at %v", connection.TestSignInEvidence, connection.Revision, testSignInNow)
	}
}

func TestFailedTestSignInPreservesPriorVerifiedEvidence(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	start := startProtocolTestSignIn(t, fixture)
	authorizationURL := mustParseURL(t, start.AuthorizationURL)
	state, nonce := authorizationURL.Query().Get("state"), authorizationURL.Query().Get("nonce")
	provider.setNonceAndRotate(nonce)
	result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
	if err != nil || result != TestSignInVerified {
		t.Fatalf("verified Test sign-in: result=%q err=%v", result, err)
	}

	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x44, 0x55, 0x66))
	deniedStart := startProtocolTestSignIn(t, fixture)
	deniedState := mustParseURL(t, deniedStart.AuthorizationURL).Query().Get("state")
	result, err = fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     deniedState,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {deniedState}, "error": {"access_denied"}}.Encode(),
	})
	if err != nil || result != TestSignInProviderDenied {
		t.Fatalf("denied Test sign-in: result=%q err=%v", result, err)
	}

	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection: found=%v err=%v", found, err)
	}
	if connection.TestSignInEvidence == nil ||
		connection.TestSignInEvidence.ConfigRevision != 1 ||
		!connection.TestSignInEvidence.VerifiedAt.Equal(testSignInNow) {
		t.Fatalf("denied retest changed evidence: %+v", connection.TestSignInEvidence)
	}
}

func TestCompletionCommitFailureRollsBackEvidenceWithAudit(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	start := startProtocolTestSignIn(t, fixture)
	authorizationURL := mustParseURL(t, start.AuthorizationURL)
	state, nonce := authorizationURL.Query().Get("state"), authorizationURL.Query().Get("nonce")
	provider.setNonceAndRotate(nonce)
	if _, err := fixture.database.Exec(`
CREATE TABLE oidc_evidence_commit_parent (id INTEGER PRIMARY KEY);
CREATE TABLE oidc_evidence_commit_child (
  id INTEGER PRIMARY KEY,
  parent_id INTEGER NOT NULL REFERENCES oidc_evidence_commit_parent(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER fail_oidc_evidence_commit
AFTER INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.test_sign_in_completed'
BEGIN
  INSERT INTO oidc_evidence_commit_child(parent_id) VALUES (999);
END;`); err != nil {
		t.Fatal(err)
	}

	result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
	if result != "" || !errors.Is(err, ErrTestTransactionOutcomeUnknown) {
		t.Fatalf("completion commit result=%q err=%v", result, err)
	}
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 0)
	assertTestSignInEvidenceCount(t, fixture, 0)
}

func TestRealEditDeletesEvidenceAndNormalizedNoOpPreservesIt(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	verifiedAt := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	seedTestSignInEvidence(t, fixture, 1, verifiedAt)

	noop := validEditInput(1)
	noop.ProviderLabel = "  " + noop.ProviderLabel + "  "
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, noop); err != nil {
		t.Fatal(err)
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection after no-op: found=%v err=%v", found, err)
	}
	if connection.Revision != 1 || connection.TestSignInEvidence == nil ||
		!connection.TestSignInEvidence.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("normalized no-op edit changed revision or evidence: revision=%d evidence=%+v", connection.Revision, connection.TestSignInEvidence)
	}

	real := validEditInput(1)
	real.ProviderLabel = "Renamed IdP"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, real); err != nil {
		t.Fatal(err)
	}
	connection, found, err = fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection after real edit: found=%v err=%v", found, err)
	}
	if connection.Revision != 2 || connection.TestSignInEvidence != nil {
		t.Fatalf("real edit kept evidence: revision=%d evidence=%+v", connection.Revision, connection.TestSignInEvidence)
	}
	assertTestSignInEvidenceCount(t, fixture, 0)
}

func TestEditAuditFailureRestoresEvidenceViaRollback(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	verifiedAt := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	seedTestSignInEvidence(t, fixture, 1, verifiedAt)
	if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TRIGGER reject_oidc_edit_audit
BEFORE INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.draft_saved'
BEGIN
  SELECT RAISE(ABORT, 'test audit rejection');
END;`); err != nil {
		t.Fatal(err)
	}

	real := validEditInput(1)
	real.ProviderLabel = "Renamed IdP"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, real); err == nil {
		t.Fatal("expected audit failure to reject the edit")
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection after rolled-back edit: found=%v err=%v", found, err)
	}
	if connection.Revision != 1 || connection.TestSignInEvidence == nil ||
		connection.TestSignInEvidence.ConfigRevision != 1 {
		t.Fatalf("rollback lost evidence: revision=%d evidence=%+v", connection.Revision, connection.TestSignInEvidence)
	}
}

func TestStaleEvidenceRevisionFailsClosedOnRead(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	seedTestSignInEvidence(t, fixture, 2, time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC))

	if _, _, err := fixture.service.Current(fixture.ctx); err == nil {
		t.Fatal("expected stale evidence revision to fail closed")
	}
}

func TestEvidenceLoadsOnceAcrossMultipleDomains(t *testing.T) {
	fixture := newServiceFixture(t)
	input := validCreateInput(testClientSecret)
	input.Domains = []string{"a.example.test", "b.example.test", "c.example.test"}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, input); err != nil {
		t.Fatal(err)
	}
	verifiedAt := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	seedTestSignInEvidence(t, fixture, 1, verifiedAt)

	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection: found=%v err=%v", found, err)
	}
	if len(connection.Domains) != 3 {
		t.Fatalf("domains = %v, want all three", connection.Domains)
	}
	if connection.TestSignInEvidence == nil ||
		connection.TestSignInEvidence.ConfigRevision != 1 ||
		!connection.TestSignInEvidence.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("evidence across domain rows = %+v", connection.TestSignInEvidence)
	}
}

func TestConcurrentEditAndReadKeepEvidenceRevisionConsistent(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	seedTestSignInEvidence(t, fixture, 1, time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC))

	done := make(chan struct{})
	readFailure := make(chan error, 1)
	go func() {
		defer close(done)
		for range 200 {
			connection, found, err := fixture.service.Current(fixture.ctx)
			if err != nil || !found {
				readFailure <- fmt.Errorf("concurrent read: found=%v err=%v", found, err)
				return
			}
			if connection.TestSignInEvidence != nil && connection.TestSignInEvidence.ConfigRevision != connection.Revision {
				readFailure <- fmt.Errorf("read evidence revision %d for Draft revision %d", connection.TestSignInEvidence.ConfigRevision, connection.Revision)
				return
			}
		}
	}()

	real := validEditInput(1)
	real.ProviderLabel = "Renamed IdP"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, real); err != nil {
		t.Fatal(err)
	}
	<-done
	select {
	case err := <-readFailure:
		t.Fatal(err)
	default:
	}
	assertTestSignInEvidenceCount(t, fixture, 0)
}

func TestEvidenceWriteRejectionFailsCompletionWithoutCompletedAudit(t *testing.T) {
	fixture := newServiceFixture(t)
	claim := claimReadyTestSignIn(t, fixture)
	if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TRIGGER reject_oidc_evidence_write
BEFORE INSERT ON company_oidc_test_sign_in_evidence
BEGIN
  SELECT RAISE(ABORT, 'test evidence rejection');
END;`); err != nil {
		t.Fatal(err)
	}

	err := fixture.service.completeTestSignIn(fixture.ctx, claim, TestSignInVerified)
	if !errors.Is(err, ErrTestTransactionUnavailable) {
		t.Fatalf("expected generic unavailable completion failure, got %v", err)
	}
	assertTestSignInEvidenceCount(t, fixture, 0)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 0)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInClaimed, 1)
}

func TestImmediateCompletedAuditRejectionRollsBackEvidenceWrittenFirst(t *testing.T) {
	fixture := newServiceFixture(t)
	claim := claimReadyTestSignIn(t, fixture)
	// The WHEN clause fires only if evidence already exists inside the same
	// transaction, so the abort itself proves the verified evidence upsert
	// happened before the completed-audit insert.
	if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TRIGGER reject_oidc_completed_audit
BEFORE INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.test_sign_in_completed'
  AND EXISTS (SELECT 1 FROM company_oidc_test_sign_in_evidence)
BEGIN
  SELECT RAISE(ABORT, 'test audit rejection');
END;`); err != nil {
		t.Fatal(err)
	}

	err := fixture.service.completeTestSignIn(fixture.ctx, claim, TestSignInVerified)
	if !errors.Is(err, ErrTestTransactionUnavailable) {
		t.Fatalf("expected generic unavailable completion failure, got %v", err)
	}
	assertTestSignInEvidenceCount(t, fixture, 0)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 0)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInClaimed, 1)
}

func TestNonSuccessCompletionPreservesEvidenceAndRecordsAttemptedResult(t *testing.T) {
	for _, result := range []TestSignInResultCode{
		TestSignInProviderDenied,
		TestSignInProviderUnavailable,
		TestSignInProviderInvalid,
		TestSignInConfigurationUnavailable,
	} {
		t.Run(string(result), func(t *testing.T) {
			fixture := newServiceFixture(t)
			claim := claimReadyTestSignIn(t, fixture)
			priorVerifiedAt := testSignInNow.Add(-time.Hour)
			seedTestSignInEvidence(t, fixture, 1, priorVerifiedAt)

			if err := fixture.service.completeTestSignIn(fixture.ctx, claim, result); err != nil {
				t.Fatal(err)
			}
			assertTestSignInEvidenceCount(t, fixture, 1)
			var revision int64
			var verifiedAt string
			if err := fixture.database.QueryRow(`
SELECT config_revision, verified_at FROM company_oidc_test_sign_in_evidence WHERE connection_id = 1`).Scan(&revision, &verifiedAt); err != nil {
				t.Fatalf("read preserved evidence: %v", err)
			}
			if revision != 1 || verifiedAt != formatCompanyOIDCTime(priorVerifiedAt) {
				t.Fatalf("non-success completion changed evidence: revision=%d verified_at=%q", revision, verifiedAt)
			}
			assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 1)
			var attempted int
			if err := fixture.database.QueryRow(
				`SELECT count(*) FROM audit_events WHERE action = ? AND details_json = ?`,
				audit.ActionOIDCConnectionTestSignInCompleted,
				fmt.Sprintf(`{"revision":1,"result_code":%q}`, string(result)),
			).Scan(&attempted); err != nil {
				t.Fatal(err)
			}
			if attempted != 1 {
				t.Fatalf("expected one completed audit recording attempted result %q", result)
			}
		})
	}
}

func TestImpossibleCalendarDateEvidenceFailsClosedOnRead(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO company_oidc_test_sign_in_evidence(connection_id, config_revision, verified_at)
VALUES (1, 1, '2026-02-30T10:05:00.000000000Z')`); err != nil {
		t.Fatalf("shape-valid impossible date must pass storage checks: %v", err)
	}

	_, _, err := fixture.service.Current(fixture.ctx)
	if err == nil || !strings.Contains(err.Error(), "test sign-in evidence is malformed") {
		t.Fatalf("expected sanitized malformed-evidence failure, got %v", err)
	}
}

func TestPartialEvidenceRowFailsClosedOnRead(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	// The shipped schema forbids partial rows, so simulate corrupted or legacy
	// storage by loosening only this test database's evidence table.
	if _, err := fixture.database.ExecContext(fixture.ctx, `
DROP TABLE company_oidc_test_sign_in_evidence;
CREATE TABLE company_oidc_test_sign_in_evidence (
  connection_id INTEGER PRIMARY KEY,
  config_revision INTEGER,
  verified_at TEXT
);
INSERT INTO company_oidc_test_sign_in_evidence(connection_id, config_revision, verified_at)
VALUES (1, 1, NULL);`); err != nil {
		t.Fatal(err)
	}

	_, _, err := fixture.service.Current(fixture.ctx)
	if err == nil || !strings.Contains(err.Error(), "test sign-in evidence is malformed") {
		t.Fatalf("expected sanitized malformed-evidence failure, got %v", err)
	}
}

func TestCompletionThenEditLeavesEditedRevisionWithoutStaleEvidence(t *testing.T) {
	fixture := newServiceFixture(t)
	claim := claimReadyTestSignIn(t, fixture)
	if err := fixture.service.completeTestSignIn(fixture.ctx, claim, TestSignInVerified); err != nil {
		t.Fatal(err)
	}
	assertTestSignInEvidenceCount(t, fixture, 1)

	edit := validEditInput(1)
	edit.ProviderLabel = "Renamed IdP"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
		t.Fatal(err)
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection after edit: found=%v err=%v", found, err)
	}
	if connection.Revision != 2 || connection.TestSignInEvidence != nil {
		t.Fatalf("edit after completion kept stale evidence: revision=%d evidence=%+v", connection.Revision, connection.TestSignInEvidence)
	}
	assertTestSignInEvidenceCount(t, fixture, 0)
}

func TestEditBeforeCompletionFailsRevisionFenceWithoutFalseEvidence(t *testing.T) {
	fixture := newServiceFixture(t)
	claim := claimReadyTestSignIn(t, fixture)
	seedTestSignInEvidence(t, fixture, 1, testSignInNow.Add(-time.Hour))
	edit := validEditInput(1)
	edit.ProviderLabel = "Renamed IdP"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
		t.Fatal(err)
	}
	assertTestSignInEvidenceCount(t, fixture, 0)

	err := fixture.service.completeTestSignIn(fixture.ctx, claim, TestSignInVerified)
	if !errors.Is(err, ErrTestTransactionUnavailable) {
		t.Fatalf("expected stale completion to fail the configuration fence, got %v", err)
	}
	assertTestSignInEvidenceCount(t, fixture, 0)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 0)
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection after stale completion: found=%v err=%v", found, err)
	}
	if connection.Revision != 2 || connection.TestSignInEvidence != nil {
		t.Fatalf("stale completion produced false evidence: revision=%d evidence=%+v", connection.Revision, connection.TestSignInEvidence)
	}
}

func claimReadyTestSignIn(t *testing.T, fixture *serviceFixture) testSignInClaim {
	t.Helper()
	initiation, _ := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
	claim, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
		State:     initiation.State,
		SessionID: testSignInSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func seedTestSignInEvidence(t *testing.T, fixture *serviceFixture, revision int64, verifiedAt time.Time) {
	t.Helper()
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO company_oidc_test_sign_in_evidence(connection_id, config_revision, verified_at)
VALUES (1, ?, ?)
ON CONFLICT(connection_id) DO UPDATE
SET config_revision = excluded.config_revision, verified_at = excluded.verified_at`,
		revision,
		formatCompanyOIDCTime(verifiedAt),
	); err != nil {
		t.Fatal(err)
	}
}

func assertTestSignInEvidenceCount(t *testing.T, fixture *serviceFixture, want int) {
	t.Helper()
	var got int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM company_oidc_test_sign_in_evidence`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("evidence count = %d, want %d", got, want)
	}
}
