package companyoidc

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

func newEnableReadyFixture(t *testing.T, provider *testSignInTLSProvider) *serviceFixture {
	t.Helper()
	fixture := newLinkReadyFixture(t, provider)
	start := startLink(t, fixture)
	result, err := completeLinkCallback(t, fixture, provider, start)
	if err != nil || result != TestSignInVerified {
		t.Fatalf("link for enable-ready fixture: result=%q err=%v", result, err)
	}
	return fixture
}

func enableCompanyLogin(t *testing.T, fixture *serviceFixture) {
	t.Helper()
	if err := fixture.service.Enable(fixture.ctx, EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
}

func insertCompanyOIDCSession(t *testing.T, fixture *serviceFixture, sessionID string, userID int64) {
	t.Helper()
	insertTestSignInSession(t, fixture, sessionID, userID, testSignInNow.Add(time.Hour))
	mustExec(t, fixture, `
INSERT INTO company_oidc_sessions(session_id, connection_id, user_id)
VALUES (?, 1, ?)`, sessionID, userID)
}

func sessionExists(t *testing.T, fixture *serviceFixture, sessionID string) bool {
	t.Helper()
	var exists int
	if err := fixture.database.QueryRow(`
SELECT EXISTS (SELECT 1 FROM sessions WHERE id = ?)`, sessionID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists == 1
}

func TestEnableActivatesOnlyWithEveryPrerequisite(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)

	enableCompanyLogin(t, fixture)

	assertActivationState(t, fixture, true, 3)
	assertTestSignInAudit(t, fixture, audit.ActionOIDCConnectionEnabled, `{"revision":1}`)

	// Enabling again conflicts: the connection is no longer disabled.
	err := fixture.service.Enable(fixture.ctx, EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second Enable error = %v, want ErrConflict", err)
	}
	assertActivationState(t, fixture, true, 3)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionEnabled, 1)
}

func TestEnableRejectsEachMissingPrerequisite(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *testing.T, fixture *serviceFixture) EnableInput
		wantErr error
	}{
		{
			name: "invalid actor",
			mutate: func(t *testing.T, fixture *serviceFixture) EnableInput {
				return EnableInput{ActorUserID: 0, ExpectedRevision: 1}
			},
			wantErr: ErrAuthorization,
		},
		{
			name: "non-administrator actor",
			mutate: func(t *testing.T, fixture *serviceFixture) EnableInput {
				mustExec(t, fixture, `DELETE FROM user_roles WHERE user_id = ?`, fixture.adminID)
				return EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}
			},
			wantErr: ErrAuthorization,
		},
		{
			name: "stale revision",
			mutate: func(t *testing.T, fixture *serviceFixture) EnableInput {
				return EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 2}
			},
			wantErr: ErrConflict,
		},
		{
			name: "no linked identity",
			mutate: func(t *testing.T, fixture *serviceFixture) EnableInput {
				mustExec(t, fixture, `DELETE FROM company_oidc_identities`)
				return EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}
			},
			wantErr: ErrNotReady,
		},
		{
			name: "identity from a different revision",
			mutate: func(t *testing.T, fixture *serviceFixture) EnableInput {
				mustExec(t, fixture, `UPDATE company_oidc_identities SET config_revision = 2 WHERE connection_id = 1`)
				return EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}
			},
			wantErr: ErrNotReady,
		},
		{
			name: "missing test sign-in evidence",
			mutate: func(t *testing.T, fixture *serviceFixture) EnableInput {
				mustExec(t, fixture, `DELETE FROM company_oidc_test_sign_in_evidence`)
				return EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}
			},
			wantErr: ErrNotReady,
		},
		{
			name: "linked administrator forced to change password",
			mutate: func(t *testing.T, fixture *serviceFixture) EnableInput {
				mustExec(t, fixture, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, fixture.adminID)
				return EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}
			},
			wantErr: ErrNotReady,
		},
		{
			name: "linked administrator disabled",
			mutate: func(t *testing.T, fixture *serviceFixture) EnableInput {
				secondAdmin := fixture.insertAdmin(t, "second-admin@example.test")
				mustExec(t, fixture, `UPDATE users SET disabled_at = '2026-07-29T00:00:00Z' WHERE id = ?`, fixture.adminID)
				return EnableInput{ActorUserID: secondAdmin, ExpectedRevision: 1}
			},
			wantErr: ErrNotReady,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			fixture := newEnableReadyFixture(t, provider)
			input := tc.mutate(t, fixture)
			if err := fixture.service.Enable(fixture.ctx, input); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Enable error = %v, want %v", err, tc.wantErr)
			}
			var enabled int64
			if err := fixture.database.QueryRow(`SELECT enabled FROM company_oidc_connections WHERE id = 1`).Scan(&enabled); err != nil {
				t.Fatal(err)
			}
			if enabled != 0 {
				t.Fatal("rejected Enable still activated the connection")
			}
			assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionEnabled, 0)
		})
	}
}

func TestEnableRequiresConfiguredEncryption(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)
	fixture.service.secrets = nil
	err := fixture.service.Enable(fixture.ctx, EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Enable without encryption error = %v, want ErrConfiguration", err)
	}
}

func TestEnableRejectsUndecryptableClientSecretWithoutStateChange(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)
	wrongKeyStore, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{0x38}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.secrets = wrongKeyStore
	discoveryBefore := provider.discoveryRequests()

	enableErr := fixture.service.Enable(fixture.ctx, EnableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1})
	if !errors.Is(enableErr, ErrConfiguration) {
		t.Fatalf("Enable with the wrong encryption key error = %v, want ErrConfiguration", enableErr)
	}
	assertActivationState(t, fixture, false, 2)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionEnabled, 0)
	if got := provider.discoveryRequests(); got != discoveryBefore {
		t.Fatalf("rejected Enable contacted the provider %d times", got-discoveryBefore)
	}
}

func TestEnableRejectsIneligibleLinkedAdministratorWithoutStateChange(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)
	secondAdmin := fixture.insertAdmin(t, "second-admin@example.test")
	mustExec(t, fixture, `UPDATE users SET disabled_at = '2026-07-29T00:00:00Z' WHERE id = ?`, fixture.adminID)
	discoveryBefore := provider.discoveryRequests()

	enableErr := fixture.service.Enable(fixture.ctx, EnableInput{ActorUserID: secondAdmin, ExpectedRevision: 1})
	if !errors.Is(enableErr, ErrNotReady) {
		t.Fatalf("Enable with a disabled linked Administrator error = %v, want ErrNotReady", enableErr)
	}
	assertActivationState(t, fixture, false, 2)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionEnabled, 0)
	if got := provider.discoveryRequests(); got != discoveryBefore {
		t.Fatalf("rejected Enable contacted the provider %d times", got-discoveryBefore)
	}
}

func TestEnableReadyReflectsOfflinePrerequisites(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, fixture *serviceFixture)
		ready  bool
	}{
		{name: "every prerequisite holds", ready: true},
		{
			name: "wrong encryption key",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				wrongKeyStore, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{0x38}, 32))
				if err != nil {
					t.Fatal(err)
				}
				fixture.service.secrets = wrongKeyStore
			},
		},
		{
			name: "no configured encryption",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				fixture.service.secrets = nil
			},
		},
		{
			name: "linked administrator disabled",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE users SET disabled_at = '2026-07-29T00:00:00Z' WHERE id = ?`, fixture.adminID)
			},
		},
		{
			name: "linked administrator forced to change password",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, fixture.adminID)
			},
		},
		{
			name: "linked administrator demoted",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `DELETE FROM user_roles WHERE user_id = ?`, fixture.adminID)
			},
		},
		{
			name: "identity linked at a stale revision",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE company_oidc_identities SET config_revision = 2 WHERE connection_id = 1`)
			},
		},
		{
			name: "missing test sign-in evidence",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `DELETE FROM company_oidc_test_sign_in_evidence`)
			},
		},
		{
			name: "already enabled",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				enableCompanyLogin(t, fixture)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			fixture := newEnableReadyFixture(t, provider)
			if tc.mutate != nil {
				tc.mutate(t, fixture)
			}
			discoveryBefore := provider.discoveryRequests()

			if got := fixture.service.EnableReady(fixture.ctx); got != tc.ready {
				t.Fatalf("EnableReady = %v, want %v", got, tc.ready)
			}

			if got := provider.discoveryRequests(); got != discoveryBefore {
				t.Fatalf("EnableReady contacted the provider %d times", got-discoveryBefore)
			}
		})
	}
}

func TestDisableRevokesOIDCSessionsAndDeletesLoginTransactions(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)
	enableCompanyLogin(t, fixture)

	insertCompanyOIDCSession(t, fixture, "oidc-session", fixture.adminID)
	startLoginTransaction(t, fixture)
	assertLoginTransactionCount(t, fixture, 1)

	// Disable works without configured encryption; operators must always be
	// able to turn company login off.
	fixture.service.secrets = nil
	if err := fixture.service.Disable(fixture.ctx, DisableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	fixture.service.secrets = fixture.secretStore

	assertActivationState(t, fixture, false, 4)
	assertLoginTransactionCount(t, fixture, 0)
	if sessionExists(t, fixture, "oidc-session") {
		t.Fatal("Disable left an OIDC-provenance session alive")
	}
	if !sessionExists(t, fixture, testSignInSessionID) {
		t.Fatal("Disable revoked a local-password session")
	}
	if got := countTableRows(t, fixture, "company_oidc_sessions"); got != 0 {
		t.Fatalf("company OIDC session rows after Disable = %d, want 0", got)
	}
	assertTestSignInAudit(t, fixture, audit.ActionOIDCConnectionDisabled, `{"revision":1,"cause":"administrator"}`)

	// The identity survives Disable; only activation state and sessions move.
	if got := countTableRows(t, fixture, "company_oidc_identities"); got != 1 {
		t.Fatalf("identities after Disable = %d, want 1", got)
	}

	if err := fixture.service.Disable(fixture.ctx, DisableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}); !errors.Is(err, ErrConflict) {
		t.Fatal("second Disable did not conflict")
	}
}

func TestMutationsAreRejectedWhileEnabled(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)
	enableCompanyLogin(t, fixture)

	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, validEditInput(1)); !errors.Is(err, ErrEnabled) {
		t.Fatalf("Edit while enabled error = %v, want ErrEnabled", err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); !errors.Is(err, ErrEnabled) {
		t.Fatalf("Check while enabled error = %v, want ErrEnabled", err)
	}
	if _, err := fixture.service.StartTestSignIn(fixture.ctx, validProtocolStartInput(fixture.adminID)); !errors.Is(err, ErrEnabled) {
		t.Fatalf("StartTestSignIn while enabled error = %v, want ErrEnabled", err)
	}
	if _, err := fixture.service.StartLink(fixture.ctx, validLinkStartInput(fixture.adminID)); !errors.Is(err, ErrLinkUnavailable) {
		t.Fatalf("StartLink while enabled error = %v, want ErrLinkUnavailable", err)
	}
	if err := fixture.service.Unlink(fixture.ctx, UnlinkInput{
		ActorUserID:      fixture.adminID,
		SessionID:        testSignInSessionID,
		ExpectedRevision: 1,
	}); !errors.Is(err, ErrEnabled) {
		t.Fatalf("Unlink while enabled error = %v, want ErrEnabled", err)
	}
	assertActivationState(t, fixture, true, 3)
}

func TestUnlinkRemovesOwnIdentityAndRevokesOIDCSessions(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)

	insertCompanyOIDCSession(t, fixture, "oidc-session", fixture.adminID)
	if err := fixture.service.Unlink(fixture.ctx, UnlinkInput{
		ActorUserID:      fixture.adminID,
		SessionID:        testSignInSessionID,
		ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	if got := countTableRows(t, fixture, "company_oidc_identities"); got != 0 {
		t.Fatalf("identities after Unlink = %d, want 0", got)
	}
	assertActivationState(t, fixture, false, 3)
	if sessionExists(t, fixture, "oidc-session") {
		t.Fatal("Unlink left an OIDC-provenance session alive")
	}
	if !sessionExists(t, fixture, testSignInSessionID) {
		t.Fatal("Unlink revoked a local-password session")
	}
	assertTestSignInAudit(t, fixture, audit.ActionOIDCIdentityUnlinked, `{"revision":1,"cause":"administrator"}`)
}

func TestUnlinkRequiresCurrentPasswordVerifiedSessionAndDisabledConnection(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)

	mustExec(t, fixture, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, fixture.adminID)
	if err := fixture.service.Unlink(fixture.ctx, UnlinkInput{
		ActorUserID:      fixture.adminID,
		SessionID:        testSignInSessionID,
		ExpectedRevision: 1,
	}); !errors.Is(err, ErrLinkAuthorization) {
		t.Fatalf("Unlink with forced password change error = %v, want ErrLinkAuthorization", err)
	}

	mustExec(t, fixture, `UPDATE local_credentials SET must_change_password = 0 WHERE user_id = ?`, fixture.adminID)
	if err := fixture.service.Unlink(fixture.ctx, UnlinkInput{
		ActorUserID:      fixture.adminID,
		SessionID:        testSignInSessionID,
		ExpectedRevision: 2,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Unlink with stale revision error = %v, want ErrConflict", err)
	}
	if got := countTableRows(t, fixture, "company_oidc_identities"); got != 1 {
		t.Fatal("rejected Unlink removed the identity")
	}
}

func TestUnlinkRejectsOtherUsersIdentity(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)

	secondAdmin := fixture.insertAdmin(t, "second-admin@example.test")
	insertCurrentLocalCredential(t, fixture, secondAdmin)
	insertTestSignInSession(t, fixture, "second-session", secondAdmin, testSignInNow.Add(time.Hour))

	if err := fixture.service.Unlink(fixture.ctx, UnlinkInput{
		ActorUserID:      secondAdmin,
		SessionID:        "second-session",
		ExpectedRevision: 1,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Unlink of another user's identity error = %v, want ErrConflict", err)
	}
	if got := countTableRows(t, fixture, "company_oidc_identities"); got != 1 {
		t.Fatal("Unlink rejection removed the identity")
	}
}
