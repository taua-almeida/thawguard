package companyoidc

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

func newLoginReadyFixture(t *testing.T, provider *testSignInTLSProvider) *serviceFixture {
	t.Helper()
	fixture := newEnableReadyFixture(t, provider)
	enableCompanyLogin(t, fixture)
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x71, 0x72, 0x73, 0x74))
	return fixture
}

func startLoginTransaction(t *testing.T, fixture *serviceFixture) LoginStart {
	t.Helper()
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x71, 0x72, 0x73, 0x74))
	start, err := fixture.service.StartLogin(fixture.ctx, LoginStartInput{CallbackURI: testSignInRedirectURI})
	if err != nil {
		t.Fatal(err)
	}
	return start
}

func completeLoginCallback(
	t *testing.T,
	fixture *serviceFixture,
	provider *testSignInTLSProvider,
	start LoginStart,
) (LoginCompletion, TestSignInResultCode, error) {
	t.Helper()
	query := mustParseURL(t, start.AuthorizationURL).Query()
	state, nonce := query.Get("state"), query.Get("nonce")
	provider.setNonceAndRotate(nonce)
	return fixture.service.CompleteLogin(fixture.ctx, LoginCallbackInput{
		State:        state,
		BrowserToken: start.BrowserToken,
		RawQuery:     url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
}

func assertLoginTransactionCount(t *testing.T, fixture *serviceFixture, want int) {
	t.Helper()
	if got := countTableRows(t, fixture, "company_oidc_login_transactions"); got != want {
		t.Fatalf("login transaction count = %d, want %d", got, want)
	}
}

func TestStartAndCompleteLoginResolvesLinkedAdministratorWithoutCreatingSessions(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLoginReadyFixture(t, provider)

	start := startLoginTransaction(t, fixture)
	query := mustParseURL(t, start.AuthorizationURL).Query()
	state := query.Get("state")
	if !canonicalPrefixedState(state, loginStatePrefix) {
		t.Fatalf("login state %q is not a canonical login.-prefixed token", state)
	}
	if !canonicalTestToken(start.BrowserToken) {
		t.Fatal("StartLogin returned a non-canonical browser token")
	}
	if strings.Contains(start.AuthorizationURL, start.BrowserToken) {
		t.Fatal("browser token leaked into the authorization URL")
	}
	if got := query.Get("scope"); got != "openid email" {
		t.Fatalf("login scope = %q, want %q", got, "openid email")
	}
	assertLoginTransactionCount(t, fixture, 1)

	sessionsBefore := countTableRows(t, fixture, "sessions")
	completion, result, err := completeLoginCallback(t, fixture, provider, start)
	if err != nil || result != TestSignInVerified {
		t.Fatalf("complete login: result=%q err=%v", result, err)
	}
	if completion.UserID != fixture.adminID || completion.ConnectionRevision != 1 || completion.ActivationGeneration != 3 {
		t.Fatalf("login completion = %+v, want user %d revision 1 generation 3", completion, fixture.adminID)
	}
	assertLoginTransactionCount(t, fixture, 0)
	if got := countTableRows(t, fixture, "sessions"); got != sessionsBefore {
		t.Fatalf("CompleteLogin changed session count from %d to %d", sessionsBefore, got)
	}
	if got := countTableRows(t, fixture, "company_oidc_sessions"); got != 0 {
		t.Fatalf("CompleteLogin created %d company OIDC session rows", got)
	}
	// No per-login audit event exists.
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionEnabled, 1)
	for _, forbidden := range []string{
		state, start.BrowserToken, "authorization-code",
		provider.accessToken, provider.refreshToken, provider.lastIDToken(), protocolTestClientSecret,
	} {
		assertNoDatabaseText(t, fixture, forbidden)
	}

	// A replayed callback fails: the transaction was consumed.
	if _, _, err := fixture.service.CompleteLogin(fixture.ctx, LoginCallbackInput{
		State:        state,
		BrowserToken: start.BrowserToken,
		RawQuery:     url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	}); !errors.Is(err, ErrLoginUnavailable) {
		t.Fatalf("replayed login callback error = %v, want ErrLoginUnavailable", err)
	}
}

func TestStartLoginRequiresEnabledConnection(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newEnableReadyFixture(t, provider)

	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x71, 0x72, 0x73, 0x74))
	if _, err := fixture.service.StartLogin(fixture.ctx, LoginStartInput{CallbackURI: testSignInRedirectURI}); !errors.Is(err, ErrLoginUnavailable) {
		t.Fatalf("StartLogin while disabled error = %v, want ErrLoginUnavailable", err)
	}
	assertLoginTransactionCount(t, fixture, 0)
}

func TestLoginAvailableRequiresOperationalPreconditions(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(t *testing.T, fixture *serviceFixture)
		available bool
	}{
		{
			name:      "operational connection",
			available: true,
		},
		{
			name: "connection disabled",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE company_oidc_connections SET enabled = 0 WHERE id = 1`)
			},
		},
		{
			name: "linked administrator demoted",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `DELETE FROM user_roles WHERE user_id = ?`, fixture.adminID)
			},
		},
		{
			name: "linked user disabled",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE users SET disabled_at = '2026-07-29T00:00:00Z' WHERE id = ?`, fixture.adminID)
			},
		},
		{
			name: "forced password change",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, fixture.adminID)
			},
		},
		{
			name: "missing linked identity",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `DELETE FROM company_oidc_identities`)
			},
		},
		{
			name: "identity linked at a stale revision",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE company_oidc_identities SET config_revision = 2 WHERE connection_id = 1`)
			},
		},
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			fixture := newLoginReadyFixture(t, provider)
			if tc.mutate != nil {
				tc.mutate(t, fixture)
			}
			discoveryBefore := provider.discoveryRequests()

			if got := fixture.service.LoginAvailable(fixture.ctx); got != tc.available {
				t.Fatalf("LoginAvailable = %v, want %v", got, tc.available)
			}

			if got := provider.discoveryRequests(); got != discoveryBefore {
				t.Fatalf("availability check contacted the provider %d times", got-discoveryBefore)
			}
			// The check never mutates state; in particular a runtime holding the
			// wrong encryption key must not disable the connection.
			if got := countTableRows(t, fixture, "company_oidc_connections"); got != 1 {
				t.Fatalf("connection row count = %d after availability check", got)
			}
			var enabled int64
			if err := fixture.database.QueryRowContext(fixture.ctx, `SELECT enabled FROM company_oidc_connections WHERE id = 1`).Scan(&enabled); err != nil {
				t.Fatal(err)
			}
			if tc.name == "wrong encryption key" && enabled != 1 {
				t.Fatal("availability check with the wrong key disabled the connection")
			}
		})
	}
}

func TestStartLoginRejectsIneligibleLinkedAdministratorWithoutDiscovery(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLoginReadyFixture(t, provider)
	mustExec(t, fixture, `DELETE FROM user_roles WHERE user_id = ?`, fixture.adminID)
	discoveryBefore := provider.discoveryRequests()

	if _, err := fixture.service.StartLogin(fixture.ctx, LoginStartInput{CallbackURI: testSignInRedirectURI}); !errors.Is(err, ErrLoginUnavailable) {
		t.Fatalf("StartLogin for a demoted linked Administrator error = %v, want ErrLoginUnavailable", err)
	}
	if got := provider.discoveryRequests(); got != discoveryBefore {
		t.Fatalf("unavailable StartLogin contacted the provider %d times", got-discoveryBefore)
	}
	assertLoginTransactionCount(t, fixture, 0)
}

func TestStartLoginHonorsLiveTransactionCap(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLoginReadyFixture(t, provider)

	insert := `
INSERT INTO company_oidc_login_transactions(
  state_digest, connection_id, config_revision, activation_generation,
  browser_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
)
VALUES (?, 1, 1, 3, ?, ?, x'01', ?, ?, ?, ?, ?)`
	for i := range loginMaxLiveTransactions {
		stateDigest := testSignInDigest(loginStateDigestPurpose, strings.Repeat("s", 10)+string(rune('a'+i%26))+strings.Repeat("x", i/26))
		browserDigest := testSignInDigest(loginBrowserDigestPurpose, strings.Repeat("b", 10)+string(rune('a'+i%26))+strings.Repeat("x", i/26))
		nonceDigest := testSignInDigest(loginNonceDigestPurpose, "nonce")
		mustExec(t, fixture, insert,
			stateDigest[:], browserDigest[:], nonceDigest[:],
			testSignInTokenEndpoint, testSignInJWKSURI, testSignInRedirectURI,
			formatCompanyOIDCTime(testSignInNow),
			formatCompanyOIDCTime(testSignInNow.Add(testSignInTransactionTTL)),
		)
	}
	assertLoginTransactionCount(t, fixture, loginMaxLiveTransactions)

	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x71, 0x72, 0x73, 0x74))
	discoveryBefore := provider.discoveryRequests()
	if _, err := fixture.service.StartLogin(fixture.ctx, LoginStartInput{CallbackURI: testSignInRedirectURI}); !errors.Is(err, ErrLoginUnavailable) {
		t.Fatalf("StartLogin at the live-transaction cap error = %v, want ErrLoginUnavailable", err)
	}
	if got := provider.discoveryRequests(); got != discoveryBefore {
		t.Fatalf("StartLogin at the live-transaction cap contacted the provider %d times", got-discoveryBefore)
	}
	assertLoginTransactionCount(t, fixture, loginMaxLiveTransactions)
}

func TestCompleteLoginConsumesTransactionOnEveryFenceFailure(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(t *testing.T, fixture *serviceFixture)
		callback func(input *LoginCallbackInput)
	}{
		{
			name: "missing browser token",
			callback: func(input *LoginCallbackInput) {
				input.BrowserToken = ""
			},
		},
		{
			name: "wrong browser token",
			callback: func(input *LoginCallbackInput) {
				input.BrowserToken = strings.Repeat("A", 43)
			},
		},
		{
			name: "transaction expired",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				fixture.service.now = func() time.Time { return testSignInNow.Add(testSignInTransactionTTL + time.Second) }
			},
		},
		{
			name: "connection disabled after initiation",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE company_oidc_connections SET enabled = 0 WHERE id = 1`)
			},
		},
		{
			name: "activation generation advanced",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE company_oidc_connections SET activation_generation = activation_generation + 1 WHERE id = 1`)
			},
		},
		{
			name: "identity unlinked after initiation",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `DELETE FROM company_oidc_identities`)
			},
		},
		{
			name: "identity relinked at a different revision",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE company_oidc_identities SET config_revision = 2 WHERE connection_id = 1`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			fixture := newLoginReadyFixture(t, provider)
			start := startLoginTransaction(t, fixture)
			state := mustParseURL(t, start.AuthorizationURL).Query().Get("state")
			tokenRequestsBefore := provider.tokenRequests()
			if tc.mutate != nil {
				tc.mutate(t, fixture)
			}

			input := LoginCallbackInput{
				State:        state,
				BrowserToken: start.BrowserToken,
				RawQuery:     url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
			}
			if tc.callback != nil {
				tc.callback(&input)
			}
			if _, _, err := fixture.service.CompleteLogin(fixture.ctx, input); !errors.Is(err, ErrLoginUnavailable) {
				t.Fatalf("CompleteLogin error = %v, want ErrLoginUnavailable", err)
			}
			assertLoginTransactionCount(t, fixture, 0)
			if got := provider.tokenRequests(); got != tokenRequestsBefore {
				t.Fatalf("fence failure contacted the token endpoint %d times", got-tokenRequestsBefore)
			}
		})
	}
}

func TestCompleteLoginRejectsWrongProviderSubject(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLoginReadyFixture(t, provider)

	mustExec(t, fixture, `UPDATE company_oidc_identities SET subject = 'different-subject' WHERE connection_id = 1`)

	start := startLoginTransaction(t, fixture)
	completion, result, err := completeLoginCallback(t, fixture, provider, start)
	if err != nil {
		t.Fatal(err)
	}
	if result != TestSignInProviderInvalid {
		t.Fatalf("wrong-subject login result = %q, want %q", result, TestSignInProviderInvalid)
	}
	if completion != (LoginCompletion{}) {
		t.Fatalf("wrong-subject login resolved a user: %+v", completion)
	}
	assertLoginTransactionCount(t, fixture, 0)
	// The provider-presented subject must not be persisted anywhere after the
	// mismatch; only the stored identity subject remains.
	assertNoDatabaseText(t, fixture, "private-provider-subject")
}

func TestCompleteLoginRejectsStaleCallbackAfterDisable(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLoginReadyFixture(t, provider)
	start := startLoginTransaction(t, fixture)
	state := mustParseURL(t, start.AuthorizationURL).Query().Get("state")

	if err := fixture.service.Disable(fixture.ctx, DisableInput{ActorUserID: fixture.adminID, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	// Disable already deleted every pending login transaction.
	assertLoginTransactionCount(t, fixture, 0)

	if _, _, err := fixture.service.CompleteLogin(fixture.ctx, LoginCallbackInput{
		State:        state,
		BrowserToken: start.BrowserToken,
		RawQuery:     url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	}); !errors.Is(err, ErrLoginUnavailable) {
		t.Fatalf("post-Disable login callback error = %v, want ErrLoginUnavailable", err)
	}
}

func TestLoginStateIsIsolatedFromLinkAndTestPurposes(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLoginReadyFixture(t, provider)
	start := startLoginTransaction(t, fixture)
	state := mustParseURL(t, start.AuthorizationURL).Query().Get("state")
	bareToken := strings.TrimPrefix(state, loginStatePrefix)

	if _, err := fixture.service.CompleteLink(fixture.ctx, LinkCallbackInput{
		State:     linkStatePrefix + bareToken,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {linkStatePrefix + bareToken}, "code": {"authorization-code"}}.Encode(),
	}); !errors.Is(err, ErrLinkUnavailable) {
		t.Fatalf("link callback with login token error = %v, want ErrLinkUnavailable", err)
	}
	if _, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     bareToken,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {bareToken}, "code": {"authorization-code"}}.Encode(),
	}); err == nil {
		t.Fatal("Test sign-in callback accepted a login token")
	}
	assertLoginTransactionCount(t, fixture, 1)

	completion, result, err := completeLoginCallback(t, fixture, provider, start)
	if err != nil || result != TestSignInVerified || completion.UserID != fixture.adminID {
		t.Fatalf("login after isolation probes: completion=%+v result=%q err=%v", completion, result, err)
	}
}
