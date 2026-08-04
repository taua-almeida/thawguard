package companyoidc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

func TestCallbackStateFromRawQueryDispatchesByShapeAlone(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5A}, testSignInTokenBytes))
	cases := []struct {
		name      string
		rawQuery  string
		wantKind  CallbackStateKind
		wantState string
	}{
		{"bare canonical token is Test", "state=" + token, CallbackStateTest, token},
		{"link prefix", "state=link." + token, CallbackStateLink, "link." + token},
		{"login prefix", "state=login." + token, CallbackStateLogin, "login." + token},
		{"missing state", "code=x", CallbackStateInvalid, ""},
		{"duplicate state", "state=" + token + "&state=" + token, CallbackStateInvalid, ""},
		{"non-canonical token", "state=short", CallbackStateInvalid, ""},
		{"unknown prefix", "state=other." + token, CallbackStateInvalid, ""},
		{"prefix with truncated token", "state=link." + token[:20], CallbackStateInvalid, ""},
		{"double prefix", "state=link.link." + token, CallbackStateInvalid, ""},
		{"oversized query", "state=" + token + "&pad=" + strings.Repeat("a", testSignInMaxRawQueryBytes), CallbackStateInvalid, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, state := CallbackStateFromRawQuery(tc.rawQuery)
			if kind != tc.wantKind || state != tc.wantState {
				t.Fatalf("CallbackStateFromRawQuery = (%d, %q), want (%d, %q)", kind, state, tc.wantKind, tc.wantState)
			}
		})
	}
}

func TestStartAndCompleteLinkPersistsIdentityAndFencesFutureCallbacks(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLinkReadyFixture(t, provider)

	start := startLink(t, fixture)
	query := mustParseURL(t, start.AuthorizationURL).Query()
	for key, want := range map[string]string{
		"scope":                 "openid email",
		"response_type":         "code",
		"response_mode":         "query",
		"client_id":             protocolTestClientID,
		"redirect_uri":          testSignInRedirectURI,
		"code_challenge_method": "S256",
	} {
		if values := query[key]; len(values) != 1 || values[0] != want {
			t.Fatalf("link authorization %s = %v, want exactly %q", key, values, want)
		}
	}
	state, nonce := query.Get("state"), query.Get("nonce")
	if !canonicalPrefixedState(state, linkStatePrefix) {
		t.Fatalf("link state %q is not a canonical link.-prefixed token", state)
	}
	if !canonicalTestToken(nonce) || !canonicalTestToken(query.Get("code_challenge")) {
		t.Fatal("link authorization URL omitted canonical nonce or S256 challenge")
	}
	assertLinkTransactionCount(t, fixture, 1)

	result, err := completeLinkCallback(t, fixture, provider, start)
	if err != nil || result != TestSignInVerified {
		t.Fatalf("complete link: result=%q err=%v", result, err)
	}

	var userID, configRevision int64
	var issuer, clientID, subject, email string
	if err := fixture.database.QueryRow(`
SELECT user_id, issuer, client_id, subject, email, config_revision
FROM company_oidc_identities WHERE connection_id = 1`).Scan(
		&userID, &issuer, &clientID, &subject, &email, &configRevision,
	); err != nil {
		t.Fatal(err)
	}
	if userID != fixture.adminID || issuer != provider.server.URL+"/tenant" ||
		clientID != protocolTestClientID || subject != "private-provider-subject" ||
		email != provider.email || configRevision != 1 {
		t.Fatalf("linked identity = user %d issuer %q client %q subject %q revision %d", userID, issuer, clientID, subject, configRevision)
	}
	assertActivationState(t, fixture, false, 2)
	assertLinkTransactionCount(t, fixture, 0)
	assertTestSignInAudit(t, fixture, audit.ActionOIDCIdentityLinked, `{"revision":1}`)
	var actor int64
	if err := fixture.database.QueryRow(`
SELECT actor_user_id FROM audit_events WHERE action = ?`, audit.ActionOIDCIdentityLinked).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != fixture.adminID {
		t.Fatalf("link audit actor = %d, want %d", actor, fixture.adminID)
	}

	if got := countTableRows(t, fixture, "sessions"); got != 1 {
		t.Fatalf("sessions after link = %d, want only the local session", got)
	}
	if got := countTableRows(t, fixture, "company_oidc_sessions"); got != 0 {
		t.Fatalf("company OIDC sessions after link = %d, want 0", got)
	}
	for _, forbidden := range []string{
		state, nonce, "authorization-code", provider.accessToken,
		provider.refreshToken, provider.lastIDToken(), protocolTestClientSecret,
	} {
		assertNoDatabaseText(t, fixture, forbidden)
	}
	auditText := protocolDatabaseText(t, fixture)
	if strings.Contains(auditText, "private-provider-subject") || strings.Contains(auditText, provider.email) {
		t.Fatal("audit text contains the provider subject or email")
	}

	// The consumed transaction and bumped generation fence a replayed callback.
	if _, err := fixture.service.CompleteLink(fixture.ctx, LinkCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	}); !errors.Is(err, ErrLinkUnavailable) {
		t.Fatalf("replayed link callback error = %v, want ErrLinkUnavailable", err)
	}
}

func TestCompleteLinkSurvivesProcessRestart(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLinkReadyFixture(t, provider)
	start := startLink(t, fixture)

	restarted := NewServiceWithChecker(
		fixture.database,
		fixture.secretStore,
		NewChecker(trustedTransport(t, provider.server)),
		"http://localhost:8080",
	)
	restarted.now = func() time.Time { return testSignInNow }
	fixture.service = restarted

	result, err := completeLinkCallback(t, fixture, provider, start)
	if err != nil || result != TestSignInVerified {
		t.Fatalf("complete link after restart: result=%q err=%v", result, err)
	}
}

func TestStartLinkRequiresCurrentCredentialedAdministratorAndExactRevision(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *testing.T, fixture *serviceFixture) LinkStartInput
		wantErr error
	}{
		{
			name: "forced password change",
			mutate: func(t *testing.T, fixture *serviceFixture) LinkStartInput {
				mustExec(t, fixture, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, fixture.adminID)
				return validLinkStartInput(fixture.adminID)
			},
			wantErr: ErrLinkAuthorization,
		},
		{
			name: "missing local credential",
			mutate: func(t *testing.T, fixture *serviceFixture) LinkStartInput {
				mustExec(t, fixture, `DELETE FROM local_credentials WHERE user_id = ?`, fixture.adminID)
				return validLinkStartInput(fixture.adminID)
			},
			wantErr: ErrLinkAuthorization,
		},
		{
			name: "demoted actor",
			mutate: func(t *testing.T, fixture *serviceFixture) LinkStartInput {
				mustExec(t, fixture, `DELETE FROM user_roles WHERE user_id = ?`, fixture.adminID)
				return validLinkStartInput(fixture.adminID)
			},
			wantErr: ErrLinkAuthorization,
		},
		{
			name: "disabled actor",
			mutate: func(t *testing.T, fixture *serviceFixture) LinkStartInput {
				mustExec(t, fixture, `UPDATE users SET disabled_at = '2026-07-29T00:00:00Z' WHERE id = ?`, fixture.adminID)
				return validLinkStartInput(fixture.adminID)
			},
			wantErr: ErrLinkAuthorization,
		},
		{
			name: "unknown session",
			mutate: func(t *testing.T, fixture *serviceFixture) LinkStartInput {
				input := validLinkStartInput(fixture.adminID)
				input.SessionID = "some-other-session"
				return input
			},
			wantErr: ErrLinkAuthorization,
		},
		{
			name: "stale revision",
			mutate: func(t *testing.T, fixture *serviceFixture) LinkStartInput {
				input := validLinkStartInput(fixture.adminID)
				input.ExpectedRevision = 2
				return input
			},
			wantErr: ErrLinkUnavailable,
		},
		{
			name: "already linked",
			mutate: func(t *testing.T, fixture *serviceFixture) LinkStartInput {
				insertLinkedIdentityRow(t, fixture, fixture.adminID, 1)
				return validLinkStartInput(fixture.adminID)
			},
			wantErr: ErrLinkUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			fixture := newLinkReadyFixture(t, provider)
			input := tc.mutate(t, fixture)
			if _, err := fixture.service.StartLink(fixture.ctx, input); !errors.Is(err, tc.wantErr) {
				t.Fatalf("StartLink error = %v, want %v", err, tc.wantErr)
			}
			assertLinkTransactionCount(t, fixture, 0)
		})
	}
}

func TestCompleteLinkConsumesTransactionOnEveryFenceFailure(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(t *testing.T, fixture *serviceFixture)
		callback func(input *LinkCallbackInput)
	}{
		{
			name: "session deleted",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `DELETE FROM sessions WHERE id = ?`, testSignInSessionID)
			},
		},
		{
			name: "session expired",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE sessions SET expires_at = '2026-07-29T00:00:00Z' WHERE id = ?`, testSignInSessionID)
			},
		},
		{
			name: "callback copied into a different session",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				insertTestSignInSession(t, fixture, "second-session", fixture.adminID, testSignInNow.Add(time.Hour))
			},
			callback: func(input *LinkCallbackInput) { input.SessionID = "second-session" },
		},
		{
			name: "forced password change after initiation",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, fixture.adminID)
			},
		},
		{
			name: "actor demoted after initiation",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `DELETE FROM user_roles WHERE user_id = ?`, fixture.adminID)
			},
		},
		{
			name: "actor disabled after initiation",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE users SET disabled_at = '2026-07-29T00:00:00Z' WHERE id = ?`, fixture.adminID)
			},
		},
		{
			name: "activation generation advanced",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE company_oidc_connections SET activation_generation = activation_generation + 1 WHERE id = 1`)
			},
		},
		{
			name: "connection enabled concurrently",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				mustExec(t, fixture, `UPDATE company_oidc_connections SET enabled = 1 WHERE id = 1`)
			},
		},
		{
			name: "transaction expired",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				fixture.service.now = func() time.Time { return testSignInNow.Add(testSignInTransactionTTL + time.Second) }
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			fixture := newLinkReadyFixture(t, provider)
			start := startLink(t, fixture)
			state, _ := linkStateAndNonce(t, start)
			tokenRequestsBefore := provider.tokenRequests()
			tc.mutate(t, fixture)

			input := LinkCallbackInput{
				State:     state,
				SessionID: testSignInSessionID,
				RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
			}
			if tc.callback != nil {
				tc.callback(&input)
			}
			if _, err := fixture.service.CompleteLink(fixture.ctx, input); !errors.Is(err, ErrLinkUnavailable) {
				t.Fatalf("CompleteLink error = %v, want ErrLinkUnavailable", err)
			}
			assertLinkTransactionCount(t, fixture, 0)
			if got := countTableRows(t, fixture, "company_oidc_identities"); got != 0 {
				t.Fatalf("fence failure linked %d identities", got)
			}
			if got := provider.tokenRequests(); got != tokenRequestsBefore {
				t.Fatalf("fence failure contacted the token endpoint %d times", got-tokenRequestsBefore)
			}
			assertAuditActionCount(t, fixture, audit.ActionOIDCIdentityLinked, 0)
		})
	}
}

func TestStartLinkReplacesPriorTransactionForSameSession(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLinkReadyFixture(t, provider)
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x44, 0x55, 0x66, 0x77, 0x88, 0x99))

	first := startLink(t, fixture)
	second := startLink(t, fixture)
	assertLinkTransactionCount(t, fixture, 1)

	firstState, _ := linkStateAndNonce(t, first)
	if _, err := fixture.service.CompleteLink(fixture.ctx, LinkCallbackInput{
		State:     firstState,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {firstState}, "code": {"authorization-code"}}.Encode(),
	}); !errors.Is(err, ErrLinkUnavailable) {
		t.Fatalf("superseded link callback error = %v, want ErrLinkUnavailable", err)
	}

	result, err := completeLinkCallback(t, fixture, provider, second)
	if err != nil || result != TestSignInVerified {
		t.Fatalf("complete replacement link: result=%q err=%v", result, err)
	}
}

func TestLinkStateIsIsolatedFromTestAndLoginPurposes(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newLinkReadyFixture(t, provider)
	start := startLink(t, fixture)
	state, _ := linkStateAndNonce(t, start)
	bareToken := strings.TrimPrefix(state, linkStatePrefix)

	// The bare link token is not a Test sign-in state: the Test flow must
	// neither succeed nor consume the pending link transaction.
	if _, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     bareToken,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {bareToken}, "code": {"authorization-code"}}.Encode(),
	}); err == nil {
		t.Fatal("Test sign-in callback accepted a link token")
	}
	assertLinkTransactionCount(t, fixture, 1)

	// A login.-prefixed copy of the same token cannot claim the link
	// transaction either.
	if _, _, err := fixture.service.CompleteLogin(fixture.ctx, LoginCallbackInput{
		State:        loginStatePrefix + bareToken,
		BrowserToken: bareToken,
		RawQuery:     url.Values{"state": {loginStatePrefix + bareToken}, "code": {"authorization-code"}}.Encode(),
	}); !errors.Is(err, ErrLoginUnavailable) {
		t.Fatalf("login callback with link token error = %v, want ErrLoginUnavailable", err)
	}
	assertLinkTransactionCount(t, fixture, 1)

	// The link flow rejects bare and foreign-prefixed states outright.
	for _, badState := range []string{bareToken, "login." + bareToken, "link.notatoken"} {
		if _, err := fixture.service.CompleteLink(fixture.ctx, LinkCallbackInput{
			State:     badState,
			SessionID: testSignInSessionID,
			RawQuery:  url.Values{"state": {badState}, "code": {"authorization-code"}}.Encode(),
		}); !errors.Is(err, ErrLinkUnavailable) {
			t.Fatalf("CompleteLink(%q) error = %v, want ErrLinkUnavailable", badState, err)
		}
	}
	assertLinkTransactionCount(t, fixture, 1)

	result, err := completeLinkCallback(t, fixture, provider, start)
	if err != nil || result != TestSignInVerified {
		t.Fatalf("link callback after isolation probes: result=%q err=%v", result, err)
	}
}

func newLinkReadyFixture(t *testing.T, provider *testSignInTLSProvider) *serviceFixture {
	t.Helper()
	fixture := newProtocolServiceFixture(t, provider)
	recordVerifiedTestSignInEvidence(t, fixture, provider)
	insertCurrentLocalCredential(t, fixture, fixture.adminID)
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x44, 0x55, 0x66))
	return fixture
}

func recordVerifiedTestSignInEvidence(t *testing.T, fixture *serviceFixture, provider *testSignInTLSProvider) {
	t.Helper()
	start := startProtocolTestSignIn(t, fixture)
	query := mustParseURL(t, start.AuthorizationURL).Query()
	state, nonce := query.Get("state"), query.Get("nonce")
	provider.setNonceAndRotate(nonce)
	result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
	if err != nil || result != TestSignInVerified {
		t.Fatalf("record Test sign-in evidence: result=%q err=%v", result, err)
	}
}

func insertCurrentLocalCredential(t *testing.T, fixture *serviceFixture, userID int64) {
	t.Helper()
	mustExec(t, fixture, `
INSERT INTO local_credentials(user_id, password_hash, must_change_password, created_at, updated_at)
VALUES (?, 'test-password-hash', 0, ?, ?)`,
		userID,
		testSignInNow.Format(time.RFC3339Nano),
		testSignInNow.Format(time.RFC3339Nano),
	)
}

func insertLinkedIdentityRow(t *testing.T, fixture *serviceFixture, userID, revision int64) {
	t.Helper()
	mustExec(t, fixture, `
INSERT INTO company_oidc_identities(
  connection_id, user_id, issuer, client_id, subject, email, config_revision, linked_at
)
VALUES (1, ?, 'https://id.example.test', 'client', 'inserted-subject', 'linked@example.test', ?, ?)`,
		userID,
		revision,
		formatCompanyOIDCTime(testSignInNow),
	)
}

func validLinkStartInput(actorID int64) LinkStartInput {
	return LinkStartInput{
		ActorUserID:      actorID,
		SessionID:        testSignInSessionID,
		ExpectedRevision: 1,
		CallbackURI:      testSignInRedirectURI,
	}
}

func startLink(t *testing.T, fixture *serviceFixture) LinkStart {
	t.Helper()
	start, err := fixture.service.StartLink(fixture.ctx, validLinkStartInput(fixture.adminID))
	if err != nil {
		t.Fatal(err)
	}
	return start
}

func linkStateAndNonce(t *testing.T, start LinkStart) (string, string) {
	t.Helper()
	query := mustParseURL(t, start.AuthorizationURL).Query()
	return query.Get("state"), query.Get("nonce")
}

func completeLinkCallback(
	t *testing.T,
	fixture *serviceFixture,
	provider *testSignInTLSProvider,
	start LinkStart,
) (TestSignInResultCode, error) {
	t.Helper()
	state, nonce := linkStateAndNonce(t, start)
	provider.setNonceAndRotate(nonce)
	return fixture.service.CompleteLink(fixture.ctx, LinkCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
}

func mustExec(t *testing.T, fixture *serviceFixture, query string, args ...any) {
	t.Helper()
	if _, err := fixture.database.ExecContext(fixture.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func assertLinkTransactionCount(t *testing.T, fixture *serviceFixture, want int) {
	t.Helper()
	if got := countTableRows(t, fixture, "company_oidc_link_transactions"); got != want {
		t.Fatalf("link transaction count = %d, want %d", got, want)
	}
}

func assertActivationState(t *testing.T, fixture *serviceFixture, wantEnabled bool, wantGeneration int64) {
	t.Helper()
	var enabled, generation int64
	if err := fixture.database.QueryRow(`
SELECT enabled, activation_generation FROM company_oidc_connections WHERE id = 1`).Scan(&enabled, &generation); err != nil {
		t.Fatal(err)
	}
	if (enabled == 1) != wantEnabled || generation != wantGeneration {
		t.Fatalf("activation state = enabled %d generation %d, want enabled %t generation %d", enabled, generation, wantEnabled, wantGeneration)
	}
}
