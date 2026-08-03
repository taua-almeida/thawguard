package companyoidc

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

func TestTestSignInDiscoveryCompatibilityIsNarrowAndDefaultsToBasic(t *testing.T) {
	document := validDiscoveryDocument("https://id.example.test", "https://id.example.test/jwks")
	document["scopes_supported"] = []string{"openid", "email"}
	if !testSignInCompatibleDiscoveryObject(t, document) {
		t.Fatal("absent token auth methods should default to client_secret_basic")
	}

	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "openid scope missing", mutate: func(value map[string]any) { value["scopes_supported"] = []string{"profile", "email"} }},
		{name: "email scope missing", mutate: func(value map[string]any) { value["scopes_supported"] = []string{"openid"} }},
		{name: "basic auth missing", mutate: func(value map[string]any) {
			value["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
		}},
		{name: "query response mode missing", mutate: func(value map[string]any) { value["response_modes_supported"] = []string{"form_post"} }},
		{name: "S256 missing", mutate: func(value map[string]any) { value["code_challenge_methods_supported"] = []string{"plain"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := validDiscoveryDocument("https://id.example.test", "https://id.example.test/jwks")
			candidate["scopes_supported"] = []string{"openid", "email"}
			candidate["token_endpoint_auth_methods_supported"] = []string{"client_secret_basic"}
			candidate["response_modes_supported"] = []string{"query"}
			candidate["code_challenge_methods_supported"] = []string{"S256"}
			tc.mutate(candidate)
			if testSignInCompatibleDiscoveryObject(t, candidate) {
				t.Fatal("accepted incompatible Test sign-in discovery metadata")
			}
		})
	}
}

func TestStartAndCompleteTestSignInPinsProtocolAndVerifiesFreshKey(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	provider.networkHook = func() error {
		_, err := fixture.database.Exec(`UPDATE users SET updated_at = updated_at WHERE id = ?`, fixture.adminID)
		return err
	}

	start := startProtocolTestSignIn(t, fixture)
	authorizationURL, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := authorizationURL.Query()
	for key, want := range map[string]string{
		"scope":                 "openid email",
		"response_type":         "code",
		"response_mode":         "query",
		"client_id":             protocolTestClientID,
		"redirect_uri":          testSignInRedirectURI,
		"code_challenge_method": "S256",
	} {
		if values := query[key]; len(values) != 1 || values[0] != want {
			t.Fatalf("authorization %s = %v, want exactly %q", key, values, want)
		}
	}
	if values := query["tenant"]; !slices.Equal(values, []string{"blue", "green"}) {
		t.Fatalf("unrelated authorization query values = %v", values)
	}
	state, nonce, challenge := query.Get("state"), query.Get("nonce"), query.Get("code_challenge")
	if !canonicalTestToken(state) || !canonicalTestToken(nonce) || !canonicalTestToken(challenge) {
		t.Fatalf("authorization URL omitted canonical state, nonce, or S256 challenge: %q %q %q", state, nonce, challenge)
	}
	provider.setNonceAndRotate(nonce)
	provider.setAdvertisedTokenEndpoint(provider.server.URL + "/secret-sink")

	result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}, "extension": {"ignored"}}.Encode(),
	})
	if err != nil || result != TestSignInVerified {
		t.Fatalf("complete Test sign-in: result=%q err=%v", result, err)
	}
	if provider.tokenRequests() != 1 || provider.secretSinkRequests() != 0 {
		t.Fatalf("pinned endpoint requests: token=%d drifted=%d", provider.tokenRequests(), provider.secretSinkRequests())
	}
	if provider.discoveryRequests() != 2 || provider.jwksRequests() != 2 {
		t.Fatalf("provider requests: discovery=%d jwks=%d, want setup+start discovery and setup+callback JWKS", provider.discoveryRequests(), provider.jwksRequests())
	}
	assertTestSignInAudit(t, fixture, audit.ActionOIDCConnectionTestSignInClaimed, `{"revision":1,"binding":"exact_session","authority":"current_administrator"}`)
	assertTestSignInAudit(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, `{"revision":1,"result_code":"verified"}`)
	assertTestSignInTransactionCount(t, fixture.database, 0)

	databaseText := protocolDatabaseText(t, fixture)
	for _, forbidden := range []string{
		"authorization-code",
		provider.accessToken,
		provider.refreshToken,
		provider.lastIDToken(),
		provider.email,
		state,
		nonce,
		protocolTestClientSecret,
	} {
		if forbidden != "" && strings.Contains(databaseText, forbidden) {
			t.Fatalf("database or audit text contains forbidden protocol material")
		}
	}
}

func TestAuthorizationEndpointOwnedQueryCollisionsFailBeforeTransaction(t *testing.T) {
	for _, owned := range []string{
		"scope", "response_type", "response_mode", "client_id", "redirect_uri",
		"state", "nonce", "code_challenge", "code_challenge_method",
	} {
		t.Run(owned, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			provider.authorizationQuery = url.Values{owned: {"provider-value"}}.Encode()
			fixture := newProtocolServiceFixture(t, provider)
			_, err := fixture.service.StartTestSignIn(fixture.ctx, validProtocolStartInput(fixture.adminID))
			if !errors.Is(err, ErrTestProviderInvalid) {
				t.Fatalf("collision result = %v", err)
			}
			assertTestSignInTransactionCount(t, fixture.database, 0)
		})
	}
}

func TestTestSignInProviderDenialAndMalformedResponseCompleteWithoutTokenExchange(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  func(string) string
		want TestSignInResultCode
	}{
		{
			name: "provider denial",
			raw: func(state string) string {
				return url.Values{"state": {state}, "error": {"access_denied"}}.Encode()
			},
			want: TestSignInProviderDenied,
		},
		{
			name: "duplicate code after claim",
			raw: func(state string) string {
				return "state=" + state + "&code=one&code=two"
			},
			want: TestSignInProviderInvalid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			fixture := newProtocolServiceFixture(t, provider)
			start := startProtocolTestSignIn(t, fixture)
			state, ok := TestSignInStateFromRawQuery(mustParseURL(t, start.AuthorizationURL).RawQuery)
			if !ok {
				t.Fatal("authorization URL has no canonical state")
			}
			result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
				State:     state,
				SessionID: testSignInSessionID,
				RawQuery:  tc.raw(state),
			})
			if err != nil || result != tc.want {
				t.Fatalf("result=%q err=%v, want %q", result, err, tc.want)
			}
			if provider.tokenRequests() != 0 {
				t.Fatal("provider response without one valid code triggered token exchange")
			}
			assertTestSignInAudit(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted,
				`{"revision":1,"result_code":"`+string(tc.want)+`"}`)
		})
	}
}

func TestTestSignInSecretFailureMapsToConfigurationUnavailable(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	start := startProtocolTestSignIn(t, fixture)
	authorizationURL := mustParseURL(t, start.AuthorizationURL)
	state, nonce := authorizationURL.Query().Get("state"), authorizationURL.Query().Get("nonce")
	provider.setNonceAndRotate(nonce)
	fixture.service.secrets = failingDecryptStore{err: errors.New("secret decryption canary")}

	result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
	if err != nil || result != TestSignInConfigurationUnavailable {
		t.Fatalf("result=%q err=%v", result, err)
	}
	if provider.tokenRequests() != 0 {
		t.Fatal("secret decryption failure triggered token exchange")
	}
	assertTestSignInAudit(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted,
		`{"revision":1,"result_code":"configuration_unavailable"}`)
}

func TestTestSignInFinalFenceLeavesClaimedWithoutCompleted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*serviceFixture) error
	}{
		{
			name: "Administrator authority lost",
			mutate: func(fixture *serviceFixture) error {
				_, err := fixture.database.Exec(`DELETE FROM user_roles WHERE user_id = ? AND role = 'admin'`, fixture.adminID)
				return err
			},
		},
		{
			name: "exact session lost",
			mutate: func(fixture *serviceFixture) error {
				_, err := fixture.database.Exec(`DELETE FROM sessions WHERE id = ?`, testSignInSessionID)
				return err
			},
		},
		{
			name: "Draft revision changed",
			mutate: func(fixture *serviceFixture) error {
				_, err := fixture.database.Exec(`UPDATE company_oidc_connections SET revision = revision + 1 WHERE id = 1`)
				return err
			},
		},
		{
			name: "setup evidence lost",
			mutate: func(fixture *serviceFixture) error {
				_, err := fixture.database.Exec(`DELETE FROM company_oidc_setup_checks WHERE connection_id = 1`)
				return err
			},
		},
		{
			name: "same-revision allowed domain replaced",
			mutate: func(fixture *serviceFixture) error {
				_, err := fixture.database.Exec(`UPDATE company_oidc_allowed_domains SET domain = 'changed.test' WHERE connection_id = 1`)
				return err
			},
		},
		{
			name: "same-revision allowed domain malformed",
			mutate: func(fixture *serviceFixture) error {
				_, err := fixture.database.Exec(`UPDATE company_oidc_allowed_domains SET domain = 'bad_domain' WHERE connection_id = 1`)
				return err
			},
		},
		{
			name: "same-revision allowed domains removed",
			mutate: func(fixture *serviceFixture) error {
				_, err := fixture.database.Exec(`DELETE FROM company_oidc_allowed_domains WHERE connection_id = 1`)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSignInTLSProvider(t)
			fixture := newProtocolServiceFixture(t, provider)
			start := startProtocolTestSignIn(t, fixture)
			authorizationURL := mustParseURL(t, start.AuthorizationURL)
			state, nonce := authorizationURL.Query().Get("state"), authorizationURL.Query().Get("nonce")
			provider.setNonceAndRotate(nonce)
			provider.networkHook = func() error { return tc.mutate(fixture) }

			result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
				State:     state,
				SessionID: testSignInSessionID,
				RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
			})
			if result != "" || !errors.Is(err, ErrTestTransactionUnavailable) {
				t.Fatalf("final fence result=%q err=%v", result, err)
			}
			assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInClaimed, 1)
			assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 0)
			assertTestSignInTransactionCount(t, fixture.database, 0)
		})
	}
}

func TestTestSignInClaimCommitUncertaintyStopsBeforeProviderWork(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	start := startProtocolTestSignIn(t, fixture)
	authorizationURL := mustParseURL(t, start.AuthorizationURL)
	state := authorizationURL.Query().Get("state")
	if _, err := fixture.database.Exec(`
CREATE TABLE oidc_test_claim_parent (id INTEGER PRIMARY KEY);
CREATE TABLE oidc_test_claim_child (
  id INTEGER PRIMARY KEY,
  parent_id INTEGER NOT NULL REFERENCES oidc_test_claim_parent(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER fail_oidc_test_claim_commit
AFTER INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.test_sign_in_claimed'
BEGIN
  INSERT INTO oidc_test_claim_child(parent_id) VALUES (999);
END;`); err != nil {
		t.Fatal(err)
	}

	_, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
	if !errors.Is(err, ErrTestTransactionOutcomeUnknown) {
		t.Fatalf("claim commit result = %v", err)
	}
	if provider.tokenRequests() != 0 || provider.jwksRequests() != 1 {
		t.Fatalf("provider work continued after uncertain claim: token=%d jwks=%d", provider.tokenRequests(), provider.jwksRequests())
	}
}

func TestTestSignInCompletionCommitUncertaintyReturnsNoTerminalResult(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	start := startProtocolTestSignIn(t, fixture)
	authorizationURL := mustParseURL(t, start.AuthorizationURL)
	state, nonce := authorizationURL.Query().Get("state"), authorizationURL.Query().Get("nonce")
	provider.setNonceAndRotate(nonce)
	if _, err := fixture.database.Exec(`
CREATE TABLE oidc_test_complete_parent (id INTEGER PRIMARY KEY);
CREATE TABLE oidc_test_complete_child (
  id INTEGER PRIMARY KEY,
  parent_id INTEGER NOT NULL REFERENCES oidc_test_complete_parent(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER fail_oidc_test_complete_commit
AFTER INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.test_sign_in_completed'
BEGIN
  INSERT INTO oidc_test_complete_child(parent_id) VALUES (999);
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
	if provider.tokenRequests() != 1 || provider.jwksRequests() != 2 {
		t.Fatalf("provider work was not completed before final commit: token=%d jwks=%d", provider.tokenRequests(), provider.jwksRequests())
	}
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInClaimed, 1)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 0)
}

func TestTestSignInCrashTruthAllowsClaimedWithoutCompleted(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	start := startProtocolTestSignIn(t, fixture)
	state := mustParseURL(t, start.AuthorizationURL).Query().Get("state")
	claim, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
		State:     state,
		SessionID: testSignInSessionID,
	})
	if err != nil || claim.configRevision != 1 {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInClaimed, 1)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 0)
	assertTestSignInTransactionCount(t, fixture.database, 0)
}

func TestStartTestSignInRequiresAdvertisedEmailScopeWhileSetupCheckPasses(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	provider.advertisedScopes = []string{"openid"}
	fixture := newProtocolServiceFixture(t, provider)

	_, err := fixture.service.StartTestSignIn(fixture.ctx, validProtocolStartInput(fixture.adminID))
	if !errors.Is(err, ErrTestProviderInvalid) {
		t.Fatalf("start without advertised email scope = %v", err)
	}
	assertTestSignInTransactionCount(t, fixture.database, 0)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInClaimed, 0)
}

func TestTestSignInEmailOutsideAllowedDomainsMapsToProviderInvalidAndPreservesEvidence(t *testing.T) {
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

	provider.setEmail("email-canary-7f3a9@unlisted.test")
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x44, 0x55, 0x66))
	retry := startProtocolTestSignIn(t, fixture)
	retryURL := mustParseURL(t, retry.AuthorizationURL)
	retryState, retryNonce := retryURL.Query().Get("state"), retryURL.Query().Get("nonce")
	provider.setNonceAndRotate(retryNonce)
	result, err = fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     retryState,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {retryState}, "code": {"authorization-code"}}.Encode(),
	})
	if err != nil || result != TestSignInProviderInvalid {
		t.Fatalf("wrong-domain Test sign-in: result=%q err=%v", result, err)
	}
	if provider.tokenRequests() != 2 {
		t.Fatalf("token requests = %d, want both runs to exchange the code", provider.tokenRequests())
	}

	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("current connection: found=%v err=%v", found, err)
	}
	if connection.TestSignInEvidence == nil ||
		connection.TestSignInEvidence.ConfigRevision != 1 ||
		!connection.TestSignInEvidence.VerifiedAt.Equal(testSignInNow) {
		t.Fatalf("wrong-domain retest changed evidence: %+v", connection.TestSignInEvidence)
	}
}

func TestTestSignInAcceptsMixedCaseEmailAcrossMultipleAllowedDomains(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	provider.domains = []string{"corp.example.test", "example.test"}
	provider.email = "Person@EXAMPLE.Test"
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
		t.Fatalf("multi-domain mixed-case Test sign-in: result=%q err=%v", result, err)
	}
	assertTestSignInAudit(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, `{"revision":1,"result_code":"verified"}`)
}

func TestTestSignInClaimConsumesTransactionWhenStoredDomainsMalformed(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	start := startProtocolTestSignIn(t, fixture)
	state := mustParseURL(t, start.AuthorizationURL).Query().Get("state")
	if _, err := fixture.database.Exec(`UPDATE company_oidc_allowed_domains SET domain = 'bad_domain' WHERE connection_id = 1`); err != nil {
		t.Fatal(err)
	}

	result, err := fixture.service.CompleteTestSignIn(fixture.ctx, TestSignInCallbackInput{
		State:     state,
		SessionID: testSignInSessionID,
		RawQuery:  url.Values{"state": {state}, "code": {"authorization-code"}}.Encode(),
	})
	if result != "" || !errors.Is(err, ErrTestTransactionUnavailable) {
		t.Fatalf("claim with malformed stored domains: result=%q err=%v", result, err)
	}
	if provider.tokenRequests() != 0 {
		t.Fatal("malformed stored domains still triggered token exchange")
	}
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInClaimed, 0)
	assertAuditActionCount(t, fixture, audit.ActionOIDCConnectionTestSignInCompleted, 0)
	assertTestSignInTransactionCount(t, fixture.database, 0)
}

func TestVerifiedTestSignInPersistsNoEmailIdentityOrSession(t *testing.T) {
	provider := newTestSignInTLSProvider(t)
	fixture := newProtocolServiceFixture(t, provider)
	usersBefore := countTableRows(t, fixture, "users")
	sessionsBefore := countTableRows(t, fixture, "sessions")
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

	if got := countTableRows(t, fixture, "users"); got != usersBefore {
		t.Fatalf("users = %d, want unchanged %d", got, usersBefore)
	}
	if got := countTableRows(t, fixture, "sessions"); got != sessionsBefore {
		t.Fatalf("sessions = %d, want unchanged %d", got, sessionsBefore)
	}
	var connectionID, revision int64
	var verifiedAt string
	if err := fixture.database.QueryRow(`
SELECT connection_id, config_revision, verified_at FROM company_oidc_test_sign_in_evidence`).Scan(&connectionID, &revision, &verifiedAt); err != nil {
		t.Fatal(err)
	}
	if connectionID != 1 || revision != 1 || verifiedAt != formatCompanyOIDCTime(testSignInNow) {
		t.Fatalf("evidence = (%d, %d, %q), want only the revision and writer-owned timestamp", connectionID, revision, verifiedAt)
	}
	assertNoDatabaseText(t, fixture, "email-canary-7f3a9")
}

func TestAuthorizationResponseShapeAndProviderErrorMapping(t *testing.T) {
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, testSignInTokenBytes))
	for _, tc := range []struct {
		name      string
		raw       string
		valid     bool
		wantCode  string
		wantError TestSignInResultCode
	}{
		{name: "code", raw: url.Values{"state": {state}, "code": {"code"}}.Encode(), valid: true, wantCode: "code"},
		{name: "denied", raw: url.Values{"state": {state}, "error": {"access_denied"}}.Encode(), valid: true, wantError: TestSignInProviderDenied},
		{name: "temporary", raw: url.Values{"state": {state}, "error": {"temporarily_unavailable"}}.Encode(), valid: true, wantError: TestSignInProviderUnavailable},
		{name: "unknown error", raw: url.Values{"state": {state}, "error": {"extension_error"}}.Encode(), valid: true, wantError: TestSignInProviderInvalid},
		{name: "unknown extension ignored", raw: url.Values{"state": {state}, "error": {"login_required"}, "extension": {"one", "two"}}.Encode(), valid: true, wantError: TestSignInProviderDenied},
		{name: "code and error", raw: url.Values{"state": {state}, "code": {"code"}, "error": {"access_denied"}}.Encode()},
		{name: "duplicate code", raw: "state=" + state + "&code=one&code=two"},
		{name: "empty code", raw: url.Values{"state": {state}, "code": {""}}.Encode()},
		{name: "control error", raw: url.Values{"state": {state}, "error": {"bad\nerror"}}.Encode()},
		{name: "malformed known value", raw: "state=" + state + "&code=%ZZ"},
		{name: "description with code", raw: url.Values{"state": {state}, "code": {"code"}, "error_description": {"not allowed"}}.Encode()},
		{name: "missing terminal", raw: url.Values{"state": {state}, "extension": {"value"}}.Encode()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, valid := parseAuthorizationResponse(tc.raw, state)
			if valid != tc.valid {
				t.Fatalf("valid = %v, want %v", valid, tc.valid)
			}
			if !valid {
				return
			}
			if response.code != tc.wantCode {
				t.Fatalf("code = %q, want %q", response.code, tc.wantCode)
			}
			if response.providerError != "" && providerAuthorizationErrorResult(response.providerError) != tc.wantError {
				t.Fatalf("provider error mapping = %q", providerAuthorizationErrorResult(response.providerError))
			}
		})
	}
}

func TestStateExtractionDoesNotParseResponseShapeBeforeClaim(t *testing.T) {
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, testSignInTokenBytes))
	for _, raw := range []string{
		"state=" + state + "&code=%ZZ",
		"state=" + state + "&code=one&code=two&error=access_denied",
		"state=" + state + "&error_description=%ZZ&extension=ignored",
	} {
		got, ok := TestSignInStateFromRawQuery(raw)
		if !ok || got != state {
			t.Fatalf("state extraction parsed post-claim fields for %q: state=%q ok=%v", raw, got, ok)
		}
	}
}

func TestClientSecretBasicUsesIndependentOAuthFormEncoding(t *testing.T) {
	const clientID = "client id:雪+%&"
	secret := []byte("s e:c%r+e&t雪")
	header := clientSecretBasic(clientID, secret)
	if !strings.HasPrefix(header, "Basic ") {
		t.Fatalf("authorization header = %q", header)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		t.Fatal(err)
	}
	want := url.QueryEscape(clientID) + ":" + url.QueryEscape(string(secret))
	if string(decoded) != want {
		t.Fatalf("decoded Basic credentials = %q, want %q", decoded, want)
	}
	if strings.Contains(strings.TrimPrefix(header, "Basic "), "-") || strings.Contains(strings.TrimPrefix(header, "Basic "), "_") {
		t.Fatal("Basic credentials used base64url alphabet")
	}
}

func TestTokenExchangeTotalErrorMappingAndRequestShape(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		transport   error
		readFailure bool
		want        TestSignInResultCode
	}{
		{name: "network", transport: errors.New("network canary"), want: TestSignInProviderUnavailable},
		{name: "read failure", status: 200, contentType: "application/json", readFailure: true, want: TestSignInProviderUnavailable},
		{name: "invalid client 400", status: 400, contentType: "application/json", body: `{"error":"invalid_client"}`, want: TestSignInConfigurationUnavailable},
		{name: "invalid client 401", status: 401, contentType: "application/json", body: `{"error":"invalid_client"}`, want: TestSignInConfigurationUnavailable},
		{name: "invalid client precedes 5xx", status: 503, contentType: "application/json", body: `{"error":"invalid_client"}`, want: TestSignInConfigurationUnavailable},
		{name: "server error", status: 400, contentType: "application/json", body: `{"error":"server_error"}`, want: TestSignInProviderUnavailable},
		{name: "server error precedes ordinary status", status: 401, contentType: "application/json", body: `{"error":"server_error"}`, want: TestSignInProviderUnavailable},
		{name: "temporary unavailable", status: 400, contentType: "application/json", body: `{"error":"temporarily_unavailable"}`, want: TestSignInProviderUnavailable},
		{name: "timeout status", status: 408, contentType: "text/plain", body: "canary", want: TestSignInProviderUnavailable},
		{name: "rate limited", status: 429, contentType: "text/plain", body: "canary", want: TestSignInProviderUnavailable},
		{name: "server status", status: 503, contentType: "text/plain", body: "canary", want: TestSignInProviderUnavailable},
		{name: "nonstandard 600 status", status: 600, contentType: "text/plain", body: "canary", want: TestSignInProviderInvalid},
		{name: "redirect", status: 302, contentType: "text/html", body: "canary", want: TestSignInProviderInvalid},
		{name: "ordinary 400", status: 400, contentType: "application/json", body: `{"error":"invalid_grant"}`, want: TestSignInProviderInvalid},
		{name: "ordinary 401", status: 401, contentType: "application/json", body: `{"error":"invalid_grant"}`, want: TestSignInProviderInvalid},
		{name: "ordinary 404", status: 404, contentType: "application/json", body: `{"error":"invalid_grant"}`, want: TestSignInProviderInvalid},
		{name: "invalid client wrong content type", status: 401, contentType: "text/plain", body: `{"error":"invalid_client"}`, want: TestSignInProviderInvalid},
		{name: "duplicate OAuth error", status: 400, contentType: "application/json", body: `{"error":"invalid_client","error":"server_error"}`, want: TestSignInProviderInvalid},
		{name: "malformed error", status: 400, contentType: "application/json", body: `{"error":`, want: TestSignInProviderInvalid},
		{name: "200 OAuth error", status: 200, contentType: "application/json", body: `{"error":"invalid_client"}`, want: TestSignInProviderInvalid},
		{name: "200 malformed", status: 200, contentType: "application/json", body: `{"access_token":`, want: TestSignInProviderInvalid},
		{name: "200 invalid UTF-8", status: 200, contentType: "application/json", body: string([]byte{'{', 0xff, '}'}), want: TestSignInProviderInvalid},
		{name: "200 oversized body", status: 200, contentType: "application/json", body: strings.Repeat("x", testSignInMaxTokenBody+1), want: TestSignInProviderInvalid},
		{name: "200 wrong content type", status: 200, contentType: "text/plain", body: `{}`, want: TestSignInProviderInvalid},
		{name: "duplicate access token", status: 200, contentType: "application/json", body: `{"access_token":"one","access_token":"two","token_type":"Bearer","id_token":"a.b.c"}`, want: TestSignInProviderInvalid},
		{name: "missing access token", status: 200, contentType: "application/json", body: `{"token_type":"Bearer","id_token":"a.b.c"}`, want: TestSignInProviderInvalid},
		{name: "oversized access token", status: 200, contentType: "application/json", body: `{"access_token":"` + strings.Repeat("a", testSignInMaxAccessToken+1) + `","token_type":"Bearer","id_token":"a.b.c"}`, want: TestSignInProviderInvalid},
		{name: "missing token type", status: 200, contentType: "application/json", body: `{"access_token":"access","id_token":"a.b.c"}`, want: TestSignInProviderInvalid},
		{name: "non Bearer", status: 200, contentType: "application/json", body: `{"access_token":"access","token_type":"MAC","id_token":"a.b.c"}`, want: TestSignInProviderInvalid},
		{name: "missing ID token", status: 200, contentType: "application/json", body: `{"access_token":"access","token_type":"Bearer"}`, want: TestSignInProviderInvalid},
		{name: "oversized ID token", status: 200, contentType: "application/json", body: `{"access_token":"access","token_type":"Bearer","id_token":"` + strings.Repeat("a", maxCompactIDTokenSize+1) + `"}`, want: TestSignInProviderInvalid},
		{name: "success", status: 200, contentType: "application/json; charset=utf-8", body: `{"access_token":"access","refresh_token":"ignored","token_type":"bearer","id_token":"a.b.c","extension":true}`, want: TestSignInVerified},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if tc.transport != nil {
					return nil, tc.transport
				}
				var body io.ReadCloser = io.NopCloser(strings.NewReader(tc.body))
				if tc.readFailure {
					body = readCloser{Reader: errorReader{}}
				}
				return &http.Response{
					StatusCode: tc.status,
					Header:     http.Header{"Content-Type": {tc.contentType}},
					Body:       body,
					Request:    request,
				}, nil
			})
			_, got := NewChecker(transport).exchangeAuthorizationCode(
				context.Background(),
				"https://id.example.test/token",
				protocolTestClientID,
				[]byte(protocolTestClientSecret),
				"code",
				testSignInRedirectURI,
				strings.Repeat("v", 43),
			)
			if got != tc.want {
				t.Fatalf("result = %q, want %q", got, tc.want)
			}
		})
	}
}

const (
	protocolTestClientID     = "client id:雪+%&"
	protocolTestClientSecret = "s e:c%r+e&t雪"
)

type testSignInTLSProvider struct {
	t                  *testing.T
	server             *httptest.Server
	key                *rsa.PrivateKey
	clientID           string
	clientSecret       string
	accessToken        string
	refreshToken       string
	authorizationQuery string
	advertisedScopes   []string
	email              string
	emailVerified      any
	domains            []string
	networkHook        func() error

	mu                      sync.Mutex
	nonce                   string
	kid                     string
	advertisedTokenEndpoint string
	discoveryCount          int
	jwksCount               int
	tokenCount              int
	secretSinkCount         int
	idToken                 string
}

func newTestSignInTLSProvider(t *testing.T) *testSignInTLSProvider {
	t.Helper()
	provider := &testSignInTLSProvider{
		t:                  t,
		key:                sharedTestRSAKey(t),
		clientID:           protocolTestClientID,
		clientSecret:       protocolTestClientSecret,
		accessToken:        "access-token-canary",
		refreshToken:       "refresh-token-canary",
		authorizationQuery: "tenant=blue&tenant=green",
		advertisedScopes:   []string{"openid", "email"},
		email:              "email-canary-7f3a9@example.test",
		emailVerified:      true,
		domains:            []string{"example.test"},
		kid:                "setup-key",
	}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	provider.advertisedTokenEndpoint = provider.server.URL + "/token"
	return provider
}

func (provider *testSignInTLSProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	issuer := provider.server.URL + "/tenant"
	switch r.URL.Path {
	case "/tenant/.well-known/openid-configuration":
		provider.discoveryCount++
		document := validDiscoveryDocument(issuer, provider.server.URL+"/jwks")
		authorizationEndpoint := provider.server.URL + "/authorize"
		if provider.authorizationQuery != "" {
			authorizationEndpoint += "?" + provider.authorizationQuery
		}
		document["authorization_endpoint"] = authorizationEndpoint
		document["token_endpoint"] = provider.advertisedTokenEndpoint
		document["scopes_supported"] = provider.advertisedScopes
		document["token_endpoint_auth_methods_supported"] = []string{"client_secret_basic"}
		document["response_modes_supported"] = []string{"query"}
		document["code_challenge_methods_supported"] = []string{"S256"}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mustJSON(provider.t, document))
	case "/jwks":
		provider.jwksCount++
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(mustJSON(provider.t, map[string]any{"keys": []any{provider.jwk()}}))
	case "/token":
		provider.tokenCount++
		if provider.networkHook != nil {
			provider.mu.Unlock()
			err := provider.networkHook()
			provider.mu.Lock()
			if err != nil {
				http.Error(w, "hook failed", http.StatusInternalServerError)
				return
			}
		}
		if r.Header.Values("Authorization") == nil || len(r.Header.Values("Authorization")) != 1 ||
			r.Header.Get("Authorization") != clientSecretBasic(provider.clientID, []byte(provider.clientSecret)) {
			http.Error(w, "invalid client", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if len(r.PostForm) != 4 || r.PostForm.Get("grant_type") != "authorization_code" ||
			r.PostForm.Get("code") != "authorization-code" ||
			r.PostForm.Get("redirect_uri") != testSignInRedirectURI ||
			!canonicalTestToken(r.PostForm.Get("code_verifier")) ||
			r.PostForm.Has("client_id") || r.PostForm.Has("client_secret") {
			http.Error(w, "invalid token request", http.StatusBadRequest)
			return
		}
		claims := map[string]any{
			"iss":   issuer,
			"sub":   "private-provider-subject",
			"aud":   provider.clientID,
			"exp":   testSignInNow.Add(5 * time.Minute).Unix(),
			"iat":   testSignInNow.Unix(),
			"nonce": provider.nonce,

			"email":          provider.email,
			"email_verified": provider.emailVerified,
		}
		provider.idToken = signTestCompact(
			provider.t,
			provider.key,
			mustMarshalJSON(provider.t, map[string]any{"alg": "RS256", "kid": provider.kid, "typ": "JWT"}),
			mustMarshalJSON(provider.t, claims),
		)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mustJSON(provider.t, map[string]any{
			"access_token":  provider.accessToken,
			"refresh_token": provider.refreshToken,
			"token_type":    "Bearer",
			"id_token":      provider.idToken,
		}))
	case "/secret-sink":
		provider.secretSinkCount++
		http.Error(w, "secret must not arrive", http.StatusInternalServerError)
	default:
		http.NotFound(w, r)
	}
}

func (provider *testSignInTLSProvider) jwk() map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": provider.kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(provider.key.N.Bytes()),
		"e":   encodeUInt(uint64(provider.key.E)),
	}
}

func (provider *testSignInTLSProvider) setNonceAndRotate(nonce string) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.nonce = nonce
	provider.kid = "callback-key"
}

func (provider *testSignInTLSProvider) setEmail(email string) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.email = email
}

func (provider *testSignInTLSProvider) setAdvertisedTokenEndpoint(endpoint string) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.advertisedTokenEndpoint = endpoint
}

func (provider *testSignInTLSProvider) discoveryRequests() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.discoveryCount
}

func (provider *testSignInTLSProvider) jwksRequests() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.jwksCount
}

func (provider *testSignInTLSProvider) tokenRequests() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.tokenCount
}

func (provider *testSignInTLSProvider) secretSinkRequests() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.secretSinkCount
}

func (provider *testSignInTLSProvider) lastIDToken() string {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.idToken
}

func newProtocolServiceFixture(t *testing.T, provider *testSignInTLSProvider) *serviceFixture {
	t.Helper()
	fixture := newServiceFixture(t)
	checker := NewChecker(trustedTransport(t, provider.server))
	fixture.service = NewServiceWithChecker(fixture.database, fixture.secretStore, checker, "http://localhost:8080")
	fixture.service.now = func() time.Time { return testSignInNow }
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, CreateInput{
		ProviderLabel: "Test provider",
		Issuer:        provider.server.URL + "/tenant",
		ClientID:      protocolTestClientID,
		ClientSecret:  protocolTestClientSecret,
		Domains:       provider.domains,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err != nil {
		t.Fatal(err)
	}
	insertTestSignInSession(t, fixture, testSignInSessionID, fixture.adminID, testSignInNow.Add(time.Hour))
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x11, 0x22, 0x33))
	return fixture
}

func startProtocolTestSignIn(t *testing.T, fixture *serviceFixture) TestSignInStart {
	t.Helper()
	start, err := fixture.service.StartTestSignIn(fixture.ctx, validProtocolStartInput(fixture.adminID))
	if err != nil {
		t.Fatal(err)
	}
	return start
}

func validProtocolStartInput(actorID int64) TestSignInStartInput {
	return TestSignInStartInput{
		ActorUserID:      actorID,
		SessionID:        testSignInSessionID,
		ExpectedRevision: 1,
		CallbackURI:      testSignInRedirectURI,
	}
}

func testSignInCompatibleDiscoveryObject(t *testing.T, value map[string]any) bool {
	t.Helper()
	object, ok := decodeJSONObject(mustJSON(t, value))
	return ok && testSignInCompatibleDiscovery(object)
}

func assertTestSignInAudit(t *testing.T, fixture *serviceFixture, action, wantDetails string) {
	t.Helper()
	var details string
	if err := fixture.database.QueryRow(`SELECT details_json FROM audit_events WHERE action = ?`, action).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if details != wantDetails {
		t.Fatalf("%s details = %s, want %s", action, details, wantDetails)
	}
}

func protocolDatabaseText(t *testing.T, fixture *serviceFixture) string {
	t.Helper()
	var value string
	if err := fixture.database.QueryRow(`
SELECT coalesce(group_concat(action || subject_id || details_json, '|'), '')
FROM audit_events`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func assertAuditActionCount(t *testing.T, fixture *serviceFixture, action string, want int) {
	t.Helper()
	var got int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM audit_events WHERE action = ?`, action).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s audit count = %d, want %d", action, got, want)
	}
}

func countTableRows(t *testing.T, fixture *serviceFixture, table string) int {
	t.Helper()
	var got int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM "` + table + `"`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

func assertNoDatabaseText(t *testing.T, fixture *serviceFixture, needle string) {
	t.Helper()
	tableRows, err := fixture.database.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer tableRows.Close()
	var tables []string
	for tableRows.Next() {
		var name string
		if err := tableRows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := tableRows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		assertNoTableText(t, fixture, table, needle)
	}
}

func assertNoTableText(t *testing.T, fixture *serviceFixture, table, needle string) {
	t.Helper()
	rows, err := fixture.database.Query(`SELECT * FROM "` + table + `"`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		for _, value := range values {
			text := fmt.Sprint(value)
			if raw, ok := value.([]byte); ok {
				text = string(raw)
			}
			if strings.Contains(text, needle) {
				t.Fatalf("table %s contains the provider email canary", table)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

type failingDecryptStore struct {
	err error
}

func (failingDecryptStore) Encrypt(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unexpected encryption")
}

func (store failingDecryptStore) Decrypt(context.Context, []byte) ([]byte, error) {
	return nil, store.err
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("read failure canary")
}

type readCloser struct {
	io.Reader
}

func (readCloser) Close() error { return nil }
