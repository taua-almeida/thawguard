package forgeidentity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

// linkRandom returns the deterministic random stream one StartLink consumes:
// 32 state bytes, 32 browser bytes, and 48 verifier bytes.
func linkRandom(seed byte) *bytes.Reader {
	stream := append(bytes.Repeat([]byte{seed}, 32), bytes.Repeat([]byte{seed + 1}, 32)...)
	stream = append(stream, bytes.Repeat([]byte{seed + 2}, 48)...)
	return bytes.NewReader(stream)
}

func linkStateForSeed(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func linkVerifierForSeed(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed + 2}, 48))
}

// startLinkForUser starts a ceremony with the deterministic seed 0x11.
func startLinkForUser(t *testing.T, f *fixture, sessionID string, userID int64) LinkStart {
	t.Helper()
	return startLinkSeeded(t, f, sessionID, userID, 0x11)
}

func startLinkSeeded(t *testing.T, f *fixture, sessionID string, userID int64, seed byte) LinkStart {
	t.Helper()
	client, found, err := f.service.OAuthClient(f.ctx)
	if err != nil || !found {
		t.Fatalf("oauth client: found=%v err=%v", found, err)
	}
	f.service.random = linkRandom(seed)
	start, err := f.service.StartLink(f.ctx, StartLinkInput{
		ActorUserID:           userID,
		SessionID:             sessionID,
		ExpectedConnectionID:  client.ConnectionID,
		ExpectedOAuthRevision: client.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	return start
}

func callbackQuery(state string, extra string) string {
	query := "state=" + url.QueryEscape(state)
	if extra != "" {
		query += "&" + extra
	}
	return query
}

// fakeForgejoProvider is the scripted token and current-user endpoint pair.
type fakeForgejoProvider struct {
	server *httptest.Server

	mu             sync.Mutex
	tokenStatus    int
	tokenBody      string
	tokenType      string
	userStatus     int
	userBody       string
	userType       string
	tokenRequests  []providerTokenRequest
	userAuthHeader []string
	// onToken runs during the token exchange, after the claim committed,
	// so tests can interleave state changes with provider I/O.
	onToken func()
}

type providerTokenRequest struct {
	authorization string
	basicUser     string
	basicPassword string
	basicOK       bool
	form          url.Values
}

func newFakeForgejoProvider(t *testing.T) *fakeForgejoProvider {
	t.Helper()
	provider := &fakeForgejoProvider{
		tokenStatus: http.StatusOK,
		tokenBody:   `{"access_token":"fixture-access-token","token_type":"Bearer","refresh_token":"fixture-refresh-token"}`,
		tokenType:   "application/json",
		userStatus:  http.StatusOK,
		userBody:    `{"id":777,"login":"fixture-user"}`,
		userType:    "application/json; charset=utf-8",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+tokenEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		provider.mu.Lock()
		defer provider.mu.Unlock()
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		record := providerTokenRequest{
			authorization: r.Header.Get("Authorization"),
			form:          r.PostForm,
		}
		record.basicUser, record.basicPassword, record.basicOK = r.BasicAuth()
		provider.tokenRequests = append(provider.tokenRequests, record)
		if provider.onToken != nil {
			provider.onToken()
		}
		w.Header().Set("Content-Type", provider.tokenType)
		w.WriteHeader(provider.tokenStatus)
		_, _ = w.Write([]byte(provider.tokenBody))
	})
	mux.HandleFunc("GET "+currentUserEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		provider.mu.Lock()
		defer provider.mu.Unlock()
		provider.userAuthHeader = append(provider.userAuthHeader, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", provider.userType)
		w.WriteHeader(provider.userStatus)
		_, _ = w.Write([]byte(provider.userBody))
	})
	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *fakeForgejoProvider) set(update func(*fakeForgejoProvider)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	update(p)
}

func newProviderFixture(t *testing.T) (*fixture, *fakeForgejoProvider) {
	t.Helper()
	f := newFixture(t)
	provider := newFakeForgejoProvider(t)
	f.insertConnection(t, provider.server.URL)
	f.saveOAuthClient(t, 0)
	return f, provider
}

func TestStartLinkCreatesBoundPendingCeremony(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	f.saveOAuthClient(t, 0)

	start := startLinkForUser(t, f, testUserSession, testUserID)
	state := linkStateForSeed(0x11)
	verifier := linkVerifierForSeed(0x11)
	if start.BrowserToken != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x12}, 32)) {
		t.Fatalf("browser token = %q", start.BrowserToken)
	}

	parsed, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != testForgeBaseURL+"/login/oauth/authorize" {
		t.Fatalf("authorization endpoint = %q", got)
	}
	values := parsed.Query()
	expected := map[string]string{
		"response_type":         "code",
		"client_id":             testClientID,
		"redirect_uri":          testPublicURL + CallbackPath,
		"scope":                 "read:user",
		"state":                 state,
		"code_challenge":        pkceS256Challenge(verifier),
		"code_challenge_method": "S256",
	}
	if len(values) != len(expected) {
		t.Fatalf("authorization URL carries %d parameters, want %d: %q", len(values), len(expected), start.AuthorizationURL)
	}
	for key, want := range expected {
		if got := values[key]; len(got) != 1 || got[0] != want {
			t.Fatalf("authorization parameter %q = %v, want %q", key, got, want)
		}
	}

	stateDigest := linkDigest(linkStateDigestPurpose, state)
	sessionDigest := linkDigest(linkSessionDigestPurpose, testUserSession)
	browserDigest := linkDigest(linkBrowserDigestPurpose, start.BrowserToken)
	var status, redirectURI, boundBaseURL, expiresAt string
	var storedSession, storedBrowser, verifierCiphertext []byte
	var connectionRevision, oauthRevision int64
	if err := f.database.QueryRowContext(f.ctx, `
SELECT status, session_binding_digest, browser_binding_digest, pkce_verifier_ciphertext,
  redirect_uri, bound_base_url, connection_revision, oauth_revision, expires_at
FROM forgejo_identity_link_transactions WHERE state_digest = ?`, stateDigest[:]).Scan(
		&status, &storedSession, &storedBrowser, &verifierCiphertext,
		&redirectURI, &boundBaseURL, &connectionRevision, &oauthRevision, &expiresAt,
	); err != nil {
		t.Fatal(err)
	}
	if status != "pending" ||
		!bytes.Equal(storedSession, sessionDigest[:]) ||
		!bytes.Equal(storedBrowser, browserDigest[:]) ||
		redirectURI != testPublicURL+CallbackPath ||
		boundBaseURL != testForgeBaseURL ||
		connectionRevision != 1 || oauthRevision != 1 {
		t.Fatalf("ceremony row: status=%q redirect=%q bound=%q revisions=%d/%d", status, redirectURI, boundBaseURL, connectionRevision, oauthRevision)
	}
	if expiresAt != formatForgeIdentityTime(testNow.Add(linkTransactionTTL)) {
		t.Fatalf("expiry = %q", expiresAt)
	}
	if bytes.Contains(verifierCiphertext, []byte(verifier)) {
		t.Fatal("PKCE verifier stored unencrypted")
	}
}

func TestStartLinkRejections(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	f.saveOAuthClient(t, 0)

	reject := func(name string, input StartLinkInput, want error) {
		t.Helper()
		f.service.random = linkRandom(0x41)
		_, err := f.service.StartLink(f.ctx, input)
		if !errors.Is(err, want) {
			t.Fatalf("%s: err = %v, want %v", name, err, want)
		}
	}
	valid := StartLinkInput{
		ActorUserID:           testUserID,
		SessionID:             testUserSession,
		ExpectedConnectionID:  1,
		ExpectedOAuthRevision: 1,
	}

	wrongConnection := valid
	wrongConnection.ExpectedConnectionID = 9
	reject("wrong connection fence", wrongConnection, ErrUnavailable)
	wrongRevision := valid
	wrongRevision.ExpectedOAuthRevision = 9
	reject("wrong oauth revision fence", wrongRevision, ErrUnavailable)
	wrongSession := valid
	wrongSession.SessionID = testOtherSession
	reject("session belonging to another user", wrongSession, ErrAuthorization)

	// A forced-password credential cannot start.
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, testUserID); err != nil {
		t.Fatal(err)
	}
	reject("forced password", valid, ErrAuthorization)
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE local_credentials SET must_change_password = 0 WHERE user_id = ?`, testUserID); err != nil {
		t.Fatal(err)
	}
	// A disabled user cannot start.
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE users SET disabled_at = ? WHERE id = ?`, testNow.Format(time.RFC3339Nano), testUserID); err != nil {
		t.Fatal(err)
	}
	reject("disabled user", valid, ErrAuthorization)
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE users SET disabled_at = NULL WHERE id = ?`, testUserID); err != nil {
		t.Fatal(err)
	}
	// An expired session cannot start.
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE sessions SET expires_at = ? WHERE id = ?`,
		testNow.Add(-time.Minute).Format(time.RFC3339Nano), testUserSession); err != nil {
		t.Fatal(err)
	}
	reject("expired session", valid, ErrAuthorization)
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE sessions SET expires_at = ? WHERE id = ?`,
		testNow.Add(time.Hour).Format(time.RFC3339Nano), testUserSession); err != nil {
		t.Fatal(err)
	}

	// An already-linked user cannot start another ceremony.
	identityID := f.insertIdentity(t, testUserID, "31", "linked-user")
	reject("already linked", valid, ErrUnavailable)
	if _, err := f.database.ExecContext(f.ctx, `DELETE FROM forgejo_identities WHERE id = ?`, identityID); err != nil {
		t.Fatal(err)
	}

	// A live row rejects a second start; an expired row does not.
	startLinkForUser(t, f, testUserSession, testUserID)
	reject("live ceremony exists", valid, ErrLinkInProgress)
	f.service.now = func() time.Time { return testNow.Add(linkTransactionTTL + time.Second) }
	if _, err := f.database.ExecContext(f.ctx, `UPDATE sessions SET expires_at = ?`,
		testNow.Add(2*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	f.service.random = linkRandom(0x51)
	if _, err := f.service.StartLink(f.ctx, valid); err != nil {
		t.Fatalf("start after expiry: %v", err)
	}
	if f.ceremonyCount(t) != 1 {
		t.Fatalf("expected exactly one live ceremony, got %d", f.ceremonyCount(t))
	}
	f.service.now = func() time.Time { return testNow }

	// The disabled client rejects starts.
	if err := f.service.DisableOAuthClient(f.ctx, testAdminID, DisableOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      1,
	}); err != nil {
		t.Fatal(err)
	}
	rejectDisabled := valid
	rejectDisabled.ExpectedOAuthRevision = 2
	reject("disabled client", rejectDisabled, ErrUnavailable)
}

func TestCancelStartDeletesOnlyPendingRow(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	f.saveOAuthClient(t, 0)

	start := startLinkForUser(t, f, testUserSession, testUserID)
	if err := f.service.CancelStart(f.ctx, start.Handle); err != nil {
		t.Fatal(err)
	}
	if f.ceremonyCount(t) != 0 {
		t.Fatal("cancel left the pending row")
	}

	second := startLinkSeeded(t, f, testUserSession, testUserID, 0x21)
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE forgejo_identity_link_transactions SET status = 'claimed'`); err != nil {
		t.Fatal(err)
	}
	if err := f.service.CancelStart(f.ctx, second.Handle); err != nil {
		t.Fatal(err)
	}
	if f.ceremonyCount(t) != 1 {
		t.Fatal("cancel removed a claimed row")
	}
}

func TestCompleteLinkCallbackLinksIdentity(t *testing.T) {
	f, provider := newProviderFixture(t)
	start := startLinkForUser(t, f, testUserSession, testUserID)
	state := linkStateForSeed(0x11)

	result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(state, "code=fixture-authorization-code"),
		SessionID:    testUserSession,
		BrowserToken: start.BrowserToken,
	})
	if err != nil || result != LinkLinked {
		t.Fatalf("callback result = %q err = %v", result, err)
	}

	var remoteID, username string
	var identityID int64
	if err := f.database.QueryRowContext(f.ctx, `
SELECT id, remote_user_id, username_at_link FROM forgejo_identities WHERE user_id = ?`, testUserID).
		Scan(&identityID, &remoteID, &username); err != nil {
		t.Fatal(err)
	}
	if remoteID != testRemoteUserID || username != testRemoteLogin {
		t.Fatalf("identity remote=%q username=%q", remoteID, username)
	}
	if f.ceremonyCount(t) != 0 {
		t.Fatal("completion left the claimed row")
	}
	linked := f.auditEvents(t, audit.ActionForgeIdentityLinked)
	if len(linked) != 1 || linked[0].SubjectType != audit.SubjectTypeForgeIdentity ||
		linked[0].SubjectID != "1" || linked[0].DetailsJSON != `{"connection_id":1}` ||
		linked[0].ActorUserID == nil || *linked[0].ActorUserID != testUserID {
		t.Fatalf("linked audit = %+v", linked)
	}

	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.tokenRequests) != 1 {
		t.Fatalf("token requests = %d", len(provider.tokenRequests))
	}
	request := provider.tokenRequests[0]
	if !request.basicOK ||
		request.basicUser != url.QueryEscape(testClientID) ||
		request.basicPassword != url.QueryEscape(testClientSecret) {
		t.Fatalf("token basic auth = %+v", request)
	}
	wantForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"fixture-authorization-code"},
		"redirect_uri":  {testPublicURL + CallbackPath},
		"code_verifier": {linkVerifierForSeed(0x11)},
	}
	if len(request.form) != len(wantForm) {
		t.Fatalf("token form keys = %v", request.form)
	}
	for key, want := range wantForm {
		if got := request.form[key]; len(got) != 1 || got[0] != want[0] {
			t.Fatalf("token form %q = %v, want %v", key, got, want)
		}
	}
	if len(request.form["client_id"]) != 0 || len(request.form["client_secret"]) != 0 {
		t.Fatal("client credentials leaked into the token request body")
	}
	if len(provider.userAuthHeader) != 1 || provider.userAuthHeader[0] != "Bearer fixture-access-token" {
		t.Fatalf("user request authorization = %v", provider.userAuthHeader)
	}

	f.assertNoSecretMaterial(t,
		testClientSecret,
		"fixture-authorization-code",
		"fixture-access-token",
		"fixture-refresh-token",
		linkVerifierForSeed(0x11),
		state,
		start.BrowserToken,
	)
}

func TestCompleteLinkCallbackProviderDenied(t *testing.T) {
	f, _ := newProviderFixture(t)
	start := startLinkForUser(t, f, testUserSession, testUserID)
	state := linkStateForSeed(0x11)

	result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(state, "error=access_denied"),
		SessionID:    testUserSession,
		BrowserToken: start.BrowserToken,
	})
	if err != nil || result != LinkProviderDenied {
		t.Fatalf("denied result = %q err = %v", result, err)
	}
	if f.ceremonyCount(t) != 0 {
		t.Fatal("denied callback left the claimed row")
	}
	if f.identityCount(t) != 0 {
		t.Fatal("denied callback linked an identity")
	}
	if len(f.auditEvents(t, audit.ActionForgeIdentityLinked)) != 0 {
		t.Fatal("denied callback wrote a linked audit event")
	}
	// Unknown provider errors are invalid; server errors are unavailable.
	second := startLinkSeeded(t, f, testUserSession, testUserID, 0x61)
	result, err = f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(0x61), "error=temporarily_unavailable"),
		SessionID:    testUserSession,
		BrowserToken: second.BrowserToken,
	})
	if err != nil || result != LinkProviderUnavailable {
		t.Fatalf("unavailable result = %q err = %v", result, err)
	}
}

func TestCompleteLinkCallbackCollisionAndAlreadyLinked(t *testing.T) {
	f, _ := newProviderFixture(t)
	// The provider account 777 is already linked to another user.
	f.insertIdentity(t, testOtherUserID, testRemoteUserID, "other-user")
	start := startLinkForUser(t, f, testUserSession, testUserID)
	state := linkStateForSeed(0x11)

	result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(state, "code=fixture-authorization-code"),
		SessionID:    testUserSession,
		BrowserToken: start.BrowserToken,
	})
	if err != nil || result != LinkCollision {
		t.Fatalf("collision result = %q err = %v", result, err)
	}
	if f.ceremonyCount(t) != 0 {
		t.Fatal("collision left the claimed row")
	}
	if f.identityCount(t) != 1 {
		t.Fatal("collision changed the identity table")
	}
	rejected := f.auditEvents(t, audit.ActionForgeIdentityLinkRejected)
	if len(rejected) != 1 || rejected[0].SubjectType != audit.SubjectTypeForgeConnection ||
		rejected[0].SubjectID != "1" || rejected[0].DetailsJSON != `{"reason":"remote_identity_collision"}` {
		t.Fatalf("rejected audit = %+v", rejected)
	}
	// Fixed evidence: the other account is never named.
	if bytes.Contains([]byte(rejected[0].DetailsJSON), []byte("other-user")) ||
		bytes.Contains([]byte(rejected[0].DetailsJSON), []byte(testRemoteUserID)) {
		t.Fatal("collision evidence names the other account")
	}

	// A user who linked after starting is rejected without a new identity.
	second := startLinkSeeded(t, f, testUserSession, testUserID, 0x71)
	f.insertIdentity(t, testUserID, "888", "self-linked")
	result, err = f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(0x71), "code=fixture-authorization-code"),
		SessionID:    testUserSession,
		BrowserToken: second.BrowserToken,
	})
	if err != nil || result != LinkAlreadyLinked {
		t.Fatalf("already-linked result = %q err = %v", result, err)
	}
	if f.ceremonyCount(t) != 0 {
		t.Fatal("already-linked left the claimed row")
	}
}

func TestCompleteLinkCallbackBindingAndFenceMismatches(t *testing.T) {
	f, _ := newProviderFixture(t)

	type mismatch struct {
		name         string
		query        func(state, browser string) string
		session      func(string) string
		browser      func(string) string
		mutate       func(t *testing.T)
		wantConsumed bool
	}
	cases := []mismatch{
		{
			name:         "wrong session",
			session:      func(string) string { return testOtherSession },
			wantConsumed: true,
		},
		{
			name:         "missing browser token",
			browser:      func(string) string { return "" },
			wantConsumed: true,
		},
		{
			name:         "wrong browser token",
			browser:      func(string) string { return linkStateForSeed(0x77) },
			wantConsumed: true,
		},
		{
			name: "expired row",
			mutate: func(t *testing.T) {
				f.service.now = func() time.Time { return testNow.Add(linkTransactionTTL + time.Second) }
				t.Cleanup(func() { f.service.now = func() time.Time { return testNow } })
				if _, err := f.database.ExecContext(f.ctx, `UPDATE sessions SET expires_at = ?`,
					testNow.Add(2*time.Hour).Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			},
			wantConsumed: true,
		},
		{
			name: "oauth revision fence",
			mutate: func(t *testing.T) {
				if _, err := f.database.ExecContext(f.ctx,
					`UPDATE forgejo_identity_oauth_clients SET oauth_revision = oauth_revision + 1`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := f.database.ExecContext(f.ctx,
						`UPDATE forgejo_identity_oauth_clients SET oauth_revision = oauth_revision - 1`); err != nil {
						t.Fatal(err)
					}
				})
			},
			wantConsumed: true,
		},
		{
			name: "connection revision fence",
			mutate: func(t *testing.T) {
				if _, err := f.database.ExecContext(f.ctx,
					`UPDATE forge_connections SET config_revision = 2`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := f.database.ExecContext(f.ctx,
						`UPDATE forge_connections SET config_revision = 1`); err != nil {
						t.Fatal(err)
					}
				})
			},
			wantConsumed: true,
		},
		{
			name: "duplicate state parameter",
			query: func(state, _ string) string {
				return "state=" + state + "&state=" + state + "&code=fixture-code"
			},
			wantConsumed: false,
		},
		{
			name: "case-fold alias of a known key",
			query: func(state, _ string) string {
				return "state=" + state + "&Code=fixture-code"
			},
			wantConsumed: false,
		},
		{
			name: "code and error together",
			query: func(state, _ string) string {
				return "state=" + state + "&code=fixture-code&error=access_denied"
			},
			wantConsumed: false,
		},
	}
	seed := byte(0x21)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := startLinkSeeded(t, f, testUserSession, testUserID, seed)
			state := linkStateForSeed(seed)
			seed += 0x10
			if tc.mutate != nil {
				tc.mutate(t)
			}
			rawQuery := callbackQuery(state, "code=fixture-code")
			if tc.query != nil {
				rawQuery = tc.query(state, start.BrowserToken)
			}
			sessionID := testUserSession
			if tc.session != nil {
				sessionID = tc.session(testUserSession)
			}
			browser := start.BrowserToken
			if tc.browser != nil {
				browser = tc.browser(start.BrowserToken)
			}
			result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
				RawQuery:     rawQuery,
				SessionID:    sessionID,
				BrowserToken: browser,
			})
			if err != nil || result != LinkStale {
				t.Fatalf("result = %q err = %v", result, err)
			}
			if f.identityCount(t) != 0 {
				t.Fatal("mismatch linked an identity")
			}
			remaining := f.ceremonyCount(t)
			if tc.wantConsumed && remaining != 0 {
				t.Fatalf("expected the row to be consumed, %d remain", remaining)
			}
			if !tc.wantConsumed && remaining != 1 {
				t.Fatalf("expected the row to survive a pre-claim rejection, %d remain", remaining)
			}
			if remaining == 1 {
				if _, err := f.database.ExecContext(f.ctx, `DELETE FROM forgejo_identity_link_transactions`); err != nil {
					t.Fatal(err)
				}
			}
		})
	}

	// An unknown but well-formed state consumes nothing.
	startLinkSeeded(t, f, testUserSession, testUserID, seed)
	result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(0x03), "code=fixture-code"),
		SessionID:    testUserSession,
		BrowserToken: linkStateForSeed(0x04),
	})
	if err != nil || result != LinkStale {
		t.Fatalf("unknown state result = %q err = %v", result, err)
	}
	if f.ceremonyCount(t) != 1 {
		t.Fatal("unknown state consumed the live ceremony")
	}

	// An already-claimed row is left alone by a replayed callback.
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE forgejo_identity_link_transactions SET status = 'claimed'`); err != nil {
		t.Fatal(err)
	}
	result, err = f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(seed), "code=fixture-code"),
		SessionID:    testUserSession,
		BrowserToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed + 1}, 32)),
	})
	if err != nil || result != LinkStale {
		t.Fatalf("claimed replay result = %q err = %v", result, err)
	}
	if f.ceremonyCount(t) != 1 {
		t.Fatal("claimed replay deleted the in-flight row")
	}
}

// TestStartLinkClearsOwnExpiredRowBehindBacklog proves a restart succeeds
// even when the bounded batch cleanup is fully consumed by other users'
// expired ceremonies and can never reach the actor's own expired row.
func TestStartLinkClearsOwnExpiredRowBehindBacklog(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	f.saveOAuthClient(t, 0)

	nowText := testNow.Format(time.RFC3339Nano)
	backlogExpiry := formatForgeIdentityTime(testNow.Add(-30 * time.Minute))
	backlogCreated := formatForgeIdentityTime(testNow.Add(-40 * time.Minute))
	for i := range linkCleanupLimit {
		foreignUserID := int64(100 + i)
		if _, err := f.database.ExecContext(f.ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (?, ?, 'Backlog user', ?, ?)`,
			foreignUserID, fmt.Sprintf("backlog-%d@example.test", i), nowText, nowText); err != nil {
			t.Fatal(err)
		}
		digest := linkDigest(linkStateDigestPurpose, fmt.Sprintf("backlog-state-%d", i))
		if _, err := f.database.ExecContext(f.ctx, `
INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (?, 1, ?, 'pending', zeroblob(32), zeroblob(32), x'01', ?, ?, 1, 1, ?, ?)`,
			digest[:], foreignUserID, testPublicURL+CallbackPath, testForgeBaseURL,
			backlogCreated, backlogExpiry); err != nil {
			t.Fatal(err)
		}
	}
	// The actor's own expired row sorts after every backlog row, so the
	// bounded batch never reaches it.
	ownDigest := linkDigest(linkStateDigestPurpose, "actor-expired-state")
	if _, err := f.database.ExecContext(f.ctx, `
INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (?, 1, ?, 'claimed', zeroblob(32), zeroblob(32), x'01', ?, ?, 1, 1, ?, ?)`,
		ownDigest[:], testUserID, testPublicURL+CallbackPath, testForgeBaseURL,
		formatForgeIdentityTime(testNow.Add(-20*time.Minute)),
		formatForgeIdentityTime(testNow.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}

	f.service.random = linkRandom(0x11)
	if _, err := f.service.StartLink(f.ctx, StartLinkInput{
		ActorUserID:           testUserID,
		SessionID:             testUserSession,
		ExpectedConnectionID:  1,
		ExpectedOAuthRevision: 1,
	}); err != nil {
		t.Fatalf("restart behind an expired backlog: %v", err)
	}
	var ownRows int
	if err := f.database.QueryRowContext(f.ctx, `
SELECT COUNT(*) FROM forgejo_identity_link_transactions WHERE user_id = ?`, testUserID).Scan(&ownRows); err != nil {
		t.Fatal(err)
	}
	if ownRows != 1 {
		t.Fatalf("actor rows after restart = %d, want exactly the fresh pending row", ownRows)
	}
}

// TestCompletionFenceConsumesClaimedRow interleaves a connection edit with
// the provider exchange: the completion must report stale and consume the
// exact claimed row so the account is not stuck in progress until expiry.
func TestCompletionFenceConsumesClaimedRow(t *testing.T) {
	f, provider := newProviderFixture(t)
	start := startLinkForUser(t, f, testUserSession, testUserID)
	provider.onToken = func() {
		if _, err := f.database.ExecContext(f.ctx,
			`UPDATE forge_connections SET config_revision = 2 WHERE id = 1`); err != nil {
			t.Error(err)
		}
	}

	result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(0x11), "code=fixture-code"),
		SessionID:    testUserSession,
		BrowserToken: start.BrowserToken,
	})
	if err != nil || result != LinkStale {
		t.Fatalf("result = %q err = %v", result, err)
	}
	if f.identityCount(t) != 0 {
		t.Fatal("stale completion linked an identity")
	}
	if f.ceremonyCount(t) != 0 {
		t.Fatal("stale completion left the claimed row; the account would stay in progress until expiry")
	}
	view, err := f.service.AccountForUser(f.ctx, testUserID)
	if err != nil || view.Status == AccountInProgress {
		t.Fatalf("account view after stale completion = %+v err=%v", view, err)
	}
}

func TestConcurrentStartLinkKeepsSingleLiveCeremony(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	f.saveOAuthClient(t, 0)

	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			_, err := f.service.StartLink(f.ctx, StartLinkInput{
				ActorUserID:           testUserID,
				SessionID:             testUserSession,
				ExpectedConnectionID:  1,
				ExpectedOAuthRevision: 1,
			})
			results[slot] = err
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for _, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrLinkInProgress):
		default:
			t.Fatalf("unexpected concurrent start error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent starts succeeded %d times, want exactly 1", succeeded)
	}
	if f.ceremonyCount(t) != 1 {
		t.Fatalf("live ceremonies = %d, want 1", f.ceremonyCount(t))
	}
}

func TestConcurrentCallbacksClaimOnce(t *testing.T) {
	f, _ := newProviderFixture(t)
	start := startLinkForUser(t, f, testUserSession, testUserID)
	state := linkStateForSeed(0x11)

	var wg sync.WaitGroup
	results := make([]LinkResultCode, 3)
	callbackErrors := make([]error, 3)
	for i := range results {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			results[slot], callbackErrors[slot] = f.service.CompleteLinkCallback(f.ctx, CallbackInput{
				RawQuery:     callbackQuery(state, "error=access_denied"),
				SessionID:    testUserSession,
				BrowserToken: start.BrowserToken,
			})
		}(i)
	}
	wg.Wait()

	denied := 0
	for i, result := range results {
		if callbackErrors[i] != nil {
			t.Fatalf("callback %d error: %v", i, callbackErrors[i])
		}
		switch result {
		case LinkProviderDenied:
			denied++
		case LinkStale:
		default:
			t.Fatalf("callback %d result = %q", i, result)
		}
	}
	if denied != 1 {
		t.Fatalf("denied outcomes = %d, want exactly 1", denied)
	}
	if f.ceremonyCount(t) != 0 {
		t.Fatal("concurrent callbacks left ceremony state")
	}
}

// TestClaimDigestsUseDistinctPurposes ensures a session id can never satisfy
// the browser binding or vice versa even with identical input material.
func TestClaimDigestsUseDistinctPurposes(t *testing.T) {
	value := "identical-material"
	session := linkDigest(linkSessionDigestPurpose, value)
	browser := linkDigest(linkBrowserDigestPurpose, value)
	state := linkDigest(linkStateDigestPurpose, value)
	if session == browser || session == state || browser == state {
		t.Fatal("digest purposes collide")
	}
	if session == sha256.Sum256([]byte(value)) {
		t.Fatal("digest omits the purpose prefix")
	}
}

func TestAuditDetailsStayFixedShape(t *testing.T) {
	f, _ := newProviderFixture(t)
	start := startLinkForUser(t, f, testUserSession, testUserID)
	if _, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(0x11), "code=fixture-authorization-code"),
		SessionID:    testUserSession,
		BrowserToken: start.BrowserToken,
	}); err != nil {
		t.Fatal(err)
	}
	for _, event := range f.auditEvents(t, audit.ActionForgeIdentityLinked) {
		var details map[string]json.RawMessage
		if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
			t.Fatal(err)
		}
		if len(details) != 1 {
			t.Fatalf("linked details = %s", event.DetailsJSON)
		}
		if _, ok := details["connection_id"]; !ok {
			t.Fatalf("linked details missing connection_id: %s", event.DetailsJSON)
		}
	}
}
