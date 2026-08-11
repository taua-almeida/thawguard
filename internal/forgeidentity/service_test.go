package forgeidentity

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

const (
	testPublicURL    = "https://thawguard.example.test"
	testAdminID      = int64(1)
	testUserID       = int64(2)
	testOtherUserID  = int64(3)
	testAdminSession = "admin-session-0001"
	testUserSession  = "user-session-0002"
	testOtherSession = "other-session-0003"
	testClientID     = "fixture-client-id"
	// testClientSecret needs characters QueryEscape rewrites, so tests can
	// prove the RFC 6749 escaping reached the Basic header.
	testClientSecret  = "fictional+oauth/secret-01"
	testForgeBaseURL  = "https://forge.example.test"
	testRemoteUserID  = "777"
	testRemoteLogin   = "fixture-user"
	testSecondaryBase = "https://second-forge.example.test"
)

var testNow = time.Date(2026, 8, 10, 12, 0, 0, 123456789, time.UTC)

type fixture struct {
	ctx      context.Context
	database *sql.DB
	service  *Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "forge-identity-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := db.LoadMigrations(testMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	secretStore, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{ctx: ctx, database: database}
	f.service = NewService(database, secretStore, nil, testPublicURL)
	f.service.now = func() time.Time { return testNow }

	nowText := testNow.Format(time.RFC3339Nano)
	expiry := testNow.Add(time.Hour).Format(time.RFC3339Nano)
	setup := []struct {
		statement string
		args      []any
	}{
		{`INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?),
       (2, 'user@example.test', 'User', ?, ?),
       (3, 'other@example.test', 'Other', ?, ?)`,
			[]any{nowText, nowText, nowText, nowText, nowText, nowText}},
		{`INSERT INTO user_roles(user_id, role, created_at) VALUES (1, 'admin', ?)`, []any{nowText}},
		{`INSERT INTO local_credentials(user_id, password_hash, must_change_password, created_at, updated_at)
VALUES (1, 'test-hash', 0, ?, ?), (2, 'test-hash', 0, ?, ?), (3, 'test-hash', 0, ?, ?)`,
			[]any{nowText, nowText, nowText, nowText, nowText, nowText}},
		{`INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES (?, 1, 'csrf-a', ?, ?), (?, 2, 'csrf-b', ?, ?), (?, 3, 'csrf-c', ?, ?)`,
			[]any{
				testAdminSession, expiry, nowText,
				testUserSession, expiry, nowText,
				testOtherSession, expiry, nowText,
			}},
	}
	for _, step := range setup {
		if _, err := database.ExecContext(ctx, step.statement, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func testMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func (f *fixture) insertConnection(t *testing.T, baseURL string) {
	t.Helper()
	canonical := formatForgeIdentityTime(testNow)
	if _, err := f.database.ExecContext(f.ctx, `
INSERT INTO forge_connections(id, provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES (1, 'forgejo', 'Fixture forge', ?, 1, 0, ?, ?)`,
		baseURL, canonical, canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ExecContext(f.ctx, `
INSERT INTO forgejo_connection_config(connection_id, organization_slug, service_pat_ciphertext, pat_attested_at, attested_by_user_id)
VALUES (1, 'fixture-org', x'0102', ?, 1)`,
		canonical); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) saveOAuthClient(t *testing.T, expectedOAuthRevision int64) {
	t.Helper()
	if err := f.service.SaveOAuthClient(f.ctx, testAdminID, SaveOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      expectedOAuthRevision,
		ClientID:                   testClientID,
		ClientSecret:               testClientSecret,
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) auditEvents(t *testing.T, action string) []audit.Event {
	t.Helper()
	events, err := audit.NewStore(f.database).List(f.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	matched := make([]audit.Event, 0, len(events))
	for _, event := range events {
		if event.Action == action {
			matched = append(matched, event)
		}
	}
	return matched
}

// assertNoSecretMaterial is the privacy canary: none of the listed values
// may appear in any audit event row.
func (f *fixture) assertNoSecretMaterial(t *testing.T, values ...string) {
	t.Helper()
	events, err := audit.NewStore(f.database).List(f.ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		row := event.Action + " " + event.SubjectType + " " + event.SubjectID + " " + event.DetailsJSON
		for _, value := range values {
			if value == "" {
				continue
			}
			if strings.Contains(row, value) {
				t.Fatalf("audit event %d leaked secret material %q: %s", event.ID, value, row)
			}
		}
	}
}

func (f *fixture) ceremonyCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.database.QueryRowContext(f.ctx,
		`SELECT COUNT(*) FROM forgejo_identity_link_transactions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func (f *fixture) identityCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.database.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM forgejo_identities`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func (f *fixture) insertIdentity(t *testing.T, userID int64, remoteID, username string) int64 {
	t.Helper()
	var id int64
	if err := f.database.QueryRowContext(f.ctx, `
INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, ?, ?, ?, ?) RETURNING id`,
		userID, remoteID, username, formatForgeIdentityTime(testNow)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestOAuthClientSaveDisableLifecycle(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)

	if _, found, err := f.service.OAuthClient(f.ctx); err != nil || found {
		t.Fatalf("unconfigured client: found=%v err=%v", found, err)
	}

	f.saveOAuthClient(t, 0)
	client, found, err := f.service.OAuthClient(f.ctx)
	if err != nil || !found {
		t.Fatalf("configured client: found=%v err=%v", found, err)
	}
	if !client.Enabled || client.ClientID != testClientID || client.Revision != 1 ||
		client.BoundBaseURL != testForgeBaseURL || client.ConnectionID != 1 {
		t.Fatalf("client = %+v", client)
	}
	saved := f.auditEvents(t, audit.ActionForgeOAuthClientUpdated)
	if len(saved) != 1 || saved[0].SubjectType != audit.SubjectTypeForgeConnection ||
		saved[0].SubjectID != "1" || saved[0].DetailsJSON != `{"oauth_revision":1}` {
		t.Fatalf("save audit = %+v", saved)
	}
	f.assertNoSecretMaterial(t, testClientSecret)
	var ciphertext []byte
	if err := f.database.QueryRowContext(f.ctx,
		`SELECT client_secret_ciphertext FROM forgejo_identity_oauth_clients`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(testClientSecret)) {
		t.Fatal("client secret stored unencrypted")
	}

	// A stale expected revision cannot save or disable.
	if err := f.service.SaveOAuthClient(f.ctx, testAdminID, SaveOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      0,
		ClientID:                   testClientID,
		ClientSecret:               testClientSecret,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save err = %v", err)
	}
	if err := f.service.DisableOAuthClient(f.ctx, testAdminID, DisableOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      2,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale disable err = %v", err)
	}

	// Re-save deletes every pending ceremony for the connection.
	startLinkForUser(t, f, testUserSession, testUserID)
	if f.ceremonyCount(t) != 1 {
		t.Fatalf("ceremonies before re-save = %d", f.ceremonyCount(t))
	}
	f.saveOAuthClient(t, 1)
	if f.ceremonyCount(t) != 0 {
		t.Fatal("re-save left ceremonies behind")
	}

	if err := f.service.DisableOAuthClient(f.ctx, testAdminID, DisableOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      2,
	}); err != nil {
		t.Fatal(err)
	}
	client, found, err = f.service.OAuthClient(f.ctx)
	if err != nil || !found || client.Enabled || client.ClientID != "" || client.Revision != 3 {
		t.Fatalf("disabled client = %+v found=%v err=%v", client, found, err)
	}
	var clientID, boundURL sql.NullString
	var secretCiphertext []byte
	if err := f.database.QueryRowContext(f.ctx,
		`SELECT client_id, client_secret_ciphertext, bound_base_url FROM forgejo_identity_oauth_clients`).
		Scan(&clientID, &secretCiphertext, &boundURL); err != nil {
		t.Fatal(err)
	}
	if clientID.Valid || boundURL.Valid || secretCiphertext != nil {
		t.Fatal("disable did not destroy the stored credentials")
	}
	disabled := f.auditEvents(t, audit.ActionForgeOAuthClientDisabled)
	if len(disabled) != 1 || disabled[0].DetailsJSON != `{"oauth_revision":3}` {
		t.Fatalf("disable audit = %+v", disabled)
	}
	// Disabling an already-disabled client is a conflict.
	if err := f.service.DisableOAuthClient(f.ctx, testAdminID, DisableOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      3,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("double disable err = %v", err)
	}
	// Re-enable inserts fresh credentials at the next revision.
	f.saveOAuthClient(t, 3)
	client, _, _ = f.service.OAuthClient(f.ctx)
	if !client.Enabled || client.Revision != 4 {
		t.Fatalf("re-enabled client = %+v", client)
	}
}

func TestOAuthClientAuthorizationAndValidation(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)

	if err := f.service.SaveOAuthClient(f.ctx, testUserID, SaveOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ClientID:                   testClientID,
		ClientSecret:               testClientSecret,
	}); !errors.Is(err, ErrAdminOnly) {
		t.Fatalf("non-admin save err = %v", err)
	}
	if err := f.service.SaveOAuthClient(f.ctx, testAdminID, SaveOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ClientID:                   "bad\tid",
		ClientSecret:               testClientSecret,
	}); !IsValidationError(err) {
		t.Fatalf("bad client id err = %v", err)
	}
	if err := f.service.SaveOAuthClient(f.ctx, testAdminID, SaveOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ClientID:                   testClientID,
		ClientSecret:               "bad secret",
	}); !IsValidationError(err) {
		t.Fatalf("bad secret err = %v", err)
	}
	noEncryption := NewService(f.database, nil, nil, testPublicURL)
	if err := noEncryption.SaveOAuthClient(f.ctx, testAdminID, SaveOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ClientID:                   testClientID,
		ClientSecret:               testClientSecret,
	}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("no-encryption save err = %v", err)
	}
	// The connection fence rejects a save issued against a different id or
	// revision.
	if err := f.service.SaveOAuthClient(f.ctx, testAdminID, SaveOAuthClientInput{
		ExpectedConnectionID:       2,
		ExpectedConnectionRevision: 1,
		ClientID:                   testClientID,
		ClientSecret:               testClientSecret,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong connection id err = %v", err)
	}
}

func TestOAuthClientDisableAtMaximumRevisionIsTerminal(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	f.saveOAuthClient(t, 0)
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE forgejo_identity_oauth_clients SET oauth_revision = ?`, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if err := f.service.DisableOAuthClient(f.ctx, testAdminID, DisableOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      math.MaxInt64,
	}); err != nil {
		t.Fatal(err)
	}
	client, found, err := f.service.OAuthClient(f.ctx)
	if err != nil || !found || client.Enabled || client.Revision != math.MaxInt64 {
		t.Fatalf("terminal disable client = %+v found=%v err=%v", client, found, err)
	}
	// The counter never wraps: re-enabling at the terminal revision fails.
	if err := f.service.SaveOAuthClient(f.ctx, testAdminID, SaveOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      math.MaxInt64,
		ClientID:                   testClientID,
		ClientSecret:               testClientSecret,
	}); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("terminal re-enable err = %v", err)
	}
	if client, _, _ := f.service.OAuthClient(f.ctx); client.Enabled || client.Revision != math.MaxInt64 {
		t.Fatalf("terminal state changed: %+v", client)
	}
}

func TestUnlinkRemovesExactIdentityAndCeremonies(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	f.saveOAuthClient(t, 0)
	identityID := f.insertIdentity(t, testUserID, testRemoteUserID, testRemoteLogin)
	if _, err := f.database.ExecContext(f.ctx, `
INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (zeroblob(32), 1, ?, 'pending', zeroblob(32), zeroblob(32), x'01', ?, ?, 1, 1, ?, ?)`,
		testUserID,
		testPublicURL+CallbackPath,
		testForgeBaseURL,
		formatForgeIdentityTime(testNow),
		formatForgeIdentityTime(testNow.Add(linkTransactionTTL)),
	); err != nil {
		t.Fatal(err)
	}

	// A stale identity id deletes nothing: no identity, no ceremony, no audit.
	if err := f.service.Unlink(f.ctx, UnlinkInput{
		ActorUserID: testUserID,
		SessionID:   testUserSession,
		IdentityID:  identityID + 100,
	}); !errors.Is(err, ErrIdentityStale) {
		t.Fatalf("stale unlink err = %v", err)
	}
	if f.identityCount(t) != 1 || f.ceremonyCount(t) != 1 {
		t.Fatal("stale unlink mutated state")
	}
	if len(f.auditEvents(t, audit.ActionForgeIdentityUnlinked)) != 0 {
		t.Fatal("stale unlink wrote audit")
	}

	// Another user cannot unlink someone else's identity.
	if err := f.service.Unlink(f.ctx, UnlinkInput{
		ActorUserID: testOtherUserID,
		SessionID:   testOtherSession,
		IdentityID:  identityID,
	}); !errors.Is(err, ErrIdentityStale) {
		t.Fatalf("cross-user unlink err = %v", err)
	}

	if err := f.service.Unlink(f.ctx, UnlinkInput{
		ActorUserID: testUserID,
		SessionID:   testUserSession,
		IdentityID:  identityID,
	}); err != nil {
		t.Fatal(err)
	}
	if f.identityCount(t) != 0 || f.ceremonyCount(t) != 0 {
		t.Fatal("unlink left identity or ceremony state")
	}
	events := f.auditEvents(t, audit.ActionForgeIdentityUnlinked)
	if len(events) != 1 || events[0].SubjectType != audit.SubjectTypeForgeIdentity ||
		events[0].SubjectID != "1" || events[0].DetailsJSON != `{"connection_id":1}` {
		t.Fatalf("unlink audit = %+v", events)
	}
	if events[0].ActorUserID == nil || *events[0].ActorUserID != testUserID {
		t.Fatalf("unlink actor = %+v", events[0].ActorUserID)
	}
	f.assertNoSecretMaterial(t, testRemoteUserID)
}

func TestPurgeRequiresDisabledOwner(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	identityID := f.insertIdentity(t, testUserID, testRemoteUserID, testRemoteLogin)

	purge := PurgeInput{
		ActorUserID:  testAdminID,
		SessionID:    testAdminSession,
		TargetUserID: testUserID,
		IdentityID:   identityID,
		ConfirmPurge: true,
	}
	if err := f.service.Purge(f.ctx, purge); !errors.Is(err, ErrIdentityStale) {
		t.Fatalf("purge of enabled owner err = %v", err)
	}
	if f.identityCount(t) != 1 {
		t.Fatal("purge of enabled owner mutated state")
	}

	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE users SET disabled_at = ? WHERE id = ?`, testNow.Format(time.RFC3339Nano), testUserID); err != nil {
		t.Fatal(err)
	}

	nonAdmin := purge
	nonAdmin.ActorUserID = testOtherUserID
	nonAdmin.SessionID = testOtherSession
	if err := f.service.Purge(f.ctx, nonAdmin); !errors.Is(err, ErrAdminOnly) {
		t.Fatalf("non-admin purge err = %v", err)
	}
	unconfirmed := purge
	unconfirmed.ConfirmPurge = false
	if err := f.service.Purge(f.ctx, unconfirmed); !IsValidationError(err) {
		t.Fatalf("unconfirmed purge err = %v", err)
	}
	wrongIdentity := purge
	wrongIdentity.IdentityID = identityID + 5
	if err := f.service.Purge(f.ctx, wrongIdentity); !errors.Is(err, ErrIdentityStale) {
		t.Fatalf("wrong identity purge err = %v", err)
	}

	if err := f.service.Purge(f.ctx, purge); err != nil {
		t.Fatal(err)
	}
	if f.identityCount(t) != 0 {
		t.Fatal("purge left the identity")
	}
	events := f.auditEvents(t, audit.ActionForgeIdentityPurged)
	if len(events) != 1 || events[0].SubjectID != "1" ||
		events[0].ActorUserID == nil || *events[0].ActorUserID != testAdminID {
		t.Fatalf("purge audit = %+v", events)
	}
	f.assertNoSecretMaterial(t, testRemoteUserID)
}

func TestIdentityReadModelsOmitRemoteID(t *testing.T) {
	f := newFixture(t)
	f.insertConnection(t, testForgeBaseURL)
	f.insertIdentity(t, testUserID, testRemoteUserID, testRemoteLogin)

	identity, found, err := f.service.IdentityForUser(f.ctx, testUserID)
	if err != nil || !found {
		t.Fatalf("identity read: found=%v err=%v", found, err)
	}
	if identity.UsernameAtLink != testRemoteLogin || identity.UserID != testUserID || identity.ConnectionID != 1 {
		t.Fatalf("identity = %+v", identity)
	}
	if has, err := f.service.HasIdentities(f.ctx); err != nil || !has {
		t.Fatalf("HasIdentities = %v err=%v", has, err)
	}
	view, err := f.service.AccountForUser(f.ctx, testUserID)
	if err != nil || view.Status != AccountLinked || view.Identity == nil {
		t.Fatalf("account view = %+v err=%v", view, err)
	}
}

func TestAccountViewStates(t *testing.T) {
	f := newFixture(t)
	// No connection at all.
	view, err := f.service.AccountForUser(f.ctx, testUserID)
	if err != nil || view.Status != AccountUnavailable {
		t.Fatalf("no-connection view = %+v err=%v", view, err)
	}
	f.insertConnection(t, testForgeBaseURL)
	// Connection but no OAuth client.
	if view, _ = f.service.AccountForUser(f.ctx, testUserID); view.Status != AccountUnavailable {
		t.Fatalf("unconfigured view = %+v", view)
	}
	f.saveOAuthClient(t, 0)
	view, err = f.service.AccountForUser(f.ctx, testUserID)
	if err != nil || view.Status != AccountReady || view.ConnectionID != 1 ||
		view.ConnectionRevision != 1 || view.OAuthRevision != 1 {
		t.Fatalf("ready view = %+v err=%v", view, err)
	}
	// A stale bound base URL pauses linking.
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE forge_connections SET base_url = ? WHERE id = 1`, testSecondaryBase); err != nil {
		t.Fatal(err)
	}
	if view, _ = f.service.AccountForUser(f.ctx, testUserID); view.Status != AccountUnavailable {
		t.Fatalf("stale bound URL view = %+v", view)
	}
	if _, err := f.database.ExecContext(f.ctx,
		`UPDATE forge_connections SET base_url = ? WHERE id = 1`, testForgeBaseURL); err != nil {
		t.Fatal(err)
	}
	// A live ceremony surfaces as in-progress.
	startLinkForUser(t, f, testUserSession, testUserID)
	if view, _ = f.service.AccountForUser(f.ctx, testUserID); view.Status != AccountInProgress {
		t.Fatalf("in-progress view = %+v", view)
	}
	// Disabled OAuth client is unavailable again.
	if err := f.service.DisableOAuthClient(f.ctx, testAdminID, DisableOAuthClientInput{
		ExpectedConnectionID:       1,
		ExpectedConnectionRevision: 1,
		ExpectedOAuthRevision:      1,
	}); err != nil {
		t.Fatal(err)
	}
	if view, _ = f.service.AccountForUser(f.ctx, testUserID); view.Status != AccountUnavailable {
		t.Fatalf("disabled view = %+v", view)
	}
}
