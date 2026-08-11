package forgeidentity

import (
	"math"
	"testing"
	"time"
)

func (f *fixture) accessIdentityRevision(t *testing.T) int64 {
	t.Helper()
	var revision int64
	if err := f.database.QueryRowContext(f.ctx, `
SELECT access_identity_revision FROM forge_connections WHERE id = 1`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

func (f *fixture) setAccessIdentityRevision(t *testing.T, revision int64) {
	t.Helper()
	if _, err := f.database.ExecContext(f.ctx, `
UPDATE forge_connections SET access_identity_revision = ? WHERE id = 1`, revision); err != nil {
		t.Fatal(err)
	}
}

func TestAccessIdentityRevisionAdvancesOnLinkUnlinkAndPurge(t *testing.T) {
	f, _ := newProviderFixture(t)
	if f.accessIdentityRevision(t) != 0 {
		t.Fatalf("initial revision = %d", f.accessIdentityRevision(t))
	}

	start := startLinkForUser(t, f, testUserSession, testUserID)
	result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(0x11), "code=fixture-authorization-code"),
		SessionID:    testUserSession,
		BrowserToken: start.BrowserToken,
	})
	if err != nil || result != LinkLinked {
		t.Fatalf("link result = %q err = %v", result, err)
	}
	if f.accessIdentityRevision(t) != 1 {
		t.Fatalf("revision after link = %d", f.accessIdentityRevision(t))
	}

	var identityID int64
	if err := f.database.QueryRowContext(f.ctx, `
SELECT id FROM forgejo_identities WHERE user_id = ?`, testUserID).Scan(&identityID); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Unlink(f.ctx, UnlinkInput{
		ActorUserID: testUserID,
		SessionID:   testUserSession,
		IdentityID:  identityID,
	}); err != nil {
		t.Fatal(err)
	}
	if f.accessIdentityRevision(t) != 2 {
		t.Fatalf("revision after unlink = %d", f.accessIdentityRevision(t))
	}

	purgedID := f.insertIdentity(t, testOtherUserID, "778", "purged-user")
	if _, err := f.database.ExecContext(f.ctx, `
UPDATE users SET disabled_at = ? WHERE id = ?`,
		testNow.Format(time.RFC3339Nano), testOtherUserID); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Purge(f.ctx, PurgeInput{
		ActorUserID:  testAdminID,
		SessionID:    testAdminSession,
		TargetUserID: testOtherUserID,
		IdentityID:   purgedID,
		ConfirmPurge: true,
	}); err != nil {
		t.Fatal(err)
	}
	if f.accessIdentityRevision(t) != 3 {
		t.Fatalf("revision after purge = %d", f.accessIdentityRevision(t))
	}
}

func TestAccessIdentityRevisionNeverWrapsAtMaximum(t *testing.T) {
	f, _ := newProviderFixture(t)
	f.setAccessIdentityRevision(t, math.MaxInt64)

	// A link at the maximum revision is blocked instead of wrapping.
	start := startLinkForUser(t, f, testUserSession, testUserID)
	result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(0x11), "code=fixture-authorization-code"),
		SessionID:    testUserSession,
		BrowserToken: start.BrowserToken,
	})
	if err != nil || result != LinkConfigurationUnavailable {
		t.Fatalf("link at maximum revision = %q err = %v", result, err)
	}
	if f.identityCount(t) != 0 {
		t.Fatal("blocked link created an identity")
	}
	if f.accessIdentityRevision(t) != math.MaxInt64 {
		t.Fatalf("revision changed to %d", f.accessIdentityRevision(t))
	}

	// Unlink remains available as a terminal same-revision reduction.
	identityID := f.insertIdentity(t, testUserID, "779", "terminal-user")
	if err := f.service.Unlink(f.ctx, UnlinkInput{
		ActorUserID: testUserID,
		SessionID:   testUserSession,
		IdentityID:  identityID,
	}); err != nil {
		t.Fatal(err)
	}
	if f.identityCount(t) != 0 {
		t.Fatal("terminal unlink left the identity")
	}
	if f.accessIdentityRevision(t) != math.MaxInt64 {
		t.Fatalf("terminal reduction changed the revision to %d", f.accessIdentityRevision(t))
	}
}
