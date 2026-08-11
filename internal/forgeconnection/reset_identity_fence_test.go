package forgeconnection

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestResetFencesIdentityLinkingState proves the connection reset is fenced
// by the identity-linking OAuth revision and blocked entirely while linked
// Forgejo identities exist.
func TestResetFencesIdentityLinkingState(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)
	canonicalNow := formatForgeConnectionTime(time.Now())
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forgejo_identity_oauth_clients(connection_id, enabled, client_id, client_secret_ciphertext, bound_base_url, oauth_revision)
VALUES (?, 1, 'fixture-client', x'01', 'https://forge.example.test', 4)`, connectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (?, 1, '55', 'fixture-user', ?)`, connectionID, canonicalNow); err != nil {
		t.Fatal(err)
	}

	// The OAuth revision fence rejects a reset confirmed before the OAuth
	// client changed; an absent row would be revision 0.
	staleOAuth := ResetInput{
		ExpectedConnectionID:  connectionID,
		ExpectedRevision:      1,
		ExpectedOAuthRevision: 3,
		ConfirmReset:          true,
	}
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, staleOAuth); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale OAuth revision reset err = %v", err)
	}

	// Linked identities block the reset even with matching fences.
	blocked := staleOAuth
	blocked.ExpectedOAuthRevision = 4
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, blocked); !errors.Is(err, ErrIdentitiesExist) {
		t.Fatalf("reset with identities err = %v", err)
	}
	if _, found, err := fixture.service.Current(fixture.ctx); err != nil || !found {
		t.Fatalf("connection should survive a blocked reset: found=%v err=%v", found, err)
	}

	if _, err := fixture.database.ExecContext(fixture.ctx, `DELETE FROM forgejo_identities`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, blocked); err != nil {
		t.Fatal(err)
	}
	// The OAuth client row cascades away with the connection.
	var count int
	if err := fixture.database.QueryRowContext(fixture.ctx,
		`SELECT COUNT(*) FROM forgejo_identity_oauth_clients`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected the OAuth client row to cascade, found %d", count)
	}
}

// TestEditFreezesURLWhileIdentitiesExist proves an installation-URL edit is
// rejected while any Forgejo identity is linked, even before the first
// successful check binds the connection, so a linked remote id can never be
// silently re-homed onto a different installation.
func TestEditFreezesURLWhileIdentitiesExist(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (?, 1, '55', 'fixture-user', ?)`, connectionID, formatForgeConnectionTime(time.Now())); err != nil {
		t.Fatal(err)
	}

	retarget := EditInput{
		DisplayName:            "Fixture Forge",
		BaseURL:                "https://moved.example.test",
		OrganizationSlug:       "fixture-org",
		ReplacementPAT:         testServicePAT,
		ReplacementPATAttested: true,
		ExpectedConnectionID:   connectionID,
		ExpectedRevision:       1,
	}
	err := fixture.service.Edit(fixture.ctx, fixture.adminID, retarget)
	if !IsValidationError(err) || !strings.Contains(err.Error(), "identities are linked") {
		t.Fatalf("URL edit with identities err = %v", err)
	}
	connection, found, loadErr := fixture.service.Current(fixture.ctx)
	if loadErr != nil || !found || connection.BaseURL != "https://forge.example.test" {
		t.Fatalf("connection after rejected edit = %+v found=%v err=%v", connection, found, loadErr)
	}

	// Same-destination edits stay ordinary while identities exist.
	rename := validEditInput(connectionID, 1)
	rename.DisplayName = "Renamed Forge"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, rename); err != nil {
		t.Fatalf("display-name edit with identities err = %v", err)
	}

	// With the identity gone, the destination edit succeeds again.
	if _, err := fixture.database.ExecContext(fixture.ctx, `DELETE FROM forgejo_identities`); err != nil {
		t.Fatal(err)
	}
	retarget.ExpectedRevision = 2
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, retarget); err != nil {
		t.Fatalf("URL edit after unlink err = %v", err)
	}
}
