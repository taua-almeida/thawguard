package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestForgeIdentityMigrationCreatesStrictTables applies everything before
// 0047, seeds prerequisite rows, applies 0047, and probes the strict CHECK,
// UNIQUE, and foreign-key surface of the three new tables.
func TestForgeIdentityMigrationCreatesStrictTables(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-forge-identity.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	identityIndex := migrationIndex(t, migrations, "0047_forgejo_identity_linking.sql")
	if err := ApplyMigrations(ctx, database, migrations[:identityIndex]); err != nil {
		t.Fatal(err)
	}
	assertTableDoesNotExist(t, database, "forgejo_identity_oauth_clients")
	assertTableDoesNotExist(t, database, "forgejo_identity_link_transactions")
	assertTableDoesNotExist(t, database, "forgejo_identities")

	const canonicalTime = "2026-08-10T12:00:00.000000000Z"
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?), (2, 'user@example.test', 'User', ?, ?);
INSERT INTO forge_connections(
  id, provider, display_name, base_url, config_revision, check_generation, created_at, updated_at
)
VALUES (1, 'forgejo', 'Fixture forge', 'https://forge.example.test', 1, 0, ?, ?);
INSERT INTO forgejo_connection_config(
  connection_id, organization_slug, service_pat_ciphertext, pat_attested_at, attested_by_user_id
)
VALUES (1, 'fixture-org', x'0102', ?, 1);`,
		canonicalTime, canonicalTime, canonicalTime, canonicalTime,
		canonicalTime, canonicalTime, canonicalTime); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	// Idempotent bookkeeping: a second apply is a no-op.
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}

	valid := []string{
		`INSERT INTO forgejo_identity_oauth_clients(connection_id, enabled, client_id, client_secret_ciphertext, bound_base_url, oauth_revision)
VALUES (1, 1, 'client-a', x'01', 'https://forge.example.test', 1)`,
		`INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (zeroblob(32), 1, 2, 'pending', zeroblob(32), zeroblob(32), x'01',
  'https://thawguard.example.test/account/forgejo/callback', 'https://forge.example.test', 1, 1,
  '2026-08-10T12:00:00.000000000Z', '2026-08-10T12:10:00.000000000Z')`,
		`INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 2, '9223372036854775807', 'fixture-user', '2026-08-10T12:00:00.000000000Z')`,
	}
	for _, statement := range valid {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatalf("valid insert failed: %v\n%s", err, statement)
		}
	}

	invalid := []struct {
		name      string
		statement string
	}{
		{"oauth enabled without credentials", `INSERT INTO forgejo_identity_oauth_clients(connection_id, enabled, client_id, client_secret_ciphertext, bound_base_url, oauth_revision)
VALUES (99, 1, NULL, NULL, NULL, 1)`},
		{"oauth disabled with credentials", `INSERT INTO forgejo_identity_oauth_clients(connection_id, enabled, client_id, client_secret_ciphertext, bound_base_url, oauth_revision)
VALUES (99, 0, 'client-b', x'01', 'https://forge.example.test', 1)`},
		{"oauth zero revision", `INSERT INTO forgejo_identity_oauth_clients(connection_id, enabled, client_id, client_secret_ciphertext, bound_base_url, oauth_revision)
VALUES (99, 1, 'client-b', x'01', 'https://forge.example.test', 0)`},
		{"transaction bad status", `INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (zeroblob(31) || x'01', 1, 1, 'completed', zeroblob(32), zeroblob(32), x'01',
  'https://thawguard.example.test/account/forgejo/callback', 'https://forge.example.test', 1, 1,
  '2026-08-10T12:00:00.000000000Z', '2026-08-10T12:10:00.000000000Z')`},
		{"transaction short digest", `INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (zeroblob(16), 1, 1, 'pending', zeroblob(32), zeroblob(32), x'01',
  'https://thawguard.example.test/account/forgejo/callback', 'https://forge.example.test', 1, 1,
  '2026-08-10T12:00:00.000000000Z', '2026-08-10T12:10:00.000000000Z')`},
		{"transaction wrong callback path", `INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (zeroblob(31) || x'02', 1, 1, 'pending', zeroblob(32), zeroblob(32), x'01',
  'https://thawguard.example.test/other/callback', 'https://forge.example.test', 1, 1,
  '2026-08-10T12:00:00.000000000Z', '2026-08-10T12:10:00.000000000Z')`},
		{"transaction expiry not after creation", `INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (zeroblob(31) || x'03', 1, 1, 'pending', zeroblob(32), zeroblob(32), x'01',
  'https://thawguard.example.test/account/forgejo/callback', 'https://forge.example.test', 1, 1,
  '2026-08-10T12:00:00.000000000Z', '2026-08-10T12:00:00.000000000Z')`},
		{"second live transaction per user", `INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (zeroblob(31) || x'04', 1, 2, 'pending', zeroblob(32), zeroblob(32), x'01',
  'https://thawguard.example.test/account/forgejo/callback', 'https://forge.example.test', 1, 1,
  '2026-08-10T12:00:00.000000000Z', '2026-08-10T12:10:00.000000000Z')`},
		{"identity zero remote id", `INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 1, '0', 'user-zero', '2026-08-10T12:00:00.000000000Z')`},
		{"identity non-numeric remote id", `INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 1, '12a', 'user-alpha', '2026-08-10T12:00:00.000000000Z')`},
		{"identity leading zero remote id", `INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 1, '07', 'user-zero-pad', '2026-08-10T12:00:00.000000000Z')`},
		{"identity remote id above signed int64", `INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 1, '9223372036854775808', 'user-overflow', '2026-08-10T12:00:00.000000000Z')`},
		{"identity remote id with embedded NUL", `INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 1, CAST(x'310078' AS TEXT), 'user-nul', '2026-08-10T12:00:00.000000000Z')`},
		{"identity duplicate user", `INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 2, '55', 'user-second', '2026-08-10T12:00:00.000000000Z')`},
		{"identity duplicate remote id", `INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 1, '9223372036854775807', 'user-dup', '2026-08-10T12:00:00.000000000Z')`},
		{"identity missing user", `INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, 99, '60', 'user-missing', '2026-08-10T12:00:00.000000000Z')`},
	}
	for _, tc := range invalid {
		if _, err := database.ExecContext(ctx, tc.statement); err == nil {
			t.Errorf("%s: insert unexpectedly succeeded", tc.name)
		}
	}

	// ON DELETE RESTRICT: neither the identity's user nor its connection can
	// be deleted while the identity exists.
	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 2`); err == nil {
		t.Error("deleting an identity owner unexpectedly succeeded")
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM forge_connections WHERE id = 1`); err == nil {
		t.Error("deleting a connection with identities unexpectedly succeeded")
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM forgejo_identities`); err != nil {
		t.Fatal(err)
	}
	// With identities gone, deleting the connection cascades the OAuth
	// client and ceremony rows.
	if _, err := database.ExecContext(ctx, `DELETE FROM forge_connections WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"forgejo_identity_oauth_clients", "forgejo_identity_link_transactions"} {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("expected %s to cascade on connection delete, found %d rows", table, count)
		}
	}

	// AUTOINCREMENT: a deleted identity row id is never reused.
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_connections(
  id, provider, display_name, base_url, config_revision, check_generation, created_at, updated_at
)
VALUES (2, 'forgejo', 'Fixture forge', 'https://forge.example.test', 1, 0, ?, ?)`,
		canonicalTime, canonicalTime); err != nil {
		t.Fatal(err)
	}
	var firstID int64
	if err := database.QueryRowContext(ctx, `
INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (2, 2, '71', 'user-a', ?) RETURNING id`, canonicalTime).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM forgejo_identities WHERE id = ?`, firstID); err != nil {
		t.Fatal(err)
	}
	var secondID int64
	if err := database.QueryRowContext(ctx, `
INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (2, 2, '72', 'user-b', ?) RETURNING id`, canonicalTime).Scan(&secondID); err != nil {
		t.Fatal(err)
	}
	if secondID <= firstID {
		t.Fatalf("identity row id was reused: first=%d second=%d", firstID, secondID)
	}

	var sql string
	if err := database.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'forgejo_identities'`).Scan(&sql); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "AUTOINCREMENT") {
		t.Fatal("forgejo_identities must declare AUTOINCREMENT so row ids are never reused")
	}
}
