package db

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCompanyOIDCAdministratorLoginMigrationPreservesConnectionAndAppliesOnce(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	loginIndex := migrationIndex(t, migrations, "0044_company_oidc_administrator_login.sql")
	if err := ApplyMigrations(ctx, database, migrations[:loginIndex]); err != nil {
		t.Fatal(err)
	}

	const timestamp = "2026-07-29T10:00:00.000000000Z"
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?);
INSERT INTO user_roles(user_id, role, created_at)
VALUES (1, 'admin', ?);
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES ('preserved-session', 1, 'preserved-csrf', '2026-07-30T10:00:00Z', ?);
INSERT INTO company_oidc_connections(
  id, provider_label, issuer, client_id, client_secret_ciphertext, revision, created_at, updated_at
)
VALUES (1, 'Preserved IdP', 'https://id.example.test', 'preserved-client', x'0102', 4, ?, ?);
INSERT INTO company_oidc_allowed_domains(connection_id, domain)
VALUES (1, 'example.test');
INSERT INTO company_oidc_setup_checks(
  connection_id, config_revision, result_code, observed_issuer,
  public_key_candidate_count, checked_at
)
VALUES (1, 4, 'verified', NULL, 2, ?);
INSERT INTO company_oidc_test_sign_in_evidence(connection_id, config_revision, verified_at)
VALUES (1, 4, '2026-07-29T10:02:00.000000000Z');`,
		timestamp,
		timestamp,
		timestamp,
		timestamp,
		timestamp,
		timestamp,
	); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, database, migrations[:loginIndex+1]); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name  string
		query string
		want  int
	}{
		{name: "user", query: `SELECT count(*) FROM users WHERE id = 1`, want: 1},
		{name: "session", query: `SELECT count(*) FROM sessions WHERE id = 'preserved-session'`, want: 1},
		{name: "preserved connection starts disabled at generation one", query: `SELECT count(*) FROM company_oidc_connections WHERE revision = 4 AND enabled = 0 AND activation_generation = 1`, want: 1},
		{name: "domain", query: `SELECT count(*) FROM company_oidc_allowed_domains WHERE domain = 'example.test'`, want: 1},
		{name: "setup evidence", query: `SELECT count(*) FROM company_oidc_setup_checks WHERE result_code = 'verified'`, want: 1},
		{name: "test sign-in evidence", query: `SELECT count(*) FROM company_oidc_test_sign_in_evidence WHERE config_revision = 4`, want: 1},
		{name: "empty identity table", query: `SELECT count(*) FROM company_oidc_identities`, want: 0},
		{name: "empty link transaction table", query: `SELECT count(*) FROM company_oidc_link_transactions`, want: 0},
		{name: "empty login transaction table", query: `SELECT count(*) FROM company_oidc_login_transactions`, want: 0},
		{name: "empty OIDC session table", query: `SELECT count(*) FROM company_oidc_sessions`, want: 0},
	} {
		var got int
		if err := database.QueryRowContext(ctx, check.query).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", check.name, err)
		}
		if got != check.want {
			t.Fatalf("expected %d %s rows, got %d", check.want, check.name, got)
		}
	}

	if err := ApplyMigrations(ctx, database, migrations[:loginIndex+1]); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0044_company_oidc_administrator_login'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected administrator-login migration applied once, got %d", applied)
	}
	assertForeignKeyCheckClean(t, database)
}

func TestCompanyOIDCIdentitySchemaConstrainsSingletonLink(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}

	const timestamp = "2026-07-29T10:00:00.000000000Z"
	const linkedAt = "2026-07-29T10:05:00.000000000Z"
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?), (2, 'second@example.test', 'Second', ?, ?);
INSERT INTO company_oidc_connections(
  id, provider_label, issuer, client_id, client_secret_ciphertext, revision, created_at, updated_at
)
VALUES (1, 'Example IdP', 'https://id.example.test', 'client-id', x'01', 3, ?, ?)`,
		timestamp, timestamp, timestamp, timestamp, timestamp, timestamp,
	); err != nil {
		t.Fatal(err)
	}

	insert := func(connection, user, subject, email, revision, linked any) error {
		_, err := database.ExecContext(ctx, `
INSERT INTO company_oidc_identities(
  connection_id, user_id, issuer, client_id, subject, email, config_revision, linked_at
)
VALUES (?, ?, 'https://id.example.test', 'client-id', ?, ?, ?, ?)`,
			connection, user, subject, email, revision, linked,
		)
		return err
	}

	if err := insert(1, 1, "subject-a", "admin@example.test", 3, linkedAt); err != nil {
		t.Fatal(err)
	}
	if err := insert(1, 2, "subject-b", "second@example.test", 3, linkedAt); err == nil {
		t.Fatal("expected schema to reject a second identity for the singleton connection")
	}
	for _, rejected := range []struct {
		name                                               string
		connection, user, subject, email, revision, linked any
	}{
		{name: "non-singleton connection", connection: 2, user: 1, subject: "s", email: "a@b.c", revision: 3, linked: linkedAt},
		{name: "zero user", connection: 1, user: 0, subject: "s", email: "a@b.c", revision: 3, linked: linkedAt},
		{name: "empty subject", connection: 1, user: 1, subject: "", email: "a@b.c", revision: 3, linked: linkedAt},
		{name: "oversized subject", connection: 1, user: 1, subject: string(make([]byte, 256)), email: "a@b.c", revision: 3, linked: linkedAt},
		{name: "undersized email", connection: 1, user: 1, subject: "s", email: "ab", revision: 3, linked: linkedAt},
		{name: "zero revision", connection: 1, user: 1, subject: "s", email: "a@b.c", revision: 0, linked: linkedAt},
		{name: "noncanonical linked_at", connection: 1, user: 1, subject: "s", email: "a@b.c", revision: 3, linked: "2026-07-29T10:05:00Z"},
	} {
		if _, err := database.ExecContext(ctx, `DELETE FROM company_oidc_identities`); err != nil {
			t.Fatal(err)
		}
		if err := insert(rejected.connection, rejected.user, rejected.subject, rejected.email, rejected.revision, rejected.linked); err == nil {
			t.Fatalf("expected schema to reject %s", rejected.name)
		}
	}

	if err := insert(1, 1, "subject-a", "admin@example.test", 3, linkedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	var identities int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM company_oidc_identities`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if identities != 0 {
		t.Fatalf("expected user deletion to cascade the identity, got %d", identities)
	}
	assertForeignKeyCheckClean(t, database)
}

func TestCompanyOIDCSessionRowsCascadeWithSessions(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}

	const timestamp = "2026-07-29T10:00:00.000000000Z"
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?);
INSERT INTO company_oidc_connections(
  id, provider_label, issuer, client_id, client_secret_ciphertext, revision, created_at, updated_at
)
VALUES (1, 'Example IdP', 'https://id.example.test', 'client-id', x'01', 3, ?, ?);
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES ('oidc-session', 1, 'csrf', '2026-07-30T10:00:00Z', ?);
INSERT INTO company_oidc_sessions(session_id, connection_id, user_id)
VALUES ('oidc-session', 1, 1);`,
		timestamp, timestamp, timestamp, timestamp, timestamp,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := database.ExecContext(ctx, `
INSERT INTO company_oidc_sessions(session_id, connection_id, user_id)
VALUES ('missing-session', 1, 1)`); err == nil {
		t.Fatal("expected schema to reject provenance for a nonexistent session")
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO company_oidc_sessions(session_id, connection_id, user_id)
VALUES ('oidc-session', 2, 1)`); err == nil {
		t.Fatal("expected schema to reject a non-singleton connection id")
	}

	if _, err := database.ExecContext(ctx, `DELETE FROM sessions WHERE id = 'oidc-session'`); err != nil {
		t.Fatal(err)
	}
	var provenance int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM company_oidc_sessions`).Scan(&provenance); err != nil {
		t.Fatal(err)
	}
	if provenance != 0 {
		t.Fatalf("expected session deletion to cascade provenance, got %d", provenance)
	}
	assertForeignKeyCheckClean(t, database)
}
