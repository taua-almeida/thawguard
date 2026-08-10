package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestForgeRepositoryBindingMigrationPreservesExact0045DataAndAppliesOnce(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-forge-binding-upgrade.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	bindingIndex := migrationIndex(t, migrations, "0046_forge_repository_bindings.sql")
	if err := ApplyMigrations(ctx, database, migrations[:bindingIndex]); err != nil {
		t.Fatal(err)
	}
	assertColumnDoesNotExist(t, database, "forge_connections", "binding_revision")
	assertTableDoesNotExist(t, database, "forge_repository_bindings")

	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?);
INSERT INTO user_roles(user_id, role, created_at)
VALUES (1, 'admin', ?);
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (11, 'forgejo', 'https://forge.example.test', 'fixture-org', 'alpha', 'release', 0, ?, ?);
INSERT INTO repository_branches(repository_id, name, protected, setup_status)
VALUES (11, 'release', 1, 'ok');
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (11, 1, 'freezer', 1, ?);
INSERT INTO forge_connections(
  id, provider, display_name, base_url, config_revision, check_generation, created_at, updated_at
)
VALUES (1, 'forgejo', 'Fixture forge', 'https://forge.example.test', 1, 1, ?, ?);
INSERT INTO forgejo_connection_config(
  connection_id, organization_slug, service_pat_ciphertext, service_user_remote_id,
  pat_attested_at, attested_by_user_id
)
VALUES (1, 'fixture-org', x'0102', '42', ?, 1);
INSERT INTO forge_organizations(
  id, connection_id, remote_organization_id, slug, display_name, observed_at
)
VALUES (10, 1, '7', 'fixture-org', 'Fixture Organization', ?);
INSERT INTO forge_visible_repositories(
  connection_id, organization_id, remote_repository_id, owner, name, default_branch,
  private, observed_check_generation, observed_at
)
VALUES (1, 10, '100', 'fixture-org', 'alpha', 'main', 1, 1, ?);
INSERT INTO forge_connection_setup_checks(
  connection_id, config_revision, check_generation, result_code, observed_version,
  visible_repository_count, visible_private_repository_count, checked_at
)
VALUES (1, 1, 1, 'visible_inventory_observed', '15.0.6', 1, 1, ?)`,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
	); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, database, migrations[:bindingIndex+1]); err != nil {
		t.Fatal(err)
	}
	assertColumnExists(t, database, "forge_connections", "binding_revision")
	assertTableExists(t, database, "forge_repository_bindings")
	for _, check := range []struct {
		name  string
		query string
		want  int
	}{
		{name: "connection and revision", query: `SELECT count(*) FROM forge_connections WHERE id = 1 AND binding_revision = 0 AND typeof(binding_revision) = 'integer'`, want: 1},
		{name: "repository", query: `SELECT count(*) FROM repositories WHERE id = 11 AND active = 0 AND default_branch = 'release'`, want: 1},
		{name: "branch", query: `SELECT count(*) FROM repository_branches WHERE repository_id = 11 AND protected = 1 AND setup_status = 'ok'`, want: 1},
		{name: "grant", query: `SELECT count(*) FROM repository_grants WHERE repository_id = 11 AND user_id = 1 AND role = 'freezer'`, want: 1},
		{name: "organization", query: `SELECT count(*) FROM forge_organizations WHERE id = 10 AND remote_organization_id = '7'`, want: 1},
		{name: "preview", query: `SELECT count(*) FROM forge_visible_repositories WHERE remote_repository_id = '100' AND default_branch = 'main'`, want: 1},
		{name: "check", query: `SELECT count(*) FROM forge_connection_setup_checks WHERE check_generation = 1 AND visible_repository_count = 1`, want: 1},
		{name: "no backfill", query: `SELECT count(*) FROM forge_repository_bindings`, want: 0},
	} {
		var got int
		if err := database.QueryRowContext(ctx, check.query).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", check.name, err)
		}
		if got != check.want {
			t.Fatalf("expected %d %s rows, got %d", check.want, check.name, got)
		}
	}

	if err := ApplyMigrations(ctx, database, migrations[:bindingIndex+1]); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0046_forge_repository_bindings'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected forge repository binding migration applied once, got %d", applied)
	}
	assertForeignKeyCheckClean(t, database)
}

func TestForgeRepositoryBindingSchemaEnforcesImmutableIdentityAndRestrictedDeletion(t *testing.T) {
	ctx := context.Background()
	database := openForgePreviewTestDatabase(t)
	insertForgePreviewConnection(t, database, 1, "forgejo", "https://forge.example.test")
	insertForgePreviewConnection(t, database, 2, "gitea", "https://other.example.test")
	if _, err := database.ExecContext(ctx, `
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES
  (11, 'forgejo', 'https://forge.example.test', 'fixture-org', 'alpha', 'main', 1, ?, ?),
  (12, 'codeberg', 'https://forge.example.test', 'fixture-org', 'beta', 'main', 1, ?, ?);
INSERT INTO forge_organizations(id, connection_id, remote_organization_id, slug, display_name, observed_at)
VALUES
  (10, 1, '7', 'fixture-org', 'Fixture Organization', ?),
  (20, 2, '8', 'other-org', 'Other Organization', ?)`,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id)
VALUES (11, 1, 10, '100')`); err != nil {
		t.Fatal(err)
	}

	for _, rejected := range []struct {
		name string
		sql  string
		args []any
	}{
		{name: "duplicate local identity", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES (11, 1, 10, '101')`},
		{name: "duplicate remote identity", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES (12, 1, 10, '100')`},
		{name: "missing local repository", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES (999, 1, 10, '102')`},
		{name: "missing connection", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES (12, 999, 10, '102')`},
		{name: "organization from another connection", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES (12, 1, 20, '102')`},
		{name: "empty remote id", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES (12, 1, 10, '')`},
		{name: "blob remote id", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES (12, 1, 10, x'31')`},
		{name: "oversized remote id", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES (12, 1, 10, ?)`, args: []any{strings.Repeat("1", 129)}},
		{name: "nonnumeric repository id", sql: `INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id) VALUES ('twelve', 1, 10, '102')`},
	} {
		if _, err := database.ExecContext(ctx, rejected.sql, rejected.args...); err == nil {
			t.Fatalf("expected schema to reject %s", rejected.name)
		}
	}
	for _, statement := range []string{
		`UPDATE forge_connections SET binding_revision = -1 WHERE id = 1`,
		`UPDATE forge_connections SET binding_revision = 'next' WHERE id = 1`,
		`DELETE FROM repositories WHERE id = 11`,
		`DELETE FROM forge_connections WHERE id = 1`,
		`DELETE FROM forge_organizations WHERE id = 10`,
	} {
		if _, err := database.ExecContext(ctx, statement); err == nil {
			t.Fatalf("expected statement to be restricted: %s", statement)
		}
	}

	if _, err := database.ExecContext(ctx, `DELETE FROM forge_repository_bindings WHERE repository_id = 11`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = 11`); err != nil {
		t.Fatalf("repository should be deletable after unbind: %v", err)
	}
	assertForeignKeyCheckClean(t, database)
}
