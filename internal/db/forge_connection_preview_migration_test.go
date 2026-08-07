package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

const forgePreviewTimestamp = "2026-08-01T10:00:00.000000000Z"

func TestForgeConnectionPreviewMigrationPreservesExact0044DataAndAppliesOnce(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-forge-preview-upgrade.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	previewIndex := migrationIndex(t, migrations, "0045_forge_connection_preview.sql")
	if err := ApplyMigrations(ctx, database, migrations[:previewIndex]); err != nil {
		t.Fatal(err)
	}
	assertTableDoesNotExist(t, database, "forge_connections")

	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?);
INSERT INTO user_roles(user_id, role, created_at)
VALUES (1, 'admin', ?);
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES ('preserved-session', 1, 'preserved-csrf', '2026-08-02T10:00:00Z', ?);
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (11, 'forgejo', 'https://forge.example.test', 'fixture-owner', 'fixture-repo', 'main', 1, ?, ?);
INSERT INTO repository_branches(repository_id, name, protected, setup_status)
VALUES (11, 'main', 1, 'ok');
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (11, 1, 'freezer', 1, ?);
INSERT INTO company_oidc_connections(
  id, provider_label, issuer, client_id, client_secret_ciphertext, revision, created_at, updated_at
)
VALUES (1, 'Preserved IdP', 'https://id.example.test', 'preserved-client', x'0102', 4, ?, ?);
INSERT INTO company_oidc_allowed_domains(connection_id, domain)
VALUES (1, 'example.test');
INSERT INTO audit_events(actor_user_id, action, subject_type, subject_id, details_json, created_at)
VALUES (1, 'repository.created', 'repository', '11', '{}', ?)`,
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

	if err := ApplyMigrations(ctx, database, migrations[:previewIndex+1]); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"forge_connections",
		"forgejo_connection_config",
		"forge_organizations",
		"forge_visible_repositories",
		"forge_connection_setup_checks",
	} {
		assertTableExists(t, database, name)
	}
	for _, check := range []struct {
		name  string
		query string
		want  int
	}{
		{name: "user", query: `SELECT count(*) FROM users WHERE id = 1`, want: 1},
		{name: "role", query: `SELECT count(*) FROM user_roles WHERE user_id = 1 AND role = 'admin'`, want: 1},
		{name: "session", query: `SELECT count(*) FROM sessions WHERE id = 'preserved-session'`, want: 1},
		{name: "repository", query: `SELECT count(*) FROM repositories WHERE id = 11 AND owner = 'fixture-owner'`, want: 1},
		{name: "branch", query: `SELECT count(*) FROM repository_branches WHERE repository_id = 11 AND name = 'main'`, want: 1},
		{name: "grant", query: `SELECT count(*) FROM repository_grants WHERE repository_id = 11 AND user_id = 1 AND role = 'freezer'`, want: 1},
		{name: "oidc connection", query: `SELECT count(*) FROM company_oidc_connections WHERE id = 1 AND revision = 4`, want: 1},
		{name: "oidc domain", query: `SELECT count(*) FROM company_oidc_allowed_domains WHERE domain = 'example.test'`, want: 1},
		{name: "audit event", query: `SELECT count(*) FROM audit_events WHERE action = 'repository.created' AND subject_id = '11'`, want: 1},
		{name: "empty forge connections", query: `SELECT count(*) FROM forge_connections`, want: 0},
		{name: "empty forgejo config", query: `SELECT count(*) FROM forgejo_connection_config`, want: 0},
		{name: "empty forge organizations", query: `SELECT count(*) FROM forge_organizations`, want: 0},
		{name: "empty visible repositories", query: `SELECT count(*) FROM forge_visible_repositories`, want: 0},
		{name: "empty setup checks", query: `SELECT count(*) FROM forge_connection_setup_checks`, want: 0},
	} {
		var got int
		if err := database.QueryRowContext(ctx, check.query).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", check.name, err)
		}
		if got != check.want {
			t.Fatalf("expected %d %s rows, got %d", check.want, check.name, got)
		}
	}

	if err := ApplyMigrations(ctx, database, migrations[:previewIndex+1]); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0045_forge_connection_preview'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected forge connection preview migration applied once, got %d", applied)
	}
	assertForeignKeyCheckClean(t, database)
}

func openForgePreviewTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-forge-preview.db")))
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
	return database
}

func insertForgePreviewConnection(t *testing.T, database *sql.DB, id int64, provider, baseURL string) {
	t.Helper()
	if _, err := database.Exec(`
INSERT INTO forge_connections(id, provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES (?, ?, 'Fixture forge', ?, 1, 0, ?, ?)`,
		id, provider, baseURL, forgePreviewTimestamp, forgePreviewTimestamp,
	); err != nil {
		t.Fatal(err)
	}
}

func TestForgeConnectionPreviewSchemaEnforcesShapesUniquenessAndCascades(t *testing.T) {
	ctx := context.Background()
	database := openForgePreviewTestDatabase(t)

	insertForgePreviewConnection(t, database, 1, "forgejo", "https://forge.example.test")

	rejectedConnections := []struct {
		name string
		sql  string
		args []any
	}{
		{
			name: "uppercase provider",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('Forgejo', 'x', 'https://a.example.test', 1, 0, ?, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "provider with slash",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('for/gejo', 'x', 'https://b.example.test', 1, 0, ?, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "oversized provider",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES (?, 'x', 'https://c.example.test', 1, 0, ?, ?)`,
			args: []any{strings.Repeat("a", 33), forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "empty display name",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('gitea', '', 'https://d.example.test', 1, 0, ?, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "zero revision",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('gitea', 'x', 'https://e.example.test', 0, 0, ?, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "negative generation",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('gitea', 'x', 'https://f.example.test', 1, -1, ?, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "noncanonical timestamp",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('gitea', 'x', 'https://g.example.test', 1, 0, '2026-08-01T10:00:00Z', ?)`,
			args: []any{forgePreviewTimestamp},
		},
		{
			name: "duplicate provider and base URL",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('forgejo', 'other', 'https://forge.example.test', 1, 0, ?, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "second forgejo connection at another URL",
			sql: `INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('forgejo', 'other', 'https://second.example.test', 1, 0, ?, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
	}
	for _, rejected := range rejectedConnections {
		if _, err := database.ExecContext(ctx, rejected.sql, rejected.args...); err == nil {
			t.Fatalf("expected schema to reject %s", rejected.name)
		}
	}

	// The partial unique index constrains only the forgejo provider: another
	// provider token may appear on several rows.
	insertForgePreviewConnection(t, database, 2, "gitea", "https://gitea-one.example.test")
	insertForgePreviewConnection(t, database, 3, "gitea", "https://gitea-two.example.test")

	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?)`, forgePreviewTimestamp, forgePreviewTimestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO forgejo_connection_config(
  connection_id, organization_slug, service_pat_ciphertext, service_user_remote_id, pat_attested_at, attested_by_user_id
)
VALUES (1, 'fixture-org', x'0102', '42', ?, 1)`, forgePreviewTimestamp); err != nil {
		t.Fatal(err)
	}
	rejectedConfigs := []struct {
		name string
		sql  string
	}{
		{
			name: "empty organization slug",
			sql: `INSERT INTO forgejo_connection_config(connection_id, organization_slug, service_pat_ciphertext, pat_attested_at)
VALUES (2, '', x'01', '` + forgePreviewTimestamp + `')`,
		},
		{
			name: "empty PAT ciphertext",
			sql: `INSERT INTO forgejo_connection_config(connection_id, organization_slug, service_pat_ciphertext, pat_attested_at)
VALUES (2, 'org', x'', '` + forgePreviewTimestamp + `')`,
		},
		{
			name: "empty service user remote id",
			sql: `INSERT INTO forgejo_connection_config(connection_id, organization_slug, service_pat_ciphertext, service_user_remote_id, pat_attested_at)
VALUES (2, 'org', x'01', '', '` + forgePreviewTimestamp + `')`,
		},
		{
			name: "noncanonical attestation timestamp",
			sql: `INSERT INTO forgejo_connection_config(connection_id, organization_slug, service_pat_ciphertext, pat_attested_at)
VALUES (2, 'org', x'01', '2026-08-01T10:00:00Z')`,
		},
	}
	for _, rejected := range rejectedConfigs {
		if _, err := database.ExecContext(ctx, rejected.sql); err == nil {
			t.Fatalf("expected schema to reject %s", rejected.name)
		}
	}
	// Deleting the attesting user clears attribution without deleting config.
	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	var attestedBy sql.NullInt64
	if err := database.QueryRowContext(ctx, `SELECT attested_by_user_id FROM forgejo_connection_config WHERE connection_id = 1`).Scan(&attestedBy); err != nil {
		t.Fatal(err)
	}
	if attestedBy.Valid {
		t.Fatalf("expected user deletion to clear attestation attribution, got %d", attestedBy.Int64)
	}

	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_organizations(id, connection_id, remote_organization_id, slug, display_name, observed_at)
VALUES (10, 1, '7', 'fixture-org', 'Fixture Organization', ?)`, forgePreviewTimestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_organizations(id, connection_id, remote_organization_id, slug, display_name, observed_at)
VALUES (11, 1, '8', 'second-org', 'Second Organization', ?)`, forgePreviewTimestamp); err == nil {
		t.Fatal("expected schema to reject a second organization for one connection")
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_organizations(id, connection_id, remote_organization_id, slug, display_name, observed_at)
VALUES (12, 2, '7', '', 'x', ?)`, forgePreviewTimestamp); err == nil {
		t.Fatal("expected schema to reject an empty organization slug")
	}

	insertVisible := func(connection, organization int64, remoteID string) error {
		_, err := database.ExecContext(ctx, `
INSERT INTO forge_visible_repositories(
  connection_id, organization_id, remote_repository_id, owner, name, default_branch,
  private, observed_check_generation, observed_at
)
VALUES (?, ?, ?, 'fixture-org', 'fixture-repo', 'main', 0, 1, ?)`,
			connection, organization, remoteID, forgePreviewTimestamp)
		return err
	}
	if err := insertVisible(1, 10, "100"); err != nil {
		t.Fatal(err)
	}
	if err := insertVisible(1, 10, "100"); err == nil {
		t.Fatal("expected schema to reject a duplicate remote repository id per connection")
	}
	if err := insertVisible(2, 10, "101"); err == nil {
		t.Fatal("expected schema to reject a preview row whose organization belongs to another connection")
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_visible_repositories(
  connection_id, organization_id, remote_repository_id, owner, name, default_branch,
  private, observed_check_generation, observed_at
)
VALUES (1, 10, '102', 'fixture-org', 'fixture-repo-two', 'main', 2, 1, ?)`, forgePreviewTimestamp); err == nil {
		t.Fatal("expected schema to reject a non-boolean private flag")
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_visible_repositories(
  connection_id, organization_id, remote_repository_id, owner, name, default_branch,
  private, observed_check_generation, observed_at
)
VALUES (1, 10, '103', 'fixture-org', 'fixture-repo-three', 'main', 1, 0, ?)`, forgePreviewTimestamp); err == nil {
		t.Fatal("expected schema to reject a zero observed check generation")
	}

	insertCheck := func(code string, repositories, privateRepositories any) error {
		_, err := database.ExecContext(ctx, `
INSERT INTO forge_connection_setup_checks(
  connection_id, config_revision, check_generation, result_code, observed_version,
  visible_repository_count, visible_private_repository_count, checked_at
)
VALUES (1, 1, 1, ?, '15.0.6', ?, ?, ?)
ON CONFLICT(connection_id) DO UPDATE SET
  result_code = excluded.result_code,
  visible_repository_count = excluded.visible_repository_count,
  visible_private_repository_count = excluded.visible_private_repository_count`,
			code, repositories, privateRepositories, forgePreviewTimestamp)
		return err
	}
	if err := insertCheck("visible_inventory_observed", 3, 1); err != nil {
		t.Fatal(err)
	}
	if err := insertCheck("visible_inventory_observed_private_read_unproven", 3, 0); err != nil {
		t.Fatal(err)
	}
	if err := insertCheck("unavailable", nil, nil); err != nil {
		t.Fatal(err)
	}
	rejectedChecks := []struct {
		name                          string
		code                          string
		repositories, privateVersions any
	}{
		{name: "unknown result code", code: "mystery", repositories: nil, privateVersions: nil},
		{name: "observed success without counts", code: "visible_inventory_observed", repositories: nil, privateVersions: nil},
		{name: "observed success without private proof", code: "visible_inventory_observed", repositories: 3, privateVersions: 0},
		{name: "private count above total", code: "visible_inventory_observed", repositories: 1, privateVersions: 2},
		{name: "unproven with private count", code: "visible_inventory_observed_private_read_unproven", repositories: 3, privateVersions: 1},
		{name: "failure with counts", code: "authentication_failed", repositories: 3, privateVersions: 0},
	}
	for _, rejected := range rejectedChecks {
		if err := insertCheck(rejected.code, rejected.repositories, rejected.privateVersions); err == nil {
			t.Fatalf("expected schema to reject %s", rejected.name)
		}
	}

	// Deleting the connection cascades config, organization, preview, and
	// check evidence in one statement.
	if _, err := database.ExecContext(ctx, `DELETE FROM forge_connections WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	for _, remaining := range []struct {
		name  string
		query string
	}{
		{name: "config", query: `SELECT count(*) FROM forgejo_connection_config WHERE connection_id = 1`},
		{name: "organizations", query: `SELECT count(*) FROM forge_organizations WHERE connection_id = 1`},
		{name: "visible repositories", query: `SELECT count(*) FROM forge_visible_repositories WHERE connection_id = 1`},
		{name: "setup checks", query: `SELECT count(*) FROM forge_connection_setup_checks WHERE connection_id = 1`},
	} {
		var got int
		if err := database.QueryRowContext(ctx, remaining.query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != 0 {
			t.Fatalf("expected connection deletion to cascade %s, got %d rows", remaining.name, got)
		}
	}
	assertForeignKeyCheckClean(t, database)
}

func TestForgeConnectionAutoincrementNeverReusesIds(t *testing.T) {
	ctx := context.Background()
	database := openForgePreviewTestDatabase(t)

	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('forgejo', 'First', 'https://forge.example.test', 1, 0, ?, ?)`,
		forgePreviewTimestamp, forgePreviewTimestamp); err != nil {
		t.Fatal(err)
	}
	var firstID int64
	if err := database.QueryRowContext(ctx, `SELECT id FROM forge_connections`).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM forge_connections`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES ('forgejo', 'Second', 'https://forge.example.test', 1, 0, ?, ?)`,
		forgePreviewTimestamp, forgePreviewTimestamp); err != nil {
		t.Fatal(err)
	}
	var secondID int64
	if err := database.QueryRowContext(ctx, `SELECT id FROM forge_connections`).Scan(&secondID); err != nil {
		t.Fatal(err)
	}
	if secondID <= firstID {
		t.Fatalf("expected recreated connection id above %d, got %d", firstID, secondID)
	}
	assertForeignKeyCheckClean(t, database)
}
