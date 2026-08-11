package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestForgeAccessShadowMigrationPreservesExact0047DataAndAppliesOnce(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-forge-shadow-upgrade.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	shadowIndex := migrationIndex(t, migrations, "0048_forge_access_shadow_snapshot.sql")
	if err := ApplyMigrations(ctx, database, migrations[:shadowIndex]); err != nil {
		t.Fatal(err)
	}
	assertColumnDoesNotExist(t, database, "forge_connections", "access_identity_revision")
	assertTableDoesNotExist(t, database, "forge_access_shadow_runs")
	assertTableDoesNotExist(t, database, "forge_access_shadow_observations")
	assertIndexDoesNotExist(t, database, "idx_forgejo_identities_id_connection")
	assertIndexDoesNotExist(t, database, "idx_forge_repository_bindings_repository_connection")

	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?);
INSERT INTO user_roles(user_id, role, created_at)
VALUES (1, 'admin', ?);
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (11, 'forgejo', 'https://forge.example.test', 'fixture-org', 'alpha', 'main', 1, ?, ?);
INSERT INTO forge_connections(
  id, provider, display_name, base_url, config_revision, check_generation,
  binding_revision, created_at, updated_at
)
VALUES (1, 'forgejo', 'Fixture forge', 'https://forge.example.test', 1, 1, 0, ?, ?);
INSERT INTO forgejo_connection_config(
  connection_id, organization_slug, service_pat_ciphertext, service_user_remote_id,
  pat_attested_at, attested_by_user_id
)
VALUES (1, 'fixture-org', x'0102', '42', ?, 1);
INSERT INTO forge_organizations(
  id, connection_id, remote_organization_id, slug, display_name, observed_at
)
VALUES (10, 1, '7', 'fixture-org', 'Fixture Organization', ?);
INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id)
VALUES (11, 1, 10, '100');
INSERT INTO forgejo_identities(id, connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (21, 1, 1, '77', 'fixture-user', ?);
INSERT INTO forge_connections(
  id, provider, display_name, base_url, config_revision, check_generation,
  binding_revision, created_at, updated_at
)
VALUES (2, 'gitea', 'Identity-free forge', 'https://other.example.test', 1, 0, 0, ?, ?)`,
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

	if err := ApplyMigrations(ctx, database, migrations[:shadowIndex+1]); err != nil {
		t.Fatal(err)
	}
	assertColumnExists(t, database, "forge_connections", "access_identity_revision")
	assertTableExists(t, database, "forge_access_shadow_runs")
	assertTableExists(t, database, "forge_access_shadow_observations")
	assertIndexExists(t, database, "idx_forgejo_identities_id_connection")
	assertIndexExists(t, database, "idx_forge_repository_bindings_repository_connection")
	assertIndexExists(t, database, "idx_forge_access_shadow_runs_single_running")
	for _, check := range []struct {
		name  string
		query string
		want  int
	}{
		{name: "linked connection backfilled to its identity count", query: `SELECT count(*) FROM forge_connections WHERE id = 1 AND access_identity_revision = 1 AND typeof(access_identity_revision) = 'integer'`, want: 1},
		{name: "identity-free connection stays at zero revision", query: `SELECT count(*) FROM forge_connections WHERE id = 2 AND access_identity_revision = 0 AND typeof(access_identity_revision) = 'integer'`, want: 1},
		{name: "exact-0047 zero binding revision preserved with its binding", query: `SELECT count(*) FROM forge_connections WHERE id = 1 AND binding_revision = 0`, want: 1},
		{name: "preserved binding", query: `SELECT count(*) FROM forge_repository_bindings WHERE repository_id = 11 AND remote_repository_id = '100'`, want: 1},
		{name: "preserved identity", query: `SELECT count(*) FROM forgejo_identities WHERE id = 21 AND remote_user_id = '77' AND username_at_link = 'fixture-user'`, want: 1},
		{name: "no backfilled runs", query: `SELECT count(*) FROM forge_access_shadow_runs`, want: 0},
		{name: "no backfilled observations", query: `SELECT count(*) FROM forge_access_shadow_observations`, want: 0},
	} {
		var got int
		if err := database.QueryRowContext(ctx, check.query).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", check.name, err)
		}
		if got != check.want {
			t.Fatalf("expected %d %s rows, got %d", check.want, check.name, got)
		}
	}

	if err := ApplyMigrations(ctx, database, migrations[:shadowIndex+1]); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0048_forge_access_shadow_snapshot'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected forge access shadow migration applied once, got %d", applied)
	}
	assertForeignKeyCheckClean(t, database)
}

// openForgeAccessShadowFixture applies every migration and seeds one bound,
// linked connection: connection 1, organization 10, repositories 11/12 bound
// as remote '100'/'101', and identities 21/22 for users 1/2.
func openForgeAccessShadowFixture(t *testing.T) *sql.DB {
	t.Helper()
	database := openForgePreviewTestDatabase(t)
	if _, err := database.Exec(`
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES
  (1, 'admin@example.test', 'Admin', ?, ?),
  (2, 'dev@example.test', 'Developer', ?, ?);
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES
  (11, 'forgejo', 'https://forge.example.test', 'fixture-org', 'alpha', 'main', 1, ?, ?),
  (12, 'forgejo', 'https://forge.example.test', 'fixture-org', 'beta', 'main', 1, ?, ?);
INSERT INTO forge_connections(
  id, provider, display_name, base_url, config_revision, check_generation,
  binding_revision, access_identity_revision, created_at, updated_at
)
VALUES (1, 'forgejo', 'Fixture forge', 'https://forge.example.test', 1, 1, 2, 2, ?, ?);
INSERT INTO forge_organizations(id, connection_id, remote_organization_id, slug, display_name, observed_at)
VALUES (10, 1, '7', 'fixture-org', 'Fixture Organization', ?);
INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id)
VALUES
  (11, 1, 10, '100'),
  (12, 1, 10, '101');
INSERT INTO forgejo_identities(id, connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES
  (21, 1, 1, '77', 'admin-user', ?),
  (22, 1, 2, '78', 'dev-user', ?)`,
		forgePreviewTimestamp, forgePreviewTimestamp,
		forgePreviewTimestamp, forgePreviewTimestamp,
		forgePreviewTimestamp, forgePreviewTimestamp,
		forgePreviewTimestamp, forgePreviewTimestamp,
		forgePreviewTimestamp, forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
	); err != nil {
		t.Fatal(err)
	}
	return database
}

const forgeAccessShadowLaterTimestamp = "2026-08-01T11:00:00.000000000Z"

func TestForgeAccessShadowRunSchemaEnforcesTruthConstraints(t *testing.T) {
	ctx := context.Background()
	database := openForgeAccessShadowFixture(t)
	// Connection 2 exists so every rejected shape below fails on the checked
	// constraint itself, never on a missing-parent foreign key.
	insertForgePreviewConnection(t, database, 2, "gitea", "https://other.example.test")

	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count, started_at
)
VALUES (1, 1, 1, 1, 2, 2, 2, 2, ?)`, forgePreviewTimestamp); err != nil {
		t.Fatal(err)
	}

	rejected := []struct {
		name string
		sql  string
		args []any
	}{
		{
			name: "second running row for the connection",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at
) VALUES (1, 1, 1, 2, 2, 2, 2, ?)`,
			args: []any{forgePreviewTimestamp},
		},
		{
			name: "running row with a finish time",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at, finished_at
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "running row with counts",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at, present_count
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, 0)`,
			args: []any{forgePreviewTimestamp},
		},
		{
			name: "complete-shaped row without a result",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at,
  present_count, unknown_count, finished_at
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, 1, 1, ?)`,
			args: []any{forgePreviewTimestamp, forgeAccessShadowLaterTimestamp},
		},
		{
			name: "unknown result code",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at,
  result_code, finished_at
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, 'observed', ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "complete without counts",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at,
  result_code, finished_at
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, 'complete', ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "complete with counts exceeding the pair product",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at,
  result_code, present_count, unknown_count, finished_at
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, 'complete', 3, 2, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "failure with pair counts",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at,
  result_code, present_count, unknown_count, finished_at
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, 'unavailable', 0, 0, ?)`,
			args: []any{forgePreviewTimestamp, forgePreviewTimestamp},
		},
		{
			name: "failure without finish",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at, result_code
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, 'unavailable')`,
			args: []any{forgePreviewTimestamp},
		},
		{
			name: "finish before start",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at,
  result_code, finished_at
) VALUES (2, 1, 1, 2, 2, 2, 2, ?, 'unavailable', ?)`,
			args: []any{forgeAccessShadowLaterTimestamp, forgePreviewTimestamp},
		},
		{
			name: "zero identity count",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at
) VALUES (2, 1, 1, 2, 2, 0, 2, ?)`,
			args: []any{forgePreviewTimestamp},
		},
		{
			name: "identity count beyond the alpha limit",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at
) VALUES (2, 1, 1, 2, 2, 11, 2, ?)`,
			args: []any{forgePreviewTimestamp},
		},
		{
			name: "pair product beyond the alpha limit",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at
) VALUES (2, 1, 1, 2, 2, 6, 5, ?)`,
			args: []any{forgePreviewTimestamp},
		},
		{
			name: "missing connection",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at
) VALUES (999, 1, 1, 2, 2, 2, 2, ?)`,
			args: []any{forgePreviewTimestamp},
		},
		{
			name: "malformed start timestamp",
			sql: `INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at
) VALUES (2, 1, 1, 2, 2, 2, 2, '2026-08-01T10:00:00Z')`,
		},
	}
	for _, tc := range rejected {
		if _, err := database.ExecContext(ctx, tc.sql, tc.args...); err == nil {
			t.Fatalf("expected schema to reject %s", tc.name)
		}
	}

	// Terminalizing the running row frees the partial unique index; complete
	// and failure terminal rows are then accepted with exact evidence shapes.
	if _, err := database.ExecContext(ctx, `
UPDATE forge_access_shadow_runs
SET result_code = 'complete', present_count = 1, unknown_count = 1, finished_at = ?
WHERE connection_id = 1 AND result_code IS NULL`, forgeAccessShadowLaterTimestamp); err != nil {
		t.Fatal(err)
	}
	// A zero captured binding revision is the accepted exact-0047 state.
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, config_revision, check_generation, binding_revision,
  access_identity_revision, identity_count, repository_count, started_at,
  result_code, finished_at
) VALUES (1, 1, 1, 0, 2, 2, 2, ?, 'interrupted', ?)`,
		forgePreviewTimestamp, forgeAccessShadowLaterTimestamp); err != nil {
		t.Fatal(err)
	}

	// Deleting the requesting user detaches the run instead of deleting it.
	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 1`); err == nil {
		t.Fatal("expected identity FK to keep the linked user alive")
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM forgejo_identities WHERE id = 21`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	// The complete run's requester detaches to NULL; the interrupted fixture
	// row never had one. Both rows must survive the user deletion.
	var runs, detached int
	if err := database.QueryRowContext(ctx, `
SELECT count(*), count(*) - count(requested_by_user_id) FROM forge_access_shadow_runs`).Scan(&runs, &detached); err != nil {
		t.Fatal(err)
	}
	if runs != 2 || detached != 2 {
		t.Fatalf("expected 2 surviving runs with detached requesters, got runs=%d detached=%d", runs, detached)
	}
	assertForeignKeyCheckClean(t, database)
}

func TestForgeAccessShadowObservationSchemaEnforcesPairEvidence(t *testing.T) {
	ctx := context.Background()
	database := openForgeAccessShadowFixture(t)
	insertForgePreviewConnection(t, database, 2, "gitea", "https://other.example.test")

	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
)
VALUES
  (1, 21, 11, 'direct_collaborator', 5, ?, 'direct_collaborator', 5, ?),
  (1, 21, 12, 'permission_unavailable', 5, ?, 'team_access', 4, ?),
  (1, 22, 11, 'identity_unresolved', 5, ?, NULL, NULL, NULL)`,
		forgeAccessShadowLaterTimestamp, forgeAccessShadowLaterTimestamp,
		forgeAccessShadowLaterTimestamp, forgePreviewTimestamp,
		forgeAccessShadowLaterTimestamp,
	); err != nil {
		t.Fatal(err)
	}

	rejected := []struct {
		name string
		sql  string
	}{
		{
			name: "duplicate pair",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
) VALUES (1, 21, 11, 'team_access', 6, '` + forgeAccessShadowLaterTimestamp + `', 'team_access', 6, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
		{
			name: "unknown reason value",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at
) VALUES (1, 22, 12, 'implicit_access', 5, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
		{
			name: "confirmed latest without matching confirmation",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at
) VALUES (1, 22, 12, 'direct_collaborator', 5, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
		{
			name: "confirmed latest with a different confirmed reason",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
) VALUES (1, 22, 12, 'direct_collaborator', 5, '` + forgeAccessShadowLaterTimestamp + `', 'team_access', 5, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
		{
			name: "unknown reason preserved as confirmation",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
) VALUES (1, 22, 12, 'permission_unavailable', 5, '` + forgeAccessShadowLaterTimestamp + `', 'permission_unavailable', 4, '` + forgePreviewTimestamp + `')`,
		},
		{
			name: "partial preserved confirmation",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason
) VALUES (1, 22, 12, 'permission_unavailable', 5, '` + forgeAccessShadowLaterTimestamp + `', 'team_access')`,
		},
		{
			name: "latest run behind the preserved confirmation",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
) VALUES (1, 22, 12, 'permission_unavailable', 3, '` + forgeAccessShadowLaterTimestamp + `', 'team_access', 4, '` + forgePreviewTimestamp + `')`,
		},
		{
			name: "unknown observation claiming its own run as the earlier confirmation",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
) VALUES (1, 22, 12, 'permission_unavailable', 5, '` + forgeAccessShadowLaterTimestamp + `', 'team_access', 5, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
		{
			name: "latest time behind the preserved confirmation",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at,
  last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
) VALUES (1, 22, 12, 'permission_unavailable', 5, '` + forgePreviewTimestamp + `', 'team_access', 4, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
		{
			name: "identity from another connection",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at
) VALUES (2, 21, 11, 'identity_unresolved', 5, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
		{
			name: "unbound repository",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at
) VALUES (1, 22, 999, 'identity_unresolved', 5, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
		{
			name: "unknown identity",
			sql: `INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id, latest_observed_at
) VALUES (1, 999, 11, 'identity_unresolved', 5, '` + forgeAccessShadowLaterTimestamp + `')`,
		},
	}
	for _, tc := range rejected {
		if _, err := database.ExecContext(ctx, tc.sql); err == nil {
			t.Fatalf("expected schema to reject %s", tc.name)
		}
	}

	// Unlink cascades that identity's observations and no others; unbind
	// cascades that repository's observations the same way.
	if _, err := database.ExecContext(ctx, `DELETE FROM forgejo_identities WHERE id = 21`); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM forge_access_shadow_observations`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("expected one observation after identity cascade, got %d", remaining)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM forge_repository_bindings WHERE repository_id = 11`); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM forge_access_shadow_observations`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("expected no observations after binding cascade, got %d", remaining)
	}
	assertForeignKeyCheckClean(t, database)
}
