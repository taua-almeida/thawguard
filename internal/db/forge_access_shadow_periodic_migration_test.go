package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestForgeAccessShadowPeriodicMigrationUpgradesExact0048Additively(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-forge-shadow-periodic-upgrade.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	periodicIndex := migrationIndex(t, migrations, "0049_forge_access_shadow_periodic.sql")
	if err := ApplyMigrations(ctx, database, migrations[:periodicIndex]); err != nil {
		t.Fatal(err)
	}
	assertTableDoesNotExist(t, database, "forge_access_shadow_periodic_config")
	assertColumnDoesNotExist(t, database, "forge_access_shadow_runs", "run_trigger")

	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Admin', ?, ?);
INSERT INTO forge_connections(
  id, provider, display_name, base_url, config_revision, check_generation,
  binding_revision, access_identity_revision, created_at, updated_at
)
VALUES (1, 'forgejo', 'Fixture forge', 'https://forge.example.test', 1, 1, 1, 1, ?, ?);
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  result_code, present_count, unknown_count, finished_at, started_at
)
VALUES (1, NULL, 1, 1, 1, 1, 1, 1, 'complete', 1, 0, ?, ?)`,
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
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (11, 'forgejo', 'https://forge.example.test', 'fixture-org', 'alpha', 'main', 1, ?, ?);
INSERT INTO forge_organizations(id, connection_id, remote_organization_id, slug, display_name, observed_at)
VALUES (10, 1, '7', 'fixture-org', 'Fixture Organization', ?);
INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id)
VALUES (11, 1, 10, '100');
INSERT INTO forgejo_identities(id, connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (21, 1, 1, '77', 'admin-user', ?);
INSERT INTO forge_access_shadow_observations(
  connection_id, identity_id, repository_id, latest_reason, latest_run_id,
  latest_observed_at, last_confirmed_reason, last_confirmed_run_id, last_confirmed_at
)
VALUES (1, 21, 11, 'direct_collaborator', 1, ?, 'direct_collaborator', 1, ?)`,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
		forgePreviewTimestamp,
	); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, database, migrations[:periodicIndex+1]); err != nil {
		t.Fatal(err)
	}
	assertTableExists(t, database, "forge_access_shadow_periodic_config")
	assertColumnExists(t, database, "forge_access_shadow_runs", "run_trigger")

	var trigger string
	var requester sql.NullInt64
	if err := database.QueryRowContext(ctx, `
SELECT run_trigger, requested_by_user_id
FROM forge_access_shadow_runs`).Scan(&trigger, &requester); err != nil {
		t.Fatal(err)
	}
	if trigger != "manual" || requester.Valid {
		t.Fatalf("upgraded run trigger/requester = %q/%+v", trigger, requester)
	}
	var observation string
	if err := database.QueryRowContext(ctx, `
SELECT latest_reason || ':' || latest_run_id || ':' || last_confirmed_reason || ':' || last_confirmed_run_id
FROM forge_access_shadow_observations
WHERE connection_id = 1 AND identity_id = 21 AND repository_id = 11`).Scan(&observation); err != nil {
		t.Fatal(err)
	}
	if observation != "direct_collaborator:1:direct_collaborator:1" {
		t.Fatalf("0049 changed retained observation %q", observation)
	}

	// An old-shaped insert still receives the additive manual default. That
	// storage fact does not make an older binary a supported mixed-version
	// writer: it cannot understand periodic state or attribution.
	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  result_code, finished_at, started_at
)
VALUES (1, NULL, 1, 1, 0, 1, 1, 1, 'interrupted', ?, ?)`,
		forgeAccessShadowLaterTimestamp,
		forgeAccessShadowLaterTimestamp,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `
SELECT run_trigger
FROM forge_access_shadow_runs
ORDER BY id DESC
LIMIT 1`).Scan(&trigger); err != nil {
		t.Fatal(err)
	}
	if trigger != "manual" {
		t.Fatalf("old-shaped insert trigger = %q", trigger)
	}

	if err := ApplyMigrations(ctx, database, migrations[:periodicIndex+1]); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `
SELECT count(*) FROM schema_migrations
WHERE version = '0049_forge_access_shadow_periodic'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("periodic migration applied %d times", applied)
	}
	assertForeignKeyCheckClean(t, database)
}

func TestForgeAccessShadowPeriodicSchemaEnforcesConfigurationAndTriggerTruth(t *testing.T) {
	ctx := context.Background()
	database := openForgeAccessShadowFixture(t)

	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_access_shadow_periodic_config(connection_id, revision, next_due_at)
VALUES (1, 1, NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE forge_access_shadow_periodic_config
SET revision = 2, next_due_at = ?
WHERE connection_id = 1`, forgeAccessShadowLaterTimestamp); err != nil {
		t.Fatal(err)
	}

	rejectedConfig := []struct {
		name string
		sql  string
	}{
		{name: "zero revision", sql: `UPDATE forge_access_shadow_periodic_config SET revision = 0 WHERE connection_id = 1`},
		{name: "noncanonical due", sql: `UPDATE forge_access_shadow_periodic_config SET next_due_at = '2026-08-01T11:00:00Z' WHERE connection_id = 1`},
		{name: "text connection id", sql: `INSERT INTO forge_access_shadow_periodic_config(connection_id, revision) VALUES ('1', 1)`},
	}
	for _, tc := range rejectedConfig {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := database.ExecContext(ctx, tc.sql); err == nil {
				t.Fatal("invalid periodic configuration was accepted")
			}
		})
	}

	if _, err := database.ExecContext(ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  run_trigger, result_code, finished_at, started_at
)
VALUES (1, NULL, 1, 1, 2, 2, 2, 2, 'periodic', 'interrupted', ?, ?)`,
		forgeAccessShadowLaterTimestamp,
		forgeAccessShadowLaterTimestamp,
	); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		trigger   string
		requester any
	}{
		{name: "unknown trigger", trigger: "scheduled", requester: nil},
		{name: "periodic human requester", trigger: "periodic", requester: int64(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := database.ExecContext(ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  run_trigger, result_code, finished_at, started_at
)
VALUES (1, ?, 1, 1, 2, 2, 2, 2, ?, 'interrupted', ?, ?)`,
				tc.requester,
				tc.trigger,
				forgeAccessShadowLaterTimestamp,
				forgeAccessShadowLaterTimestamp,
			); err == nil {
				t.Fatal("invalid run trigger/requester shape was accepted")
			}
		})
	}

	if _, err := database.ExecContext(ctx, `
DELETE FROM forgejo_identities WHERE connection_id = 1;
DELETE FROM forge_repository_bindings WHERE connection_id = 1;
DELETE FROM forge_connections WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	var configs int
	if err := database.QueryRowContext(ctx, `
SELECT count(*) FROM forge_access_shadow_periodic_config`).Scan(&configs); err != nil {
		t.Fatal(err)
	}
	if configs != 0 {
		t.Fatalf("periodic config survived connection deletion: %d", configs)
	}
	assertForeignKeyCheckClean(t, database)
}
