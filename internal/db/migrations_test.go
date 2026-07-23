package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadMigrationsSortsSQLFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"002_second.sql": "select 2;",
		"001_first.sql":  "select 1;",
		"README.md":      "ignore me",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	migrations, err := LoadMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 2 {
		t.Fatalf("expected 2 migrations, got %d", len(migrations))
	}
	if migrations[0].Name != "001_first.sql" || migrations[1].Name != "002_second.sql" {
		t.Fatalf("migrations not sorted: %+v", migrations)
	}
}

func TestOpenAndApplyMigrationsAgainstSQLite(t *testing.T) {
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

	assertPragmaInt(t, database, "foreign_keys", 1)
	assertPragmaInt(t, database, "busy_timeout", int((5 * time.Second).Milliseconds()))
	assertPragmaText(t, database, "journal_mode", "wal")
	assertTableExists(t, database, "repository_webhook_secrets")
	assertColumnExists(t, database, "status_publication_intents", "updated_at")
	assertIndexExists(t, database, "idx_status_publication_intents_idempotency")
	assertTableExists(t, database, "status_publication_attempts")
	assertIndexExists(t, database, "idx_status_publication_attempts_recent")
	assertStatusPublicationLiveModesAllowed(t, database)
	assertColumnExists(t, database, "branch_freezes", "scheduled")
	assertColumnExists(t, database, "branch_freezes", "planned_ends_at")
	assertColumnExists(t, database, "branch_freezes", "needs_recompute")
	assertIndexExists(t, database, "idx_branch_freezes_scheduled_due")
	assertIndexExists(t, database, "idx_branch_freezes_planned_unfreeze_due")
	assertIndexExists(t, database, "idx_branch_freezes_recompute")
	var indexSQL string
	if err := database.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_branch_freezes_planned_unfreeze_due'`).Scan(&indexSQL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(indexSQL, "scheduled = 1") || !strings.Contains(indexSQL, "status = 'active' AND planned_ends_at IS NOT NULL") {
		t.Fatalf("expected generalized active planned-unfreeze index, got %q", indexSQL)
	}
	assertIndexDoesNotExist(t, database, "idx_branch_freezes_scheduled_recompute")
	assertColumnExists(t, database, "jobs", "repository_id")
	assertColumnExists(t, database, "jobs", "generation")
	assertIndexExists(t, database, "idx_jobs_one_repository_reconciliation")
	assertIndexExists(t, database, "idx_jobs_repository_reconciliation_due")
	assertColumnExists(t, database, "sessions", "csrf_token")
	assertIndexExists(t, database, "idx_sessions_expires_at")
	assertTableExists(t, database, "user_roles")
	assertColumnExists(t, database, "users", "disabled_at")
	assertColumnExists(t, database, "users", "must_change_password")
	assertColumnExists(t, database, "repositories", "enforcement_state")
	assertColumnExists(t, database, "repositories", "enforcement_failure_reason")
	assertColumnExists(t, database, "repositories", "enforcement_failed_at")
	assertEnforcementStateConstraint(t, database)
	assertTableExists(t, database, "repository_branches")

	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0001_initial").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected initial migration to be recorded once, got %d", applied)
	}

	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0001_initial").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected idempotent migration record, got %d", applied)
	}

	_, err = database.ExecContext(ctx, `INSERT INTO sessions(id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`, "missing-user", 999, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	if err == nil {
		t.Fatal("expected foreign-key violation for session with missing user")
	}
}

func TestApplyMigrationsAddsSetupChecksToExistingInitialDatabase(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	if _, err := database.ExecContext(ctx, ensureMigrationsTableSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
CREATE TABLE repositories (
  id INTEGER PRIMARY KEY,
  default_branch TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE repository_branches (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  protected INTEGER NOT NULL DEFAULT 0,
  setup_status TEXT NOT NULL DEFAULT 'unknown',
  last_checked_at TEXT,
  UNIQUE (repository_id, name)
);
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'freezer', 'thaw_approver', 'viewer')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE branch_freezes (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  branch TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('scheduled', 'active', 'ended', 'cancelled')),
  reason TEXT NOT NULL,
  starts_at TEXT,
  ends_at TEXT,
  created_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY,
  actor_user_id INTEGER,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
INSERT INTO repositories(id, default_branch, active) VALUES (7001, 'main', 1), (7002, '', 1);
INSERT INTO repository_branches(repository_id, name, protected, setup_status, last_checked_at)
VALUES (7001, 'production', 1, 'ok', '2026-07-01T00:00:00Z');
INSERT INTO users(id, email, display_name, password_hash, role, created_at, updated_at)
VALUES
  (101, 'admin@example.test', 'Admin', 'hash', 'admin', '2026-07-08T12:00:00Z', '2026-07-08T12:00:00Z'),
  (102, 'freezer@example.test', 'Freezer', 'hash', 'freezer', '2026-07-08T12:00:00Z', '2026-07-08T12:00:00Z');
INSERT INTO sessions(id, user_id, expires_at, created_at)
VALUES ('legacy-session', 101, '2026-07-09T12:00:00Z', '2026-07-08T12:00:00Z');
INSERT INTO branch_freezes(id, repository_id, branch, status, reason, starts_at, ends_at, created_at, updated_at)
VALUES
  (7001, 7001, 'main', 'scheduled', 'future freeze', '2026-07-10T18:00:00Z', NULL, '2026-07-08T12:00:00Z', '2026-07-08T12:00:00Z'),
  (7002, 7001, 'release/1.4', 'ended', 'historical freeze', '2026-06-01T18:00:00Z', '2026-06-02T18:00:00Z', '2026-06-01T12:00:00Z', '2026-06-02T18:00:00Z'),
  (7003, 7001, 'main', 'ended', 'older duplicate freeze', '2026-05-01T18:00:00Z', '2026-05-02T18:00:00Z', '2026-05-01T12:00:00Z', '2026-05-02T18:00:00Z');`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, "0001_initial", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	assertTableExists(t, database, "setup_checks")
	assertTableExists(t, database, "status_results")
	assertColumnExists(t, database, "status_results", "target_branch")
	assertTableExists(t, database, "pull_request_cache")
	assertTableExists(t, database, "status_publication_intents")
	assertColumnExists(t, database, "status_publication_intents", "updated_at")
	assertTableExists(t, database, "status_publication_attempts")
	assertTableExists(t, database, "webhook_deliveries")
	assertColumnExists(t, database, "webhook_deliveries", "processing_started_at")
	assertTableExists(t, database, "repository_webhook_secrets")
	assertColumnExists(t, database, "branch_freezes", "scheduled")
	assertColumnExists(t, database, "branch_freezes", "planned_ends_at")
	assertColumnExists(t, database, "branch_freezes", "needs_recompute")
	assertColumnExists(t, database, "sessions", "csrf_token")
	assertTableExists(t, database, "user_roles")
	assertUserRoles(t, database, 101, []string{"admin", "freezer", "thaw_approver", "viewer"})
	assertUserRoles(t, database, 102, []string{"freezer"})
	assertUserEnabledWithoutForcedPasswordChange(t, database, 101)
	assertUserEnabledWithoutForcedPasswordChange(t, database, 102)
	var sessionCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id = 'legacy-session'`).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 0 {
		t.Fatalf("expected legacy sessions without csrf tokens to be removed, got %d", sessionCount)
	}
	var scheduledFlag int
	if err := database.QueryRowContext(ctx, `SELECT scheduled FROM branch_freezes WHERE id = 7001`).Scan(&scheduledFlag); err != nil {
		t.Fatal(err)
	}
	if scheduledFlag != 1 {
		t.Fatalf("expected existing scheduled freeze row to be backfilled, got %d", scheduledFlag)
	}

	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0002_setup_checks").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected setup checks migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0005_status_results").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected status results migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0006_pull_request_cache").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected pull request cache migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0007_status_publication_intents").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected status publication intents migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0008_webhook_deliveries").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected webhook deliveries migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0009_repository_webhook_secrets").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected repository webhook secrets migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0010_webhook_delivery_claims").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected webhook delivery claims migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0011_status_publication_idempotency").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected status publication idempotency migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0012_status_publication_attempts").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected status publication attempts migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0013_status_publication_live_modes").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected status publication live modes migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0015_scheduled_freeze_windows").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected scheduled freeze windows migration to be recorded once, got %d", applied)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0016_relax_scheduled_freeze_branch_duplicates").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected scheduled freeze duplicate relaxation migration to be recorded once, got %d", applied)
	}
	assertColumnExists(t, database, "repositories", "enforcement_state")
	var enforcementState string
	if err := database.QueryRowContext(ctx, `SELECT enforcement_state FROM repositories WHERE id = 7001`).Scan(&enforcementState); err != nil {
		t.Fatal(err)
	}
	if enforcementState != "setup_incomplete" {
		t.Fatalf("expected existing repository to migrate to setup_incomplete enforcement, got %q", enforcementState)
	}

	assertManagedBranch(t, database, 7001, "main", 0, "unknown")
	assertManagedBranch(t, database, 7001, "release/1.4", 0, "unknown")
	assertManagedBranch(t, database, 7001, "production", 1, "ok")
	var branchCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_branches WHERE repository_id = 7001`).Scan(&branchCount); err != nil {
		t.Fatal(err)
	}
	if branchCount != 3 {
		t.Fatalf("expected duplicate default/freeze branches to backfill once each, got %d rows", branchCount)
	}
	var lastCheckedAt sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT last_checked_at FROM repository_branches WHERE repository_id = 7001 AND name = 'production'`).Scan(&lastCheckedAt); err != nil {
		t.Fatal(err)
	}
	if !lastCheckedAt.Valid || lastCheckedAt.String != "2026-07-01T00:00:00Z" {
		t.Fatalf("expected existing branch setup evidence to be preserved, got %+v", lastCheckedAt)
	}
	var emptyDefaultBranches int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_branches WHERE repository_id = 7002`).Scan(&emptyDefaultBranches); err != nil {
		t.Fatal(err)
	}
	if emptyDefaultBranches != 0 {
		t.Fatalf("expected no managed branch for repository with empty default branch, got %d rows", emptyDefaultBranches)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, "0020_backfill_managed_repository_branches").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected managed branch backfill migration to be recorded once, got %d", applied)
	}
	assertWebhookDeliveriesAreRepositoryScoped(t, database)
	assertIndexExists(t, database, "idx_audit_events_subject_type_id")
	assertIndexExists(t, database, "idx_status_publication_intents_idempotency")
	assertIndexExists(t, database, "idx_status_publication_attempts_recent")
	assertIndexExists(t, database, "idx_branch_freezes_scheduled_due")
	assertIndexExists(t, database, "idx_branch_freezes_planned_unfreeze_due")
	assertIndexExists(t, database, "idx_branch_freezes_recompute")
	assertIndexDoesNotExist(t, database, "idx_branch_freezes_scheduled_recompute")
	assertIndexDoesNotExist(t, database, "idx_branch_freezes_one_active")
	assertIndexDoesNotExist(t, database, "idx_branch_freezes_one_open")
	assertStatusPublicationLiveModesAllowed(t, database)
}

func TestApplyMigrationsDedupesStatusPublicationIntents(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	if _, err := database.ExecContext(ctx, ensureMigrationsTableSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
CREATE TABLE repositories (
  id INTEGER PRIMARY KEY,
  default_branch TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE repository_branches (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  protected INTEGER NOT NULL DEFAULT 0,
  setup_status TEXT NOT NULL DEFAULT 'unknown',
  last_checked_at TEXT,
  UNIQUE (repository_id, name)
);
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'freezer', 'thaw_approver', 'viewer')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE branch_freezes (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  branch TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('scheduled', 'active', 'ended', 'cancelled')),
  reason TEXT NOT NULL,
  starts_at TEXT,
  ends_at TEXT,
  created_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY,
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE status_results (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE
);
CREATE TABLE status_publication_intents (
  id INTEGER PRIMARY KEY,
  status_result_id INTEGER NOT NULL REFERENCES status_results(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  pull_request_index INTEGER NOT NULL,
  target_branch TEXT NOT NULL,
  head_sha TEXT NOT NULL,
  context TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('success', 'failure', 'pending', 'error')),
  description TEXT NOT NULL,
  target_url TEXT,
  delivery_mode TEXT NOT NULL CHECK (delivery_mode IN ('local_record')),
  created_at TEXT NOT NULL
);
INSERT INTO repositories(id, active) VALUES (1, 1);
INSERT INTO status_results(id, repository_id) VALUES (1, 1), (2, 1), (3, 1);
INSERT INTO status_publication_intents(id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, target_url, delivery_mode, created_at)
VALUES
  (1, 1, 1, 42, 'main', 'abc123', 'thawguard/freeze', 'failure', 'old failure', NULL, 'local_record', '2026-06-30T12:00:00Z'),
  (2, 2, 1, 43, 'release', 'abc123', 'thawguard/freeze', 'success', 'latest state', NULL, 'local_record', '2026-06-30T12:05:00Z'),
  (3, 3, 1, 44, 'main', 'def456', 'thawguard/freeze', 'failure', 'other head', NULL, 'local_record', '2026-06-30T12:10:00Z');
`); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"0001_initial", "0002_setup_checks", "0003_active_freeze_uniqueness", "0004_audit_subject_type_index", "0005_status_results", "0006_pull_request_cache", "0007_status_publication_intents", "0008_webhook_deliveries", "0009_repository_webhook_secrets", "0010_webhook_delivery_claims"} {
		if _, err := database.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}

	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	assertColumnExists(t, database, "status_publication_intents", "updated_at")
	assertIndexExists(t, database, "idx_status_publication_intents_idempotency")

	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM status_publication_intents`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected duplicate publication intent to be removed, got %d rows", count)
	}
	var statusResultID int64
	var description string
	var updatedAt string
	if err := database.QueryRowContext(ctx, `SELECT status_result_id, description, updated_at FROM status_publication_intents WHERE repository_id = 1 AND head_sha = 'abc123' AND context = 'thawguard/freeze' AND delivery_mode = 'local_record'`).Scan(&statusResultID, &description, &updatedAt); err != nil {
		t.Fatal(err)
	}
	if statusResultID != 2 || description != "latest state" || updatedAt != "2026-06-30T12:05:00Z" {
		t.Fatalf("expected latest duplicate row to win, got status_result_id=%d description=%q updated_at=%q", statusResultID, description, updatedAt)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO status_publication_intents(status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, delivery_mode, created_at, updated_at) VALUES (3, 1, 45, 'main', 'abc123', 'thawguard/freeze', 'failure', 'duplicate', 'local_record', '2026-06-30T12:15:00Z', '2026-06-30T12:15:00Z')`); err == nil {
		t.Fatal("expected unique idempotency key to reject duplicate publication intent")
	}
}

func TestApplyMigrationsRebuildsWebhookDeliveriesForRepositoryScopedClaims(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	if _, err := database.ExecContext(ctx, ensureMigrationsTableSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
CREATE TABLE repositories (
  id INTEGER PRIMARY KEY,
  default_branch TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE repository_branches (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  protected INTEGER NOT NULL DEFAULT 0,
  setup_status TEXT NOT NULL DEFAULT 'unknown',
  last_checked_at TEXT,
  UNIQUE (repository_id, name)
);
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'freezer', 'thaw_approver', 'viewer')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE branch_freezes (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  branch TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('scheduled', 'active', 'ended', 'cancelled')),
  reason TEXT NOT NULL,
  starts_at TEXT,
  ends_at TEXT,
  created_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY,
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE webhook_deliveries (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER REFERENCES repositories(id) ON DELETE SET NULL,
  delivery_id TEXT NOT NULL,
  event TEXT NOT NULL,
  action TEXT,
  received_at TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  processed_at TEXT,
  error TEXT,
  UNIQUE (delivery_id)
);
CREATE TABLE status_results (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE
);
CREATE TABLE status_publication_intents (
  id INTEGER PRIMARY KEY,
  status_result_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  pull_request_index INTEGER NOT NULL,
  target_branch TEXT NOT NULL,
  head_sha TEXT NOT NULL,
  context TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('success', 'failure', 'pending', 'error')),
  description TEXT NOT NULL,
  target_url TEXT,
  delivery_mode TEXT NOT NULL CHECK (delivery_mode IN ('local_record')),
  created_at TEXT NOT NULL
);
INSERT INTO repositories(id, active) VALUES (1, 1), (2, 1);
INSERT INTO webhook_deliveries(id, repository_id, delivery_id, event, action, received_at, verified, processed_at, error)
VALUES
  (1, 1, 'retry-me', 'pull_request', 'opened', '2026-06-30T12:00:00.000000000Z', 1, '2026-06-30T12:00:01.000000000Z', 'webhook processing failed'),
  (2, 1, 'terminal-validation', 'pull_request', 'opened', '2026-06-30T12:00:02.000000000Z', 1, '2026-06-30T12:00:03.000000000Z', 'webhook validation failed'),
  (3, 1, 'unprocessed', 'pull_request', 'opened', '2026-06-30T12:00:04.000000000Z', 1, NULL, NULL);
`); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"0001_initial", "0002_setup_checks", "0003_active_freeze_uniqueness", "0004_audit_subject_type_index", "0005_status_results", "0006_pull_request_cache", "0007_status_publication_intents", "0008_webhook_deliveries", "0009_repository_webhook_secrets"} {
		if _, err := database.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}

	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	assertColumnExists(t, database, "webhook_deliveries", "processing_started_at")

	var retryProcessedAt sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT processed_at FROM webhook_deliveries WHERE delivery_id = 'retry-me'`).Scan(&retryProcessedAt); err != nil {
		t.Fatal(err)
	}
	if retryProcessedAt.Valid {
		t.Fatalf("expected retryable processing failure to clear processed_at, got %q", retryProcessedAt.String)
	}
	var terminalProcessedAt sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT processed_at FROM webhook_deliveries WHERE delivery_id = 'terminal-validation'`).Scan(&terminalProcessedAt); err != nil {
		t.Fatal(err)
	}
	if !terminalProcessedAt.Valid {
		t.Fatal("expected terminal validation delivery to keep processed_at")
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO webhook_deliveries(repository_id, delivery_id, event, received_at, verified) VALUES (2, 'retry-me', 'pull_request', '2026-06-30T12:00:05.000000000Z', 1)`); err != nil {
		t.Fatalf("expected repository-scoped duplicate delivery id after rebuild: %v", err)
	}
}

func TestImmediatePlannedUnfreezeMigrationPreservesFreezeDataAndAppliesOnce(t *testing.T) {
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
	plannedUnfreezeIndex := migrationIndex(t, migrations, "0023_immediate_planned_unfreezes.sql")
	if err := ApplyMigrations(ctx, database, migrations[:plannedUnfreezeIndex]); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (77, 'forgejo', 'https://codeberg.org', 'example', 'release', 'main', 1, '2026-07-12T10:00:00.000000000Z', '2026-07-12T10:00:00.000000000Z');
INSERT INTO branch_freezes(id, repository_id, branch, status, reason, starts_at, scheduled, planned_ends_at, created_at, updated_at)
VALUES
  (701, 77, 'main', 'active', 'immediate', '2026-07-12T10:00:00.000000000Z', 0, '2026-07-13T09:00:00.000000000Z', '2026-07-12T10:00:00.000000000Z', '2026-07-12T10:00:00.000000000Z'),
  (702, 77, 'release', 'active', 'scheduled', '2026-07-12T11:00:00.000000000Z', 1, '2026-07-13T10:00:00.000000000Z', '2026-07-12T10:00:00.000000000Z', '2026-07-12T11:00:00.000000000Z');`); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, database, migrations[:plannedUnfreezeIndex+1]); err != nil {
		t.Fatal(err)
	}
	assertIndexExists(t, database, "idx_branch_freezes_planned_unfreeze_due")
	assertIndexExists(t, database, "idx_branch_freezes_recompute")
	var preserved int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM branch_freezes WHERE id IN (701, 702) AND planned_ends_at IS NOT NULL`).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	if preserved != 2 {
		t.Fatalf("expected immediate and scheduled planned ends preserved, got %d", preserved)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0023_immediate_planned_unfreezes'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected migration recorded once, got %d", applied)
	}
}

func TestRepositoryReconciliationMigrationPreservesExistingJobsAndAppliesOnce(t *testing.T) {
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
	reconciliationIndex := migrationIndex(t, migrations, "0024_repository_reconciliation_jobs.sql")
	if err := ApplyMigrations(ctx, database, migrations[:reconciliationIndex]); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO jobs(id, type, payload_json, run_at, locked_at, attempts, last_error, created_at)
VALUES (77, 'legacy_job', '{"safe":true}', '2026-07-13T10:00:00.000000000Z', NULL, 2, 'legacy safe error', '2026-07-13T09:00:00.000000000Z');
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, enforcement_state, created_at, updated_at)
VALUES
  (78, 'forgejo', 'https://codeberg.org', 'example', 'unhealthy', 'main', 1, 'unhealthy', '2026-07-13T09:00:00.000000000Z', '2026-07-13T09:00:00.000000000Z'),
  (79, 'forgejo', 'https://codeberg.org', 'example', 'pending-marker', 'main', 1, 'active', '2026-07-13T09:00:00.000000000Z', '2026-07-13T09:00:00.000000000Z');
INSERT INTO branch_freezes(id, repository_id, branch, status, reason, starts_at, needs_recompute, created_at, updated_at)
VALUES (790, 79, 'main', 'ended', 'pending convergence', '2026-07-13T08:00:00.000000000Z', 1, '2026-07-13T08:00:00.000000000Z', '2026-07-13T09:00:00.000000000Z')`); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	assertColumnExists(t, database, "jobs", "repository_id")
	assertColumnExists(t, database, "jobs", "generation")
	assertIndexExists(t, database, "idx_jobs_one_repository_reconciliation")
	assertIndexExists(t, database, "idx_jobs_repository_reconciliation_due")
	var payload string
	var repositoryID sql.NullInt64
	var generation, attempts int
	if err := database.QueryRowContext(ctx, `SELECT payload_json, repository_id, generation, attempts FROM jobs WHERE id = 77`).Scan(&payload, &repositoryID, &generation, &attempts); err != nil {
		t.Fatal(err)
	}
	if payload != `{"safe":true}` || repositoryID.Valid || generation != 0 || attempts != 2 {
		t.Fatalf("expected legacy job preserved, payload=%q repository=%+v generation=%d attempts=%d", payload, repositoryID, generation, attempts)
	}
	var backfilled int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE type = 'reconcile_repository_enforcement' AND repository_id IN (78, 79) AND generation = 1`).Scan(&backfilled); err != nil {
		t.Fatal(err)
	}
	if backfilled != 2 {
		t.Fatalf("expected unhealthy and pending-marker repositories backfilled, got %d", backfilled)
	}
	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0024_repository_reconciliation_jobs'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected reconciliation migration applied once, got %d", applied)
	}
}

func TestRepositoryGrantsCutoverSnapshotsEffectiveLegacyAuthorityWithAuditEvidence(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, DefaultConfig(filepath.Join(t.TempDir(), "thawguard-cutover-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	cutoverIndex := migrationIndex(t, migrations, "0032_repository_grants_cutover.sql")
	if err := ApplyMigrations(ctx, database, migrations[:cutoverIndex]); err != nil {
		t.Fatal(err)
	}

	const createdAt = "2026-07-22T09:00:00.000000000Z"
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, password_hash, role, disabled_at, must_change_password, created_at, updated_at)
VALUES
  (1, 'override@example.test', 'Explicit Override', 'hash', 'admin', NULL, 0, ?, ?),
  (2, 'fallback-freezer@example.test', 'Fallback Freezer', 'hash', 'freezer', NULL, 0, ?, ?),
  (3, 'fallback-admin@example.test', 'Fallback Admin', 'hash', 'admin', NULL, 0, ?, ?),
  (4, 'admin-approver@example.test', 'Admin Approver', 'hash', 'viewer', NULL, 0, ?, ?),
  (5, 'disabled@example.test', 'Disabled Freezer', 'hash', 'viewer', ?, 0, ?, ?),
  (6, 'manual@example.test', 'Manual Existing', 'hash', 'viewer', NULL, 0, ?, ?),
  (7, 'admin-only@example.test', 'Admin Only', 'hash', 'admin', NULL, 0, ?, ?);
INSERT INTO user_roles(user_id, role, created_at) VALUES
  (1, 'viewer', ?),
  (4, 'admin', ?),
  (4, 'thaw_approver', ?),
  (5, 'freezer', ?),
  (6, 'viewer', ?),
  (6, 'freezer', ?),
  (7, 'admin', ?);
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES
  (10, 'forgejo', 'https://forge.example.test', 'acme', 'api', 'main', 1, ?, ?),
  (11, 'forgejo', 'https://forge.example.test', 'acme', 'web', 'main', 1, ?, ?);
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (10, 6, 'viewer', 7, '2026-07-22T08:00:00.000000000Z');`,
		createdAt, createdAt, createdAt, createdAt, createdAt, createdAt, createdAt, createdAt,
		"2026-07-22T08:30:00.000000000Z", createdAt, createdAt, createdAt, createdAt, createdAt,
		createdAt, createdAt, createdAt, createdAt, createdAt, createdAt, createdAt,
		createdAt, createdAt, createdAt, createdAt,
	); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}

	// Any explicit role row suppresses users.role fallback. User 1 therefore
	// keeps Viewer only and must not regain Admin from users.role.
	assertUserRoles(t, database, 1, []string{"viewer"})
	assertUserRoles(t, database, 3, []string{"admin"})
	assertUserRoles(t, database, 4, []string{"admin", "thaw_approver"})

	expected := map[string]bool{
		"10/1/viewer": true, "11/1/viewer": true,
		"10/2/freezer": true, "11/2/freezer": true,
		"10/4/thaw_approver": true, "11/4/thaw_approver": true,
		"10/5/freezer": true, "11/5/freezer": true,
		"10/6/viewer": true, "11/6/viewer": true,
		"10/6/freezer": true, "11/6/freezer": true,
	}
	rows, err := database.QueryContext(ctx, `SELECT repository_id, user_id, role FROM repository_grants`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for rows.Next() {
		var repositoryID, userID int64
		var role string
		if err := rows.Scan(&repositoryID, &userID, &role); err != nil {
			t.Fatal(err)
		}
		got[fmt.Sprintf("%d/%d/%s", repositoryID, userID, role)] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(expected) {
		t.Fatalf("expected %d grants, got %d: %v", len(expected), len(got), got)
	}
	for key := range expected {
		if !got[key] {
			t.Fatalf("missing snapshotted grant %s: %v", key, got)
		}
	}

	var manualActor sql.NullInt64
	var manualAt string
	if err := database.QueryRowContext(ctx, `
SELECT granted_by_user_id, granted_at
FROM repository_grants
WHERE repository_id = 10 AND user_id = 6 AND role = 'viewer'`).Scan(&manualActor, &manualAt); err != nil {
		t.Fatal(err)
	}
	if !manualActor.Valid || manualActor.Int64 != 7 || manualAt != "2026-07-22T08:00:00.000000000Z" {
		t.Fatalf("expected existing manual metadata preserved, actor=%+v at=%q", manualActor, manualAt)
	}

	var timestampCount, migratedCount int
	if err := database.QueryRowContext(ctx, `
SELECT count(DISTINCT granted_at), count(*)
FROM repository_grants
WHERE NOT (repository_id = 10 AND user_id = 6 AND role = 'viewer')`).Scan(&timestampCount, &migratedCount); err != nil {
		t.Fatal(err)
	}
	if timestampCount != 1 || migratedCount != 11 {
		t.Fatalf("expected 11 migrated rows sharing one timestamp, rows=%d timestamps=%d", migratedCount, timestampCount)
	}
	var auditCount, badActorCount, matchingTimestampCount int
	if err := database.QueryRowContext(ctx, `
SELECT
  count(*),
  count(actor_user_id),
  sum(CASE WHEN created_at IN (
    SELECT granted_at FROM repository_grants
    WHERE NOT (repository_id = 10 AND user_id = 6 AND role = 'viewer')
  ) THEN 1 ELSE 0 END)
FROM audit_events
WHERE action = 'repository_grant.added'
  AND subject_type = 'repository'
  AND json_valid(details_json)
  AND json_extract(details_json, '$.actor_kind') = 'system'
  AND json_extract(details_json, '$.actor_role') = 'migration'
  AND json_extract(details_json, '$.provenance') = 'legacy_authorization_cutover'`).Scan(&auditCount, &badActorCount, &matchingTimestampCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 11 || badActorCount != 0 || matchingTimestampCount != 11 {
		t.Fatalf("expected one system audit per migrated grant, count=%d actors=%d timestamps=%d", auditCount, badActorCount, matchingTimestampCount)
	}

	if _, err := database.ExecContext(ctx, `
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (12, 'forgejo', 'https://forge.example.test', 'acme', 'future', 'main', 1, ?, ?)`, createdAt, createdAt); err != nil {
		t.Fatal(err)
	}
	var futureGrants int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE repository_id = 12`).Scan(&futureGrants); err != nil {
		t.Fatal(err)
	}
	if futureGrants != 0 {
		t.Fatalf("expected a post-cutover repository to receive no implicit grants, got %d", futureGrants)
	}
	var adminScoped int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE user_id IN (3, 7)`).Scan(&adminScoped); err != nil {
		t.Fatal(err)
	}
	if adminScoped != 0 {
		t.Fatalf("expected admin-only users to receive no scoped grants, got %d", adminScoped)
	}
}

func TestUserAccountManagementMigrationPreservesUsersAndSessionsAndAppliesOnce(t *testing.T) {
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
	accountIndex := migrationIndex(t, migrations, "0025_user_account_management.sql")
	if err := ApplyMigrations(ctx, database, migrations[:accountIndex]); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, password_hash, role, created_at, updated_at)
VALUES (301, 'admin@example.test', 'Admin', 'hash', 'admin', '2026-07-12T10:00:00.000000000Z', '2026-07-12T10:00:00.000000000Z');
INSERT INTO user_roles(user_id, role, created_at)
VALUES (301, 'admin', '2026-07-12T10:00:00.000000000Z'), (301, 'viewer', '2026-07-12T10:00:00.000000000Z');
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES ('existing-session', 301, 'csrf-token', '2027-01-01T00:00:00.000000000Z', '2026-07-12T10:00:00.000000000Z');`); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	assertColumnExists(t, database, "users", "disabled_at")
	assertColumnExists(t, database, "users", "must_change_password")
	assertUserEnabledWithoutForcedPasswordChange(t, database, 301)
	assertUserRoles(t, database, 301, []string{"admin", "viewer"})
	var sessionCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id = 'existing-session' AND user_id = 301 AND csrf_token = 'csrf-token'`).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 1 {
		t.Fatalf("expected existing session to survive account management migration, got %d", sessionCount)
	}

	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0025_user_account_management'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected account management migration applied once, got %d", applied)
	}
}

func TestCreatedByKindMigrationBackfillsFromAuditEvents(t *testing.T) {
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
	createdByKindIndex := migrationIndex(t, migrations, "0026_branch_freeze_created_by_kind.sql")
	if err := ApplyMigrations(ctx, database, migrations[:createdByKindIndex]); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (81, 'forgejo', 'https://codeberg.org', 'example', 'release', 'main', 1, '2026-07-12T10:00:00.000000000Z', '2026-07-12T10:00:00.000000000Z');
INSERT INTO branch_freezes(id, repository_id, branch, status, reason, starts_at, scheduled, created_at, updated_at)
VALUES
  (801, 81, 'main', 'active', 'user freeze', '2026-07-12T10:00:00.000000000Z', 0, '2026-07-12T10:00:00.000000000Z', '2026-07-12T10:00:00.000000000Z'),
  (802, 81, 'release', 'scheduled', 'scheduled freeze', '2026-07-20T10:00:00.000000000Z', 1, '2026-07-12T11:00:00.000000000Z', '2026-07-12T11:00:00.000000000Z'),
  (803, 81, 'develop', 'ended', 'no audit trail', '2026-07-12T09:00:00.000000000Z', 0, '2026-07-12T09:00:00.000000000Z', '2026-07-12T09:30:00.000000000Z');
INSERT INTO audit_events(actor_user_id, action, subject_type, subject_id, details_json, created_at)
VALUES
  (NULL, 'branch_freeze.created', 'branch_freeze', '801', '{"actor_kind":"user"}', '2026-07-12T10:00:00.000000000Z'),
  (NULL, 'freeze_schedule.created', 'branch_freeze', '802', '{"actor_kind":"bootstrap_admin"}', '2026-07-12T11:00:00.000000000Z');`); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, database, migrations[:createdByKindIndex+1]); err != nil {
		t.Fatal(err)
	}
	assertColumnExists(t, database, "branch_freezes", "created_by_kind")
	for _, tc := range []struct {
		freezeID int64
		want     string
	}{
		{801, "user"},
		{802, "bootstrap_admin"},
		{803, ""},
	} {
		var kind string
		if err := database.QueryRowContext(ctx, `SELECT created_by_kind FROM branch_freezes WHERE id = ?`, tc.freezeID).Scan(&kind); err != nil {
			t.Fatal(err)
		}
		if kind != tc.want {
			t.Fatalf("expected freeze %d created_by_kind %q, got %q", tc.freezeID, tc.want, kind)
		}
	}
}

func TestRepositoryGrantsMigrationCreatesEmptyTableAndPreservesLegacyRows(t *testing.T) {
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
	grantsIndex := migrationIndex(t, migrations, "0031_repository_grants.sql")
	if err := ApplyMigrations(ctx, database, migrations[:grantsIndex]); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, password_hash, role, created_at, updated_at)
VALUES (401, 'admin@example.test', 'Admin', 'hash', 'admin', '2026-07-20T10:00:00.000000000Z', '2026-07-20T10:00:00.000000000Z');
INSERT INTO user_roles(user_id, role, created_at)
VALUES (401, 'admin', '2026-07-20T10:00:00.000000000Z'), (401, 'freezer', '2026-07-20T10:00:00.000000000Z');`); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	var grantCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants`).Scan(&grantCount); err != nil {
		t.Fatal(err)
	}
	if grantCount != 0 {
		t.Fatalf("expected repository_grants to start empty with no backfill, got %d rows", grantCount)
	}
	var storedRole string
	if err := database.QueryRowContext(ctx, `SELECT role FROM users WHERE id = 401`).Scan(&storedRole); err != nil {
		t.Fatal(err)
	}
	if storedRole != "admin" {
		t.Fatalf("expected users.role to survive unchanged, got %q", storedRole)
	}
	assertUserRoles(t, database, 401, []string{"admin", "freezer"})
	var indexCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_repository_grants_user_id'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatalf("expected user_id index on repository_grants, got %d", indexCount)
	}

	if err := ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0031_repository_grants'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected repository grants migration applied once, got %d", applied)
	}
}

func TestRepositoryGrantsSchemaEnforcesRolesKeysAndCascades(t *testing.T) {
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
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, password_hash, role, created_at, updated_at)
VALUES
  (501, 'admin@example.test', 'Admin', 'hash', 'admin', '2026-07-20T10:00:00.000000000Z', '2026-07-20T10:00:00.000000000Z'),
  (502, 'lead@example.test', 'Lead', 'hash', 'viewer', '2026-07-20T10:00:00.000000000Z', '2026-07-20T10:00:00.000000000Z');
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, created_at, updated_at)
VALUES
  (601, 'forgejo', 'https://forge.example.test', 'taua-almeida', 'thawguard', 'main', '2026-07-20T10:00:00.000000000Z', '2026-07-20T10:00:00.000000000Z'),
  (602, 'forgejo', 'https://forge.example.test', 'taua-almeida', 'other', 'main', '2026-07-20T10:00:00.000000000Z', '2026-07-20T10:00:00.000000000Z');`); err != nil {
		t.Fatal(err)
	}

	if _, err := database.ExecContext(ctx, `
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (601, 502, 'admin', 501, '2026-07-20T10:00:00.000000000Z')`); err == nil {
		t.Fatal("expected admin to be rejected as a repository role at the schema level")
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES
  (601, 502, 'freezer', 501, '2026-07-20T10:00:00.000000000Z'),
  (602, 502, 'viewer', 501, '2026-07-20T10:00:00.000000000Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (601, 502, 'freezer', 501, '2026-07-20T11:00:00.000000000Z')`); err == nil {
		t.Fatal("expected duplicate (repository, user, role) grant to violate the primary key")
	}

	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 501`); err != nil {
		t.Fatal(err)
	}
	var grantedBy sql.NullInt64
	if err := database.QueryRowContext(ctx, `SELECT granted_by_user_id FROM repository_grants WHERE repository_id = 601 AND user_id = 502 AND role = 'freezer'`).Scan(&grantedBy); err != nil {
		t.Fatal(err)
	}
	if grantedBy.Valid {
		t.Fatalf("expected granter deletion to clear granted_by_user_id, got %d", grantedBy.Int64)
	}

	if _, err := database.ExecContext(ctx, `DELETE FROM repositories WHERE id = 602`); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants WHERE repository_id = 602`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("expected repository deletion to cascade its grants, got %d rows", remaining)
	}

	if _, err := database.ExecContext(ctx, `DELETE FROM users WHERE id = 502`); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM repository_grants`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("expected user deletion to cascade their grants, got %d rows", remaining)
	}
}

func migrationIndex(t *testing.T, migrations []Migration, name string) int {
	t.Helper()
	for i, migration := range migrations {
		if migration.Name == name {
			return i
		}
	}
	t.Fatalf("expected migration %s to exist, got %+v", name, migrations)
	return -1
}

func assertUserEnabledWithoutForcedPasswordChange(t *testing.T, database *sql.DB, userID int64) {
	t.Helper()
	var disabledAt sql.NullString
	var mustChangePassword int
	if err := database.QueryRow(`SELECT disabled_at, must_change_password FROM users WHERE id = ?`, userID).Scan(&disabledAt, &mustChangePassword); err != nil {
		t.Fatal(err)
	}
	if disabledAt.Valid || mustChangePassword != 0 {
		t.Fatalf("expected user %d to stay enabled without forced password change, got disabled_at=%+v must_change_password=%d", userID, disabledAt, mustChangePassword)
	}
}

func assertEnforcementStateConstraint(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO repositories(forge, base_url, owner, name, default_branch, active, enforcement_state, created_at, updated_at) VALUES ('forgejo', 'https://codeberg.org', 'enforcement-owner', 'enforcement-repo', 'main', 1, 'shadow', '2026-07-01T00:00:00.000000000Z', '2026-07-01T00:00:00.000000000Z')`); err == nil {
		t.Fatal("expected invalid enforcement state to be rejected by check constraint")
	}
	if _, err := database.Exec(`INSERT INTO repositories(forge, base_url, owner, name, default_branch, active, created_at, updated_at) VALUES ('forgejo', 'https://codeberg.org', 'enforcement-owner', 'enforcement-repo', 'main', 1, '2026-07-01T00:00:00.000000000Z', '2026-07-01T00:00:00.000000000Z')`); err != nil {
		t.Fatalf("expected repository insert without enforcement state to default: %v", err)
	}
	var enforcementState string
	if err := database.QueryRow(`SELECT enforcement_state FROM repositories WHERE owner = 'enforcement-owner' AND name = 'enforcement-repo'`).Scan(&enforcementState); err != nil {
		t.Fatal(err)
	}
	if enforcementState != "setup_incomplete" {
		t.Fatalf("expected setup_incomplete default enforcement state, got %q", enforcementState)
	}
}

func assertManagedBranch(t *testing.T, database *sql.DB, repositoryID int64, name string, protected int, setupStatus string) {
	t.Helper()
	var gotProtected int
	var gotSetupStatus string
	if err := database.QueryRow(`SELECT protected, setup_status FROM repository_branches WHERE repository_id = ? AND name = ?`, repositoryID, name).Scan(&gotProtected, &gotSetupStatus); err != nil {
		t.Fatalf("expected managed branch %d/%s to exist: %v", repositoryID, name, err)
	}
	if gotProtected != protected || gotSetupStatus != setupStatus {
		t.Fatalf("managed branch %d/%s: want protected=%d setup_status=%q, got protected=%d setup_status=%q", repositoryID, name, protected, setupStatus, gotProtected, gotSetupStatus)
	}
}

func assertWebhookDeliveriesAreRepositoryScoped(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO repositories(id, active) VALUES (1, 1), (2, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO webhook_deliveries(repository_id, delivery_id, event, received_at, verified) VALUES (1, 'delivery-1', 'pull_request', '2026-06-30T12:00:00.000000000Z', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO webhook_deliveries(repository_id, delivery_id, event, received_at, verified) VALUES (2, 'delivery-1', 'pull_request', '2026-06-30T12:00:01.000000000Z', 1)`); err != nil {
		t.Fatalf("expected same delivery id to be allowed for another repository: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO webhook_deliveries(repository_id, delivery_id, event, received_at, verified) VALUES (1, 'delivery-1', 'pull_request', '2026-06-30T12:00:02.000000000Z', 1)`); err == nil {
		t.Fatal("expected duplicate delivery id for the same repository to be rejected")
	}
}

func assertStatusPublicationLiveModesAllowed(t *testing.T, database *sql.DB) {
	t.Helper()
	insertStatusPublicationTestRepository(t, database)
	if _, err := database.Exec(`INSERT OR IGNORE INTO status_results(id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, created_at) VALUES (9001, 9001, 1, 'main', 'abc123', 'thawguard/freeze', 'failure', 'blocked', '2026-07-01T00:00:00.000000000Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO status_publication_intents(status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, delivery_mode, created_at, updated_at) VALUES (9001, 9001, 1, 'main', 'abc123', 'thawguard/freeze', 'failure', 'blocked', 'forgejo_status', '2026-07-01T00:00:00.000000000Z', '2026-07-01T00:00:00.000000000Z')`); err != nil {
		t.Fatalf("expected forgejo status publication intent mode to be allowed: %v", err)
	}
	var publicationID int64
	if err := database.QueryRow(`SELECT id FROM status_publication_intents WHERE repository_id = 9001 AND delivery_mode = 'forgejo_status'`).Scan(&publicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO status_publication_attempts(publication_id, status_result_id, repository_id, pull_request_index, target_branch, head_sha, context, state, description, mode, result, error, attempted_at) VALUES (?, 9001, 9001, 1, 'main', 'abc123', 'thawguard/freeze', 'failure', 'blocked', 'forgejo_status', 'failed', 'forge returned 500', '2026-07-01T00:00:01.000000000Z')`, publicationID); err != nil {
		t.Fatalf("expected forgejo status publication attempt mode/result to be allowed: %v", err)
	}
}

func insertStatusPublicationTestRepository(t *testing.T, database *sql.DB) {
	t.Helper()
	if tableHasColumn(t, database, "repositories", "forge") {
		if _, err := database.Exec(`INSERT OR IGNORE INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at) VALUES (9001, 'forgejo', 'https://codeberg.org', 'example-owner', 'example-repo', 'main', 1, '2026-07-01T00:00:00.000000000Z', '2026-07-01T00:00:00.000000000Z')`); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO repositories(id, active) VALUES (9001, 1)`); err != nil {
		t.Fatal(err)
	}
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func assertPragmaInt(t *testing.T, database *sql.DB, name string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow("PRAGMA " + name).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("PRAGMA %s: want %d, got %d", name, want, got)
	}
}

func assertPragmaText(t *testing.T, database *sql.DB, name string, want string) {
	t.Helper()
	var got string
	if err := database.QueryRow("PRAGMA " + name).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("PRAGMA %s: want %q, got %q", name, want, got)
	}
}

func assertTableExists(t *testing.T, database *sql.DB, name string) {
	t.Helper()
	var found string
	if err := database.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&found); err != nil {
		t.Fatalf("expected table %s to exist: %v", name, err)
	}
}

func assertUserRoles(t *testing.T, database *sql.DB, userID int64, want []string) {
	t.Helper()
	rows, err := database.Query(`SELECT role FROM user_roles WHERE user_id = ?`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			t.Fatal(err)
		}
		got[role] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("user %d roles: want %v, got %v", userID, want, got)
	}
	for _, role := range want {
		if !got[role] {
			t.Fatalf("user %d roles: want %v, got %v", userID, want, got)
		}
	}
}

func assertIndexExists(t *testing.T, database *sql.DB, name string) {
	t.Helper()
	var found string
	if err := database.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&found); err != nil {
		t.Fatalf("expected index %s to exist: %v", name, err)
	}
}

func assertIndexDoesNotExist(t *testing.T, database *sql.DB, name string) {
	t.Helper()
	var found string
	err := database.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("expected index %s not to exist", name)
}

func assertColumnExists(t *testing.T, database *sql.DB, table string, column string) {
	t.Helper()
	if tableHasColumn(t, database, table, column) {
		return
	}
	t.Fatalf("expected column %s.%s to exist", table, column)
}

func tableHasColumn(t *testing.T, database *sql.DB, table string, column string) bool {
	t.Helper()
	rows, err := database.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}
