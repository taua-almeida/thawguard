package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
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
  active INTEGER NOT NULL DEFAULT 1
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
);`); err != nil {
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
	assertWebhookDeliveriesAreRepositoryScoped(t, database)
	assertIndexExists(t, database, "idx_branch_freezes_one_active")
	assertIndexExists(t, database, "idx_audit_events_subject_type_id")
	assertIndexExists(t, database, "idx_status_publication_intents_idempotency")
	assertIndexExists(t, database, "idx_status_publication_attempts_recent")
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
  active INTEGER NOT NULL DEFAULT 1
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
  active INTEGER NOT NULL DEFAULT 1
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

func assertIndexExists(t *testing.T, database *sql.DB, name string) {
	t.Helper()
	var found string
	if err := database.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&found); err != nil {
		t.Fatalf("expected index %s to exist: %v", name, err)
	}
}

func assertColumnExists(t *testing.T, database *sql.DB, table string, column string) {
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
			return
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("expected column %s.%s to exist", table, column)
}
