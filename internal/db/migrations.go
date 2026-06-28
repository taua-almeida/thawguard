package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const DefaultMigrationsDir = "migrations"

type Migration struct {
	Name string
	SQL  string
}

const ensureMigrationsTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);`

func LoadMigrations(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, Migration{Name: entry.Name(), SQL: string(contents)})
	}
	return migrations, nil
}

func ApplyMigrations(ctx context.Context, database *sql.DB, migrations []Migration) error {
	if database == nil {
		return errors.New("database is nil")
	}
	if _, err := database.ExecContext(ctx, ensureMigrationsTableSQL); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	for _, migration := range migrations {
		version := strings.TrimSuffix(migration.Name, filepath.Ext(migration.Name))
		applied, err := migrationApplied(ctx, database, version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", migration.Name, err)
		}

		if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", migration.Name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", migration.Name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", migration.Name, err)
		}
	}
	return nil
}

func migrationApplied(ctx context.Context, database *sql.DB, version string) (bool, error) {
	var existing string
	err := database.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, version).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}
	return true, nil
}
