package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const DriverName = "sqlite"

type Config struct {
	Path            string
	BusyTimeout     time.Duration
	ForeignKeys     bool
	WAL             bool
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

func DefaultConfig(path string) Config {
	return Config{
		Path:         path,
		BusyTimeout:  5 * time.Second,
		ForeignKeys:  true,
		WAL:          true,
		MaxOpenConns: 4,
		MaxIdleConns: 4,
	}
}

func Open(ctx context.Context, cfg Config) (*sql.DB, error) {
	if cfg.Path == "" {
		cfg.Path = "thawguard.db"
	}
	if cfg.BusyTimeout == 0 {
		cfg.BusyTimeout = 5 * time.Second
	}
	if cfg.MaxOpenConns == 0 {
		cfg.MaxOpenConns = 4
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = cfg.MaxOpenConns
	}

	database, err := sql.Open(DriverName, DSN(cfg))
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(cfg.MaxOpenConns)
	database.SetMaxIdleConns(cfg.MaxIdleConns)
	if cfg.ConnMaxLifetime > 0 {
		database.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func DSN(cfg Config) string {
	params := url.Values{}
	if cfg.ForeignKeys {
		params.Add("_pragma", "foreign_keys(ON)")
	}
	if cfg.BusyTimeout > 0 {
		params.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", cfg.BusyTimeout.Milliseconds()))
	}
	if cfg.WAL {
		params.Add("_pragma", "journal_mode(WAL)")
	}

	query := params.Encode()
	if query == "" {
		return cfg.Path
	}
	if strings.Contains(cfg.Path, "?") {
		return cfg.Path + "&" + query
	}
	return cfg.Path + "?" + query
}
