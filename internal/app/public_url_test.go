package app

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/config"
)

func TestRunRejectsInvalidPublicURLBeforeDatabaseOpenOrConfigLog(t *testing.T) {
	const canary = "public-url-leak-canary"
	databasePath := filepath.Join(t.TempDir(), "must-not-open.db")
	var logs bytes.Buffer
	application := New(config.Config{
		HTTPAddr:     "127.0.0.1:0",
		DatabasePath: databasePath,
		PublicURL:    "https://example.test/" + canary,
	}, slog.New(slog.NewTextHandler(&logs, nil)))

	err := application.Run(context.Background())
	if err == nil {
		t.Fatal("expected invalid public URL to stop startup")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("startup error exposed rejected public URL: %q", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("expected no configuration log before public URL validation, got %q", logs.String())
	}
	if _, statErr := os.Stat(databasePath); !os.IsNotExist(statErr) {
		t.Fatalf("database was touched before public URL validation: %v", statErr)
	}
}
