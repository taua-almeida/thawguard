package config

import "testing"

func TestFromEnvDefaults(t *testing.T) {
	for _, key := range []string{"THAWGUARD_HTTP_ADDR", "THAWGUARD_DB_PATH", "THAWGUARD_PUBLIC_URL", "THAWGUARD_ENV", "THAWGUARD_SECRET_KEY"} {
		t.Setenv(key, "")
	}
	cfg := FromEnv()
	if cfg.HTTPAddr != "127.0.0.1:8080" || cfg.DatabasePath != "thawguard.db" || cfg.PublicURL != "http://localhost:8080" || cfg.Environment != "development" || cfg.SecretKey != "" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("THAWGUARD_HTTP_ADDR", "127.0.0.1:9999")
	t.Setenv("THAWGUARD_DB_PATH", "/data/thawguard.db")
	t.Setenv("THAWGUARD_SECRET_KEY", "base64-key")
	cfg := FromEnv()
	if cfg.HTTPAddr != "127.0.0.1:9999" || cfg.DatabasePath != "/data/thawguard.db" || cfg.SecretKey != "base64-key" {
		t.Fatalf("unexpected overrides: %+v", cfg)
	}
}
