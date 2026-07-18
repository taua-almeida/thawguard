package config

import "os"

type Config struct {
	HTTPAddr     string
	DatabasePath string
	PublicURL    string
	Environment  string
	SecretKey    string
	// DevMode enables development-only routes such as the component
	// gallery at /dev/preview. Never enable in production.
	DevMode bool
}

func FromEnv() Config {
	return Config{
		HTTPAddr:     env("THAWGUARD_HTTP_ADDR", "127.0.0.1:8080"),
		DatabasePath: env("THAWGUARD_DB_PATH", "thawguard.db"),
		PublicURL:    env("THAWGUARD_PUBLIC_URL", "http://localhost:8080"),
		Environment:  env("THAWGUARD_ENV", "development"),
		SecretKey:    env("THAWGUARD_SECRET_KEY", ""),
		DevMode:      os.Getenv("THAWGUARD_DEV") == "1",
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
