// Package config loads the small set of environment variables bbmcp accepts.
//
// Everything else (Keycloak, Bitbucket, AI, policy) is configured at runtime
// through the admin UI and stored encrypted in PostgreSQL, so that an
// air-gapped deployment only needs these four values.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config holds the process-level configuration.
type Config struct {
	DatabaseURL          string
	BootstrapAdmin       string
	BootstrapAdminPasswd string
	EncryptionKey        []byte
	Addr                 string
}

// Load reads and validates configuration from the environment.
func Load() (*Config, error) {
	c := &Config{
		DatabaseURL:          firstEnv("DATABASE_URL", "POSTGRES_DSN"),
		BootstrapAdmin:       firstEnv("BOOTSTRAP_ADMIN"),
		BootstrapAdminPasswd: firstEnv("BOOTSTRAP_ADMIN_PASSWORD"),
		Addr:                 envOr("BBMCP_ADDR", ":8080"),
	}

	var missing []string
	if c.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if c.BootstrapAdmin == "" {
		missing = append(missing, "BOOTSTRAP_ADMIN")
	}
	if c.BootstrapAdminPasswd == "" {
		missing = append(missing, "BOOTSTRAP_ADMIN_PASSWORD")
	}
	raw := firstEnv("ENCRYPTION_KEY")
	if raw == "" {
		missing = append(missing, "ENCRYPTION_KEY")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("필수 환경변수 누락: %s", strings.Join(missing, ", "))
	}

	key, err := parseKey(raw)
	if err != nil {
		return nil, fmt.Errorf("ENCRYPTION_KEY: %w", err)
	}
	c.EncryptionKey = key
	return c, nil
}

// parseKey accepts a 32-byte key as hex, base64, or raw text.
func parseKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, errors.New("32바이트 키가 필요합니다 (hex 64자, base64 44자, 또는 평문 32자)")
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
