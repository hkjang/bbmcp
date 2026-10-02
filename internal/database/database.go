// Package database owns the PostgreSQL pool and schema migrations.
package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed all:migrations
var migrationFS embed.FS

// DB wraps a pgx pool.
type DB struct {
	Pool *pgxpool.Pool
}

// Open connects to PostgreSQL, retrying so that a container start order
// mismatch in an air-gapped compose deployment is not fatal.
func Open(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("DSN 파싱 실패: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		lastErr = pool.Ping(pingCtx)
		cancel()
		if lastErr == nil {
			return &DB{Pool: pool}, nil
		}
		// Waiting helps when PostgreSQL is still starting. It never helps when
		// the database name or the credentials are wrong, and retrying those
		// for a minute turns a typo into an unexplained hang.
		if fatal, reason := fatalConnectError(lastErr); fatal {
			pool.Close()
			return nil, fmt.Errorf("PostgreSQL 연결 실패(%s): %w", reason, lastErr)
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	pool.Close()
	return nil, fmt.Errorf("PostgreSQL 연결 실패: %w", lastErr)
}

// fatalConnectError reports configuration errors that retrying cannot fix.
func fatalConnectError(err error) (bool, string) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false, ""
	}
	switch pgErr.Code {
	case "3D000":
		return true, "데이터베이스가 존재하지 않습니다"
	case "28P01":
		return true, "비밀번호가 올바르지 않습니다"
	case "28000":
		return true, "인증이 거부되었습니다"
	case "42501":
		return true, "권한이 부족합니다"
	default:
		return false, ""
	}
}

// Close releases the pool.
func (d *DB) Close() { d.Pool.Close() }

// Migrate applies every embedded migration that has not run yet.
func (d *DB) Migrate(ctx context.Context) error {
	if _, err := d.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists bool
		if err := d.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, name,
		).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := d.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("마이그레이션 %s 실패: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations(version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
