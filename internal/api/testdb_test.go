package api

import (
	"context"
	"testing"
	"time"

	"github.com/hkjang/bbmcp/internal/database"
)

// openTestDB connects with a short deadline: in tests a database that is not
// running should fail immediately rather than consuming the retry window that
// exists for container start-up ordering in production.
func openTestDB(t *testing.T, dsn string) (*database.DB, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return database.Open(ctx, dsn)
}
