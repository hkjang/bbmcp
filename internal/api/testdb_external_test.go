package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/hkjang/bbmcp/internal/database"
)

// openTestDB connects with a short deadline so a stopped test database fails
// fast instead of waiting out the production start-up retry window.
func openTestDB(t *testing.T, dsn string) (*database.DB, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return database.Open(ctx, dsn)
}
