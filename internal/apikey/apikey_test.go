package apikey_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hkjang/bbmcp/internal/apikey"
	"github.com/hkjang/bbmcp/internal/crypto"
	"github.com/hkjang/bbmcp/internal/database"
	"github.com/hkjang/bbmcp/internal/settings"
)

func newService(t *testing.T) (*apikey.Service, *database.DB, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL이 설정되지 않아 통합 테스트를 건너뜁니다")
	}
	ctx := context.Background()
	db, err := database.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`TRUNCATE users, api_keys, key_roles, settings RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users(id, username, display_name, source) VALUES (1,'hkjang','hkjang','local')
		 ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	store := settings.NewStore(db.Pool, sealer)
	svc := apikey.NewService(db.Pool, sealer, store)
	if err := svc.SeedRoles(ctx); err != nil {
		t.Fatalf("SeedRoles: %v", err)
	}
	return svc, db, ctx
}

func TestCreateAndVerify(t *testing.T) {
	svc, _, ctx := newService(t)

	issued, err := svc.Create(ctx, 1, "ci", "reader", nil, 30)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if issued.Secret == "" {
		t.Fatal("no secret returned")
	}
	if issued.Key.ExpiresAt == nil || issued.Key.ExpiresAt.Before(time.Now()) {
		t.Fatal("expiry was not set")
	}

	v, err := svc.Verify(ctx, issued.Secret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Key.ID != issued.Key.ID {
		t.Fatal("verified a different key")
	}
	if !apikey.HasScope(v.Scopes, apikey.ScopeBitbucketRead) {
		t.Fatalf("reader scopes = %v", v.Scopes)
	}
	if apikey.HasScope(v.Scopes, apikey.ScopePRExecute) {
		t.Fatal("reader key carried an execute scope")
	}

	if _, err := svc.Verify(ctx, "bbmcp_wrong_secret"); err == nil {
		t.Fatal("a forged key verified")
	}
	if _, err := svc.Verify(ctx, issued.Secret+"x"); err == nil {
		t.Fatal("a mutated secret verified")
	}
}

func TestKeyCannotExceedItsRole(t *testing.T) {
	svc, _, ctx := newService(t)
	// Asking for execute on a reader role must not widen the key.
	_, err := svc.Create(ctx, 1, "sneaky", "reader", []string{apikey.ScopePRExecute}, 0)
	if err == nil {
		t.Fatal("a reader key was issued with an execute scope")
	}

	issued, err := svc.Create(ctx, 1, "narrow", "executor", []string{apikey.ScopeBitbucketRead}, 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	v, err := svc.Verify(ctx, issued.Secret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(v.Scopes) != 1 || v.Scopes[0] != apikey.ScopeBitbucketRead {
		t.Fatalf("narrowed scopes = %v", v.Scopes)
	}
}

func TestRotationKeepsOldKeyUsableDuringGrace(t *testing.T) {
	svc, _, ctx := newService(t)
	old, err := svc.Create(ctx, 1, "ci", "reader", nil, 30)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fresh, err := svc.Rotate(ctx, old.Key.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if fresh.Secret == old.Secret {
		t.Fatal("rotation reused the secret")
	}
	if fresh.Key.RotatedFrom == nil || *fresh.Key.RotatedFrom != old.Key.ID {
		t.Fatal("rotation lineage was not recorded")
	}
	if _, err := svc.Verify(ctx, fresh.Secret); err != nil {
		t.Fatalf("new key does not verify: %v", err)
	}
	// The default grace window keeps the old key alive so clients can switch.
	if _, err := svc.Verify(ctx, old.Secret); err != nil {
		t.Fatalf("old key died before the grace window elapsed: %v", err)
	}

	if err := svc.Revoke(ctx, old.Key.ID, "회전 완료"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Verify(ctx, old.Secret); err == nil {
		t.Fatal("a revoked key still verifies")
	}
}

func TestEditingRoleScopesAppliesToExistingKeys(t *testing.T) {
	svc, _, ctx := newService(t)
	issued, err := svc.Create(ctx, 1, "ci", "writer", nil, 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, err := svc.Verify(ctx, issued.Secret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !apikey.HasScope(before.Scopes, apikey.ScopePRWrite) {
		t.Fatalf("writer scopes = %v", before.Scopes)
	}

	// The key permission scheme is editable; narrowing a role must take
	// effect on keys that were already issued under it.
	if err := svc.SaveRole(ctx, apikey.Role{
		Name: "writer", Description: "조회 전용으로 축소",
		Scopes: []string{apikey.ScopeBitbucketRead},
	}); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}
	after, err := svc.Verify(ctx, issued.Secret)
	if err != nil {
		t.Fatalf("Verify after edit: %v", err)
	}
	if apikey.HasScope(after.Scopes, apikey.ScopePRWrite) {
		t.Fatalf("narrowed role still grants write: %v", after.Scopes)
	}
}

func TestBuiltinRoleCannotBeDeleted(t *testing.T) {
	svc, _, ctx := newService(t)
	if err := svc.DeleteRole(ctx, "reader"); err == nil {
		t.Fatal("a builtin role was deleted")
	}
	if err := svc.SaveRole(ctx, apikey.Role{
		Name: "custom", Scopes: []string{apikey.ScopeBitbucketRead},
	}); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}
	if err := svc.DeleteRole(ctx, "custom"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
}

func TestUnknownScopeIsRejected(t *testing.T) {
	svc, _, ctx := newService(t)
	if err := svc.SaveRole(ctx, apikey.Role{
		Name: "bad", Scopes: []string{"bb:everything"},
	}); err == nil {
		t.Fatal("an unknown scope was accepted")
	}
}

func TestMaxKeysPerUserIsEnforced(t *testing.T) {
	svc, db, ctx := newService(t)
	store := settings.NewStore(db.Pool, mustSealer(t))
	pol := settings.DefaultKeyPolicy()
	pol.MaxKeysPerUser = 2
	if err := store.Put(ctx, settings.KeyKeyPolicy, pol, "test"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// The service holds its own store instance, so point it at the same rows.
	svc2 := apikey.NewService(db.Pool, mustSealer(t), store)

	for i := 0; i < 2; i++ {
		if _, err := svc2.Create(ctx, 1, "k", "reader", nil, 0); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}
	if _, err := svc2.Create(ctx, 1, "over", "reader", nil, 0); err == nil {
		t.Fatal("the per-user key limit was not enforced")
	}
	_ = svc
}

func mustSealer(t *testing.T) *crypto.Sealer {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	s, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}
