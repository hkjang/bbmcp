package settings

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/crypto"
)

// Store reads and writes settings groups with a process-local cache.
type Store struct {
	pool   *pgxpool.Pool
	sealer *crypto.Sealer

	mu    sync.RWMutex
	cache map[string]cached
}

// cached is one group as read from the database.
type cached struct {
	body json.RawMessage
	at   time.Time
}

// cacheTTL bounds how long a process serves a group without re-reading it.
// Put refreshes only the process that saved; with more than one gateway on
// the same database, the others pick the change up within this window.
const cacheTTL = 30 * time.Second

// NewStore builds a settings store.
func NewStore(pool *pgxpool.Pool, sealer *crypto.Sealer) *Store {
	return &Store{pool: pool, sealer: sealer, cache: map[string]cached{}}
}

// Sealer exposes the shared sealer for callers that need to encrypt a field.
func (s *Store) Sealer() *crypto.Sealer { return s.sealer }

// raw loads a group's JSON, consulting the cache first.
func (s *Store) raw(ctx context.Context, key string) (json.RawMessage, error) {
	s.mu.RLock()
	v, cachedOK := s.cache[key]
	s.mu.RUnlock()
	if cachedOK && time.Since(v.at) < cacheTTL {
		return v.body, nil
	}

	var body []byte
	err := s.pool.QueryRow(ctx, `SELECT value_json FROM settings WHERE key=$1`, key).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		body = nil
	} else if err != nil {
		// A failed refresh keeps the last known settings. Falling back to the
		// defaults instead would, for one, drop an IP allowlist while the
		// database is briefly unavailable.
		if cachedOK {
			return v.body, nil
		}
		return nil, err
	}
	s.mu.Lock()
	s.cache[key] = cached{body: body, at: time.Now()}
	s.mu.Unlock()
	return body, nil
}

// load unmarshals a group over the provided defaults.
func load[T any](ctx context.Context, s *Store, key string, def T) (T, error) {
	body, err := s.raw(ctx, key)
	if err != nil {
		return def, err
	}
	if len(body) == 0 {
		return def, nil
	}
	out := def
	if err := json.Unmarshal(body, &out); err != nil {
		return def, err
	}
	return out, nil
}

// Put replaces a group and invalidates the cache.
func (s *Store) Put(ctx context.Context, key string, value any, actor string) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO settings(key, value_json, updated_at, updated_by)
		VALUES ($1, $2, NOW(), $3)
		ON CONFLICT (key) DO UPDATE
		   SET value_json = EXCLUDED.value_json,
		       updated_at = NOW(),
		       updated_by = EXCLUDED.updated_by`, key, body, actor)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cache[key] = cached{body: body, at: time.Now()}
	s.mu.Unlock()
	return nil
}

// Invalidate drops the cached copy of a group (or all groups when key == "").
func (s *Store) Invalidate(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" {
		s.cache = map[string]cached{}
		return
	}
	delete(s.cache, key)
}

// Reveal decrypts a sealed settings field.
func (s *Store) Reveal(envelope string) (string, error) {
	if envelope == "" {
		return "", nil
	}
	return s.sealer.Open(envelope)
}

// Seal encrypts a plaintext settings field.
func (s *Store) Seal(plaintext string) (string, error) {
	return s.sealer.Seal(plaintext)
}

// Typed accessors. Each returns shipped defaults when unset.

func (s *Store) Keycloak(ctx context.Context) (Keycloak, error) {
	return load(ctx, s, KeyKeycloak, DefaultKeycloak())
}
func (s *Store) Bitbucket(ctx context.Context) (Bitbucket, error) {
	return load(ctx, s, KeyBitbucket, DefaultBitbucket())
}
func (s *Store) Permission(ctx context.Context) (Permission, error) {
	return load(ctx, s, KeyPermission, DefaultPermission())
}
func (s *Store) AI(ctx context.Context) (AI, error) {
	return load(ctx, s, KeyAI, DefaultAI())
}
func (s *Store) Security(ctx context.Context) (Security, error) {
	return load(ctx, s, KeySecurity, DefaultSecurity())
}
func (s *Store) UI(ctx context.Context) (UI, error) {
	return load(ctx, s, KeyUI, DefaultUI())
}
func (s *Store) KeyPolicy(ctx context.Context) (KeyPolicy, error) {
	return load(ctx, s, KeyKeyPolicy, DefaultKeyPolicy())
}
func (s *Store) MCP(ctx context.Context) (MCP, error) {
	return load(ctx, s, KeyMCP, DefaultMCP())
}

// MigrateMCPRegistration turns MCP registration proxying back on, once, for
// Keycloak settings saved before this marker existed, and reports whether it
// did.
//
// Up to v0.2.5 the switch only decided whether this gateway answered
// /oauth/register; MCP clients were sent to Keycloak either way. Since v0.2.6
// off means "send MCP clients to Keycloak's own registration", which Keycloak
// 13 and older refuse for every MCP client (invalid_client_metadata). Nothing
// recorded which meaning a stored "off" was chosen under, including values
// saved by v0.2.6 to v0.2.8, so it is reset once and the operator can turn
// it off again. Settings saved from now on carry MCPRegistrationReviewed and
// are left alone.
func (s *Store) MigrateMCPRegistration(ctx context.Context, actor string) (bool, error) {
	body, err := s.raw(ctx, KeyKeycloak)
	if err != nil || len(body) == 0 {
		return false, err
	}
	kc := DefaultKeycloak()
	if err := json.Unmarshal(body, &kc); err != nil {
		return false, err
	}
	if kc.MCPRegistrationReviewed {
		return false, nil
	}
	changed := !kc.MCPAllowDCR
	kc.MCPAllowDCR = true
	kc.MCPRegistrationReviewed = true
	return changed, s.Put(ctx, KeyKeycloak, kc, actor)
}
