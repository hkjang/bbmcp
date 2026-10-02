package apikey

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/crypto"
	"github.com/hkjang/bbmcp/internal/settings"
)

// Prefix is the human-visible marker of a bbmcp key.
const Prefix = "bbmcp"

// ErrInvalidKey is returned for an unknown, revoked or expired key.
var ErrInvalidKey = errors.New("API 키가 유효하지 않습니다")

// Role is an entry of the editable key permission scheme.
type Role struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Scopes      []string  `json:"scopes"`
	Builtin     bool      `json:"builtin"`
	UpdatedAt   time.Time `json:"updatedAt,omitempty"`
}

// Key is an issued API key (never carrying the secret after creation).
type Key struct {
	ID            uuid.UUID  `json:"id"`
	UserID        int64      `json:"userId"`
	Username      string     `json:"username,omitempty"`
	Name          string     `json:"name"`
	Prefix        string     `json:"prefix"`
	Role          string     `json:"role"`
	Scopes        []string   `json:"scopes"`
	RotatedFrom   *uuid.UUID `json:"rotatedFrom,omitempty"`
	RotationDueAt *time.Time `json:"rotationDueAt,omitempty"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt    *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
	RevokedReason string     `json:"revokedReason,omitempty"`
	Status        string     `json:"status"`
}

// Service manages keys and roles.
type Service struct {
	pool   *pgxpool.Pool
	sealer *crypto.Sealer
	store  *settings.Store
}

// NewService builds the service.
func NewService(pool *pgxpool.Pool, sealer *crypto.Sealer, store *settings.Store) *Service {
	return &Service{pool: pool, sealer: sealer, store: store}
}

// SeedRoles inserts the builtin roles if they are missing.
func (s *Service) SeedRoles(ctx context.Context) error {
	for _, r := range BuiltinRoles() {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO key_roles(name, description, scopes, builtin)
			VALUES ($1,$2,$3,TRUE)
			ON CONFLICT (name) DO NOTHING`, r.Name, r.Description, r.Scopes); err != nil {
			return err
		}
	}
	return nil
}

// Roles lists the key permission scheme.
func (s *Service) Roles(ctx context.Context) ([]Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name, description, scopes, builtin, updated_at FROM key_roles ORDER BY builtin DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Role{}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.Name, &r.Description, &r.Scopes, &r.Builtin, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Role loads one role.
func (s *Service) Role(ctx context.Context, name string) (*Role, error) {
	var r Role
	err := s.pool.QueryRow(ctx,
		`SELECT name, description, scopes, builtin, updated_at FROM key_roles WHERE name=$1`, name).
		Scan(&r.Name, &r.Description, &r.Scopes, &r.Builtin, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("키 역할 %q 를 찾을 수 없습니다", name)
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// SaveRole creates or updates a role. Scope membership is always editable,
// including for builtin roles, so the permission scheme can change over time.
func (s *Service) SaveRole(ctx context.Context, r Role) error {
	for _, sc := range r.Scopes {
		if !ValidScope(sc) {
			return fmt.Errorf("알 수 없는 스코프: %s", sc)
		}
	}
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("역할 이름이 필요합니다")
	}
	if r.Scopes == nil {
		r.Scopes = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO key_roles(name, description, scopes, builtin, updated_at)
		VALUES ($1,$2,$3,FALSE,NOW())
		ON CONFLICT (name) DO UPDATE
		   SET description = EXCLUDED.description,
		       scopes = EXCLUDED.scopes,
		       updated_at = NOW()`, r.Name, r.Description, r.Scopes)
	return err
}

// DeleteRole removes a non-builtin role.
func (s *Service) DeleteRole(ctx context.Context, name string) error {
	var builtin bool
	err := s.pool.QueryRow(ctx, `SELECT builtin FROM key_roles WHERE name=$1`, name).Scan(&builtin)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if builtin {
		return errors.New("기본 제공 역할은 삭제할 수 없습니다")
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM key_roles WHERE name=$1`, name)
	return err
}

const keyCols = `k.id, k.user_id, u.username, k.name, k.prefix, COALESCE(k.key_role,''),
	k.scopes, k.rotated_from, k.rotation_due_at, k.expires_at, k.last_used_at,
	k.created_at, k.revoked_at, COALESCE(k.revoked_reason,'')`

func scanKey(row pgx.Row) (*Key, error) {
	var k Key
	if err := row.Scan(&k.ID, &k.UserID, &k.Username, &k.Name, &k.Prefix, &k.Role,
		&k.Scopes, &k.RotatedFrom, &k.RotationDueAt, &k.ExpiresAt, &k.LastUsedAt,
		&k.CreatedAt, &k.RevokedAt, &k.RevokedReason); err != nil {
		return nil, err
	}
	k.Status = statusOf(k)
	return &k, nil
}

func statusOf(k Key) string {
	now := time.Now()
	switch {
	case k.RevokedAt != nil:
		return "revoked"
	case k.ExpiresAt != nil && k.ExpiresAt.Before(now):
		return "expired"
	case k.RotationDueAt != nil && k.RotationDueAt.Before(now):
		return "rotation_due"
	default:
		return "active"
	}
}

// List returns the keys of one user, or every key when userID is 0.
func (s *Service) List(ctx context.Context, userID int64) ([]Key, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+keyCols+`
		FROM api_keys k JOIN users u ON u.id = k.user_id
		WHERE ($1 = 0 OR k.user_id = $1)
		ORDER BY k.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Key{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// Issued is a freshly created key: the secret is returned exactly once.
type Issued struct {
	Key    Key    `json:"key"`
	Secret string `json:"secret"`
}

// Create issues a new key for a user.
func (s *Service) Create(ctx context.Context, userID int64, name, roleName string, scopes []string, ttlDays int) (*Issued, error) {
	pol, err := s.store.KeyPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if roleName == "" {
		roleName = pol.DefaultRole
	}
	role, err := s.Role(ctx, roleName)
	if err != nil {
		return nil, err
	}
	// A key may only narrow its role, never widen it.
	effective := role.Scopes
	if len(scopes) > 0 {
		effective = intersect(role.Scopes, scopes)
		if len(effective) == 0 {
			return nil, errors.New("요청한 스코프가 역할에 포함되지 않습니다")
		}
	}

	if pol.MaxKeysPerUser > 0 {
		var active int
		if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_keys
			WHERE user_id=$1 AND revoked_at IS NULL
			  AND (expires_at IS NULL OR expires_at > NOW())`, userID).Scan(&active); err != nil {
			return nil, err
		}
		if active >= pol.MaxKeysPerUser {
			return nil, fmt.Errorf("활성 키 개수 상한(%d)에 도달했습니다", pol.MaxKeysPerUser)
		}
	}

	prefix, err := randomPrefix(10)
	if err != nil {
		return nil, err
	}
	secretPart, err := crypto.RandomToken(32)
	if err != nil {
		return nil, err
	}
	full := fmt.Sprintf("%s_%s_%s", Prefix, prefix, secretPart)

	if ttlDays <= 0 {
		ttlDays = pol.KeyTTLDays
	}
	var expires *time.Time
	if ttlDays > 0 {
		t := time.Now().AddDate(0, 0, ttlDays)
		expires = &t
	}
	var rotationDue *time.Time
	if pol.RotationDays > 0 {
		t := time.Now().AddDate(0, 0, pol.RotationDays)
		rotationDue = &t
	}

	id := uuid.New()
	_, err = s.pool.Exec(ctx, `
		INSERT INTO api_keys(id, user_id, name, prefix, key_hmac, key_role, scopes,
			rotation_due_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		id, userID, name, prefix, s.sealer.HMAC(full), role.Name, effective, rotationDue, expires)
	if err != nil {
		return nil, err
	}
	created, err := s.byID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &Issued{Key: *created, Secret: full}, nil
}

func (s *Service) byID(ctx context.Context, id uuid.UUID) (*Key, error) {
	return scanKey(s.pool.QueryRow(ctx, `SELECT `+keyCols+`
		FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.id=$1`, id))
}

// ByID exposes a single key.
func (s *Service) ByID(ctx context.Context, id uuid.UUID) (*Key, error) { return s.byID(ctx, id) }

// Rotate issues a replacement key and schedules the old one for revocation
// after the configured grace period, so clients can switch without downtime.
func (s *Service) Rotate(ctx context.Context, id uuid.UUID) (*Issued, error) {
	old, err := s.byID(ctx, id)
	if err != nil {
		return nil, err
	}
	pol, err := s.store.KeyPolicy(ctx)
	if err != nil {
		return nil, err
	}

	issued, err := s.Create(ctx, old.UserID, old.Name, old.Role, old.Scopes, pol.KeyTTLDays)
	if err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET rotated_from=$2 WHERE id=$1`, issued.Key.ID, old.ID); err != nil {
		return nil, err
	}

	grace := pol.GraceHours
	if grace <= 0 {
		if err := s.Revoke(ctx, old.ID, "키 회전"); err != nil {
			return nil, err
		}
	} else {
		if _, err := s.pool.Exec(ctx, `
			UPDATE api_keys
			SET expires_at = LEAST(COALESCE(expires_at, NOW() + make_interval(hours => $2)),
			                       NOW() + make_interval(hours => $2)),
			    revoked_reason = '키 회전 유예'
			WHERE id = $1`, old.ID, grace); err != nil {
			return nil, err
		}
	}
	issued.Key.RotatedFrom = &old.ID
	return issued, nil
}

// Revoke disables a key immediately.
func (s *Service) Revoke(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at=NOW(), revoked_reason=$2 WHERE id=$1 AND revoked_at IS NULL`,
		id, reason)
	return err
}

// UpdateScopes narrows or re-grants a key's scopes within its role.
func (s *Service) UpdateScopes(ctx context.Context, id uuid.UUID, roleName string, scopes []string) error {
	role, err := s.Role(ctx, roleName)
	if err != nil {
		return err
	}
	effective := role.Scopes
	if len(scopes) > 0 {
		effective = intersect(role.Scopes, scopes)
		if len(effective) == 0 {
			return errors.New("요청한 스코프가 역할에 포함되지 않습니다")
		}
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE api_keys SET key_role=$2, scopes=$3 WHERE id=$1`, id, role.Name, effective)
	return err
}

// Verified is the result of authenticating an API key.
type Verified struct {
	Key    Key
	Scopes []string
}

// Verify authenticates a raw API key string.
//
// The secret segment is base64url and may itself contain "_", so the key is
// split into exactly three fields rather than on every separator.
func (s *Service) Verify(ctx context.Context, raw string) (*Verified, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != Prefix || parts[1] == "" || parts[2] == "" {
		return nil, ErrInvalidKey
	}
	k, err := scanKey(s.pool.QueryRow(ctx, `SELECT `+keyCols+`
		FROM api_keys k JOIN users u ON u.id=k.user_id
		WHERE k.prefix=$1`, parts[1]))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidKey
	}
	if err != nil {
		return nil, err
	}

	var stored string
	if err := s.pool.QueryRow(ctx, `SELECT key_hmac FROM api_keys WHERE id=$1`, k.ID).
		Scan(&stored); err != nil {
		return nil, ErrInvalidKey
	}
	if !crypto.ConstantTimeEqual(stored, s.sealer.HMAC(raw)) {
		return nil, ErrInvalidKey
	}
	if k.RevokedAt != nil {
		return nil, fmt.Errorf("%w: 폐기된 키입니다", ErrInvalidKey)
	}
	if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("%w: 만료된 키입니다", ErrInvalidKey)
	}

	// Scopes always re-derive from the current role so that editing the
	// permission scheme takes effect on existing keys immediately.
	scopes := k.Scopes
	if k.Role != "" {
		if role, err := s.Role(ctx, k.Role); err == nil {
			scopes = intersect(role.Scopes, k.Scopes)
		}
	}
	_, _ = s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at=NOW() WHERE id=$1`, k.ID)
	return &Verified{Key: *k, Scopes: scopes}, nil
}

// DueForRotation lists keys whose rotation date has passed.
func (s *Service) DueForRotation(ctx context.Context, userID int64) ([]Key, error) {
	all, err := s.List(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := []Key{}
	for _, k := range all {
		if k.Status == "rotation_due" {
			out = append(out, k)
		}
	}
	return out, nil
}

// prefixAlphabet avoids "_" so the key prefix never collides with the
// separator used in the key format bbmcp_<prefix>_<secret>.
const prefixAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// randomPrefix returns a lookup prefix of n alphabet characters.
func randomPrefix(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = prefixAlphabet[int(b)%len(prefixAlphabet)]
	}
	return string(out), nil
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, v := range a {
		set[strings.ToLower(v)] = true
	}
	out := []string{}
	for _, v := range b {
		if set[strings.ToLower(v)] {
			out = append(out, v)
		}
	}
	return out
}
