// Package auth owns local accounts, browser sessions, Keycloak OIDC login
// (including silent SSO) and the request middleware that turns a credential
// into an authenticated principal.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/crypto"
)

// ErrNotFound is returned when a user row does not exist.
var ErrNotFound = errors.New("사용자를 찾을 수 없습니다")

// User is a bbmcp account. Accounts are either local (bootstrap admin and
// operator-created) or provisioned from Keycloak on first login.
type User struct {
	ID             int64      `json:"id"`
	Username       string     `json:"username"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"displayName"`
	KeycloakSub    string     `json:"keycloakSub,omitempty"`
	IsServiceAdmin bool       `json:"isServiceAdmin"`
	Roles          []string   `json:"roles"`
	Active         bool       `json:"active"`
	Source         string     `json:"source"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastLoginAt    *time.Time `json:"lastLoginAt,omitempty"`
	HasPassword    bool       `json:"hasPassword"`
}

// Users is the user repository.
type Users struct{ pool *pgxpool.Pool }

// NewUsers builds the repository.
func NewUsers(pool *pgxpool.Pool) *Users { return &Users{pool: pool} }

const userCols = `id, username, COALESCE(email,''), COALESCE(display_name,''),
	COALESCE(keycloak_sub,''), is_service_admin, roles, active, source,
	created_at, last_login_at, (password_hash IS NOT NULL)`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.KeycloakSub,
		&u.IsServiceAdmin, &u.Roles, &u.Active, &u.Source, &u.CreatedAt,
		&u.LastLoginAt, &u.HasPassword)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ByID loads a user by primary key.
func (r *Users) ByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
}

// ByUsername loads a user by case-insensitive username.
func (r *Users) ByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE lower(username)=lower($1)`, username))
}

// PasswordHash returns the stored bcrypt hash for a local account.
func (r *Users) PasswordHash(ctx context.Context, id int64) (string, error) {
	var hash *string
	if err := r.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, id).
		Scan(&hash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	if hash == nil {
		return "", nil
	}
	return *hash, nil
}

// List returns users ordered by username, optionally filtered by substring.
func (r *Users) List(ctx context.Context, q string, limit int) ([]User, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `SELECT `+userCols+` FROM users
		WHERE ($1 = '' OR username ILIKE '%'||$1||'%' OR COALESCE(display_name,'') ILIKE '%'||$1||'%'
		       OR COALESCE(email,'') ILIKE '%'||$1||'%')
		ORDER BY username LIMIT $2`, strings.TrimSpace(q), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// CreateLocal inserts a local account with a password.
func (r *Users) CreateLocal(ctx context.Context, username, password, display, email string, admin bool, roles []string) (*User, error) {
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}
	if roles == nil {
		roles = []string{}
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO users(username, email, display_name, password_hash, is_service_admin, roles, source)
		VALUES ($1,$2,$3,$4,$5,$6,'local')`,
		username, nullable(email), nullable(display), hash, admin, roles)
	if err != nil {
		return nil, err
	}
	return r.ByUsername(ctx, username)
}

// EnsureBootstrapAdmin creates or repairs the bootstrap administrator so the
// operator can always sign in with the environment-provided credentials.
func (r *Users) EnsureBootstrapAdmin(ctx context.Context, username, password string) error {
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO users(username, display_name, password_hash, is_service_admin, roles, active, source)
		VALUES ($1, $1, $2, TRUE, ARRAY['bitbucket-mcp-admin'], TRUE, 'bootstrap')
		ON CONFLICT (username) DO UPDATE
		   SET password_hash = EXCLUDED.password_hash,
		       is_service_admin = TRUE,
		       active = TRUE,
		       updated_at = NOW()`, username, hash)
	return err
}

// UpsertFromKeycloak provisions or refreshes a user seen in an OIDC token.
func (r *Users) UpsertFromKeycloak(ctx context.Context, sub, username, email, display string, roles []string, admin bool) (*User, error) {
	if roles == nil {
		roles = []string{}
	}
	// A local account with the same username is linked rather than duplicated.
	_, err := r.pool.Exec(ctx, `
		INSERT INTO users(username, email, display_name, keycloak_sub, roles, is_service_admin, source)
		VALUES ($1,$2,$3,$4,$5,$6,'keycloak')
		ON CONFLICT (username) DO UPDATE
		   SET email = COALESCE(EXCLUDED.email, users.email),
		       display_name = COALESCE(EXCLUDED.display_name, users.display_name),
		       keycloak_sub = EXCLUDED.keycloak_sub,
		       roles = EXCLUDED.roles,
		       is_service_admin = users.is_service_admin OR EXCLUDED.is_service_admin,
		       updated_at = NOW()`,
		username, nullable(email), nullable(display), sub, roles, admin)
	if err != nil {
		return nil, fmt.Errorf("keycloak 사용자 동기화 실패: %w", err)
	}
	return r.ByUsername(ctx, username)
}

// TouchLogin records a successful sign-in.
func (r *Users) TouchLogin(ctx context.Context, id int64) {
	_, _ = r.pool.Exec(ctx, `UPDATE users SET last_login_at=NOW() WHERE id=$1`, id)
}

// SetPassword replaces a user's password.
func (r *Users) SetPassword(ctx context.Context, id int64, password string) error {
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx,
		`UPDATE users SET password_hash=$2, updated_at=NOW() WHERE id=$1`, id, hash)
	return err
}

// Update applies administrative changes to a user.
func (r *Users) Update(ctx context.Context, id int64, display, email string, admin, active bool, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET display_name=$2, email=$3, is_service_admin=$4,
		       active=$5, roles=$6, updated_at=NOW() WHERE id=$1`,
		id, nullable(display), nullable(email), admin, active, roles)
	return err
}

// Delete removes a user account.
func (r *Users) Delete(ctx context.Context, id int64) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

// CountAdmins reports how many active service administrators remain.
func (r *Users) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE is_service_admin AND active`).Scan(&n)
	return n, err
}

func nullable(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
