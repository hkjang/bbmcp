// Package identity binds a Keycloak subject to a Bitbucket user.
//
// The first mapping is discovered from preferred_username, but the durable
// identity is the pair (Keycloak sub, Bitbucket user id): a later rename on
// either side does not silently point the gateway at a different person.
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/bitbucket"
)

// ErrUnmapped means no Bitbucket account could be bound to the subject.
var ErrUnmapped = errors.New("Bitbucket 사용자 매핑을 찾을 수 없습니다")

// Mapping is a stored identity binding.
type Mapping struct {
	ID                int64      `json:"id"`
	KeycloakSub       string     `json:"keycloakSub"`
	KeycloakUsername  string     `json:"keycloakUsername"`
	BitbucketUserID   int64      `json:"bitbucketUserId"`
	BitbucketUsername string     `json:"bitbucketUsername"`
	BitbucketEmail    string     `json:"bitbucketEmail"`
	BitbucketDisplay  string     `json:"bitbucketDisplay"`
	MappingType       string     `json:"mappingType"`
	Active            bool       `json:"active"`
	LastError         string     `json:"lastError,omitempty"`
	MappedAt          time.Time  `json:"mappedAt"`
	VerifiedAt        *time.Time `json:"verifiedAt,omitempty"`
}

// MappingError is a failed mapping attempt surfaced in the admin UI.
type MappingError struct {
	ID               int64     `json:"id"`
	KeycloakSub      string    `json:"keycloakSub"`
	KeycloakUsername string    `json:"keycloakUsername"`
	Reason           string    `json:"reason"`
	OccurredAt       time.Time `json:"occurredAt"`
}

// Mapper resolves and stores identity bindings.
type Mapper struct {
	pool     *pgxpool.Pool
	provider *bitbucket.Provider
}

// NewMapper builds the mapper.
func NewMapper(pool *pgxpool.Pool, provider *bitbucket.Provider) *Mapper {
	return &Mapper{pool: pool, provider: provider}
}

const mapCols = `id, keycloak_sub, keycloak_username, bitbucket_user_id,
	bitbucket_username, COALESCE(bitbucket_email,''), COALESCE(bitbucket_display,''),
	mapping_type, active, COALESCE(last_error,''), mapped_at, verified_at`

func scanMapping(row pgx.Row) (*Mapping, error) {
	var m Mapping
	err := row.Scan(&m.ID, &m.KeycloakSub, &m.KeycloakUsername, &m.BitbucketUserID,
		&m.BitbucketUsername, &m.BitbucketEmail, &m.BitbucketDisplay, &m.MappingType,
		&m.Active, &m.LastError, &m.MappedAt, &m.VerifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnmapped
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// BySub loads a mapping by Keycloak subject.
func (m *Mapper) BySub(ctx context.Context, sub string) (*Mapping, error) {
	return scanMapping(m.pool.QueryRow(ctx,
		`SELECT `+mapCols+` FROM bitbucket_identity_mapping WHERE keycloak_sub=$1`, sub))
}

// List returns mappings for the admin UI.
func (m *Mapper) List(ctx context.Context, q string, limit int) ([]Mapping, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := m.pool.Query(ctx, `SELECT `+mapCols+` FROM bitbucket_identity_mapping
		WHERE ($1='' OR keycloak_username ILIKE '%'||$1||'%' OR bitbucket_username ILIKE '%'||$1||'%')
		ORDER BY keycloak_username LIMIT $2`, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mapping{}
	for rows.Next() {
		one, err := scanMapping(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *one)
	}
	return out, rows.Err()
}

// Resolve returns the Bitbucket identity for a Keycloak subject, discovering
// it from the username on first contact.
func (m *Mapper) Resolve(ctx context.Context, sub, username string) (*Mapping, error) {
	if existing, err := m.BySub(ctx, sub); err == nil {
		if !existing.Active {
			return nil, fmt.Errorf("%w: 매핑이 비활성 상태입니다 (%s)", ErrUnmapped, existing.BitbucketUsername)
		}
		if existing.KeycloakUsername != username {
			_, _ = m.pool.Exec(ctx,
				`UPDATE bitbucket_identity_mapping SET keycloak_username=$2, updated_at=NOW() WHERE keycloak_sub=$1`,
				sub, username)
			existing.KeycloakUsername = username
		}
		return existing, nil
	}
	return m.autoMap(ctx, sub, username)
}

// autoMap performs the first-contact lookup by exact username match.
func (m *Mapper) autoMap(ctx context.Context, sub, username string) (*Mapping, error) {
	adapter, _, err := m.provider.Adapter(ctx)
	if err != nil {
		m.recordError(ctx, sub, username, err.Error())
		return nil, err
	}
	cred, err := m.provider.ServiceCredential(ctx)
	if err != nil {
		m.recordError(ctx, sub, username, err.Error())
		return nil, err
	}
	bbUser, err := adapter.FindUserByUsername(ctx, cred, username)
	if err != nil {
		m.recordError(ctx, sub, username, err.Error())
		return nil, fmt.Errorf("%w: %v", ErrUnmapped, err)
	}
	if !bbUser.Active {
		reason := fmt.Sprintf("Bitbucket 계정 %s 이 비활성 상태입니다", bbUser.Name)
		m.recordError(ctx, sub, username, reason)
		return nil, fmt.Errorf("%w: %s", ErrUnmapped, reason)
	}
	return m.Upsert(ctx, sub, username, bbUser, "auto")
}

// Upsert writes a mapping, rejecting a Bitbucket account already bound to a
// different Keycloak subject.
func (m *Mapper) Upsert(ctx context.Context, sub, username string, bbUser *bitbucket.User, kind string) (*Mapping, error) {
	var otherSub string
	err := m.pool.QueryRow(ctx,
		`SELECT keycloak_sub FROM bitbucket_identity_mapping WHERE bitbucket_user_id=$1`,
		bbUser.ID).Scan(&otherSub)
	if err == nil && otherSub != sub {
		reason := fmt.Sprintf("Bitbucket 사용자 %s 는 이미 다른 Keycloak 주체에 매핑되어 있습니다", bbUser.Name)
		m.recordError(ctx, sub, username, reason)
		return nil, fmt.Errorf("%w: %s", ErrUnmapped, reason)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	_, err = m.pool.Exec(ctx, `
		INSERT INTO bitbucket_identity_mapping(keycloak_sub, keycloak_username,
			bitbucket_user_id, bitbucket_username, bitbucket_email, bitbucket_display,
			mapping_type, active, verified_at, last_error)
		VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,NOW(),NULL)
		ON CONFLICT (keycloak_sub) DO UPDATE
		   SET keycloak_username = EXCLUDED.keycloak_username,
		       bitbucket_user_id = EXCLUDED.bitbucket_user_id,
		       bitbucket_username = EXCLUDED.bitbucket_username,
		       bitbucket_email = EXCLUDED.bitbucket_email,
		       bitbucket_display = EXCLUDED.bitbucket_display,
		       mapping_type = EXCLUDED.mapping_type,
		       active = TRUE,
		       verified_at = NOW(),
		       last_error = NULL,
		       updated_at = NOW()`,
		sub, username, bbUser.ID, bbUser.Name, bbUser.EmailAddress, bbUser.DisplayName, kind)
	if err != nil {
		return nil, err
	}
	return m.BySub(ctx, sub)
}

// Verify re-checks a stored mapping against Bitbucket.
func (m *Mapper) Verify(ctx context.Context, sub string) (*Mapping, error) {
	existing, err := m.BySub(ctx, sub)
	if err != nil {
		return nil, err
	}
	adapter, _, err := m.provider.Adapter(ctx)
	if err != nil {
		return nil, err
	}
	cred, err := m.provider.ServiceCredential(ctx)
	if err != nil {
		return nil, err
	}
	bbUser, err := adapter.FindUserByUsername(ctx, cred, existing.BitbucketUsername)
	if err != nil {
		_, _ = m.pool.Exec(ctx,
			`UPDATE bitbucket_identity_mapping SET last_error=$2, verified_at=NULL, updated_at=NOW() WHERE keycloak_sub=$1`,
			sub, err.Error())
		return nil, err
	}
	if bbUser.ID != existing.BitbucketUserID {
		reason := fmt.Sprintf("Bitbucket 사용자 ID가 %d → %d 로 변경되었습니다", existing.BitbucketUserID, bbUser.ID)
		_, _ = m.pool.Exec(ctx,
			`UPDATE bitbucket_identity_mapping SET last_error=$2, verified_at=NULL, updated_at=NOW() WHERE keycloak_sub=$1`,
			sub, reason)
		return nil, errors.New(reason)
	}
	return m.Upsert(ctx, sub, existing.KeycloakUsername, bbUser, existing.MappingType)
}

// SetActive enables or disables a mapping.
func (m *Mapper) SetActive(ctx context.Context, sub string, active bool) error {
	_, err := m.pool.Exec(ctx,
		`UPDATE bitbucket_identity_mapping SET active=$2, updated_at=NOW() WHERE keycloak_sub=$1`,
		sub, active)
	return err
}

// Delete removes a mapping so it can be rebuilt.
func (m *Mapper) Delete(ctx context.Context, sub string) error {
	_, err := m.pool.Exec(ctx, `DELETE FROM bitbucket_identity_mapping WHERE keycloak_sub=$1`, sub)
	return err
}

// ManualMap binds a subject to a Bitbucket username chosen by an admin.
func (m *Mapper) ManualMap(ctx context.Context, sub, keycloakUsername, bitbucketUsername string) (*Mapping, error) {
	adapter, _, err := m.provider.Adapter(ctx)
	if err != nil {
		return nil, err
	}
	cred, err := m.provider.ServiceCredential(ctx)
	if err != nil {
		return nil, err
	}
	bbUser, err := adapter.FindUserByUsername(ctx, cred, bitbucketUsername)
	if err != nil {
		return nil, err
	}
	return m.Upsert(ctx, sub, keycloakUsername, bbUser, "manual")
}

func (m *Mapper) recordError(ctx context.Context, sub, username, reason string) {
	_, _ = m.pool.Exec(ctx,
		`INSERT INTO identity_mapping_errors(keycloak_sub, keycloak_username, reason) VALUES ($1,$2,$3)`,
		sub, username, reason)
}

// Errors lists recent mapping failures.
func (m *Mapper) Errors(ctx context.Context, limit int) ([]MappingError, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := m.pool.Query(ctx,
		`SELECT id, keycloak_sub, keycloak_username, reason, occurred_at
		 FROM identity_mapping_errors ORDER BY occurred_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MappingError{}
	for rows.Next() {
		var e MappingError
		if err := rows.Scan(&e.ID, &e.KeycloakSub, &e.KeycloakUsername, &e.Reason, &e.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClearErrors empties the mapping error list.
func (m *Mapper) ClearErrors(ctx context.Context) error {
	_, err := m.pool.Exec(ctx, `DELETE FROM identity_mapping_errors`)
	return err
}
