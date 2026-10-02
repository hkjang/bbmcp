package bitbucket

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/settings"
)

// ErrNoServicePAT means the admin has not configured the service account yet.
var ErrNoServicePAT = errors.New("Bitbucket 서비스 계정 PAT이 설정되지 않았습니다")

// ErrNoUserPAT means the user has not registered a personal token.
var ErrNoUserPAT = errors.New("등록된 Bitbucket 개인 액세스 토큰이 없습니다")

// Provider builds adapters from the admin-managed settings and resolves the
// credential a call should run under.
type Provider struct {
	store *settings.Store
	pool  *pgxpool.Pool

	mu     sync.Mutex
	key    string
	client *Client
}

// NewProvider builds the provider.
func NewProvider(store *settings.Store, pool *pgxpool.Pool) *Provider {
	return &Provider{store: store, pool: pool}
}

// Reset drops the cached client after a settings change.
func (p *Provider) Reset() {
	p.mu.Lock()
	p.client, p.key = nil, ""
	p.mu.Unlock()
}

// Adapter returns an adapter for the current settings.
func (p *Provider) Adapter(ctx context.Context) (Adapter, settings.Bitbucket, error) {
	cfg, err := p.store.Bitbucket(ctx)
	if err != nil {
		return nil, cfg, err
	}
	key := fmt.Sprintf("%s|%s|%d|%t", cfg.BaseURL, cfg.RestPrefix, cfg.TimeoutSec, cfg.InsecureSkipTLS)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == key && p.client != nil {
		return p.client, cfg, nil
	}
	c, err := NewClient(cfg)
	if err != nil {
		return nil, cfg, err
	}
	p.client, p.key = c, key
	return c, cfg, nil
}

// ServiceCredential returns the central service account credential.
func (p *Provider) ServiceCredential(ctx context.Context) (Credential, error) {
	cfg, err := p.store.Bitbucket(ctx)
	if err != nil {
		return Credential{}, err
	}
	pat, err := p.store.Reveal(cfg.ServicePATEnc)
	if err != nil {
		return Credential{}, err
	}
	if strings.TrimSpace(pat) == "" {
		return Credential{}, ErrNoServicePAT
	}
	return Credential{Mode: "service", Username: cfg.ServiceUsername, Token: pat}, nil
}

// UserPAT is a stored personal token for User Mode attribution.
type UserPAT struct {
	UserID        int64  `json:"userId"`
	BitbucketUser string `json:"bitbucketUser"`
	HasToken      bool   `json:"hasToken"`
	VerifiedAt    *int64 `json:"verifiedAt,omitempty"`
}

// UserCredential returns the user's own PAT credential.
func (p *Provider) UserCredential(ctx context.Context, userID int64) (Credential, error) {
	var bbUser, enc string
	err := p.pool.QueryRow(ctx,
		`SELECT bitbucket_user, pat_enc FROM user_bitbucket_pat WHERE user_id=$1`, userID).
		Scan(&bbUser, &enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrNoUserPAT
	}
	if err != nil {
		return Credential{}, err
	}
	pat, err := p.store.Reveal(enc)
	if err != nil {
		return Credential{}, err
	}
	if pat == "" {
		return Credential{}, ErrNoUserPAT
	}
	return Credential{Mode: "user", Username: bbUser, Token: pat}, nil
}

// SaveUserPAT stores a user's personal token encrypted at rest.
func (p *Provider) SaveUserPAT(ctx context.Context, userID int64, bbUser, pat string) error {
	enc, err := p.store.Seal(pat)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO user_bitbucket_pat(user_id, bitbucket_user, pat_enc, updated_at)
		VALUES ($1,$2,$3,NOW())
		ON CONFLICT (user_id) DO UPDATE
		   SET bitbucket_user = EXCLUDED.bitbucket_user,
		       pat_enc = EXCLUDED.pat_enc,
		       verified_at = NULL,
		       updated_at = NOW()`, userID, bbUser, enc)
	return err
}

// DeleteUserPAT removes a user's personal token.
func (p *Provider) DeleteUserPAT(ctx context.Context, userID int64) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM user_bitbucket_pat WHERE user_id=$1`, userID)
	return err
}

// MarkUserPATVerified records a successful connectivity check.
func (p *Provider) MarkUserPATVerified(ctx context.Context, userID int64) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE user_bitbucket_pat SET verified_at=NOW() WHERE user_id=$1`, userID)
	return err
}

// UserPATInfo reports whether a user has a token registered.
func (p *Provider) UserPATInfo(ctx context.Context, userID int64) (*UserPAT, error) {
	var out UserPAT
	out.UserID = userID
	var verified *int64
	err := p.pool.QueryRow(ctx, `
		SELECT bitbucket_user, (pat_enc <> ''),
		       (EXTRACT(EPOCH FROM verified_at))::BIGINT
		FROM user_bitbucket_pat WHERE user_id=$1`, userID).
		Scan(&out.BitbucketUser, &out.HasToken, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		return &out, nil
	}
	if err != nil {
		return nil, err
	}
	out.VerifiedAt = verified
	return &out, nil
}
