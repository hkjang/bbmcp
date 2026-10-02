package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/crypto"
)

// SessionCookie is the browser cookie carrying the opaque session token.
const SessionCookie = "bbmcp_session"

// ErrSession is returned for a missing, expired or revoked session.
var ErrSession = errors.New("세션이 유효하지 않습니다")

// Session is a browser session record.
type Session struct {
	ID        uuid.UUID
	UserID    int64
	ExpiresAt time.Time
}

// Sessions is the browser session repository.
type Sessions struct {
	pool   *pgxpool.Pool
	sealer *crypto.Sealer
}

// NewSessions builds the repository.
func NewSessions(pool *pgxpool.Pool, sealer *crypto.Sealer) *Sessions {
	return &Sessions{pool: pool, sealer: sealer}
}

// Create issues a new session and returns the raw token for the cookie.
func (s *Sessions) Create(ctx context.Context, userID int64, ttl time.Duration, ip, ua string) (string, *Session, error) {
	token, err := crypto.RandomToken(32)
	if err != nil {
		return "", nil, err
	}
	sess := &Session{ID: uuid.New(), UserID: userID, ExpiresAt: time.Now().Add(ttl)}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO web_sessions(id, user_id, token_hash, ip, user_agent, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		sess.ID, userID, s.sealer.HMAC(token), ip, ua, sess.ExpiresAt)
	if err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

// Resolve validates a raw token and returns its session.
func (s *Sessions) Resolve(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, ErrSession
	}
	var sess Session
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, expires_at FROM web_sessions
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > NOW()`,
		s.sealer.HMAC(token)).Scan(&sess.ID, &sess.UserID, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSession
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// Revoke invalidates a single session by raw token.
func (s *Sessions) Revoke(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE web_sessions SET revoked_at=NOW() WHERE token_hash=$1`, s.sealer.HMAC(token))
	return err
}

// RevokeUser invalidates every session for a user.
func (s *Sessions) RevokeUser(ctx context.Context, userID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE web_sessions SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return err
}

// Cleanup removes expired rows; called periodically.
func (s *Sessions) Cleanup(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM web_sessions WHERE expires_at < NOW() - INTERVAL '7 days'`)
	return err
}

// SetCookie writes the session cookie. Secure is derived from the request so
// the same image works behind plain HTTP in an isolated network and behind
// TLS termination in production.
func SetCookie(w http.ResponseWriter, r *http.Request, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	})
}

// ClearCookie expires the session cookie.
func ClearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}
