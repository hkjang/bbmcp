package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hkjang/bbmcp/internal/apikey"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/crypto"
	"github.com/hkjang/bbmcp/internal/identity"
	"github.com/hkjang/bbmcp/internal/settings"
	"github.com/hkjang/bbmcp/internal/tools"
)

// ErrUnauthenticated is returned when no usable credential is present.
var ErrUnauthenticated = errors.New("인증 정보가 없습니다")

// Service resolves credentials into principals and serves the login endpoints.
type Service struct {
	Users    *Users
	Sessions *Sessions
	OIDC     *OIDC
	Mapper   *identity.Mapper
	Keys     *apikey.Service
	Store    *settings.Store
	Audit    *audit.Logger
	Sealer   *crypto.Sealer
}

// Identity is the authenticated caller as seen by the web API.
type Identity struct {
	User        *User             `json:"user"`
	Mapping     *identity.Mapping `json:"bitbucket,omitempty"`
	Scopes      []string          `json:"scopes"`
	AuthMode    string            `json:"authMode"`
	KeycloakSub string            `json:"keycloakSub"`
	APIKeyID    string            `json:"apiKeyId,omitempty"`
}

// subjectFor returns the durable subject for a user: the Keycloak subject when
// the account came from SSO, and a stable local identifier otherwise.
func subjectFor(u *User) string {
	if u.KeycloakSub != "" {
		return u.KeycloakSub
	}
	return "local:" + strings.ToLower(u.Username)
}

// Resolve authenticates a request, trying session cookie, bearer token and
// API key in that order.
func (s *Service) Resolve(ctx context.Context, r *http.Request) (*Identity, error) {
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		sess, err := s.Sessions.Resolve(ctx, c.Value)
		if err == nil {
			u, err := s.Users.ByID(ctx, sess.UserID)
			if err != nil {
				return nil, err
			}
			if !u.Active {
				return nil, errors.New("비활성 계정입니다")
			}
			return s.identityFor(ctx, u, "session", ""), nil
		}
	}

	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz != "" {
		scheme, token, _ := strings.Cut(authz, " ")
		token = strings.TrimSpace(token)
		switch {
		case strings.EqualFold(scheme, "bearer") && strings.HasPrefix(token, apikey.Prefix+"_"):
			return s.resolveAPIKey(ctx, token)
		case strings.EqualFold(scheme, "bearer"):
			return s.resolveOIDCBearer(ctx, token)
		}
	}
	if raw := strings.TrimSpace(r.Header.Get("X-API-Key")); raw != "" {
		return s.resolveAPIKey(ctx, raw)
	}
	return nil, ErrUnauthenticated
}

func (s *Service) resolveAPIKey(ctx context.Context, raw string) (*Identity, error) {
	v, err := s.Keys.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	u, err := s.Users.ByID(ctx, v.Key.UserID)
	if err != nil {
		return nil, err
	}
	if !u.Active {
		return nil, errors.New("비활성 계정의 키입니다")
	}
	id := s.identityFor(ctx, u, "apikey", v.Key.ID.String())
	id.Scopes = v.Scopes
	return id, nil
}

func (s *Service) resolveOIDCBearer(ctx context.Context, token string) (*Identity, error) {
	claims, err := s.OIDC.VerifyAccessToken(ctx, token)
	if err != nil {
		return nil, err
	}
	kc, err := s.Store.Keycloak(ctx)
	if err != nil {
		return nil, err
	}
	if kc.RequireRole != "" && !claims.HasRole(kc.RequireRole) {
		return nil, fmt.Errorf("%s 역할이 필요합니다", kc.RequireRole)
	}
	u, err := s.Users.UpsertFromKeycloak(ctx, claims.Subject, claims.Username,
		claims.Email, claims.DisplayName, claims.Roles, claims.HasRole(kc.AdminRole))
	if err != nil {
		return nil, err
	}
	id := s.identityFor(ctx, u, "oauth", "")
	id.Scopes = tools.ScopesForRoles(claims.Roles)
	if u.IsServiceAdmin {
		id.Scopes = tools.ScopesForRoles([]string{tools.RoleAdmin})
	}
	return id, nil
}

// identityFor assembles the identity, resolving the Bitbucket mapping lazily.
func (s *Service) identityFor(ctx context.Context, u *User, mode, keyID string) *Identity {
	id := &Identity{
		User:        u,
		AuthMode:    mode,
		KeycloakSub: subjectFor(u),
		APIKeyID:    keyID,
		Scopes:      tools.ScopesForRoles(u.Roles),
	}
	if u.IsServiceAdmin {
		id.Scopes = tools.ScopesForRoles([]string{tools.RoleAdmin})
	}
	if m, err := s.Mapper.Resolve(ctx, id.KeycloakSub, u.Username); err == nil {
		id.Mapping = m
	}
	return id
}

// Principal converts an identity into a tool principal.
func (id *Identity) Principal(client, ip string, preferUserPAT bool) tools.Principal {
	p := tools.Principal{
		UserID:         id.User.ID,
		KeycloakSub:    id.KeycloakSub,
		Username:       id.User.Username,
		DisplayName:    id.User.DisplayName,
		Roles:          id.User.Roles,
		Scopes:         id.Scopes,
		IsServiceAdmin: id.User.IsServiceAdmin,
		AuthMode:       id.AuthMode,
		Client:         client,
		IP:             ip,
		PreferUserPAT:  preferUserPAT,
	}
	if id.Mapping != nil {
		p.BitbucketUserID = id.Mapping.BitbucketUserID
		p.BitbucketUsername = id.Mapping.BitbucketUsername
	}
	if p.IsServiceAdmin {
		p.Roles = appendUnique(p.Roles, tools.RoleAdmin)
	}
	return p
}

func appendUnique(list []string, v string) []string {
	for _, item := range list {
		if strings.EqualFold(item, v) {
			return list
		}
	}
	return append(list, v)
}

// LoginLocal verifies a username/password pair and creates a session.
func (s *Service) LoginLocal(ctx context.Context, username, password, ip, ua string) (string, time.Duration, *Identity, error) {
	sec, err := s.Store.Security(ctx)
	if err != nil {
		return "", 0, nil, err
	}
	ttl := time.Duration(sec.SessionTTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}

	u, err := s.Users.ByUsername(ctx, username)
	if err != nil || !u.Active {
		return "", 0, nil, errors.New("아이디 또는 비밀번호가 올바르지 않습니다")
	}
	hash, err := s.Users.PasswordHash(ctx, u.ID)
	if err != nil || hash == "" || !crypto.VerifyPassword(hash, password) {
		s.Audit.Write(ctx, audit.Entry{
			Category: audit.CatAuth, Action: "login.local", KeycloakUsername: username,
			Success: false, ErrorCode: "BAD_CREDENTIALS", IP: ip,
		})
		return "", 0, nil, errors.New("아이디 또는 비밀번호가 올바르지 않습니다")
	}

	token, _, err := s.Sessions.Create(ctx, u.ID, ttl, ip, ua)
	if err != nil {
		return "", 0, nil, err
	}
	s.Users.TouchLogin(ctx, u.ID)
	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatAuth, Action: "login.local", KeycloakUsername: u.Username,
		Success: true, IP: ip, AuthMode: "session",
	})
	return token, ttl, s.identityFor(ctx, u, "session", ""), nil
}

// oidcState is the short-lived state carried in a cookie across the redirect.
type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Silent   bool   `json:"q"`
	ReturnTo string `json:"r"`
	Redirect string `json:"d"`
	Issued   int64  `json:"t"`
}

// StateCookie is the cookie holding the in-flight OIDC state.
const StateCookie = "bbmcp_oidc"

// SealState encrypts the OIDC state for the cookie.
func (s *Service) SealState(st oidcState) (string, error) {
	body, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	return s.Sealer.Seal(base64.RawURLEncoding.EncodeToString(body))
}

// OpenState decrypts and validates the OIDC state cookie.
func (s *Service) OpenState(raw string) (*oidcState, error) {
	plain, err := s.Sealer.Open(raw)
	if err != nil {
		return nil, err
	}
	body, err := base64.RawURLEncoding.DecodeString(plain)
	if err != nil {
		return nil, err
	}
	var st oidcState
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, err
	}
	if time.Since(time.Unix(st.Issued, 0)) > 10*time.Minute {
		return nil, errors.New("로그인 상태가 만료되었습니다")
	}
	return &st, nil
}

// NewState builds a fresh OIDC state.
func NewState(silent bool, returnTo, redirect string) (oidcState, error) {
	state, err := crypto.RandomToken(16)
	if err != nil {
		return oidcState{}, err
	}
	nonce, err := crypto.RandomToken(16)
	if err != nil {
		return oidcState{}, err
	}
	verifier, err := crypto.RandomToken(32)
	if err != nil {
		return oidcState{}, err
	}
	return oidcState{
		State: state, Nonce: nonce, Verifier: verifier, Silent: silent,
		ReturnTo: returnTo, Redirect: redirect, Issued: time.Now().Unix(),
	}, nil
}

// CompleteOIDC turns verified claims into a session.
func (s *Service) CompleteOIDC(ctx context.Context, claims *Claims, ip, ua string) (string, time.Duration, *Identity, error) {
	kc, err := s.Store.Keycloak(ctx)
	if err != nil {
		return "", 0, nil, err
	}
	if kc.RequireRole != "" && !claims.HasRole(kc.RequireRole) {
		return "", 0, nil, fmt.Errorf("%s 역할이 없어 로그인할 수 없습니다", kc.RequireRole)
	}

	var u *User
	if kc.AutoProvision {
		u, err = s.Users.UpsertFromKeycloak(ctx, claims.Subject, claims.Username,
			claims.Email, claims.DisplayName, claims.Roles, claims.HasRole(kc.AdminRole))
	} else {
		u, err = s.Users.ByUsername(ctx, claims.Username)
		if err == nil {
			u, err = s.Users.UpsertFromKeycloak(ctx, claims.Subject, claims.Username,
				claims.Email, claims.DisplayName, claims.Roles, claims.HasRole(kc.AdminRole))
		}
	}
	if err != nil {
		return "", 0, nil, err
	}
	if !u.Active {
		return "", 0, nil, errors.New("비활성 계정입니다")
	}

	sec, err := s.Store.Security(ctx)
	if err != nil {
		return "", 0, nil, err
	}
	ttl := time.Duration(sec.SessionTTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	token, _, err := s.Sessions.Create(ctx, u.ID, ttl, ip, ua)
	if err != nil {
		return "", 0, nil, err
	}
	s.Users.TouchLogin(ctx, u.ID)
	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatAuth, Action: "login.oidc", KeycloakSub: claims.Subject,
		KeycloakUsername: claims.Username, Success: true, IP: ip, AuthMode: "oauth",
		Detail: map[string]any{"roles": claims.Roles},
	})
	return token, ttl, s.identityFor(ctx, u, "session", ""), nil
}
