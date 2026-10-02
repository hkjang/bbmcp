package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	oidclib "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/hkjang/bbmcp/internal/settings"
)

// Claims is the subset of an OIDC token bbmcp relies on.
type Claims struct {
	Subject     string
	Username    string
	Email       string
	DisplayName string
	Roles       []string
	Raw         map[string]any
}

// OIDC lazily builds an OIDC provider from admin-managed settings and
// rebuilds it whenever the issuer or client changes.
type OIDC struct {
	store *settings.Store

	mu       sync.Mutex
	cacheKey string
	provider *oidclib.Provider
	verifier *oidclib.IDTokenVerifier
}

// NewOIDC builds the manager.
func NewOIDC(store *settings.Store) *OIDC { return &OIDC{store: store} }

// Config returns the current Keycloak settings with the client secret decrypted.
func (o *OIDC) Config(ctx context.Context) (settings.Keycloak, string, error) {
	kc, err := o.store.Keycloak(ctx)
	if err != nil {
		return kc, "", err
	}
	secret, err := o.store.Reveal(kc.ClientSecretEnc)
	if err != nil {
		return kc, "", err
	}
	return kc, secret, nil
}

// Enabled reports whether SSO is configured well enough to attempt.
func (o *OIDC) Enabled(ctx context.Context) bool {
	kc, err := o.store.Keycloak(ctx)
	if err != nil {
		return false
	}
	return kc.Enabled && kc.Issuer != "" && kc.ClientID != ""
}

func httpClientFor(insecure bool, timeout time.Duration) *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - operator opt-in for internal CAs
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// provide returns a provider/verifier pair for the current settings.
func (o *OIDC) provide(ctx context.Context) (*oidclib.Provider, *oidclib.IDTokenVerifier, settings.Keycloak, string, error) {
	kc, secret, err := o.Config(ctx)
	if err != nil {
		return nil, nil, kc, "", err
	}
	if !kc.Enabled || kc.Issuer == "" || kc.ClientID == "" {
		return nil, nil, kc, "", errors.New("Keycloak SSO가 설정되지 않았습니다")
	}

	key := fmt.Sprintf("%s|%s|%t", kc.Issuer, kc.ClientID, kc.InsecureSkipTLS)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cacheKey == key && o.provider != nil {
		return o.provider, o.verifier, kc, secret, nil
	}

	cctx := oidclib.ClientContext(ctx, httpClientFor(kc.InsecureSkipTLS, 15*time.Second))
	provider, err := oidclib.NewProvider(cctx, strings.TrimRight(kc.Issuer, "/"))
	if err != nil {
		return nil, nil, kc, "", fmt.Errorf("Keycloak 디스커버리 실패: %w", err)
	}
	o.provider = provider
	o.verifier = provider.Verifier(&oidclib.Config{ClientID: kc.ClientID})
	o.cacheKey = key
	return o.provider, o.verifier, kc, secret, nil
}

// Reset clears the cached provider after a settings change.
func (o *OIDC) Reset() {
	o.mu.Lock()
	o.provider, o.verifier, o.cacheKey = nil, nil, ""
	o.mu.Unlock()
}

// OAuth2Config builds the exchange configuration.
func (o *OIDC) OAuth2Config(ctx context.Context, redirectURL string) (*oauth2.Config, settings.Keycloak, error) {
	provider, _, kc, secret, err := o.provide(ctx)
	if err != nil {
		return nil, kc, err
	}
	if redirectURL == "" {
		redirectURL = kc.RedirectURL
	}
	scopes := kc.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidclib.ScopeOpenID, "profile", "email"}
	}
	return &oauth2.Config{
		ClientID:     kc.ClientID,
		ClientSecret: secret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}, kc, nil
}

// Exchange trades an authorization code for tokens and verifies the ID token.
func (o *OIDC) Exchange(ctx context.Context, redirectURL, code, verifier, nonce string) (*Claims, string, error) {
	cfg, kc, err := o.OAuth2Config(ctx, redirectURL)
	if err != nil {
		return nil, "", err
	}
	cctx := context.WithValue(ctx, oauth2.HTTPClient, httpClientFor(kc.InsecureSkipTLS, 20*time.Second))
	opts := []oauth2.AuthCodeOption{}
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}
	tok, err := cfg.Exchange(cctx, code, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("토큰 교환 실패: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, "", errors.New("id_token이 응답에 없습니다")
	}
	claims, err := o.VerifyIDToken(ctx, rawID, nonce)
	if err != nil {
		return nil, "", err
	}
	return claims, rawID, nil
}

// VerifyIDToken validates an ID token and extracts claims.
func (o *OIDC) VerifyIDToken(ctx context.Context, raw, nonce string) (*Claims, error) {
	_, verifier, kc, _, err := o.provide(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := verifier.Verify(oidclib.ClientContext(ctx,
		httpClientFor(kc.InsecureSkipTLS, 15*time.Second)), raw)
	if err != nil {
		return nil, fmt.Errorf("ID 토큰 검증 실패: %w", err)
	}
	if nonce != "" && tok.Nonce != nonce {
		return nil, errors.New("nonce 불일치")
	}
	return claimsFrom(tok, kc)
}

// VerifyAccessToken validates a bearer access token presented to /mcp.
// Keycloak access tokens carry the client in azp rather than aud, so the
// audience check is relaxed and the authorized party is checked instead.
func (o *OIDC) VerifyAccessToken(ctx context.Context, raw string) (*Claims, error) {
	provider, _, kc, _, err := o.provide(ctx)
	if err != nil {
		return nil, err
	}
	v := provider.Verifier(&oidclib.Config{SkipClientIDCheck: true})
	tok, err := v.Verify(oidclib.ClientContext(ctx,
		httpClientFor(kc.InsecureSkipTLS, 15*time.Second)), raw)
	if err != nil {
		return nil, fmt.Errorf("액세스 토큰 검증 실패: %w", err)
	}
	return claimsFrom(tok, kc)
}

func claimsFrom(tok *oidclib.IDToken, kc settings.Keycloak) (*Claims, error) {
	var raw map[string]any
	if err := tok.Claims(&raw); err != nil {
		return nil, err
	}
	usernameClaim := kc.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "preferred_username"
	}
	c := &Claims{
		Subject:  tok.Subject,
		Username: strings.TrimSpace(stringClaim(raw, usernameClaim)),
		Email:    stringClaim(raw, "email"),
		Roles:    rolesAt(raw, kc.RoleClaimPath),
		Raw:      raw,
	}
	c.DisplayName = stringClaim(raw, "name")
	if c.DisplayName == "" {
		c.DisplayName = c.Username
	}
	if c.Username == "" {
		return nil, fmt.Errorf("토큰에 %s 클레임이 없습니다", usernameClaim)
	}
	return c, nil
}

func stringClaim(raw map[string]any, path string) string {
	v := lookup(raw, path)
	s, _ := v.(string)
	return s
}

// rolesAt reads a dotted claim path (default realm_access.roles).
func rolesAt(raw map[string]any, path string) []string {
	if path == "" {
		path = "realm_access.roles"
	}
	out := []string{}
	for _, p := range strings.Split(path, ",") {
		v := lookup(raw, strings.TrimSpace(p))
		switch t := v.(type) {
		case []any:
			for _, item := range t {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
		case []string:
			out = append(out, t...)
		case string:
			out = append(out, t)
		}
	}
	return out
}

func lookup(raw map[string]any, path string) any {
	cur := any(raw)
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

// HasRole reports whether the claim set contains role.
func (c *Claims) HasRole(role string) bool {
	if role == "" {
		return true
	}
	for _, r := range c.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// MarshalRoles is a helper for audit payloads.
func (c *Claims) MarshalRoles() string {
	b, _ := json.Marshal(c.Roles)
	return string(b)
}
