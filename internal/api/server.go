// Package api exposes the HTTP surface of bbmcp: the admin console API, the
// personal (self-service) API, the Keycloak login endpoints, the AI streaming
// proxy and the MCP endpoint, plus the embedded React application.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/aiproxy"
	"github.com/hkjang/bbmcp/internal/apikey"
	"github.com/hkjang/bbmcp/internal/approval"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/auth"
	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/httpx"
	"github.com/hkjang/bbmcp/internal/identity"
	"github.com/hkjang/bbmcp/internal/mcp"
	"github.com/hkjang/bbmcp/internal/permission"
	"github.com/hkjang/bbmcp/internal/policy"
	"github.com/hkjang/bbmcp/internal/settings"
	"github.com/hkjang/bbmcp/internal/tools"
	"github.com/hkjang/bbmcp/internal/version"
)

// Deps are the collaborators the HTTP layer needs.
type Deps struct {
	Pool      *pgxpool.Pool
	Store     *settings.Store
	Auth      *auth.Service
	Users     *auth.Users
	Sessions  *auth.Sessions
	Keys      *apikey.Service
	Mapper    *identity.Mapper
	Provider  *bitbucket.Provider
	Resolver  *permission.Resolver
	Policy    *policy.Engine
	Approvals *approval.Engine
	Registry  *tools.Registry
	Executor  *tools.Executor
	Audit     *audit.Logger
	AI        *aiproxy.Proxy
	Static    http.Handler
}

// Server is the bbmcp HTTP server.
type Server struct {
	Deps
	limiter *httpx.RateLimiter
	mcp     *mcp.Server
	asMeta  asMetadataCache
	trace   *discoveryTrace
	booted  time.Time
	// proxyHint logs the untrusted forwarding-header warning once.
	proxyHint sync.Once
}

// New builds the server and its routes.
func New(d Deps) *Server {
	s := &Server{Deps: d, limiter: httpx.NewRateLimiter(), trace: newDiscoveryTrace(), booted: time.Now()}
	s.mcp = mcp.NewServer(d.Executor, s, d.Store, d.Pool)
	return s
}

type ctxKey string

const identityKey ctxKey = "bbmcp.identity"

// Router builds the HTTP routes.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// No middleware.RealIP: it rewrites RemoteAddr from X-Forwarded-For and
	// X-Real-IP for every caller, which made the IP allowlist and rate limits
	// spoofable even with proxy headers untrusted. httpx.ClientIP reads those
	// headers itself, and only when TrustProxyHeaders is set.
	r.Use(middleware.Recoverer)
	r.Use(s.securityHeaders)
	r.Use(s.ipAllowlist)

	r.Get("/healthz", s.health)
	r.Get("/readyz", s.ready)
	r.Get("/metrics", s.metrics)
	s.mountOAuth(r)

	r.Route("/auth", func(r chi.Router) {
		r.Get("/oidc/start", s.oidcStart)
		r.Get("/oidc/callback", s.oidcCallback)
		r.Get("/oidc/silent", s.oidcSilentFrame)
	})

	r.Route("/api", func(r chi.Router) {
		r.Use(httpx.NoCacheMiddleware)
		r.Get("/version", s.versionInfo)
		r.Get("/config", s.publicConfig)

		r.Post("/auth/login", s.login)
		r.Post("/auth/logout", s.logout)
		r.Get("/auth/me", s.whoami)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			s.mountPersonal(r)
			r.Route("/ai", func(r chi.Router) {
				r.Post("/chat", s.aiChat)
				r.Get("/models", s.aiModels)
			})
			r.Route("/admin", func(r chi.Router) {
				r.Use(s.requireAdmin)
				s.mountAdmin(r)
			})
		})
	})

	r.HandleFunc("/mcp", s.handleMCP)
	r.HandleFunc("/mcp/*", s.handleMCP)

	if s.Static != nil {
		r.NotFound(s.Static.ServeHTTP)
	}
	return r
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	// Lets an operator see which build answers, including on the 401 that
	// starts a client's OAuth discovery.
	w.Header().Set(versionHeader, version.Version)
	sec, _ := s.Store.Security(r.Context())
	ip := httpx.ClientIP(r, sec.TrustProxyHeaders)
	if !s.limiter.Allow("mcp:"+ip, sec.RateLimitPerMin, sec.RateLimitBurst) {
		httpx.FailCode(w, http.StatusTooManyRequests, "RATE_LIMITED", "요청이 너무 많습니다")
		return
	}
	s.mcp.Handle(w, r)
}

// PrincipalFor implements mcp.Authenticator.
func (s *Server) PrincipalFor(r *http.Request) (tools.Principal, error) {
	id, err := s.Auth.Resolve(r.Context(), r)
	if err != nil {
		return tools.Principal{}, err
	}
	sec, _ := s.Store.Security(r.Context())
	client := r.Header.Get("User-Agent")
	prefer := s.preferUserPAT(r.Context(), id.User.ID)
	return id.Principal(client, httpx.ClientIP(r, sec.TrustProxyHeaders), prefer), nil
}

// Challenge implements mcp.Authenticator, pointing clients at Keycloak.
//
// The resource_metadata hint is what starts an MCP client's OAuth flow: it
// reads the protected resource metadata, finds the authorization server and
// signs the user in. When a token was presented but rejected, the reason is
// included so the client reports something actionable instead of looping.
func (s *Server) Challenge(r *http.Request) string {
	ctx := r.Context()
	cfg, _ := s.Store.MCP(ctx)
	parts := []string{
		`resource_metadata="` + s.resourceMetadataURL(r, cfg) + `"`,
	}
	if kc, err := s.Store.Keycloak(ctx); err == nil && len(kc.MCPScopes) > 0 {
		parts = append(parts, `scope="`+strings.Join(kc.MCPScopes, " ")+`"`)
	}
	presented := strings.TrimSpace(r.Header.Get("Authorization")) != ""
	if presented {
		parts = append([]string{`error="invalid_token"`}, parts...)
	}
	detail := "자격증명 없음"
	if presented {
		detail = "토큰 거부"
	}
	s.traceRequest(r, traceChallenge, http.StatusUnauthorized, detail)
	return "Bearer " + strings.Join(parts, ", ")
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) ipAllowlist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sec, err := s.Store.Security(r.Context())
		if err == nil && !sec.TrustProxyHeaders && (r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "") {
			// Behind a reverse proxy every client now looks like the proxy;
			// say so once instead of leaving a lockout to be guessed at.
			s.proxyHint.Do(func() {
				slog.Warn("프록시 헤더(X-Forwarded-For/X-Real-IP)가 오지만 '프록시 헤더 신뢰'가 꺼져 있어 접속 주소로 쓰지 않습니다. " +
					"리버스 프록시 뒤라면 보안 설정에서 켜십시오. IP 허용 목록과 요청 제한이 프록시 주소 기준으로 동작합니다.")
			})
		}
		if err == nil && len(sec.IPAllowlist) > 0 {
			ip := httpx.ClientIP(r, sec.TrustProxyHeaders)
			if !httpx.IPAllowed(ip, sec.IPAllowlist) {
				httpx.FailCode(w, http.StatusForbidden, "IP_DENIED", "허용되지 않은 접근 주소입니다")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.Auth.Resolve(r.Context(), r)
		if err != nil {
			code := "UNAUTHENTICATED"
			if !errors.Is(err, auth.ErrUnauthenticated) {
				code = "AUTH_FAILED"
			}
			httpx.FailCode(w, http.StatusUnauthorized, code, "로그인이 필요합니다")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
	})
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identityOf(r)
		if id == nil || !id.User.IsServiceAdmin {
			httpx.FailCode(w, http.StatusForbidden, "ADMIN_REQUIRED", "서비스 관리자 권한이 필요합니다")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func identityOf(r *http.Request) *auth.Identity {
	v, _ := r.Context().Value(identityKey).(*auth.Identity)
	return v
}

func (s *Server) versionInfo(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, version.Current())
}

// publicConfig is what the login screen needs before anybody is signed in.
func (s *Server) publicConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ui, _ := s.Store.UI(ctx)
	kc, _ := s.Store.Keycloak(ctx)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ui":      ui,
		"version": version.Current(),
		"auth": map[string]any{
			"keycloakEnabled": kc.Enabled && kc.Issuer != "" && kc.ClientID != "",
			"silentSso":       kc.Enabled && kc.SilentSSO,
			"startUrl":        "/auth/oidc/start",
			"silentUrl":       "/auth/oidc/silent",
			"localLogin":      true,
		},
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "bbmcp",
		"version": version.Version,
		"time":    time.Now().UTC(),
	})
}

// baseURL is this gateway's public origin as the caller reached it.
//
// Forwarding headers are only believed when the operator said a proxy is in
// front; otherwise a client could forge the origin bbmcp builds redirect URIs
// from. The result is normalised so it matches what Keycloak has registered.
func (s *Server) baseURL(r *http.Request) string {
	trust := true
	if sec, err := s.Store.Security(r.Context()); err == nil {
		trust = sec.TrustProxyHeaders
	}
	return httpx.RequestBaseURL(r, trust)
}
