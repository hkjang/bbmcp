package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/crypto"
	"github.com/hkjang/bbmcp/internal/database"
	"github.com/hkjang/bbmcp/internal/httpx"
	"github.com/hkjang/bbmcp/internal/settings"
)

// fakeKeycloak serves the discovery document a real realm would.
func fakeKeycloak(t *testing.T, withDCR bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	doc := func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/protocol/openid-connect/auth",
			"token_endpoint":                        srv.URL + "/protocol/openid-connect/token",
			"jwks_uri":                              srv.URL + "/protocol/openid-connect/certs",
			"code_challenge_methods_supported":      []string{"plain", "S256"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"response_types_supported":              []string{"code"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		}
		if withDCR {
			body["registration_endpoint"] = srv.URL + "/clients-registrations/openid-connect"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
	mux.HandleFunc("/.well-known/openid-configuration", doc)
	// Keycloak does not serve the oauth-authorization-server path on every
	// version, so the fake answers 404 there to exercise the fallback.
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newOAuthServer builds an api.Server backed by the test database.
func newOAuthServer(t *testing.T) (*Server, *settings.Store, context.Context) {
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
	if _, err := db.Pool.Exec(ctx, `DELETE FROM settings`); err != nil {
		t.Fatalf("clear settings: %v", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 5)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	store := settings.NewStore(db.Pool, sealer)
	srv := &Server{
		Deps:    Deps{Pool: db.Pool, Store: store, Audit: audit.New(db.Pool)},
		limiter: httpx.NewRateLimiter(),
	}
	return srv, store, ctx
}

func configureKeycloak(t *testing.T, store *settings.Store, ctx context.Context, mutate func(*settings.Keycloak)) {
	t.Helper()
	kc := settings.DefaultKeycloak()
	kc.Enabled = true
	kc.ClientID = "bbmcp"
	if mutate != nil {
		mutate(&kc)
	}
	if err := store.Put(ctx, settings.KeyKeycloak, kc, "test"); err != nil {
		t.Fatalf("settings: %v", err)
	}
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("응답 파싱 실패: %v (%s)", err, rec.Body.String())
	}
	return out
}

func TestProtectedResourceMetadataPointsAtKeycloak(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPRequiredScope = "mcp"
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-protected-resource", nil)
	srv.protectedResource(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("상태 코드 %d", rec.Code)
	}
	body := decode(t, rec)
	if body["resource"] != "https://bbmcp.local" {
		t.Errorf("resource = %v", body["resource"])
	}
	servers, _ := body["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != kcSrv.URL {
		t.Fatalf("authorization_servers = %v", body["authorization_servers"])
	}
	scopes, _ := body["scopes_supported"].([]any)
	found := false
	for _, s := range scopes {
		if s == "mcp" {
			found = true
		}
	}
	if !found {
		t.Errorf("필수 스코프가 광고되지 않았습니다: %v", scopes)
	}
}

func TestProtectedResourceOmitsServerWhenOAuthOff(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPOAuthEnabled = false
	})

	rec := httptest.NewRecorder()
	srv.protectedResource(rec, httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-protected-resource", nil))
	servers, _ := decode(t, rec)["authorization_servers"].([]any)
	if len(servers) != 0 {
		t.Fatalf("MCP OAuth 가 꺼졌는데 인가 서버를 광고했습니다: %v", servers)
	}
}

func TestAuthorizationServerMetadataFallsBackToOpenIDConfiguration(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = kcSrv.URL })

	rec := httptest.NewRecorder()
	srv.authorizationServerMetadata(rec,
		httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-authorization-server", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("상태 코드 %d: %s", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if body["issuer"] != kcSrv.URL {
		t.Errorf("issuer = %v (Keycloak 을 그대로 가리켜야 합니다)", body["issuer"])
	}
	if body["token_endpoint"] != kcSrv.URL+"/protocol/openid-connect/token" {
		t.Errorf("token_endpoint = %v", body["token_endpoint"])
	}
	// With registration proxying on, clients are sent to this gateway.
	if body["registration_endpoint"] != "https://bbmcp.local/oauth/register" {
		t.Errorf("registration_endpoint = %v", body["registration_endpoint"])
	}
}

func TestAuthorizationServerMetadataKeepsKeycloakRegistrationWhenProxyOff(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPAllowDCR = false
	})

	rec := httptest.NewRecorder()
	srv.authorizationServerMetadata(rec,
		httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-authorization-server", nil))
	body := decode(t, rec)
	if body["registration_endpoint"] != kcSrv.URL+"/clients-registrations/openid-connect" {
		t.Errorf("registration_endpoint = %v", body["registration_endpoint"])
	}
}

func TestAuthorizationServerMetadataHiddenWhenDisabled(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Enabled = false
		kc.Issuer = "https://sso.example/realms/x"
	})

	rec := httptest.NewRecorder()
	srv.authorizationServerMetadata(rec,
		httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-authorization-server", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("상태 코드 %d, 404 여야 합니다", rec.Code)
	}
}

func TestRegisterClientReturnsPublicClient(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, false)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPClientID = "bbmcp-mcp"
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register",
		jsonBody(`{"redirect_uris":["http://127.0.0.1:33418/callback"],"client_name":"Claude Code"}`))
	srv.registerClient(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("상태 코드 %d: %s", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if body["client_id"] != "bbmcp-mcp" {
		t.Errorf("client_id = %v", body["client_id"])
	}
	if _, has := body["client_secret"]; has {
		t.Error("공개 클라이언트에 시크릿이 발급되었습니다")
	}
	if body["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method = %v", body["token_endpoint_auth_method"])
	}
	uris, _ := body["redirect_uris"].([]any)
	if len(uris) != 1 || uris[0] != "http://127.0.0.1:33418/callback" {
		t.Errorf("redirect_uris = %v", body["redirect_uris"])
	}
	if body["client_name"] != "Claude Code" {
		t.Errorf("client_name = %v", body["client_name"])
	}
}

func TestRegisterClientRefusedWhenDisabled(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, false)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPAllowDCR = false
	})

	rec := httptest.NewRecorder()
	srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register", jsonBody(`{}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("상태 코드 %d, 403 이어야 합니다", rec.Code)
	}
	if decode(t, rec)["error"] != "access_denied" {
		t.Errorf("error = %v", decode(t, rec)["error"])
	}
}

func TestRegisterClientRefusedWithoutClientID(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, false)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPClientID = ""
	})

	rec := httptest.NewRecorder()
	srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register", jsonBody(`{}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("상태 코드 %d, 409 여야 합니다", rec.Code)
	}
}

func TestChallengeCarriesResourceMetadataAndError(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = kcSrv.URL })

	// No credential: the client is told where to start.
	anon := httptest.NewRequest(http.MethodPost, "https://bbmcp.local/mcp", nil)
	got := srv.Challenge(anon)
	if want := `resource_metadata="https://bbmcp.local/.well-known/oauth-protected-resource"`; !contains(got, want) {
		t.Fatalf("challenge = %q", got)
	}
	if contains(got, "invalid_token") {
		t.Errorf("자격증명이 없는데 invalid_token 을 보냈습니다: %q", got)
	}

	// A rejected credential: say so, so the client stops retrying blindly.
	withToken := httptest.NewRequest(http.MethodPost, "https://bbmcp.local/mcp", nil)
	withToken.Header.Set("Authorization", "Bearer broken")
	if got := srv.Challenge(withToken); !contains(got, `error="invalid_token"`) {
		t.Fatalf("challenge = %q", got)
	}
}

func TestMCPOAuthDiagnosticReportsReadiness(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPClientID = "bbmcp-mcp"
	})

	rec := httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))

	body := decode(t, rec)
	if body["ok"] != true {
		t.Fatalf("ok = %v (%s)", body["ok"], rec.Body.String())
	}
	if body["keycloakSupportsDynamicRegistration"] != true {
		t.Error("Keycloak 의 동적 등록 지원을 감지하지 못했습니다")
	}
	as, _ := body["authorizationServer"].(map[string]any)
	if as["tokenEndpoint"] != kcSrv.URL+"/protocol/openid-connect/token" {
		t.Errorf("tokenEndpoint = %v", as["tokenEndpoint"])
	}
}

func TestMCPOAuthDiagnosticWarnsWithoutClientID(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, false)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPClientID = ""
		kc.MCPAllowDCR = false
	})

	rec := httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))
	body := decode(t, rec)
	if body["ok"] == true {
		t.Fatal("클라이언트 ID 없이 준비 완료로 보고했습니다")
	}
	warnings, _ := body["warnings"].([]any)
	if len(warnings) < 2 {
		t.Fatalf("경고가 부족합니다: %v", warnings)
	}
}

func jsonBody(body string) *strings.Reader { return strings.NewReader(body) }

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
