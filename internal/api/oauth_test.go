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
			// Keycloak advertises RFC 9207, and CIMD when that feature is on.
			"authorization_response_iss_parameter_supported": true,
			"client_id_metadata_document_supported":          true,
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
	db, err := openTestDB(t, dsn)
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

// With registration proxying on, clients must be sent here and not to
// Keycloak: a client registers wherever the advertised server's metadata says,
// and Keycloak's anonymous registration refuses MCP clients in most realms
// (invalid_client_metadata, Trusted Hosts) or creates clients this gateway's
// audience check rejects.
func TestProtectedResourceMetadataNamesGatewayWhenProxyingRegistration(t *testing.T) {
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
	if len(servers) != 1 || servers[0] != "https://bbmcp.local" {
		t.Fatalf("authorization_servers = %v (등록 대행 중에는 게이트웨이여야 합니다)", body["authorization_servers"])
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

func TestProtectedResourceMetadataNamesKeycloakWhenProxyOff(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL + "/"
		kc.MCPAllowDCR = false
	})

	rec := httptest.NewRecorder()
	srv.protectedResource(rec, httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-protected-resource", nil))
	servers, _ := decode(t, rec)["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != kcSrv.URL {
		t.Fatalf("authorization_servers = %v", servers)
	}
}

// A client follows authorization_servers[0] and then checks that the metadata
// it fetched names that same issuer (RFC 8414 §3.3). Whatever is advertised,
// the document served for it has to agree.
func TestAdvertisedAuthorizationServerMatchesMetadataIssuer(t *testing.T) {
	for _, proxy := range []bool{true, false} {
		srv, store, ctx := newOAuthServer(t)
		kcSrv := fakeKeycloak(t, true)
		configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
			kc.Issuer = kcSrv.URL
			kc.MCPAllowDCR = proxy
		})

		rec := httptest.NewRecorder()
		srv.protectedResource(rec, httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-protected-resource", nil))
		servers, _ := decode(t, rec)["authorization_servers"].([]any)
		if len(servers) != 1 {
			t.Fatalf("proxy=%t: authorization_servers = %v", proxy, servers)
		}
		advertised, _ := servers[0].(string)

		var issuer, registration any
		if advertised == "https://bbmcp.local" {
			rec = httptest.NewRecorder()
			srv.authorizationServerMetadata(rec,
				httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-authorization-server", nil))
			body := decode(t, rec)
			issuer, registration = body["issuer"], body["registration_endpoint"]
		} else {
			resp, err := http.Get(advertised + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatalf("proxy=%t: %v", proxy, err)
			}
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			_ = resp.Body.Close()
			issuer, registration = body["issuer"], body["registration_endpoint"]
		}
		if issuer != advertised {
			t.Errorf("proxy=%t: 광고한 인가 서버 %s 의 메타데이터 issuer = %v", proxy, advertised, issuer)
		}
		wantReg := kcSrv.URL + "/clients-registrations/openid-connect"
		if proxy {
			wantReg = "https://bbmcp.local/oauth/register"
		}
		if registration != wantReg {
			t.Errorf("proxy=%t: registration_endpoint = %v, want %s", proxy, registration, wantReg)
		}
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
	// The gateway is the advertised authorization server, so it is the issuer;
	// sign-in and tokens still happen at Keycloak.
	if body["issuer"] != "https://bbmcp.local" {
		t.Errorf("issuer = %v (광고한 인가 서버와 같아야 합니다)", body["issuer"])
	}
	if body["authorization_endpoint"] != kcSrv.URL+"/protocol/openid-connect/auth" {
		t.Errorf("authorization_endpoint = %v", body["authorization_endpoint"])
	}
	if body["token_endpoint"] != kcSrv.URL+"/protocol/openid-connect/token" {
		t.Errorf("token_endpoint = %v", body["token_endpoint"])
	}
	// With registration proxying on, clients are sent to this gateway.
	if body["registration_endpoint"] != "https://bbmcp.local/oauth/register" {
		t.Errorf("registration_endpoint = %v", body["registration_endpoint"])
	}
	// Keycloak's iss can never equal this issuer, and CIMD would bypass the
	// pre-registered client.
	for _, key := range []string{"authorization_response_iss_parameter_supported", "client_id_metadata_document_supported"} {
		if _, ok := body[key]; ok {
			t.Errorf("%s 를 그대로 전달했습니다", key)
		}
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
	if body["issuer"] != kcSrv.URL {
		t.Errorf("issuer = %v", body["issuer"])
	}
	if body["authorization_response_iss_parameter_supported"] != true {
		t.Error("Keycloak 을 그대로 광고할 때는 메타데이터를 바꾸지 않아야 합니다")
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
	if body["advertisedAuthorizationServer"] != "https://bbmcp.local" {
		t.Errorf("advertisedAuthorizationServer = %v", body["advertisedAuthorizationServer"])
	}
}

func TestMCPOAuthDiagnosticWarnsWhenClientsGoToKeycloakRegistration(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPAllowDCR = false
	})

	rec := httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))
	body := decode(t, rec)
	if body["advertisedAuthorizationServer"] != kcSrv.URL {
		t.Errorf("advertisedAuthorizationServer = %v", body["advertisedAuthorizationServer"])
	}
	warnings, _ := body["warnings"].([]any)
	found := false
	for _, w := range warnings {
		if text, _ := w.(string); strings.Contains(text, "invalid_client_metadata") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Keycloak 익명 등록으로 가는 구성을 경고하지 않았습니다: %v", warnings)
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

func TestRegisterClientRejectsUnusableRedirect(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, false)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPClientID = "bbmcp-mcp"
	})

	// Each of these would reach Keycloak and come back as an opaque
	// "Invalid parameter: redirect_uri" page, so they are refused here.
	for _, body := range []string{
		`{"redirect_uris":["http://example.com/cb"]}`,
		`{"redirect_uris":["http://127.0.0.1:*/cb"]}`,
		`{"redirect_uris":["/relative/cb"]}`,
		`{"redirect_uris":["https://app.local/cb#frag"]}`,
	} {
		rec := httptest.NewRecorder()
		srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register", jsonBody(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s → 상태 %d, 400 이어야 합니다", body, rec.Code)
			continue
		}
		if decode(t, rec)["error"] != "invalid_redirect_uri" {
			t.Errorf("%s → error = %v", body, decode(t, rec)["error"])
		}
	}

	// Loopback HTTP is how MCP clients actually receive the callback.
	for _, body := range []string{
		`{"redirect_uris":["http://127.0.0.1:41234/callback"]}`,
		`{"redirect_uris":["http://localhost:8765/oauth/cb"]}`,
		`{"redirect_uris":["https://app.company.local/cb"]}`,
	} {
		rec := httptest.NewRecorder()
		srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register", jsonBody(body)))
		if rec.Code != http.StatusCreated {
			t.Errorf("%s → 상태 %d, 201 이어야 합니다 (%s)", body, rec.Code, rec.Body.String())
		}
	}
}

func TestMCPOAuthReportListsUrisToRegister(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPClientID = "bbmcp-mcp"
	})

	rec := httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))
	body := decode(t, rec)

	if body["webRedirectUri"] != "https://bbmcp.local/auth/oidc/callback" {
		t.Errorf("webRedirectUri = %v", body["webRedirectUri"])
	}
	loopback, _ := body["loopbackRedirectUris"].([]any)
	if len(loopback) != 2 || loopback[0] != "http://127.0.0.1:*" {
		t.Errorf("loopbackRedirectUris = %v", body["loopbackRedirectUris"])
	}
}
