package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/hkjang/bbmcp/internal/settings"
)

// The metadata named in the 401 describes the MCP endpoint, and strict
// clients (VS Code, Gemini CLI, 이룸에이전트) compare it with the URL they
// called. The root document still describes the origin.
func TestProtectedResourceDescribesTheURLItWasDerivedFrom(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = kcSrv.URL })

	for path, want := range map[string]string{
		"/.well-known/oauth-protected-resource":     "https://bbmcp.local",
		"/.well-known/oauth-protected-resource/mcp": "https://bbmcp.local/mcp",
	} {
		rec := httptest.NewRecorder()
		srv.protectedResource(rec, httptest.NewRequest(http.MethodGet, "https://bbmcp.local"+path, nil))
		if got := decode(t, rec)["resource"]; got != want {
			t.Errorf("%s: resource = %v, want %s", path, got, want)
		}
	}
}

// A stale copy of these documents is what keeps a client on an old
// authorization server, so none of them may be cached, and each names the
// build that answered.
func TestDiscoveryAnswersAreNotCachedAndNameTheBuild(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = kcSrv.URL })
	srv.trace = newDiscoveryTrace()
	router := srv.oauthRouterForTest()

	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/.well-known/oauth-protected-resource/mcp", ""},
		{http.MethodGet, "/.well-known/oauth-authorization-server", ""},
		{http.MethodGet, "/.well-known/openid-configuration", ""},
		{http.MethodPost, "/oauth/register", `{"redirect_uris":["http://127.0.0.1:41234/callback"]}`},
		{http.MethodGet, "/.well-known/oauth-authorization-server/some/other", ""},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, "https://bbmcp.local"+c.path, strings.NewReader(c.body)))
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get(versionHeader) == "" {
			t.Errorf("%s %s: Cache-Control=%q %s=%q", c.method, c.path, rec.Header().Get("Cache-Control"), versionHeader, rec.Header().Get(versionHeader))
		}
	}

	// An unknown variant is a JSON 404, not the console's HTML.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-authorization-server/some/other", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Header().Get("Content-Type"), "json") {
		t.Errorf("unknown well-known: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestRegisterClientCapsAndDedupesRedirects(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = kcSrv.URL })

	many := []string{}
	for i := 0; i < maxRegistrationRedirects+1; i++ {
		many = append(many, fmt.Sprintf("http://127.0.0.1:%d/cb", 40000+i))
	}
	body, _ := json.Marshal(map[string]any{"redirect_uris": many})
	rec := httptest.NewRecorder()
	srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register", strings.NewReader(string(body))))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d 개를 받았습니다: %d", len(many), rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register",
		jsonBody(`{"redirect_uris":["http://127.0.0.1:41234/cb","http://127.0.0.1:41234/cb"]}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("상태 %d (%s)", rec.Code, rec.Body.String())
	}
	if got, _ := decode(t, rec)["redirect_uris"].([]any); len(got) != 1 {
		t.Errorf("redirect_uris = %v", got)
	}
}

// Without an audit row for every refusal, "no oauth.register entry" would not
// prove the client never asked this gateway.
func TestRegisterClientAuditsEveryRefusal(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPAllowDCR = false
	})
	if _, err := srv.Pool.Exec(ctx, `DELETE FROM audit_log WHERE action='oauth.register'`); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register",
		jsonBody(`{"redirect_uris":["http://127.0.0.1:41234/cb"]}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("상태 %d", rec.Code)
	}
	var n int
	_ = srv.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='oauth.register' AND success=false`).Scan(&n)
	if n != 1 {
		t.Fatalf("거부 감사 기록 %d 건", n)
	}
}

// A missing client is its own error: telling the operator to add a redirect
// URI to a client that does not exist sends them the wrong way.
func TestRegisterClientNamesAMissingKeycloakClient(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token",
		})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<p class="instruction">Client not found.</p>`))
	})
	kcSrv := httptest.NewServer(mux)
	t.Cleanup(kcSrv.Close)
	issuer = kcSrv.URL
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = issuer })

	rec := httptest.NewRecorder()
	srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register",
		jsonBody(`{"redirect_uris":["http://localhost:58023/callback"]}`)))
	desc, _ := decode(t, rec)["error_description"].(string)
	if rec.Code != http.StatusBadRequest || !strings.Contains(desc, "bbmcp-mcp 가 없습니다") || strings.Contains(desc, "localhost:*") {
		t.Fatalf("%d %s", rec.Code, desc)
	}

	rec = httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))
	if decode(t, rec)["ok"] == true {
		t.Fatal("클라이언트가 없는데 연결 가능으로 보고했습니다")
	}
}

// The mirror copies Keycloak's cached document. Removing the registration
// endpoint from the nested mTLS aliases must not edit that shared document:
// concurrent requests would otherwise race on it, which in Go is fatal.
// Run with -race.
func TestMirrorDoesNotEditTheCachedKeycloakDocument(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token",
			"registration_endpoint": issuer + "/clients-registrations/openid-connect",
			"mtls_endpoint_aliases": map[string]any{
				"token_endpoint":        issuer + "/token",
				"registration_endpoint": issuer + "/clients-registrations/openid-connect",
			},
		})
	})
	kcSrv := httptest.NewServer(mux)
	t.Cleanup(kcSrv.Close)
	issuer = kcSrv.URL
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = issuer })

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			srv.authorizationServerMetadata(rec, httptest.NewRequest(http.MethodGet, "https://bbmcp.local/.well-known/oauth-authorization-server", nil))
			aliases, _ := decode(t, rec)["mtls_endpoint_aliases"].(map[string]any)
			if _, ok := aliases["registration_endpoint"]; ok || aliases["token_endpoint"] == nil {
				t.Errorf("mtls_endpoint_aliases = %v", aliases)
			}
		}()
	}
	wg.Wait()

	kc, _ := store.Keycloak(ctx)
	cachedDoc, _ := srv.fetchASMetadata(ctx, kc)
	if aliases, _ := cachedDoc["mtls_endpoint_aliases"].(map[string]any); aliases["registration_endpoint"] == nil {
		t.Fatal("캐시된 Keycloak 문서가 바뀌었습니다")
	}
}

func TestMCPOAuthDiagnosticIsNotReadyWhileKeycloakRegisters(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) {
		kc.Issuer = kcSrv.URL
		kc.MCPAllowDCR = false
	})
	rec := httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))
	body := decode(t, rec)
	if body["ok"] == true || body["keycloakRegisters"] != true {
		t.Fatalf("ok=%v keycloakRegisters=%v", body["ok"], body["keycloakRegisters"])
	}
	v, _ := body["version"].(map[string]any)
	if v["version"] == "" || v["version"] == nil {
		t.Errorf("version = %v", body["version"])
	}
}

func TestMigrateMCPRegistrationResetsOnlyValuesSavedUnderTheOldMeaning(t *testing.T) {
	_, store, ctx := newOAuthServer(t)

	// Nothing stored: nothing to migrate.
	if changed, err := store.MigrateMCPRegistration(ctx, "test"); err != nil || changed {
		t.Fatalf("빈 설정: changed=%t err=%v", changed, err)
	}

	// Saved before v0.2.9 with the switch off: turned back on once.
	old := map[string]any{"enabled": true, "issuer": "https://sso.example/realms/x", "mcpOauthEnabled": true,
		"mcpClientId": "bbmcp-mcp", "mcpAllowDynamicRegistration": false}
	if err := store.Put(ctx, settings.KeyKeycloak, old, "test"); err != nil {
		t.Fatal(err)
	}
	if changed, err := store.MigrateMCPRegistration(ctx, "test"); err != nil || !changed {
		t.Fatalf("옛 값: changed=%t err=%v", changed, err)
	}
	kc, _ := store.Keycloak(ctx)
	if !kc.MCPAllowDCR || !kc.MCPRegistrationReviewed {
		t.Fatalf("이전 후 %+v", kc)
	}
	if kc.Issuer != "https://sso.example/realms/x" {
		t.Errorf("다른 설정이 바뀌었습니다: %s", kc.Issuer)
	}

	// Switched off again under the current meaning: left alone.
	kc.MCPAllowDCR = false
	if err := store.Put(ctx, settings.KeyKeycloak, kc, "test"); err != nil {
		t.Fatal(err)
	}
	if changed, _ := store.MigrateMCPRegistration(ctx, "test"); changed {
		t.Fatal("의도적으로 끈 값을 되돌렸습니다")
	}
	if kc, _ := store.Keycloak(ctx); kc.MCPAllowDCR {
		t.Fatal("의도적으로 끈 값이 켜졌습니다")
	}
}

func TestCheckKeycloakRegistrationGuardsTheCleanup(t *testing.T) {
	deleted := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { deleted = true }))
	t.Cleanup(other.Close)
	endpoint := registrationEndpoint(t, 201, map[string]any{
		"client_id": "c1", "registration_client_uri": other.URL + "/client/1", "registration_access_token": "rat",
	}, nil)
	got := checkKeycloakRegistration(t.Context(), settings.Keycloak{}, endpoint)
	if deleted || got.Problem == "" || got.CreatedClientID != "c1" {
		t.Fatalf("다른 출처로 토큰을 보냈거나 경고가 없습니다: deleted=%t %+v", deleted, got)
	}

	// Keycloak refuses the delete: the result says so and names the client.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "c2", "registration_client_uri": srv.URL + "/c2", "registration_access_token": "rat"})
	}))
	t.Cleanup(srv.Close)
	got = checkKeycloakRegistration(t.Context(), settings.Keycloak{}, srv.URL)
	if got.Deleted || !strings.Contains(got.Problem, "c2") {
		t.Fatalf("%+v", got)
	}
}

func TestDiscoveryTraceIsBoundedPerKind(t *testing.T) {
	tr := newDiscoveryTrace()
	long := strings.Repeat("가", 1000)
	for i := 0; i < tracePerSecond*3; i++ {
		tr.record(traceEvent{Kind: traceChallenge, Agent: long, Path: long})
	}
	tr.record(traceEvent{Kind: traceRegister})
	events := tr.snapshot()
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Kind]++
	}
	// The flood of 401s is capped, and it does not push out the registration.
	if counts[traceChallenge] != tracePerSecond || counts[traceRegister] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	for _, e := range events {
		if len(e.Agent) > 170 || len(e.Path) > 170 {
			t.Fatalf("길이 제한이 없습니다: %d", len(e.Agent))
		}
	}
}

// oauthRouterForTest serves only the discovery and registration routes.
func (s *Server) oauthRouterForTest() http.Handler {
	r := chi.NewRouter()
	s.mountOAuth(r)
	return r
}

// A Keycloak that compares a host-level wildcard as a string prefix
// (Keycloak 10 with http://127.0.0.1:*) also sends the login result to
// http://127.0.0.1:@attacker/, which the browser takes to the attacker. The
// check must find it and refuse to call the setup ready.
func TestMCPOAuthDiagnosticFindsAWildcardThatAdmitsAttackers(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token",
			"registration_endpoint": issuer + "/reg", "code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != "bbmcp-mcp" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`<p class="instruction">Client not found.</p>`))
			return
		}
		redirect := q.Get("redirect_uri")
		if !strings.HasPrefix(redirect, "http://127.0.0.1:") && !strings.HasPrefix(redirect, "http://localhost:") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, redirect+"?error=login_required", http.StatusFound)
	})
	kcSrv := httptest.NewServer(mux)
	t.Cleanup(kcSrv.Close)
	issuer = kcSrv.URL
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = issuer })

	rec := httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))
	body := decode(t, rec)
	unsafe, _ := body["unsafeRedirects"].([]any)
	if body["ok"] == true || len(unsafe) == 0 {
		t.Fatalf("ok=%v unsafeRedirects=%v", body["ok"], body["unsafeRedirects"])
	}
	found := false
	for _, w := range body["warnings"].([]any) {
		if text, _ := w.(string); strings.HasPrefix(text, "보안:") && strings.Contains(text, "--callback-port") {
			found = true
		}
	}
	if !found {
		t.Errorf("보안 경고가 없습니다: %v", body["warnings"])
	}
}

// Registration refuses a redirect URI carrying user info outright.
func TestRegisterClientRefusesUserInfoRedirect(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloak(t, true)
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = kcSrv.URL })
	rec := httptest.NewRecorder()
	srv.registerClient(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/oauth/register",
		jsonBody(`{"redirect_uris":["http://127.0.0.1:@attacker.example/cb"]}`)))
	if rec.Code != http.StatusBadRequest || decode(t, rec)["error"] != "invalid_redirect_uri" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// Keycloak 10 with the recommended http://127.0.0.1/callback keeps the port
// of IP addresses, so 127.0.0.1 callbacks on random ports are refused while
// localhost (Claude Code) works. That setup is ready, with a warning.
func TestMCPOAuthDiagnosticIsReadyWhenOnlyIPLoopbackIsRefused(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloakWith(t, true, func(u string) bool { return strings.HasPrefix(u, "http://localhost:") })
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = kcSrv.URL })

	rec := httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))
	body := decode(t, rec)
	if body["ok"] != true {
		t.Fatalf("ok = %v (%v)", body["ok"], body["warnings"])
	}
	found := false
	for _, w := range body["warnings"].([]any) {
		if text, _ := w.(string); strings.Contains(text, "127.0.0.1") && strings.Contains(text, "포트를 무시하지 않는") {
			found = true
		}
	}
	if !found {
		t.Errorf("127.0.0.1 경고가 없습니다: %v", body["warnings"])
	}
}

// On Keycloak 10 the safe setup is a fixed callback port registered exactly,
// so random loopback ports are refused on both hosts. That is not a failure.
func TestMCPOAuthDiagnosticAcceptsAFixedPortSetup(t *testing.T) {
	srv, store, ctx := newOAuthServer(t)
	kcSrv := fakeKeycloakWith(t, true, func(u string) bool { return u == "http://localhost:33333/callback" })
	configureKeycloak(t, store, ctx, func(kc *settings.Keycloak) { kc.Issuer = kcSrv.URL })

	rec := httptest.NewRecorder()
	srv.testMCPOAuth(rec, httptest.NewRequest(http.MethodPost, "https://bbmcp.local/api/admin/test/mcp-oauth", nil))
	body := decode(t, rec)
	if body["ok"] != true {
		t.Fatalf("ok = %v (%v)", body["ok"], body["warnings"])
	}
	found := false
	for _, w := range body["warnings"].([]any) {
		if text, _ := w.(string); strings.Contains(text, "고정 포트 설정이라면 정상") {
			found = true
		}
	}
	if !found {
		t.Errorf("고정 포트 안내가 없습니다: %v", body["warnings"])
	}
}
