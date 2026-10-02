package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hkjang/bbmcp/internal/aiproxy"
	"github.com/hkjang/bbmcp/internal/api"
	"github.com/hkjang/bbmcp/internal/apikey"
	"github.com/hkjang/bbmcp/internal/approval"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/auth"
	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/crypto"
	"github.com/hkjang/bbmcp/internal/database"
	"github.com/hkjang/bbmcp/internal/identity"
	"github.com/hkjang/bbmcp/internal/permission"
	"github.com/hkjang/bbmcp/internal/policy"
	"github.com/hkjang/bbmcp/internal/settings"
	"github.com/hkjang/bbmcp/internal/tools"
)

// keycloakStub is a Keycloak realm good enough to complete an MCP OAuth flow:
// it publishes discovery metadata and a JWKS, and mints signed access tokens.
type keycloakStub struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newKeycloakStub(t *testing.T, withDCR bool) *keycloakStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	stub := &keycloakStub{key: key, kid: "bbmcp-test-key"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"issuer":                                stub.srv.URL,
			"authorization_endpoint":                stub.srv.URL + "/protocol/openid-connect/auth",
			"token_endpoint":                        stub.srv.URL + "/protocol/openid-connect/token",
			"jwks_uri":                              stub.srv.URL + "/protocol/openid-connect/certs",
			"end_session_endpoint":                  stub.srv.URL + "/protocol/openid-connect/logout",
			"code_challenge_methods_supported":      []string{"plain", "S256"},
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if withDCR {
			body["registration_endpoint"] = stub.srv.URL + "/clients-registrations/openid-connect"
		}
		writeJSON(w, body)
	})
	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		pub := key.PublicKey
		writeJSON(w, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA",
			"kid": stub.kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	stub.srv = httptest.NewServer(mux)
	t.Cleanup(stub.srv.Close)
	return stub
}

// token mints an access token the way Keycloak would for a public client.
func (k *keycloakStub) token(t *testing.T, mutate func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                k.srv.URL,
		"sub":                "5fcad5e8-0000-4000-8000-000000000001",
		"aud":                "account",
		"azp":                "bbmcp-mcp",
		"typ":                "Bearer",
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"scope":              "openid profile email",
		"preferred_username": "hkjang",
		"email":              "hkjang@example.com",
		"name":               "장현규",
		"realm_access":       map[string]any{"roles": []string{"bitbucket-mcp-user"}},
	}
	if mutate != nil {
		mutate(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = k.kid
	signed, err := tok.SignedString(k.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// gateway is a fully wired bbmcp server in front of a stub Bitbucket.
type gateway struct {
	srv   *httptest.Server
	store *settings.Store
	ctx   context.Context
}

func newGateway(t *testing.T, kc *keycloakStub) *gateway {
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
	if _, err := db.Pool.Exec(ctx, `TRUNCATE users, settings, bitbucket_identity_mapping,
		identity_mapping_errors, mcp_tools, audit_log, mcp_sessions RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	bbStub := newBitbucketStub(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 11)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	store := settings.NewStore(db.Pool, sealer)

	kcCfg := settings.DefaultKeycloak()
	kcCfg.Enabled = true
	kcCfg.Issuer = kc.srv.URL
	kcCfg.ClientID = "bbmcp"
	kcCfg.MCPClientID = "bbmcp-mcp"
	if err := store.Put(ctx, settings.KeyKeycloak, kcCfg, "test"); err != nil {
		t.Fatalf("keycloak settings: %v", err)
	}

	pat, _ := store.Seal("service-pat")
	bbCfg := settings.DefaultBitbucket()
	bbCfg.BaseURL = bbStub.URL
	bbCfg.ServiceUsername = "mcp-service"
	bbCfg.ServicePATEnc = pat
	if err := store.Put(ctx, settings.KeyBitbucket, bbCfg, "test"); err != nil {
		t.Fatalf("bitbucket settings: %v", err)
	}

	auditLog := audit.New(db.Pool)
	users := auth.NewUsers(db.Pool)
	sessions := auth.NewSessions(db.Pool, sealer)
	keys := apikey.NewService(db.Pool, sealer, store)
	provider := bitbucket.NewProvider(store, db.Pool)
	resolver := permission.NewResolver(store, provider)
	mapper := identity.NewMapper(db.Pool, provider)
	policies := policy.NewEngine(db.Pool)
	approvals := approval.NewEngine(db.Pool)
	registry := tools.NewRegistry(db.Pool)
	if err := registry.Sync(ctx); err != nil {
		t.Fatalf("registry: %v", err)
	}
	if err := keys.SeedRoles(ctx); err != nil {
		t.Fatalf("roles: %v", err)
	}

	authSvc := &auth.Service{
		Users: users, Sessions: sessions, OIDC: auth.NewOIDC(store), Mapper: mapper,
		Keys: keys, Store: store, Audit: auditLog, Sealer: sealer,
	}
	executor := tools.NewExecutor(tools.Deps{
		Registry: registry, Provider: provider, Resolver: resolver, Policy: policies,
		Approvals: approvals, Audit: auditLog, Store: store,
	})
	server := api.New(api.Deps{
		Pool: db.Pool, Store: store, Auth: authSvc, Users: users, Sessions: sessions,
		Keys: keys, Mapper: mapper, Provider: provider, Resolver: resolver,
		Policy: policies, Approvals: approvals, Registry: registry, Executor: executor,
		Audit: auditLog, AI: aiproxy.New(store),
	})

	srv := httptest.NewServer(server.Router())
	t.Cleanup(srv.Close)

	// The resource URL must match the test server so discovery is self-consistent.
	mcpCfg := settings.DefaultMCP()
	mcpCfg.ResourceURL = srv.URL
	if err := store.Put(ctx, settings.KeyMCP, mcpCfg, "test"); err != nil {
		t.Fatalf("mcp settings: %v", err)
	}
	return &gateway{srv: srv, store: store, ctx: ctx}
}

// newBitbucketStub answers the handful of calls this flow makes.
func newBitbucketStub(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/1.0/users", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("filter") == "hkjang" {
			writeJSON(w, map[string]any{"size": 1, "isLastPage": true, "values": []any{
				map[string]any{"id": 142, "name": "hkjang", "slug": "hkjang",
					"displayName": "장현규", "emailAddress": "hkjang@example.com", "active": true},
			}})
			return
		}
		writeJSON(w, map[string]any{"size": 0, "isLastPage": true, "values": []any{}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"message":"unhandled"}]}`, http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (g *gateway) post(t *testing.T, path, bearer, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, g.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := g.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (g *gateway) getJSON(t *testing.T, url string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := g.srv.Client().Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// TestMCPOAuthDiscoveryAndCall walks the path an MCP client takes: an
// unauthenticated call, discovery from the challenge, dynamic registration,
// and finally a tool call with a Keycloak-signed access token.
func TestMCPOAuthDiscoveryAndCall(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)

	// 1. An unauthenticated MCP call is refused with a discovery pointer.
	resp, _ := gw.post(t, "/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("상태 코드 %d, 401 이어야 합니다", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, "resource_metadata=") {
		t.Fatalf("WWW-Authenticate = %q", challenge)
	}
	metaURL := between(challenge, `resource_metadata="`, `"`)
	if metaURL == "" {
		t.Fatalf("resource_metadata 를 추출할 수 없습니다: %q", challenge)
	}

	// 2. Protected resource metadata names the authorization server.
	resp, meta := gw.getJSON(t, metaURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("리소스 메타데이터 상태 %d", resp.StatusCode)
	}
	servers, _ := meta["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != kc.srv.URL {
		t.Fatalf("authorization_servers = %v", meta["authorization_servers"])
	}

	// 3. The mirrored authorization server metadata carries Keycloak's
	//    endpoints and this gateway's registration endpoint.
	resp, asMeta := gw.getJSON(t, gw.srv.URL+"/.well-known/oauth-authorization-server")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("인가 서버 메타데이터 상태 %d", resp.StatusCode)
	}
	if asMeta["issuer"] != kc.srv.URL {
		t.Errorf("issuer = %v", asMeta["issuer"])
	}
	regEndpoint, _ := asMeta["registration_endpoint"].(string)
	if regEndpoint != gw.srv.URL+"/oauth/register" {
		t.Fatalf("registration_endpoint = %v", asMeta["registration_endpoint"])
	}

	// 4. Dynamic registration hands back the configured public client.
	resp, reg := gw.post(t, "/oauth/register", "",
		`{"redirect_uris":["http://127.0.0.1:41234/callback"],"client_name":"테스트 클라이언트"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("등록 상태 %d: %v", resp.StatusCode, reg)
	}
	if reg["client_id"] != "bbmcp-mcp" {
		t.Fatalf("client_id = %v", reg["client_id"])
	}

	// 5. A token from that client is accepted and the user is provisioned and
	//    mapped to their Bitbucket account.
	token := kc.token(t, nil)
	resp, out := gw.post(t, "/mcp", token,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1"}}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize 상태 %d: %v", resp.StatusCode, out)
	}
	result, _ := out["result"].(map[string]any)
	if result == nil {
		t.Fatalf("initialize 결과 없음: %v", out)
	}
	instructions, _ := result["instructions"].(string)
	if !strings.Contains(instructions, "hkjang") {
		t.Errorf("요청자가 지시문에 보이지 않습니다: %q", instructions)
	}

	// 6. The identity tool confirms the Keycloak ↔ Bitbucket binding.
	_, out = gw.post(t, "/mcp", token,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bitbucket_me","arguments":{}}}`)
	result, _ = out["result"].(map[string]any)
	structured, _ := result["structuredContent"].(map[string]any)
	if structured["bitbucketUsername"] != "hkjang" {
		t.Fatalf("bitbucketUsername = %v (%v)", structured["bitbucketUsername"], result)
	}
	if structured["authMode"] != "oauth" {
		t.Errorf("authMode = %v", structured["authMode"])
	}

	// A reader role sees only read tools.
	_, out = gw.post(t, "/mcp", token, `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`)
	result, _ = out["result"].(map[string]any)
	list, _ := result["tools"].([]any)
	if len(list) == 0 {
		t.Fatal("도구 목록이 비어 있습니다")
	}
	for _, item := range list {
		tool, _ := item.(map[string]any)
		ann, _ := tool["annotations"].(map[string]any)
		if ann["risk"] != "READ" {
			t.Fatalf("조회 역할에게 %v 도구가 노출되었습니다", tool["name"])
		}
	}
}

func TestMCPOAuthRejectsTokenFromAnotherClient(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)

	// Same realm, same signing key, different client: must not get in.
	token := kc.token(t, func(c jwt.MapClaims) {
		c["azp"] = "grafana"
		c["aud"] = "account"
	})
	resp, _ := gw.post(t, "/mcp", token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("상태 코드 %d, 401 이어야 합니다", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestMCPOAuthRejectsExpiredAndUnsignedTokens(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)

	expired := kc.token(t, func(c jwt.MapClaims) {
		c["exp"] = time.Now().Add(-time.Minute).Unix()
		c["iat"] = time.Now().Add(-2 * time.Minute).Unix()
	})
	if resp, _ := gw.post(t, "/mcp", expired, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("만료 토큰 상태 %d", resp.StatusCode)
	}

	// A token signed by somebody else entirely.
	other := newKeycloakStub(t, false)
	forged := other.token(t, func(c jwt.MapClaims) { c["iss"] = kc.srv.URL })
	if resp, _ := gw.post(t, "/mcp", forged, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("위조 토큰 상태 %d", resp.StatusCode)
	}
}

func TestMCPOAuthRequiredScopeIsEnforced(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)

	cfg, err := gw.store.Keycloak(gw.ctx)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	cfg.MCPRequiredScope = "mcp"
	if err := gw.store.Put(gw.ctx, settings.KeyKeycloak, cfg, "test"); err != nil {
		t.Fatalf("settings: %v", err)
	}

	without := kc.token(t, func(c jwt.MapClaims) { c["scope"] = "openid profile email" })
	if resp, _ := gw.post(t, "/mcp", without, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("스코프 없는 토큰 상태 %d, 401 이어야 합니다", resp.StatusCode)
	}

	with := kc.token(t, func(c jwt.MapClaims) { c["scope"] = "openid profile email mcp" })
	resp, out := gw.post(t, "/mcp", with, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("스코프 있는 토큰 상태 %d: %v", resp.StatusCode, out)
	}
}

func TestMCPOAuthDisabledFallsBackToApiKeysOnly(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)

	cfg, _ := gw.store.Keycloak(gw.ctx)
	cfg.MCPOAuthEnabled = false
	if err := gw.store.Put(gw.ctx, settings.KeyKeycloak, cfg, "test"); err != nil {
		t.Fatalf("settings: %v", err)
	}

	token := kc.token(t, nil)
	if resp, _ := gw.post(t, "/mcp", token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("상태 코드 %d, 401 이어야 합니다", resp.StatusCode)
	}
	// Discovery stops advertising the authorization server as well.
	_, meta := gw.getJSON(t, gw.srv.URL+"/.well-known/oauth-protected-resource")
	if servers, _ := meta["authorization_servers"].([]any); len(servers) != 0 {
		t.Errorf("authorization_servers = %v", servers)
	}
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
