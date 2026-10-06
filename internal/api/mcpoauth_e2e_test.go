package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/aiproxy"
	"github.com/hkjang/bbmcp/internal/api"
	"github.com/hkjang/bbmcp/internal/apikey"
	"github.com/hkjang/bbmcp/internal/approval"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/auth"
	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/crypto"
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
	pool  *pgxpool.Pool
	bb    *bitbucketStub
	ctx   context.Context
}

func newGateway(t *testing.T, kc *keycloakStub) *gateway {
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
	if err := users.EnsureBootstrapAdmin(ctx, "admin", "bootstrap-password"); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
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
	return &gateway{srv: srv, store: store, pool: db.Pool, bb: bbStub, ctx: ctx}
}

// bitbucketStub answers the handful of calls these flows make. projects is
// mutable so a test can decide what /projects returns; everything else stays
// unhandled on purpose, which is what Bitbucket 6.9.1 looks like to the
// permission resolver when the service account cannot read a grant table.
type bitbucketStub struct {
	*httptest.Server
	projects []map[string]any
}

func newBitbucketStub(t *testing.T) *bitbucketStub {
	t.Helper()
	stub := &bitbucketStub{}
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
	mux.HandleFunc("/rest/api/1.0/projects", func(w http.ResponseWriter, r *http.Request) {
		values := make([]any, 0, len(stub.projects))
		for _, p := range stub.projects {
			values = append(values, p)
		}
		writeJSON(w, map[string]any{"size": len(values), "limit": 25,
			"isLastPage": true, "values": values})
	})
	// Only /projects/{key} is served here; /projects/{key}/permissions/... must
	// fall through to the 404 below so the resolver takes its forbidden path.
	mux.HandleFunc("/rest/api/1.0/projects/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/rest/api/1.0/projects/")
		for _, p := range stub.projects {
			if p["key"] == key {
				writeJSON(w, p)
				return
			}
		}
		http.Error(w, `{"errors":[{"message":"unhandled"}]}`, http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"message":"unhandled"}]}`, http.StatusNotFound)
	})
	stub.Server = httptest.NewServer(mux)
	t.Cleanup(stub.Close)
	return stub
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

// send is post with arbitrary extra headers and an arbitrary method, for the
// cases that need to echo Mcp-Session-Id back at the gateway.
func (g *gateway) send(t *testing.T, method, path, bearer, body string, hdr map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, g.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
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

// login signs in and returns a cookie jar holding the session.
func (g *gateway) login(t *testing.T, username, password string) *cookiejar.Jar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar}
	resp, err := client.Post(g.srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login 상태 %d", resp.StatusCode)
	}
	return jar
}

func (g *gateway) putJSON(t *testing.T, jar *cookiejar.Jar, path, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, g.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Jar: jar}).Do(req)
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

	// 2. Protected resource metadata names the authorization server. It is
	//    this gateway, because the gateway is what hands out the MCP client.
	resp, meta := gw.getJSON(t, metaURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("리소스 메타데이터 상태 %d", resp.StatusCode)
	}
	servers, _ := meta["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != gw.srv.URL {
		t.Fatalf("authorization_servers = %v", meta["authorization_servers"])
	}

	// 3. The client fetches metadata from the server it was given, as a real
	//    one does, and requires the issuer to echo it. Sign-in and tokens stay
	//    at Keycloak; registration comes to this gateway.
	asURL, _ := servers[0].(string)
	resp, asMeta := gw.getJSON(t, asURL+"/.well-known/oauth-authorization-server")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("인가 서버 메타데이터 상태 %d", resp.StatusCode)
	}
	if asMeta["issuer"] != asURL {
		t.Errorf("issuer = %v, 광고한 인가 서버 %s 와 달라 클라이언트가 거부합니다", asMeta["issuer"], asURL)
	}
	if asMeta["authorization_endpoint"] != kc.srv.URL+"/protocol/openid-connect/auth" {
		t.Errorf("authorization_endpoint = %v", asMeta["authorization_endpoint"])
	}
	if asMeta["token_endpoint"] != kc.srv.URL+"/protocol/openid-connect/token" {
		t.Errorf("token_endpoint = %v", asMeta["token_endpoint"])
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

// TestMCPSessionIDIsIssuedAndTracked pins the whole session lifecycle: the
// initialize response has to hand the client the session id it just recorded,
// because touchSession/closeSession read that id back out of the request
// header. Without the header the admin console's active-session metric is
// wrong in both directions — live sessions age out of it after an hour while
// finished ones stay open forever.
func TestMCPSessionIDIsIssuedAndTracked(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)
	token := kc.token(t, nil)

	// 1. initialize issues the session id in the response header.
	resp, out := gw.post(t, "/mcp", token,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1"}}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize 상태 %d: %v", resp.StatusCode, out)
	}
	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatalf("initialize 응답에 Mcp-Session-Id 헤더가 없습니다 (헤더: %v)", resp.Header)
	}

	// It must be the row openSession just inserted, and the same id the
	// instructions text advertises.
	var rowID string
	var createdAt, lastSeenAt time.Time
	var closedAt *time.Time
	if err := gw.pool.QueryRow(gw.ctx,
		`SELECT id, created_at, last_seen_at, closed_at FROM mcp_sessions`).
		Scan(&rowID, &createdAt, &lastSeenAt, &closedAt); err != nil {
		t.Fatalf("mcp_sessions 조회: %v", err)
	}
	if rowID != sessionID {
		t.Fatalf("헤더 세션 id = %q, mcp_sessions 행 = %q", sessionID, rowID)
	}
	result, _ := out["result"].(map[string]any)
	instructions, _ := result["instructions"].(string)
	if !strings.Contains(instructions, sessionID) {
		t.Errorf("지시문에 세션 id %q 가 없습니다: %q", sessionID, instructions)
	}

	// 2. Echoing the header back makes touchSession actually run.
	hdr := map[string]string{"Mcp-Session-Id": sessionID}
	resp, out = gw.send(t, http.MethodPost, "/mcp", token,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list 상태 %d: %v", resp.StatusCode, out)
	}
	if err := gw.pool.QueryRow(gw.ctx,
		`SELECT last_seen_at FROM mcp_sessions WHERE id=$1`, sessionID).Scan(&lastSeenAt); err != nil {
		t.Fatalf("last_seen_at 조회: %v", err)
	}
	if !lastSeenAt.After(createdAt) {
		t.Errorf("last_seen_at (%s) 이 created_at (%s) 보다 커야 합니다 — touchSession 이 돌지 않았습니다",
			lastSeenAt, createdAt)
	}

	// 3. DELETE with the same header closes the session.
	resp, _ = gw.send(t, http.MethodDelete, "/mcp", token, "", hdr)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /mcp 상태 %d, 204 이어야 합니다", resp.StatusCode)
	}
	if err := gw.pool.QueryRow(gw.ctx,
		`SELECT closed_at FROM mcp_sessions WHERE id=$1`, sessionID).Scan(&closedAt); err != nil {
		t.Fatalf("closed_at 조회: %v", err)
	}
	if closedAt == nil {
		t.Errorf("closed_at 이 NULL 입니다 — closeSession 이 돌지 않았습니다")
	}
}

// TestMCPSessionIDNotIssuedWithoutAuth proves the session id is minted after
// authentication, not before: a refused initialize must neither carry the
// header nor leave a row behind.
func TestMCPSessionIDNotIssuedWithoutAuth(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)

	resp, _ := gw.post(t, "/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1"}}}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("상태 코드 %d, 401 이어야 합니다", resp.StatusCode)
	}
	if got := resp.Header.Get("Mcp-Session-Id"); got != "" {
		t.Errorf("인증 실패 응답에 Mcp-Session-Id = %q 가 붙었습니다", got)
	}
	var n int
	if err := gw.pool.QueryRow(gw.ctx, `SELECT count(*) FROM mcp_sessions`).Scan(&n); err != nil {
		t.Fatalf("mcp_sessions 조회: %v", err)
	}
	if n != 0 {
		t.Errorf("인증 실패인데 mcp_sessions 행이 %d 개 생겼습니다", n)
	}
}

// TestMCPResponseTruncationKeepsValidUTF8 pins the KB cap in callTool: the
// response body is cut to a byte offset, so with non-ASCII content — which is
// the normal case for this product, Korean repository text — the cut lands in
// the middle of a 3-byte rune two times out of three. json.Marshal then swaps
// the broken bytes for U+FFFD and the client is handed a corrupted last
// character. The three paddings below shift the Korean run by one byte each,
// covering every residue mod 3, so at least two of them cut mid-rune.
func TestMCPResponseTruncationKeepsValidUTF8(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)
	token := kc.token(t, nil)

	// A 1KB cap with a 6KB project description guarantees the cut.
	mcpCfg, err := gw.store.MCP(gw.ctx)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	mcpCfg.MaxResponseKB = 1
	if err := gw.store.Put(gw.ctx, settings.KeyMCP, mcpCfg, "test"); err != nil {
		t.Fatalf("mcp settings: %v", err)
	}

	for _, pad := range []string{"", "A", "AA"} {
		// Public so the REST resolver grants read without any grant table.
		gw.bb.projects = []map[string]any{{
			"id": 1, "key": "AI", "name": "AI", "type": "NORMAL", "public": true,
			"description": pad + strings.Repeat("한", 2000),
		}}

		_, out := gw.post(t, "/mcp", token,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bitbucket_projects","arguments":{}}}`)
		result, _ := out["result"].(map[string]any)
		structured, _ := result["structuredContent"].(map[string]any)
		if structured["truncated"] != true {
			t.Fatalf("pad %dB: 절단이 일어나지 않았습니다 — 테스트 전제가 깨졌습니다: %v",
				len(pad), out)
		}
		content, _ := result["content"].([]any)
		if len(content) == 0 {
			t.Fatalf("pad %dB: content 가 비어 있습니다: %v", len(pad), out)
		}
		block, _ := content[0].(map[string]any)
		text, _ := block["text"].(string)

		// The source data holds no U+FFFD, so any replacement character in the
		// response was manufactured by cutting a rune in half.
		if i := strings.IndexRune(text, '�'); i >= 0 {
			t.Errorf("pad %dB: 절단된 응답 %d번째 바이트에 U+FFFD 가 있습니다 — 문자 중간에서 잘렸습니다 (…%q…)",
				len(pad), i, text[max(0, i-12):min(len(text), i+12)])
		}
		if !strings.Contains(text, "1KB 제한으로 잘렸습니다") {
			t.Errorf("pad %dB: 절단 안내 문구가 없습니다: …%q", len(pad), tail(text, 80))
		}
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
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

// TestLogoutOmitsUnregisteredPostLogoutRedirect guards the most common source
// of "Invalid parameter" on logout: sending a post_logout_redirect_uri that
// nobody registered in Keycloak.
func TestLogoutOmitsUnregisteredPostLogoutRedirect(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)

	// Nothing configured: the parameter must not be sent at all.
	resp, body := gw.post(t, "/api/auth/logout", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("상태 코드 %d", resp.StatusCode)
	}
	logoutURL, _ := body["ssoLogoutUrl"].(string)
	if logoutURL == "" {
		t.Fatal("ssoLogoutUrl 이 비어 있습니다")
	}
	if strings.Contains(logoutURL, "post_logout_redirect_uri") {
		t.Fatalf("등록되지 않은 post_logout_redirect_uri 를 보냈습니다: %s", logoutURL)
	}
	if !strings.Contains(logoutURL, "client_id=bbmcp") {
		t.Errorf("client_id 가 없습니다: %s", logoutURL)
	}

	// Configured deliberately: it is sent, normalised.
	cfg, _ := gw.store.Keycloak(gw.ctx)
	cfg.PostLogoutURL = "https://BBMCP.local:443/"
	if err := gw.store.Put(gw.ctx, settings.KeyKeycloak, cfg, "test"); err != nil {
		t.Fatalf("settings: %v", err)
	}
	_, body = gw.post(t, "/api/auth/logout", "", "")
	logoutURL, _ = body["ssoLogoutUrl"].(string)
	if !strings.Contains(logoutURL, "post_logout_redirect_uri=https%3A%2F%2Fbbmcp.local") {
		t.Fatalf("정규화된 post_logout_redirect_uri 가 없습니다: %s", logoutURL)
	}
}

// TestSettingsRejectMalformedUrls keeps a typo from becoming a Keycloak error
// page later in the flow.
func TestSettingsRejectMalformedUrls(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)

	// An admin session is needed for the settings API.
	jar := gw.login(t, "admin", "bootstrap-password")

	cases := []struct{ name, payload string }{
		{"스킴 없는 Issuer", `{"value":{"enabled":true,"issuer":"sso.company.local/realms/x","clientId":"bbmcp"},"secrets":{}}`},
		{"질의 문자열 Issuer", `{"value":{"enabled":true,"issuer":"https://sso.local/realms/x?a=1","clientId":"bbmcp"},"secrets":{}}`},
		{"경로가 틀린 Redirect", `{"value":{"enabled":true,"issuer":"` + kc.srv.URL + `","clientId":"bbmcp","redirectUrl":"https://bbmcp.local/callback"},"secrets":{}}`},
		{"SSO 켜고 Issuer 없음", `{"value":{"enabled":true,"issuer":"","clientId":"bbmcp"},"secrets":{}}`},
	}
	for _, c := range cases {
		resp, body := gw.putJSON(t, jar, "/api/admin/settings/keycloak", c.payload)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: 상태 %d, 400 이어야 합니다 (%v)", c.name, resp.StatusCode, body)
			continue
		}
		if body["code"] != "INVALID_URL" {
			t.Errorf("%s: code = %v", c.name, body["code"])
		}
	}

	// A valid payload is normalised on the way in.
	resp, _ := gw.putJSON(t, jar, "/api/admin/settings/keycloak",
		`{"value":{"enabled":true,"issuer":"`+kc.srv.URL+`/","clientId":" bbmcp ","redirectUrl":"https://BBMCP.local:443/auth/oidc/callback"},"secrets":{}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("정상 설정이 거부되었습니다: %d", resp.StatusCode)
	}
	saved, err := gw.store.Keycloak(gw.ctx)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if saved.Issuer != kc.srv.URL {
		t.Errorf("issuer = %q (후행 슬래시가 정리되어야 합니다)", saved.Issuer)
	}
	if saved.ClientID != "bbmcp" {
		t.Errorf("clientId = %q (공백이 정리되어야 합니다)", saved.ClientID)
	}
	if saved.RedirectURL != "https://bbmcp.local/auth/oidc/callback" {
		t.Errorf("redirectUrl = %q", saved.RedirectURL)
	}
}
