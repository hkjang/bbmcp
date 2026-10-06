package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/httpx"
	"github.com/hkjang/bbmcp/internal/settings"
)

// OAuth discovery for MCP clients.
//
// An MCP client that receives a 401 from /mcp follows RFC 9728: it reads the
// resource_metadata URL from WWW-Authenticate, fetches the protected resource
// metadata, and from there the authorization server metadata. bbmcp publishes
// both, and mirrors Keycloak's authorization server metadata on its own origin
// so clients that only probe the resource origin also succeed.
//
// With registration proxying on, the gateway names itself as the authorization
// server and its mirrored document replaces Keycloak's registration_endpoint
// with this gateway's own, which hands out the pre-configured public MCP
// client. That is what lets a client connect without an operator registering
// it by hand, in deployments where Keycloak's dynamic registration is closed.
// Authorization and token requests still go straight to Keycloak.

// asMetadataCache caches the upstream authorization server metadata.
type asMetadataCache struct {
	mu      sync.Mutex
	key     string
	body    map[string]any
	fetched time.Time
}

const asMetadataTTL = 5 * time.Minute

// mountOAuth registers the discovery and registration endpoints.
func (s *Server) mountOAuth(r interface {
	Get(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
}) {
	// RFC 9728 protected resource metadata, at the root and with the MCP path
	// appended, since clients derive both forms from the resource URL.
	r.Get("/.well-known/oauth-protected-resource", s.protectedResource)
	r.Get("/.well-known/oauth-protected-resource/mcp", s.protectedResource)

	// RFC 8414 authorization server metadata, mirrored from Keycloak.
	r.Get("/.well-known/oauth-authorization-server", s.authorizationServerMetadata)
	r.Get("/.well-known/oauth-authorization-server/mcp", s.authorizationServerMetadata)
	r.Get("/.well-known/openid-configuration", s.authorizationServerMetadata)
	r.Get("/.well-known/openid-configuration/mcp", s.authorizationServerMetadata)

	// RFC 7591 dynamic client registration, answered with a static client.
	r.Post("/oauth/register", s.registerClient)
}

// resourceURL is the identifier MCP clients use for this gateway.
func (s *Server) resourceURL(r *http.Request, cfg settings.MCP) string {
	if normalized := httpx.NormalizeBaseURL(cfg.ResourceURL); normalized != "" {
		return normalized
	}
	return s.baseURL(r)
}

// protectedResource publishes the OAuth metadata an MCP client needs to find
// the authorization server and the scopes this resource expects.
func (s *Server) protectedResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kc, _ := s.Store.Keycloak(ctx)
	cfg, _ := s.Store.MCP(ctx)
	resource := s.resourceURL(r, cfg)

	servers := []string{}
	if as := s.advertisedAuthorizationServer(r, kc, cfg); as != "" {
		servers = append(servers, as)
	}

	scopes := kc.MCPScopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	if want := strings.TrimSpace(kc.MCPRequiredScope); want != "" && !containsFold(scopes, want) {
		scopes = append(scopes, want)
	}

	httpx.JSON(w, http.StatusOK, map[string]any{
		"resource":                 resource,
		"authorization_servers":    servers,
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         scopes,
		"resource_name":            "bbmcp",
		"resource_documentation":   "https://hkjang.github.io/bbmcp/",
	})
}

// advertisedAuthorizationServer is the authorization server an MCP client is
// told to use, or "" when MCP OAuth is off.
//
// Clients register wherever that server's own metadata says, so when this
// gateway hands out the pre-registered client it has to name itself. Naming
// Keycloak sends every client to Keycloak's anonymous registration, which most
// realms refuse (Trusted Hosts, allowed client scopes, metadata Keycloak will
// not accept: invalid_client_metadata), and which, when it does succeed,
// creates a client whose tokens fail this gateway's audience check.
func (s *Server) advertisedAuthorizationServer(r *http.Request, kc settings.Keycloak, cfg settings.MCP) string {
	if !kc.Enabled || !kc.MCPOAuthEnabled || kc.Issuer == "" {
		return ""
	}
	if kc.MCPAllowDCR {
		return s.resourceURL(r, cfg)
	}
	return strings.TrimRight(kc.Issuer, "/")
}

// authorizationServerMetadata mirrors Keycloak's metadata on this origin.
func (s *Server) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kc, err := s.Store.Keycloak(ctx)
	if err != nil {
		httpx.FailCode(w, http.StatusInternalServerError, "SETTINGS_ERROR", err.Error())
		return
	}
	if !kc.Enabled || !kc.MCPOAuthEnabled || kc.Issuer == "" {
		httpx.FailCode(w, http.StatusNotFound, "OAUTH_DISABLED",
			"이 게이트웨이에서 MCP OAuth 가 설정되지 않았습니다")
		return
	}

	body, err := s.fetchASMetadata(ctx, kc)
	if err != nil {
		httpx.FailCode(w, http.StatusBadGateway, "DISCOVERY_FAILED", err.Error())
		return
	}

	out := make(map[string]any, len(body)+1)
	for k, v := range body {
		out[k] = v
	}
	if kc.MCPAllowDCR {
		cfg, _ := s.Store.MCP(ctx)
		self := s.resourceURL(r, cfg)
		// The protected resource metadata names this gateway, and clients check
		// that the document they fetch names the same issuer (RFC 8414 §3.3).
		out["issuer"] = self
		out["registration_endpoint"] = self + "/oauth/register"
		// Keycloak puts its own issuer in the authorization response, which can
		// never match this one. Advertising the parameter would make a client
		// that checks RFC 9207 reject the response once the MCP client stops
		// sending it ("Exclude Issuer From Authentication Response").
		delete(out, "authorization_response_iss_parameter_supported")
		// A client that can use a metadata document URL as its client_id would
		// skip registration and reach Keycloak as a client this gateway rejects.
		delete(out, "client_id_metadata_document_supported")
	}
	httpx.JSON(w, http.StatusOK, out)
}

// fetchASMetadata loads and caches the upstream metadata document.
func (s *Server) fetchASMetadata(ctx context.Context, kc settings.Keycloak) (map[string]any, error) {
	issuer := strings.TrimRight(kc.Issuer, "/")
	key := fmt.Sprintf("%s|%t", issuer, kc.InsecureSkipTLS)

	s.asMeta.mu.Lock()
	if s.asMeta.key == key && s.asMeta.body != nil && time.Since(s.asMeta.fetched) < asMetadataTTL {
		cached := s.asMeta.body
		s.asMeta.mu.Unlock()
		return cached, nil
	}
	s.asMeta.mu.Unlock()

	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if kc.InsecureSkipTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - operator opt-in for internal CAs
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	var lastErr error
	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+path, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("%s 응답 %d", path, resp.StatusCode)
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			lastErr = err
			continue
		}

		s.asMeta.mu.Lock()
		s.asMeta.key, s.asMeta.body, s.asMeta.fetched = key, body, time.Now()
		s.asMeta.mu.Unlock()
		return body, nil
	}
	if lastErr == nil {
		lastErr = errors.New("알 수 없는 오류")
	}
	return nil, fmt.Errorf("Keycloak 메타데이터를 가져올 수 없습니다: %w", lastErr)
}

// registrationRequest is the subset of RFC 7591 bbmcp reads.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// registerClient answers dynamic client registration with the pre-configured
// public MCP client.
//
// bbmcp does not create Keycloak clients: it hands back the one the operator
// registered, so an MCP client can complete discovery without anybody editing
// its configuration by hand. The redirect URIs it asks for must already be
// allowed on that Keycloak client, which the admin console explains.
func (s *Server) registerClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kc, err := s.Store.Keycloak(ctx)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if !kc.Enabled || !kc.MCPOAuthEnabled {
		writeOAuthError(w, http.StatusNotFound, "invalid_request",
			"이 게이트웨이에서 MCP OAuth 가 설정되지 않았습니다")
		return
	}
	if !kc.MCPAllowDCR {
		writeOAuthError(w, http.StatusForbidden, "access_denied",
			"동적 클라이언트 등록이 비활성화되어 있습니다. 관리자에게 MCP 클라이언트 ID 를 요청하십시오.")
		return
	}
	clientID := strings.TrimSpace(kc.MCPClientID)
	if clientID == "" {
		writeOAuthError(w, http.StatusConflict, "invalid_request",
			"MCP 클라이언트 ID 가 설정되지 않았습니다")
		return
	}

	sec, _ := s.Store.Security(ctx)
	ip := httpx.ClientIP(r, sec.TrustProxyHeaders)
	if !s.limiter.Allow("register:"+ip, 30, 10) {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable",
			"등록 요청이 너무 많습니다")
		return
	}

	var req registrationRequest
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req)
	}

	scope := strings.TrimSpace(req.Scope)
	if scope == "" {
		scope = strings.Join(kc.MCPScopes, " ")
	}
	if scope == "" {
		scope = "openid profile email"
	}
	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	responses := req.ResponseTypes
	if len(responses) == 0 {
		responses = []string{"code"}
	}
	redirects := req.RedirectURIs
	if redirects == nil {
		redirects = []string{}
	}
	// Handing out a client_id for a redirect URI Keycloak will not accept only
	// moves the failure to a Keycloak error page the user cannot act on. Reject
	// it here, where the message can say what to register.
	if bad, reason := unusableRedirect(redirects); bad != "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri",
			fmt.Sprintf("리다이렉트 URI %q 를 사용할 수 없습니다: %s", bad, reason))
		return
	}

	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatAuth,
		Action:   "oauth.register",
		Success:  true,
		IP:       ip,
		Message:  "MCP 클라이언트 등록 요청",
		Detail: map[string]any{
			"clientName":   req.ClientName,
			"redirectUris": redirects,
			"clientId":     clientID,
		},
	})

	// A public client: no secret is issued, PKCE carries the proof.
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"client_name":                defaultString(req.ClientName, "bbmcp MCP client"),
		"redirect_uris":              redirects,
		"grant_types":                grants,
		"response_types":             responses,
		"token_endpoint_auth_method": "none",
		"scope":                      scope,
	})
}

// unusableRedirect finds a redirect URI that Keycloak would reject anyway.
//
// MCP clients listen on an ephemeral loopback port, so loopback HTTP is the
// expected shape; everything else must be https. Wildcards, fragments and
// relative URIs are never valid redirect targets.
func unusableRedirect(uris []string) (string, string) {
	for _, raw := range uris {
		value := strings.TrimSpace(raw)
		if value == "" {
			return raw, "값이 비어 있습니다"
		}
		u, err := url.Parse(value)
		if err != nil {
			return raw, "주소 형식이 올바르지 않습니다"
		}
		switch {
		case u.Scheme == "":
			return raw, "스킴이 없습니다 (http:// 또는 https://)"
		case u.Fragment != "":
			return raw, "프래그먼트(#)를 포함할 수 없습니다"
		case strings.Contains(value, "*"):
			return raw, "와일드카드는 클라이언트가 보낼 수 없습니다"
		}
		// A custom scheme (myapp://) is used by desktop clients; Keycloak
		// accepts it when registered, so it passes here too.
		if u.Scheme == "http" && !httpx.IsLoopbackHost(u.Host) {
			return raw, "루프백이 아닌 주소는 https 여야 합니다"
		}
		if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
			return raw, "호스트가 없습니다"
		}
	}
	return "", ""
}

// writeOAuthError emits an RFC 6749 style error body.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	httpx.JSON(w, status, map[string]any{
		"error":             code,
		"error_description": description,
	})
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// mcpOAuthReport is the admin diagnostic for the MCP OAuth path.
type mcpOAuthReport struct {
	OK                  bool              `json:"ok"`
	Error               string            `json:"error,omitempty"`
	Issuer              string            `json:"issuer,omitempty"`
	ResourceURL         string            `json:"resourceUrl"`
	ResourceMetadataURL string            `json:"resourceMetadataUrl"`
	AuthorizationServer map[string]string `json:"authorizationServer,omitempty"`
	AdvertisedServer    string            `json:"advertisedAuthorizationServer,omitempty"`
	KeycloakSupportsDCR bool              `json:"keycloakSupportsDynamicRegistration"`
	GatewayDCREndpoint  string            `json:"gatewayRegistrationEndpoint,omitempty"`
	MCPClientID         string            `json:"mcpClientId"`
	WebRedirectURI      string            `json:"webRedirectUri"`
	LoopbackRedirects   []string          `json:"loopbackRedirectUris"`
	AcceptedAudiences   []string          `json:"acceptedAudiences"`
	RequiredScope       string            `json:"requiredScope,omitempty"`
	Scopes              []string          `json:"scopes"`
	Warnings            []string          `json:"warnings,omitempty"`
	ClientConfig        map[string]any    `json:"clientConfigExample"`
}

// testMCPOAuth reports whether an MCP client can complete OAuth against this
// deployment, and what it will see at each discovery step.
func (s *Server) testMCPOAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kc, err := s.Store.Keycloak(ctx)
	if err != nil {
		httpx.JSON(w, http.StatusOK, mcpOAuthReport{Error: err.Error()})
		return
	}
	cfg, _ := s.Store.MCP(ctx)
	resource := s.resourceURL(r, cfg)

	report := mcpOAuthReport{
		ResourceURL:         resource,
		ResourceMetadataURL: resource + "/.well-known/oauth-protected-resource",
		WebRedirectURI:      s.redirectURI(r, kc.RedirectURL),
		// MCP clients bind an ephemeral loopback port, so Keycloak needs a
		// wildcard port on the public client or every attempt fails with
		// "Invalid parameter: redirect_uri".
		LoopbackRedirects: []string{
			"http://127.0.0.1:*",
			"http://localhost:*",
		},
		Issuer:            strings.TrimRight(kc.Issuer, "/"),
		MCPClientID:       kc.MCPClientID,
		AcceptedAudiences: kc.MCPAudienceSet(),
		RequiredScope:     kc.MCPRequiredScope,
		Scopes:            kc.MCPScopes,
		ClientConfig: map[string]any{
			"mcpServers": map[string]any{
				"bbmcp": map[string]any{"type": "http", "url": resource + "/mcp"},
			},
		},
	}

	switch {
	case !kc.Enabled:
		report.Error = "Keycloak SSO 가 꺼져 있어 MCP OAuth 를 사용할 수 없습니다"
		httpx.JSON(w, http.StatusOK, report)
		return
	case !kc.MCPOAuthEnabled:
		report.Error = "MCP OAuth 가 꺼져 있습니다. API 키로만 연결할 수 있습니다"
		httpx.JSON(w, http.StatusOK, report)
		return
	case kc.Issuer == "":
		report.Error = "Issuer URL 이 설정되지 않았습니다"
		httpx.JSON(w, http.StatusOK, report)
		return
	}

	meta, err := s.fetchASMetadata(ctx, kc)
	if err != nil {
		report.Error = err.Error()
		httpx.JSON(w, http.StatusOK, report)
		return
	}

	pick := func(key string) string {
		v, _ := meta[key].(string)
		return v
	}
	report.AuthorizationServer = map[string]string{
		"issuer":                pick("issuer"),
		"authorizationEndpoint": pick("authorization_endpoint"),
		"tokenEndpoint":         pick("token_endpoint"),
		"registrationEndpoint":  pick("registration_endpoint"),
		"jwksUri":               pick("jwks_uri"),
	}
	report.KeycloakSupportsDCR = pick("registration_endpoint") != ""
	report.AdvertisedServer = s.advertisedAuthorizationServer(r, kc, cfg)
	if kc.MCPAllowDCR {
		report.GatewayDCREndpoint = resource + "/oauth/register"
	}

	// Checks that decide whether a real client will get through.
	if !containsFold(methodsOf(meta, "code_challenge_methods_supported"), "S256") {
		report.Warnings = append(report.Warnings,
			"Keycloak 메타데이터에 PKCE S256 이 보이지 않습니다. MCP 클라이언트는 공개 클라이언트 + PKCE 로 동작합니다.")
	}
	if strings.TrimSpace(kc.MCPClientID) == "" {
		report.Warnings = append(report.Warnings,
			"MCP 클라이언트 ID 가 비어 있습니다. Keycloak 에 공개 클라이언트를 만들고 그 ID 를 입력하십시오.")
	}
	if !report.KeycloakSupportsDCR && !kc.MCPAllowDCR {
		report.Warnings = append(report.Warnings,
			"Keycloak 이 동적 등록을 제공하지 않고 게이트웨이 등록 대행도 꺼져 있습니다. "+
				"클라이언트에 MCP 클라이언트 ID 를 직접 설정해야 합니다.")
	}
	if report.KeycloakSupportsDCR && !kc.MCPAllowDCR {
		report.Warnings = append(report.Warnings,
			"게이트웨이 등록 대행이 꺼져 있어 MCP 클라이언트가 Keycloak 익명 동적 등록으로 갑니다. "+
				"Trusted Hosts·허용 스코프 정책에 막히면 insufficient_scope 또는 invalid_client_metadata 가 나고, "+
				"통과해도 새로 만들어진 클라이언트의 토큰은 허용 클라이언트가 아니어서 거부됩니다. 등록 대행을 켜십시오.")
	}
	if strings.HasPrefix(resource, "http://") && !strings.Contains(resource, "localhost") &&
		!strings.Contains(resource, "127.0.0.1") {
		report.Warnings = append(report.Warnings,
			"리소스 URL 이 평문 HTTP 입니다. 운영에서는 HTTPS 를 사용하십시오.")
	}
	// The most common failure in practice is a resource URL that does not match
	// how clients actually reach the gateway, which sends them to a callback
	// Keycloak has never seen.
	if cfg.ResourceURL != "" && cfg.ResourceURL != s.baseURL(r) {
		report.Warnings = append(report.Warnings,
			"리소스 URL("+cfg.ResourceURL+")이 현재 접속 주소("+s.baseURL(r)+")와 다릅니다. "+
				"리버스 프록시 뒤라면 정상이지만, MCP 클라이언트가 실제로 접속하는 주소여야 합니다.")
	}

	report.OK = report.Error == "" && strings.TrimSpace(kc.MCPClientID) != ""
	httpx.JSON(w, http.StatusOK, report)
}

// methodsOf reads a string-array field from a metadata document.
func methodsOf(meta map[string]any, key string) []string {
	raw, ok := meta[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
