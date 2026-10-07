package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/httpx"
	"github.com/hkjang/bbmcp/internal/settings"
	"github.com/hkjang/bbmcp/internal/version"
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

// versionHeader names the build that answered, so one request shows whether
// an old process, another server or a cache replied.
const versionHeader = "X-Bbmcp-Version"

// mountOAuth registers the discovery and registration endpoints.
func (s *Server) mountOAuth(r interface {
	Get(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
}) {
	// RFC 9728 protected resource metadata, at the root and with the MCP path
	// appended, since clients derive both forms from the resource URL.
	r.Get("/.well-known/oauth-protected-resource", discovery(s.protectedResource))
	r.Get("/.well-known/oauth-protected-resource/mcp", discovery(s.protectedResource))

	// RFC 8414 authorization server metadata, mirrored from Keycloak.
	r.Get("/.well-known/oauth-authorization-server", discovery(s.authorizationServerMetadata))
	r.Get("/.well-known/oauth-authorization-server/mcp", discovery(s.authorizationServerMetadata))
	r.Get("/.well-known/openid-configuration", discovery(s.authorizationServerMetadata))
	r.Get("/.well-known/openid-configuration/mcp", discovery(s.authorizationServerMetadata))

	// Any other well-known path is an error, not the console's HTML: a client
	// probing a variant should get a 404 it understands.
	r.Get("/.well-known/*", discovery(s.unknownWellKnown))

	// RFC 7591 dynamic client registration, answered with a static client.
	r.Post("/oauth/register", discovery(s.registerClient))
}

// discovery marks an answer that must never be cached: a stale copy of these
// documents is exactly what keeps a client on an old authorization server.
func discovery(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(versionHeader, version.Version)
		h(w, r)
	}
}

func (s *Server) unknownWellKnown(w http.ResponseWriter, r *http.Request) {
	s.traceRequest(r, traceUnknown, http.StatusNotFound, "")
	httpx.FailCode(w, http.StatusNotFound, "NOT_FOUND", "알 수 없는 well-known 경로입니다")
}

// traceRequest records one discovery step from this request.
func (s *Server) traceRequest(r *http.Request, kind string, status int, detail string) {
	if s.trace == nil {
		return
	}
	sec, _ := s.Store.Security(r.Context())
	s.trace.record(traceEvent{
		Kind:   kind,
		Method: r.Method,
		Path:   r.URL.Path,
		Status: status,
		IP:     httpx.ClientIP(r, sec.TrustProxyHeaders),
		Agent:  r.UserAgent(),
		Detail: detail,
	})
}

// resourceMetadataURL is where the 401 challenge sends clients: the
// protected resource metadata for the MCP endpoint itself.
func (s *Server) resourceMetadataURL(r *http.Request, cfg settings.MCP) string {
	return s.resourceURL(r, cfg) + "/.well-known/oauth-protected-resource/mcp"
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
	// RFC 9728 §3.3: the document served with the MCP path appended describes
	// that path. Clients that follow the hint in the 401 compare resource with
	// the URL they called, and some require them to be identical.
	if strings.HasSuffix(r.URL.Path, "/mcp") {
		resource += "/mcp"
	}

	servers := []string{}
	if as := s.advertisedAuthorizationServer(r, kc, cfg); as != "" {
		servers = append(servers, as)
	}
	s.traceRequest(r, traceResourceMeta, http.StatusOK, "authorization_servers="+strings.Join(servers, ","))

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
		s.traceRequest(r, traceServerMeta, http.StatusNotFound, "MCP OAuth 꺼짐")
		httpx.FailCode(w, http.StatusNotFound, "OAUTH_DISABLED",
			"이 게이트웨이에서 MCP OAuth 가 설정되지 않았습니다")
		return
	}

	body, err := s.fetchASMetadata(ctx, kc)
	if err != nil {
		s.traceRequest(r, traceServerMeta, http.StatusBadGateway, err.Error())
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
		// The client handed out here is public. Older Keycloak (10, for one)
		// accepts public clients at its token endpoint but does not list
		// "none", and a client choosing from this list would then pick a
		// method that needs a secret it was never given.
		out["token_endpoint_auth_methods_supported"] = withNone(body["token_endpoint_auth_methods_supported"])
		// Keycloak repeats its registration endpoint among the mTLS aliases.
		// body is the cached document every request shares, so the nested
		// map is copied, never edited.
		if aliases, ok := body["mtls_endpoint_aliases"].(map[string]any); ok {
			trimmed := make(map[string]any, len(aliases))
			for k, v := range aliases {
				if k != "registration_endpoint" {
					trimmed[k] = v
				}
			}
			out["mtls_endpoint_aliases"] = trimmed
		}
	}
	registration, _ := out["registration_endpoint"].(string)
	s.traceRequest(r, traceServerMeta, http.StatusOK, "registration_endpoint="+registration)
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

	client := keycloakHTTPClient(kc)

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

// withNone returns a token_endpoint_auth_methods_supported list that
// includes "none", keeping the methods Keycloak listed.
func withNone(listed any) []string {
	out := []string{}
	if items, ok := listed.([]any); ok {
		for _, item := range items {
			if method, ok := item.(string); ok {
				out = append(out, method)
			}
		}
	}
	if !containsFold(out, "none") {
		out = append(out, "none")
	}
	return out
}

// keycloakHTTPClient is the client bbmcp uses for its own calls to Keycloak.
func keycloakHTTPClient(kc settings.Keycloak) *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if kc.InsecureSkipTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - operator opt-in for internal CAs
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
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
	sec, _ := s.Store.Security(ctx)
	ip := httpx.ClientIP(r, sec.TrustProxyHeaders)
	// Each registration may ask Keycloak about its redirect URIs, so callers
	// are limited before any of that work starts.
	if !s.limiter.Allow("register:"+ip, 30, 10) {
		s.traceRequest(r, traceRegister, http.StatusTooManyRequests, "요청이 너무 많음")
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable",
			"등록 요청이 너무 많습니다")
		return
	}

	var req registrationRequest
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req)
	}
	detail := map[string]any{
		"clientName":   clip(req.ClientName, 120),
		"redirectUris": clipAll(req.RedirectURIs, maxRegistrationRedirects, 300),
	}
	// Every refusal is recorded, so "no oauth.register entry" really means the
	// client never asked this gateway.
	refuse := func(status int, code, message string) {
		s.Audit.Write(ctx, audit.Entry{
			Category: audit.CatAuth,
			Action:   "oauth.register",
			Success:  false,
			IP:       ip,
			Message:  "MCP 클라이언트 등록 거부: " + message,
			Detail:   detail,
		})
		s.traceRequest(r, traceRegister, status, code+": "+message)
		writeOAuthError(w, status, code, message)
	}

	kc, err := s.Store.Keycloak(ctx)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if !kc.Enabled || !kc.MCPOAuthEnabled {
		refuse(http.StatusNotFound, "invalid_request", "이 게이트웨이에서 MCP OAuth 가 설정되지 않았습니다")
		return
	}
	if !kc.MCPAllowDCR {
		refuse(http.StatusForbidden, "access_denied",
			"동적 클라이언트 등록이 비활성화되어 있습니다. 관리자에게 MCP 클라이언트 ID 를 요청하십시오.")
		return
	}
	clientID := strings.TrimSpace(kc.MCPClientID)
	if clientID == "" {
		refuse(http.StatusConflict, "invalid_request", "MCP 클라이언트 ID 가 설정되지 않았습니다")
		return
	}
	detail["clientId"] = clientID

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
	redirects := dedupe(req.RedirectURIs)
	if len(redirects) > maxRegistrationRedirects {
		refuse(http.StatusBadRequest, "invalid_redirect_uri",
			fmt.Sprintf("리다이렉트 URI 는 %d 개까지 받습니다", maxRegistrationRedirects))
		return
	}
	// Handing out a client_id for a redirect URI Keycloak will not accept only
	// moves the failure to a Keycloak error page the user cannot act on. Reject
	// it here, where the message can say what to register.
	if bad, reason := unusableRedirect(redirects); bad != "" {
		refuse(http.StatusBadRequest, "invalid_redirect_uri",
			fmt.Sprintf("리다이렉트 URI %q 를 사용할 수 없습니다: %s", clip(bad, 300), reason))
		return
	}

	// Keycloak, not this gateway, decides whether the browser may come back to
	// these addresses. Asking it now turns its "Invalid parameter:
	// redirect_uri" page into a message the client shows, naming the value to
	// register.
	// The overall budget bounds the requests sent to Keycloak, not the
	// registrations: once it is spent the check is skipped, as it is when
	// Keycloak cannot be reached, and the client still gets its ID. Otherwise
	// one caller rotating forwarded addresses could lock everyone out.
	if !s.limiter.Allow("register-probe:*", 300, 60) {
		detail["redirectCheck"] = "건너뜀 (요청이 많음)"
	} else if meta, err := s.fetchASMetadata(ctx, kc); err == nil {
		authEndpoint, _ := meta["authorization_endpoint"].(string)
		kept, refused, refusal := checkRegistrationRedirects(ctx, kc, authEndpoint, clientID, redirects)
		if len(refused) > 0 {
			stored := make([]redirectCheck, 0, len(refused))
			for _, c := range refused {
				c.URI, c.Detail = clip(c.URI, 300), clip(c.Detail, 200)
				stored = append(stored, c)
			}
			detail["refusedByKeycloak"] = stored
		}
		if refusal != "" {
			refuse(http.StatusBadRequest, "invalid_redirect_uri", refusal)
			return
		}
		redirects = kept
	}

	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatAuth,
		Action:   "oauth.register",
		Success:  true,
		IP:       ip,
		Message:  "MCP 클라이언트 등록 요청",
		Detail:   detail,
	})
	s.traceRequest(r, traceRegister, http.StatusCreated, "client_id="+clientID)

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

// maxRegistrationRedirects bounds the redirect URIs one registration may ask
// about. VS Code, the most generous client seen, sends four.
const maxRegistrationRedirects = 8

func dedupe(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func clipAll(values []string, max, n int) []string {
	out := []string{}
	for i, v := range values {
		if i == max {
			out = append(out, fmt.Sprintf("… 외 %d 개", len(values)-max))
			break
		}
		out = append(out, clip(v, n))
	}
	return out
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
		if len(value) > 2048 {
			return raw, "2048 자보다 깁니다"
		}
		u, err := url.Parse(value)
		if err != nil {
			return raw, "주소 형식이 올바르지 않습니다"
		}
		// http://127.0.0.1:@host/ reads as user info "127.0.0.1:" and host
		// "host"; no client needs it, and it is how a loose wildcard is abused.
		if u.User != nil {
			return raw, "사용자 정보(@)를 포함할 수 없습니다"
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
	OK      bool         `json:"ok"`
	Version version.Info `json:"version"`
	// KeycloakRegisters is set while MCP clients are sent to Keycloak's own
	// dynamic registration (registration proxying off).
	KeycloakRegisters   bool              `json:"keycloakRegisters,omitempty"`
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
	RedirectChecks      []redirectCheck   `json:"redirectChecks,omitempty"`
	// UnsafeRedirects lists attacker-shaped redirect URIs Keycloak accepts.
	UnsafeRedirects   []string       `json:"unsafeRedirects,omitempty"`
	AcceptedAudiences []string       `json:"acceptedAudiences"`
	RequiredScope     string         `json:"requiredScope,omitempty"`
	Scopes            []string       `json:"scopes"`
	Warnings          []string       `json:"warnings,omitempty"`
	ClientConfig      map[string]any `json:"clientConfigExample"`
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
		Version:             version.Current(),
		ResourceURL:         resource,
		ResourceMetadataURL: s.resourceMetadataURL(r, cfg),
		WebRedirectURI:      s.redirectURI(r, kc.RedirectURL),
		// MCP clients bind an ephemeral loopback port. A loopback URI
		// registered without a port matches any port (Keycloak 10: localhost
		// only), and unlike http://localhost:* it cannot be stretched to
		// http://localhost:@attacker.example/ on Keycloaks that compare
		// wildcards as a string prefix.
		LoopbackRedirects: []string{
			"http://localhost/callback",
			"http://127.0.0.1/callback",
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
	} else {
		report.Warnings = append(report.Warnings, s.checkLoopbackRedirects(ctx, kc, pick("authorization_endpoint"), &report)...)
	}
	if !report.KeycloakSupportsDCR && !kc.MCPAllowDCR {
		report.Warnings = append(report.Warnings,
			"Keycloak 이 동적 등록을 제공하지 않고 게이트웨이 등록 대행도 꺼져 있습니다. "+
				"클라이언트에 MCP 클라이언트 ID 를 직접 설정해야 합니다.")
	}
	if report.KeycloakSupportsDCR && !kc.MCPAllowDCR {
		report.KeycloakRegisters = true
		report.Warnings = append([]string{
			"게이트웨이 등록 대행이 꺼져 있어 MCP 클라이언트가 Keycloak 에 직접 동적 등록합니다. " +
				"Keycloak 13 이하(예: 10)는 MCP 클라이언트(공개 클라이언트) 등록을 invalid_client_metadata 로 거부하고, " +
				"14 이상도 Trusted Hosts·허용 스코프 정책에 막히거나, 통과해도 새로 생긴 클라이언트의 토큰은 허용 클라이언트가 아니어서 거부됩니다. " +
				"등록 대행을 켜거나, 클라이언트에 MCP 클라이언트 ID 를 고정하십시오. 'Keycloak 동적 등록 시험' 으로 Keycloak 의 답을 확인할 수 있습니다.",
		}, report.Warnings...)
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

	// Sending clients to Keycloak's own registration is not reported as
	// ready: on most realms, and on every Keycloak before 14, it cannot work.
	report.OK = report.Error == "" && strings.TrimSpace(kc.MCPClientID) != "" && !report.KeycloakRegisters
	// Not ready when the client is missing, or when the realm takes random
	// loopback ports but not on localhost, where Claude Code and most clients
	// call back. Random ports refused on both hosts is a fixed-port setup and
	// a refusal only for 127.0.0.1 is how Keycloak 10 treats IP addresses;
	// both stay warnings.
	if len(report.RedirectChecks) == 2 {
		ip, lh := report.RedirectChecks[0], report.RedirectChecks[1]
		if ip.ClientMissing || lh.ClientMissing || (ip.Accepted && !lh.Accepted && lh.Error == "") {
			report.OK = false
		}
	}
	if len(report.UnsafeRedirects) > 0 {
		report.OK = false
	}
	httpx.JSON(w, http.StatusOK, report)
}

// checkLoopbackRedirects asks Keycloak about the two callback shapes MCP
// clients use, an ephemeral port on 127.0.0.1 or on localhost (Claude Code
// uses localhost), and returns warnings for what it refuses.
func (s *Server) checkLoopbackRedirects(ctx context.Context, kc settings.Keycloak, authEndpoint string, report *mcpOAuthReport) []string {
	warnings := []string{}
	if open := checkWildcardBypass(ctx, kc, authEndpoint, kc.MCPClientID); len(open) > 0 {
		report.UnsafeRedirects = open
		warnings = append(warnings, fmt.Sprintf(
			"보안: Keycloak 이 %s 같은 주소로도 로그인 결과를 보냅니다. 브라우저는 '@' 뒤의 호스트로 가므로, 공격자가 만든 링크로 로그인한 사람의 "+
				"인증 코드가 공격자 서버로 갑니다. %s 클라이언트의 Valid redirect URIs 에서 와일드카드(http://localhost:* 등)와 포트 없는 "+
				"localhost 주소를 지우십시오. Keycloak 10 은 localhost 의 ':' 부터 다음 '/' 까지를 포트로 보고 지운 뒤 비교하므로 둘 다 이렇게 뚫립니다. "+
				"대신 클라이언트에 고정 콜백 포트를 설정하고 그 주소를 정확히 등록하십시오(예: http://localhost:33333/callback, Claude Code 는 --callback-port 33333).",
			open[0], kc.MCPClientID))
	}
	port := 49152 + rand.IntN(16000)
	checks := []redirectCheck{}
	for _, host := range []string{"127.0.0.1", "localhost"} {
		checks = append(checks, checkRedirect(ctx, kc, authEndpoint, kc.MCPClientID, fmt.Sprintf("http://%s:%d/callback", host, port)))
	}
	report.RedirectChecks = append(report.RedirectChecks, checks...)
	ip, lh := checks[0], checks[1]

	switch {
	case ip.Error != "" || lh.Error != "":
		for _, c := range checks {
			if c.Error != "" {
				warnings = append(warnings, "리다이렉트 URI 를 Keycloak 에 확인하지 못했습니다: "+c.Error)
			}
		}
	case ip.ClientMissing || lh.ClientMissing:
		warnings = append(warnings, refusalMessage(kc.MCPClientID, ip))
	case !ip.Accepted && !lh.Accepted:
		// Neither loopback host takes a random port: a fixed-port setup, which
		// is the safe one on Keycloak 10, or a client with nothing registered.
		warnings = append(warnings, fmt.Sprintf(
			"%s 클라이언트가 임의 포트의 루프백 콜백(%s, %s)을 받지 않습니다. 고정 포트 설정이라면 정상입니다: "+
				"클라이언트에 고정 콜백 포트를 설정하고(Claude Code: --callback-port 또는 oauth.callbackPort) 그 주소를 "+
				"Valid redirect URIs 에 정확히 등록했는지 확인하십시오(예: http://localhost:33333/callback). 그렇지 않으면 로그인 창에 "+
				"Invalid parameter: redirect_uri 가 납니다.", kc.MCPClientID, ip.URI, lh.URI))
	default:
		for _, c := range checks {
			if !c.Accepted {
				warnings = append(warnings, refusalMessage(kc.MCPClientID, c)+
					" 이대로면 그 주소를 쓰는 클라이언트의 로그인 창에 Invalid parameter: redirect_uri 가 납니다.")
			}
		}
	}
	for _, c := range checks {
		if c.SendsIssuer && kc.MCPAllowDCR {
			warnings = append(warnings, "Keycloak 이 로그인 응답에 자기 issuer 를 붙입니다. "+
				kc.MCPClientID+" 클라이언트의 Exclude Issuer From Authentication Response 를 켜십시오. "+
				"이를 검사하는 클라이언트(Python MCP SDK 등)가 로그인을 거부합니다.")
			break
		}
	}
	return warnings
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
