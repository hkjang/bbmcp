package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hkjang/bbmcp/internal/apikey"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/httpx"
	"github.com/hkjang/bbmcp/internal/identity"
	"github.com/hkjang/bbmcp/internal/policy"
	"github.com/hkjang/bbmcp/internal/settings"
	"github.com/hkjang/bbmcp/internal/tools"
	"github.com/hkjang/bbmcp/internal/version"
)

// mountAdmin registers the service administrator routes.
func (s *Server) mountAdmin(r chi.Router) {
	r.Get("/dashboard", s.adminDashboard)
	r.Get("/system", s.adminSystem)

	r.Get("/settings", s.getAllSettings)
	r.Get("/settings/{group}", s.getSettings)
	r.Put("/settings/{group}", s.putSettings)
	r.Post("/test/{target}", s.testTarget)

	r.Get("/users", s.listUsers)
	r.Post("/users", s.createUser)
	r.Patch("/users/{id}", s.updateUser)
	r.Post("/users/{id}/password", s.setUserPassword)
	r.Delete("/users/{id}", s.deleteUser)

	r.Get("/identity/mappings", s.listMappings)
	r.Post("/identity/mappings", s.createMapping)
	r.Post("/identity/mappings/{sub}/verify", s.verifyMapping)
	r.Post("/identity/mappings/{sub}/active", s.setMappingActive)
	r.Delete("/identity/mappings/{sub}", s.deleteMapping)
	r.Get("/identity/errors", s.listMappingErrors)
	r.Delete("/identity/errors", s.clearMappingErrors)

	r.Get("/tools", s.listTools)
	r.Patch("/tools/{name}", s.patchTool)
	r.Post("/tools/sync", s.syncTools)
	r.Get("/tool-groups", s.listToolGroups)

	r.Get("/policy/rules", s.listRules)
	r.Post("/policy/rules", s.createRule)
	r.Put("/policy/rules/{id}", s.updateRule)
	r.Delete("/policy/rules/{id}", s.deleteRule)
	r.Post("/policy/evaluate", s.evaluatePolicy)

	r.Get("/approvals", s.listApprovals)
	r.Post("/approvals/{id}/decide", s.decideApproval)

	r.Get("/keys", s.listAllKeys)
	r.Post("/keys/{id}/revoke", s.revokeAnyKey)
	r.Post("/keys/{id}/rotate", s.rotateAnyKey)
	r.Get("/key-roles", s.keyRoles)
	r.Put("/key-roles/{name}", s.saveKeyRole)
	r.Delete("/key-roles/{name}", s.deleteKeyRole)
	r.Get("/key-scopes", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, http.StatusOK, apikey.AllScopes())
	})

	r.Get("/audit", s.listAudit)
	r.Post("/audit/purge", s.purgeAudit)
	r.Get("/sessions", s.listMCPSessions)
}

// ---------- dashboard & system ----------

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{"version": version.Current()}

	counts := map[string]int{}
	for key, query := range map[string]string{
		"users":            `SELECT COUNT(*) FROM users WHERE active`,
		"mappings":         `SELECT COUNT(*) FROM bitbucket_identity_mapping WHERE active`,
		"mappingErrors":    `SELECT COUNT(*) FROM identity_mapping_errors`,
		"activeKeys":       `SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`,
		"rotationDue":      `SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL AND rotation_due_at < NOW()`,
		"pendingApprovals": `SELECT COUNT(*) FROM approval_requests WHERE status='pending' AND expires_at > NOW()`,
		"enabledTools":     `SELECT COUNT(*) FROM mcp_tools WHERE enabled`,
		"policyRules":      `SELECT COUNT(*) FROM policy_rules`,
		"mcpSessions":      `SELECT COUNT(*) FROM mcp_sessions WHERE closed_at IS NULL AND last_seen_at > NOW() - INTERVAL '1 hour'`,
	} {
		var n int
		if err := s.Pool.QueryRow(ctx, query).Scan(&n); err == nil {
			counts[key] = n
		}
	}
	out["counts"] = counts

	var calls24, errors24 int
	_ = s.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE category IN ('tool','write') AND occurred_at > NOW() - INTERVAL '24 hours'`).Scan(&calls24)
	_ = s.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE success = FALSE AND occurred_at > NOW() - INTERVAL '24 hours'`).Scan(&errors24)
	out["toolCalls24h"] = calls24
	out["failures24h"] = errors24

	if rows, err := s.Pool.Query(ctx, `
		SELECT tool_name, COUNT(*) FROM audit_log
		WHERE tool_name IS NOT NULL AND occurred_at > NOW() - INTERVAL '7 days'
		GROUP BY tool_name ORDER BY COUNT(*) DESC LIMIT 10`); err == nil {
		defer rows.Close()
		top := []map[string]any{}
		for rows.Next() {
			var name string
			var n int
			if rows.Scan(&name, &n) == nil {
				top = append(top, map[string]any{"tool": name, "calls": n})
			}
		}
		out["topTools"] = top
	}

	recent, _, err := s.Audit.List(ctx, audit.Query{Limit: 15})
	if err == nil {
		out["recentAudit"] = recent
	}
	out["health"] = s.healthSnapshot(ctx)
	httpx.JSON(w, http.StatusOK, out)
}

// postLogoutRegistrations lists what Keycloak needs for logout to return here.
func postLogoutRegistrations(configured string) []string {
	if strings.TrimSpace(configured) == "" {
		return []string{}
	}
	return []string{configured}
}

// healthSnapshot checks every dependency the readiness probe cares about.
func (s *Server) healthSnapshot(ctx context.Context) map[string]any {
	out := map[string]any{}

	dbOK := s.Pool.Ping(ctx) == nil
	out["database"] = component(dbOK, "PostgreSQL")

	kc, err := s.Store.Keycloak(ctx)
	switch {
	case err != nil:
		out["keycloak"] = component(false, err.Error())
	case !kc.Enabled:
		out["keycloak"] = map[string]any{"ok": true, "detail": "비활성(로컬 로그인만)", "skipped": true}
	default:
		_, _, kerr := s.Auth.OIDC.OAuth2Config(ctx, kc.RedirectURL)
		out["keycloak"] = component(kerr == nil, detailOf(kerr, "디스커버리 정상"))
	}

	adapter, bb, aerr := s.Provider.Adapter(ctx)
	if aerr != nil {
		out["bitbucket"] = component(false, aerr.Error())
		out["servicePat"] = component(false, "Bitbucket 미설정")
	} else {
		cred, cerr := s.Provider.ServiceCredential(ctx)
		if cerr != nil {
			out["bitbucket"] = component(false, cerr.Error())
			out["servicePat"] = component(false, cerr.Error())
		} else {
			perr := adapter.Ping(ctx, cred)
			out["bitbucket"] = component(perr == nil, detailOf(perr, bb.BaseURL))
			out["servicePat"] = component(perr == nil, detailOf(perr, bb.ServiceUsername))
		}
	}

	perm, _ := s.Store.Permission(ctx)
	if perm.Mode == "plugin" {
		herr := s.Resolver.PluginHealth(ctx)
		out["permissionPlugin"] = component(herr == nil, detailOf(herr, perm.PluginBaseURL))
	} else {
		out["permissionPlugin"] = map[string]any{
			"ok": true, "detail": "REST 폴백 모드", "skipped": true,
		}
	}

	ai, _ := s.Store.AI(ctx)
	if ai.Enabled {
		out["ai"] = map[string]any{"ok": true, "detail": ai.Provider + " / " + ai.Model}
	} else {
		out["ai"] = map[string]any{"ok": true, "detail": "비활성", "skipped": true}
	}
	return out
}

func component(ok bool, detail string) map[string]any {
	return map[string]any{"ok": ok, "detail": detail}
}

func detailOf(err error, okDetail string) string {
	if err != nil {
		return err.Error()
	}
	return okDetail
}

func (s *Server) adminSystem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{"version": version.Current(), "health": s.healthSnapshot(ctx)}

	var dbVersion, dbName, dbSize string
	_ = s.Pool.QueryRow(ctx, `SELECT version()`).Scan(&dbVersion)
	_ = s.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName)
	_ = s.Pool.QueryRow(ctx, `SELECT pg_size_pretty(pg_database_size(current_database()))`).Scan(&dbSize)
	out["database"] = map[string]any{"version": dbVersion, "name": dbName, "size": dbSize}

	if rows, err := s.Pool.Query(ctx,
		`SELECT version, applied_at FROM schema_migrations ORDER BY version`); err == nil {
		defer rows.Close()
		migrations := []map[string]any{}
		for rows.Next() {
			var v string
			var at time.Time
			if rows.Scan(&v, &at) == nil {
				migrations = append(migrations, map[string]any{"version": v, "appliedAt": at})
			}
		}
		out["migrations"] = migrations
	}

	stat := s.Pool.Stat()
	out["pool"] = map[string]any{
		"total": stat.TotalConns(), "idle": stat.IdleConns(), "acquired": stat.AcquiredConns(),
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	snapshot := s.healthSnapshot(r.Context())
	ready := true
	for _, v := range snapshot {
		if m, ok := v.(map[string]any); ok {
			if skipped, _ := m["skipped"].(bool); skipped {
				continue
			}
			if ok2, _ := m["ok"].(bool); !ok2 {
				ready = false
			}
		}
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	httpx.JSON(w, status, map[string]any{"ready": ready, "components": snapshot})
}

// metrics exposes Prometheus text-format counters built from the audit log.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var sb strings.Builder
	emit := func(name, help, typ string, value any, labels string) {
		sb.WriteString("# HELP " + name + " " + help + "\n")
		sb.WriteString("# TYPE " + name + " " + typ + "\n")
		sb.WriteString(name + labels + " " + toStr(value) + "\n")
	}

	count := func(query string) int {
		var n int
		_ = s.Pool.QueryRow(ctx, query).Scan(&n)
		return n
	}
	emit("bbmcp_build_info", "빌드 정보", "gauge", 1,
		`{version="`+version.Version+`",commit="`+version.Commit+`"}`)
	emit("bbmcp_tool_requests_total", "도구 호출 수", "counter",
		count(`SELECT COUNT(*) FROM audit_log WHERE category IN ('tool','write')`), "")
	emit("bbmcp_tool_errors_total", "도구 실패 수", "counter",
		count(`SELECT COUNT(*) FROM audit_log WHERE success=FALSE AND tool_name IS NOT NULL`), "")
	emit("bbmcp_permission_denied_total", "권한 거부 수", "counter",
		count(`SELECT COUNT(*) FROM audit_log WHERE error_code IN ('PERMISSION_DENIED','POLICY_DENIED','BRANCH_RESTRICTED')`), "")
	emit("bbmcp_identity_mapping_errors_total", "식별 매핑 실패 수", "counter",
		count(`SELECT COUNT(*) FROM identity_mapping_errors`), "")
	emit("bbmcp_approval_requests_total", "승인 요청 수", "counter",
		count(`SELECT COUNT(*) FROM approval_requests`), "")
	emit("bbmcp_approval_pending", "대기 중 승인 수", "gauge",
		count(`SELECT COUNT(*) FROM approval_requests WHERE status='pending'`), "")
	emit("bbmcp_api_keys_active", "활성 API 키 수", "gauge",
		count(`SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL`), "")
	emit("bbmcp_mcp_sessions_active", "활성 MCP 세션 수", "gauge",
		count(`SELECT COUNT(*) FROM mcp_sessions WHERE closed_at IS NULL AND last_seen_at > NOW() - INTERVAL '1 hour'`), "")

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(sb.String()))
}

func toStr(v any) string {
	switch t := v.(type) {
	case int:
		return strconv.Itoa(t)
	case int32:
		return strconv.Itoa(int(t))
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return "0"
	}
}

// ---------- settings ----------

// maskedSettings returns a group with secrets replaced by presence flags.
func (s *Server) maskedSettings(ctx context.Context, group string) (any, error) {
	switch group {
	case settings.KeyKeycloak:
		cfg, err := s.Store.Keycloak(ctx)
		if err != nil {
			return nil, err
		}
		has := cfg.ClientSecretEnc != ""
		cfg.ClientSecretEnc = ""
		return map[string]any{"value": cfg, "secrets": map[string]bool{"clientSecret": has}}, nil
	case settings.KeyBitbucket:
		cfg, err := s.Store.Bitbucket(ctx)
		if err != nil {
			return nil, err
		}
		has := cfg.ServicePATEnc != ""
		cfg.ServicePATEnc = ""
		return map[string]any{"value": cfg, "secrets": map[string]bool{"servicePat": has}}, nil
	case settings.KeyPermission:
		cfg, err := s.Store.Permission(ctx)
		if err != nil {
			return nil, err
		}
		has := cfg.PluginSecretEnc != ""
		cfg.PluginSecretEnc = ""
		return map[string]any{"value": cfg, "secrets": map[string]bool{"pluginSecret": has}}, nil
	case settings.KeyAI:
		cfg, err := s.Store.AI(ctx)
		if err != nil {
			return nil, err
		}
		has := cfg.APIKeyEnc != ""
		cfg.APIKeyEnc = ""
		return map[string]any{
			"value":   cfg,
			"secrets": map[string]bool{"apiKey": has},
			"limits":  map[string]any{"maxTokenCeiling": settings.MaxTokenCeiling},
		}, nil
	case settings.KeySecurity:
		cfg, err := s.Store.Security(ctx)
		return map[string]any{"value": cfg}, err
	case settings.KeyUI:
		cfg, err := s.Store.UI(ctx)
		return map[string]any{"value": cfg}, err
	case settings.KeyKeyPolicy:
		cfg, err := s.Store.KeyPolicy(ctx)
		return map[string]any{"value": cfg}, err
	case settings.KeyMCP:
		cfg, err := s.Store.MCP(ctx)
		return map[string]any{"value": cfg}, err
	default:
		return nil, errNotFound("알 수 없는 설정 그룹입니다: " + group)
	}
}

func (s *Server) getAllSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{}
	for _, g := range []string{settings.KeyKeycloak, settings.KeyBitbucket,
		settings.KeyPermission, settings.KeyAI, settings.KeySecurity,
		settings.KeyUI, settings.KeyKeyPolicy, settings.KeyMCP} {
		v, err := s.maskedSettings(ctx, g)
		if err != nil {
			httpx.Fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		out[g] = v
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	v, err := s.maskedSettings(r.Context(), chi.URLParam(r, "group"))
	if err != nil {
		writeErr(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

// putSettings replaces a settings group. Secrets are only overwritten when a
// non-empty plaintext value is supplied, so a save from the UI never wipes a
// stored credential the operator did not retype.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	group := chi.URLParam(r, "group")
	actor := identityOf(r).User.Username

	var body struct {
		Value   map[string]any    `json:"value"`
		Secrets map[string]string `json:"secrets"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}

	var err error
	switch group {
	case settings.KeyKeycloak:
		cur, e := s.Store.Keycloak(ctx)
		if e != nil {
			httpx.Fail(w, http.StatusInternalServerError, e.Error())
			return
		}
		next := cur
		if e := remarshal(body.Value, &next); e != nil {
			httpx.Fail(w, http.StatusBadRequest, e.Error())
			return
		}
		next.ClientSecretEnc = cur.ClientSecretEnc
		if v := strings.TrimSpace(body.Secrets["clientSecret"]); v != "" {
			if next.ClientSecretEnc, err = s.Store.Seal(v); err != nil {
				httpx.Fail(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		if next.UsernameClaim == "" {
			next.UsernameClaim = "preferred_username"
		}
		// Validate what the operator typed, then store the normalised form so
		// the string bbmcp sends matches what they registered in Keycloak.
		next.ClientID = strings.TrimSpace(next.ClientID)
		next.MCPClientID = strings.TrimSpace(next.MCPClientID)
		for _, field := range []struct {
			label  string
			target *string
			path   bool
		}{
			{"Issuer URL", &next.Issuer, false},
			{"Redirect URI", &next.RedirectURL, true},
			{"로그아웃 후 이동 URL", &next.PostLogoutURL, true},
		} {
			var cleaned string
			var verr error
			if field.path {
				cleaned, verr = httpx.CleanRedirectURI(field.label, *field.target, false)
			} else {
				cleaned, verr = httpx.CleanBaseURL(field.label, *field.target, false)
			}
			if verr != nil {
				httpx.FailCode(w, http.StatusBadRequest, "INVALID_URL", verr.Error())
				return
			}
			*field.target = cleaned
		}
		if next.Enabled && next.Issuer == "" {
			httpx.FailCode(w, http.StatusBadRequest, "INVALID_URL",
				"Keycloak SSO 를 켜려면 Issuer URL 이 필요합니다")
			return
		}
		if next.RedirectURL != "" && !strings.HasSuffix(next.RedirectURL, CallbackPath) {
			httpx.FailCode(w, http.StatusBadRequest, "INVALID_URL",
				"Redirect URI 는 "+CallbackPath+" 로 끝나야 합니다. 이 경로에서만 콜백을 받습니다.")
			return
		}
		err = s.Store.Put(ctx, group, next, actor)
		s.Auth.OIDC.Reset()

	case settings.KeyBitbucket:
		cur, e := s.Store.Bitbucket(ctx)
		if e != nil {
			httpx.Fail(w, http.StatusInternalServerError, e.Error())
			return
		}
		next := cur
		if e := remarshal(body.Value, &next); e != nil {
			httpx.Fail(w, http.StatusBadRequest, e.Error())
			return
		}
		next.ServicePATEnc = cur.ServicePATEnc
		if v := strings.TrimSpace(body.Secrets["servicePat"]); v != "" {
			if next.ServicePATEnc, err = s.Store.Seal(v); err != nil {
				httpx.Fail(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		if next.RestPrefix == "" {
			next.RestPrefix = "/rest/api/1.0"
		}
		if cleaned, verr := httpx.CleanBaseURL("Bitbucket 기본 URL", next.BaseURL, false); verr != nil {
			httpx.FailCode(w, http.StatusBadRequest, "INVALID_URL", verr.Error())
			return
		} else {
			next.BaseURL = cleaned
		}
		if next.DefaultAuthMode != "user" {
			next.DefaultAuthMode = "service"
		}
		err = s.Store.Put(ctx, group, next, actor)
		s.Provider.Reset()
		s.Resolver.Reset()

	case settings.KeyPermission:
		cur, e := s.Store.Permission(ctx)
		if e != nil {
			httpx.Fail(w, http.StatusInternalServerError, e.Error())
			return
		}
		next := cur
		if e := remarshal(body.Value, &next); e != nil {
			httpx.Fail(w, http.StatusBadRequest, e.Error())
			return
		}
		next.PluginSecretEnc = cur.PluginSecretEnc
		if v := strings.TrimSpace(body.Secrets["pluginSecret"]); v != "" {
			if next.PluginSecretEnc, err = s.Store.Seal(v); err != nil {
				httpx.Fail(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		if next.Mode != "plugin" {
			next.Mode = "rest"
		}
		if cleaned, verr := httpx.CleanBaseURL("권한 플러그인 URL", next.PluginBaseURL, false); verr != nil {
			httpx.FailCode(w, http.StatusBadRequest, "INVALID_URL", verr.Error())
			return
		} else {
			next.PluginBaseURL = cleaned
		}
		if next.Mode == "plugin" && next.PluginBaseURL == "" {
			httpx.FailCode(w, http.StatusBadRequest, "INVALID_URL",
				"플러그인 모드에서는 플러그인 기본 URL 이 필요합니다")
			return
		}
		err = s.Store.Put(ctx, group, next, actor)
		s.Resolver.Reset()

	case settings.KeyAI:
		cur, e := s.Store.AI(ctx)
		if e != nil {
			httpx.Fail(w, http.StatusInternalServerError, e.Error())
			return
		}
		next := cur
		if e := remarshal(body.Value, &next); e != nil {
			httpx.Fail(w, http.StatusBadRequest, e.Error())
			return
		}
		next.APIKeyEnc = cur.APIKeyEnc
		if v := strings.TrimSpace(body.Secrets["apiKey"]); v != "" {
			if next.APIKeyEnc, err = s.Store.Seal(v); err != nil {
				httpx.Fail(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		if cleaned, verr := httpx.CleanBaseURL("AI 기본 URL", next.BaseURL, false); verr != nil {
			httpx.FailCode(w, http.StatusBadRequest, "INVALID_URL", verr.Error())
			return
		} else {
			next.BaseURL = cleaned
		}
		if next.MaxTokens > settings.MaxTokenCeiling {
			next.MaxTokens = settings.MaxTokenCeiling
		}
		if next.MaxTokens <= 0 {
			next.MaxTokens = 8192
		}
		if next.ContextLimit <= 0 || next.ContextLimit > settings.MaxTokenCeiling {
			next.ContextLimit = settings.MaxTokenCeiling
		}
		err = s.Store.Put(ctx, group, next, actor)

	case settings.KeySecurity:
		cur, _ := s.Store.Security(ctx)
		next := cur
		if e := remarshal(body.Value, &next); e != nil {
			httpx.Fail(w, http.StatusBadRequest, e.Error())
			return
		}
		if next.SessionTTLMinutes <= 0 {
			next.SessionTTLMinutes = 480
		}
		if next.ApprovalTTLMin <= 0 {
			next.ApprovalTTLMin = 15
		}
		err = s.Store.Put(ctx, group, next, actor)

	case settings.KeyUI:
		cur, _ := s.Store.UI(ctx)
		next := cur
		if e := remarshal(body.Value, &next); e != nil {
			httpx.Fail(w, http.StatusBadRequest, e.Error())
			return
		}
		if next.FontScale < 0.8 || next.FontScale > 1.6 {
			next.FontScale = 1.0
		}
		if next.ServiceName == "" {
			next.ServiceName = "bbmcp"
		}
		err = s.Store.Put(ctx, group, next, actor)

	case settings.KeyKeyPolicy:
		cur, _ := s.Store.KeyPolicy(ctx)
		next := cur
		if e := remarshal(body.Value, &next); e != nil {
			httpx.Fail(w, http.StatusBadRequest, e.Error())
			return
		}
		err = s.Store.Put(ctx, group, next, actor)

	case settings.KeyMCP:
		cur, _ := s.Store.MCP(ctx)
		next := cur
		if e := remarshal(body.Value, &next); e != nil {
			httpx.Fail(w, http.StatusBadRequest, e.Error())
			return
		}
		if cleaned, verr := httpx.CleanBaseURL("리소스 URL", next.ResourceURL, false); verr != nil {
			httpx.FailCode(w, http.StatusBadRequest, "INVALID_URL", verr.Error())
			return
		} else {
			next.ResourceURL = cleaned
		}
		err = s.Store.Put(ctx, group, next, actor)

	default:
		httpx.Fail(w, http.StatusNotFound, "알 수 없는 설정 그룹입니다")
		return
	}
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatAdmin, Action: "settings.update",
		KeycloakUsername: actor, Success: true,
		Detail: map[string]any{"group": group},
	})
	v, err := s.maskedSettings(ctx, group)
	if err != nil {
		writeErr(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

// testTarget runs a connectivity check against a configured dependency.
func (s *Server) testTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch chi.URLParam(r, "target") {
	case "bitbucket":
		adapter, bb, err := s.Provider.Adapter(ctx)
		if err != nil {
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		cred, err := s.Provider.ServiceCredential(ctx)
		if err != nil {
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := adapter.Ping(ctx, cred); err != nil {
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		out := map[string]any{"ok": true, "baseUrl": bb.BaseURL}
		if bb.ServiceUsername != "" {
			if u, err := adapter.FindUserByUsername(ctx, cred, bb.ServiceUsername); err == nil {
				out["serviceAccount"] = u
			} else {
				out["warning"] = "서비스 계정 사용자 조회 실패: " + err.Error()
			}
		}
		if projects, _, err := adapter.Projects(ctx, cred, "", 0, 5); err == nil {
			out["sampleProjects"] = projects
		}
		httpx.JSON(w, http.StatusOK, out)

	case "keycloak":
		kc, _, err := s.Auth.OIDC.Config(ctx)
		if err != nil {
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.Auth.OIDC.Reset()
		redirect := s.redirectURI(r, kc.RedirectURL)
		derived := s.baseURL(r) + CallbackPath

		// Whatever bbmcp will actually send is reported verbatim, so the
		// operator can paste it into Keycloak instead of guessing.
		out := map[string]any{
			"redirectUri":        redirect,
			"derivedRedirectUri": derived,
			"postLogoutUri":      kc.PostLogoutURL,
			"register": map[string]any{
				"validRedirectUris":           []string{redirect},
				"webOrigins":                  []string{s.baseURL(r)},
				"validPostLogoutRedirectUris": postLogoutRegistrations(kc.PostLogoutURL),
			},
		}
		warnings := []string{}
		if kc.RedirectURL != "" && kc.RedirectURL != derived {
			warnings = append(warnings, "설정한 Redirect URI 와 현재 접속 주소에서 유도한 값이 다릅니다. "+
				"리버스 프록시를 쓴다면 정상이지만, Keycloak 에는 설정값("+redirect+")이 등록되어 있어야 합니다.")
		}
		if kc.PostLogoutURL == "" {
			warnings = append(warnings, "로그아웃 후 이동 URL 이 비어 있어 로그아웃 시 Keycloak 화면에 머무릅니다. "+
				"앱으로 돌아오게 하려면 값을 넣고 Keycloak 의 Valid post logout redirect URIs 에도 같은 값을 등록하십시오.")
		}

		cfg, _, err := s.Auth.OIDC.OAuth2Config(ctx, redirect)
		if err != nil {
			out["ok"] = false
			out["error"] = err.Error()
			out["warnings"] = warnings
			httpx.JSON(w, http.StatusOK, out)
			return
		}
		out["ok"] = true
		out["authUrl"] = cfg.Endpoint.AuthURL
		out["tokenUrl"] = cfg.Endpoint.TokenURL
		out["scopes"] = cfg.Scopes

		// Ask Keycloak whether it will send the browser back to the redirect
		// URI, rather than leaving that to the first person who signs in.
		check := checkRedirect(ctx, kc, cfg.Endpoint.AuthURL, kc.ClientID, redirect)
		out["redirectCheck"] = check
		switch {
		case check.Error != "":
			warnings = append(warnings, "Redirect URI 를 Keycloak 에 확인하지 못했습니다: "+check.Error)
		case !check.Accepted:
			out["ok"] = false
			out["error"] = fmt.Sprintf("Keycloak 이 Redirect URI %s 를 거부합니다 (Keycloak: %s). "+
				"%s 클라이언트의 Valid redirect URIs 에 아래 값을 그대로 등록하십시오.", redirect, check.Detail, kc.ClientID)
		}
		if len(warnings) > 0 {
			out["warnings"] = warnings
		}
		httpx.JSON(w, http.StatusOK, out)

	case "permission":
		perm, _ := s.Store.Permission(ctx)
		if perm.Mode != "plugin" {
			username := strings.TrimSpace(r.URL.Query().Get("username"))
			project := strings.TrimSpace(r.URL.Query().Get("project"))
			if username == "" || project == "" {
				httpx.JSON(w, http.StatusOK, map[string]any{
					"ok": true, "mode": "rest",
					"detail": "REST 폴백 모드입니다. username, project 쿼리로 실제 판정을 시험할 수 있습니다.",
				})
				return
			}
			dec, err := s.Resolver.Project(ctx, username, project)
			if err != nil {
				httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "rest", "decision": dec})
			return
		}
		if err := s.Resolver.PluginHealth(ctx); err != nil {
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "plugin"})

	case "mcp-oauth":
		s.testMCPOAuth(w, r)

	case "ai":
		reply, err := s.AI.Test(ctx)
		if err != nil {
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "reply": reply})

	default:
		httpx.Fail(w, http.StatusNotFound, "알 수 없는 점검 대상입니다")
	}
}

// ---------- users ----------

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Users.List(r.Context(), r.URL.Query().Get("q"), queryInt(r, "limit", 200))
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, users)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username    string   `json:"username"`
		Password    string   `json:"password"`
		DisplayName string   `json:"displayName"`
		Email       string   `json:"email"`
		IsAdmin     bool     `json:"isServiceAdmin"`
		Roles       []string `json:"roles"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	if strings.TrimSpace(body.Username) == "" || len(body.Password) < 10 {
		httpx.Fail(w, http.StatusBadRequest, "사용자명과 10자 이상의 비밀번호가 필요합니다")
		return
	}
	u, err := s.Users.CreateLocal(r.Context(), strings.TrimSpace(body.Username), body.Password,
		body.DisplayName, body.Email, body.IsAdmin, body.Roles)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatAdmin, Action: "user.create",
		KeycloakUsername: identityOf(r).User.Username, Success: true,
		Detail: map[string]any{"target": u.Username},
	})
	httpx.JSON(w, http.StatusCreated, u)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "ID 형식이 올바르지 않습니다")
		return
	}
	target, err := s.Users.ByID(ctx, id)
	if err != nil {
		httpx.Fail(w, http.StatusNotFound, "사용자를 찾을 수 없습니다")
		return
	}
	var body struct {
		DisplayName string   `json:"displayName"`
		Email       string   `json:"email"`
		IsAdmin     bool     `json:"isServiceAdmin"`
		Active      bool     `json:"active"`
		Roles       []string `json:"roles"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	// Never let the last administrator remove their own access.
	if target.IsServiceAdmin && (!body.IsAdmin || !body.Active) {
		if n, err := s.Users.CountAdmins(ctx); err == nil && n <= 1 {
			httpx.Fail(w, http.StatusConflict, "마지막 서비스 관리자는 변경할 수 없습니다")
			return
		}
	}
	if err := s.Users.Update(ctx, id, body.DisplayName, body.Email,
		body.IsAdmin, body.Active, body.Roles); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !body.Active {
		_ = s.Sessions.RevokeUser(ctx, id)
	}
	updated, _ := s.Users.ByID(ctx, id)
	httpx.JSON(w, http.StatusOK, updated)
}

func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "ID 형식이 올바르지 않습니다")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := httpx.Decode(r, &body); err != nil || len(body.Password) < 10 {
		httpx.Fail(w, http.StatusBadRequest, "10자 이상의 비밀번호가 필요합니다")
		return
	}
	if err := s.Users.SetPassword(r.Context(), id, body.Password); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.Sessions.RevokeUser(r.Context(), id)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "ID 형식이 올바르지 않습니다")
		return
	}
	if id == identityOf(r).User.ID {
		httpx.Fail(w, http.StatusConflict, "자기 계정은 삭제할 수 없습니다")
		return
	}
	target, err := s.Users.ByID(ctx, id)
	if err == nil && target.IsServiceAdmin {
		if n, err := s.Users.CountAdmins(ctx); err == nil && n <= 1 {
			httpx.Fail(w, http.StatusConflict, "마지막 서비스 관리자는 삭제할 수 없습니다")
			return
		}
	}
	if err := s.Users.Delete(ctx, id); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- identity mapping ----------

func (s *Server) listMappings(w http.ResponseWriter, r *http.Request) {
	list, err := s.Mapper.List(r.Context(), r.URL.Query().Get("q"), queryInt(r, "limit", 200))
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, list)
}

func (s *Server) createMapping(w http.ResponseWriter, r *http.Request) {
	var body struct {
		KeycloakSub       string `json:"keycloakSub"`
		KeycloakUsername  string `json:"keycloakUsername"`
		BitbucketUsername string `json:"bitbucketUsername"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	sub := strings.TrimSpace(body.KeycloakSub)
	if sub == "" && body.KeycloakUsername != "" {
		sub = "local:" + strings.ToLower(strings.TrimSpace(body.KeycloakUsername))
	}
	if sub == "" || body.BitbucketUsername == "" {
		httpx.Fail(w, http.StatusBadRequest, "keycloakSub(또는 keycloakUsername)과 bitbucketUsername이 필요합니다")
		return
	}
	m, err := s.Mapper.ManualMap(r.Context(), sub,
		strings.TrimSpace(body.KeycloakUsername), strings.TrimSpace(body.BitbucketUsername))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, m)
}

func (s *Server) verifyMapping(w http.ResponseWriter, r *http.Request) {
	m, err := s.Mapper.Verify(r.Context(), chi.URLParam(r, "sub"))
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "mapping": m})
}

func (s *Server) setMappingActive(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Active bool `json:"active"`
	}
	_ = httpx.Decode(r, &body)
	if err := s.Mapper.SetActive(r.Context(), chi.URLParam(r, "sub"), body.Active); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) deleteMapping(w http.ResponseWriter, r *http.Request) {
	if err := s.Mapper.Delete(r.Context(), chi.URLParam(r, "sub")); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) listMappingErrors(w http.ResponseWriter, r *http.Request) {
	list, err := s.Mapper.Errors(r.Context(), queryInt(r, "limit", 100))
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, list)
}

func (s *Server) clearMappingErrors(w http.ResponseWriter, r *http.Request) {
	if err := s.Mapper.ClearErrors(r.Context()); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- tools ----------

func (s *Server) listTools(w http.ResponseWriter, r *http.Request) {
	recs, err := s.Registry.List(r.Context())
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, recs)
}

func (s *Server) patchTool(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	_, rec, err := s.Registry.Get(r.Context(), name)
	if err != nil {
		httpx.Fail(w, http.StatusNotFound, err.Error())
		return
	}
	body := struct {
		Enabled          *bool   `json:"enabled"`
		RequiresApproval *bool   `json:"requiresApproval"`
		MinRole          *string `json:"minRole"`
	}{}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	enabled, approval, minRole := rec.Enabled, rec.RequiresApproval, rec.MinRole
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if body.RequiresApproval != nil {
		approval = *body.RequiresApproval
	}
	if body.MinRole != nil {
		minRole = *body.MinRole
	}
	// Execute-risk tools may never run unapproved.
	if rec.Risk == tools.RiskExecute {
		approval = true
	}
	if err := s.Registry.Update(r.Context(), name, enabled, approval, minRole); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatAdmin, Action: "tool.update",
		KeycloakUsername: identityOf(r).User.Username, ToolName: name, Success: true,
		Detail: map[string]any{"enabled": enabled, "requiresApproval": approval, "minRole": minRole},
	})
	_, updated, _ := s.Registry.Get(r.Context(), name)
	httpx.JSON(w, http.StatusOK, updated)
}

func (s *Server) syncTools(w http.ResponseWriter, r *http.Request) {
	if err := s.Registry.Sync(r.Context()); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	recs, _ := s.Registry.List(r.Context())
	httpx.JSON(w, http.StatusOK, recs)
}

func (s *Server) listToolGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.Registry.Groups(r.Context())
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, groups)
}

// ---------- policy ----------

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.Policy.Rules(r.Context())
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, rules)
}

func validRule(r policy.Rule) error {
	switch r.Kind {
	case policy.KindProject, policy.KindRepository, policy.KindBranch:
	default:
		return errBadRequest("kind 는 project, repository, branch 중 하나여야 합니다")
	}
	if r.Effect != policy.EffectAllow && r.Effect != policy.EffectDeny {
		return errBadRequest("effect 는 allow 또는 deny 여야 합니다")
	}
	if strings.TrimSpace(r.Pattern) == "" {
		return errBadRequest("pattern 이 필요합니다")
	}
	switch strings.ToUpper(r.RiskCap) {
	case "", "READ", "WRITE", "EXECUTE", "ADMIN":
	default:
		return errBadRequest("riskCap 값이 올바르지 않습니다")
	}
	return nil
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var rule policy.Rule
	if err := httpx.Decode(r, &rule); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	rule.RiskCap = strings.ToUpper(rule.RiskCap)
	if err := validRule(rule); err != nil {
		writeErr(w, err)
		return
	}
	id, err := s.Policy.Create(r.Context(), rule)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	rule.ID = id
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatAdmin, Action: "policy.create",
		KeycloakUsername: identityOf(r).User.Username, Success: true,
		Detail: map[string]any{"kind": rule.Kind, "pattern": rule.Pattern, "effect": rule.Effect},
	})
	httpx.JSON(w, http.StatusCreated, rule)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "ID 형식이 올바르지 않습니다")
		return
	}
	var rule policy.Rule
	if err := httpx.Decode(r, &rule); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	rule.ID = id
	rule.RiskCap = strings.ToUpper(rule.RiskCap)
	if err := validRule(rule); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.Policy.Update(r.Context(), rule); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, rule)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "ID 형식이 올바르지 않습니다")
		return
	}
	if err := s.Policy.Delete(r.Context(), id); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// evaluatePolicy lets an administrator dry-run the ACL against a resource.
func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Project    string `json:"project"`
		Repository string `json:"repository"`
		Branch     string `json:"branch"`
		Username   string `json:"username"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	verdict, err := s.Policy.Evaluate(r.Context(), body.Project, body.Repository, body.Branch)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{"policy": verdict}
	if body.Username != "" && body.Project != "" {
		if body.Repository != "" {
			if dec, err := s.Resolver.Repository(r.Context(), body.Username, body.Project, body.Repository); err == nil {
				out["permission"] = dec
			} else {
				out["permissionError"] = err.Error()
			}
		} else if dec, err := s.Resolver.Project(r.Context(), body.Username, body.Project); err == nil {
			out["permission"] = dec
		} else {
			out["permissionError"] = err.Error()
		}
	}
	httpx.JSON(w, http.StatusOK, out)
}

// ---------- approvals ----------

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	list, err := s.Approvals.List(r.Context(), r.URL.Query().Get("status"), "", queryInt(r, "limit", 100))
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, list)
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "ID 형식이 올바르지 않습니다")
		return
	}
	var body struct {
		Approve bool   `json:"approve"`
		Note    string `json:"note"`
	}
	_ = httpx.Decode(r, &body)
	out, err := s.Approvals.Decide(ctx, reqID, body.Approve, identityOf(r).User.Username, body.Note)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatApproval, Action: "approval.decide",
		KeycloakUsername: identityOf(r).User.Username, ToolName: out.ToolName,
		ApprovalID: &reqID, Success: true,
		Detail: map[string]any{"approve": body.Approve, "requester": out.Username},
	})
	httpx.JSON(w, http.StatusOK, out)
}

// ---------- keys ----------

func (s *Server) listAllKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Keys.List(r.Context(), int64(queryInt(r, "userId", 0)))
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, keys)
}

func (s *Server) revokeAnyKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "ID 형식이 올바르지 않습니다")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = httpx.Decode(r, &body)
	if body.Reason == "" {
		body.Reason = "관리자 폐기"
	}
	if err := s.Keys.Revoke(r.Context(), id, body.Reason); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatKey, Action: "key.revoke.admin",
		KeycloakUsername: identityOf(r).User.Username, Success: true,
		Detail: map[string]any{"keyId": id, "reason": body.Reason},
	})
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) rotateAnyKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "ID 형식이 올바르지 않습니다")
		return
	}
	issued, err := s.Keys.Rotate(r.Context(), id)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, issued)
}

func (s *Server) saveKeyRole(w http.ResponseWriter, r *http.Request) {
	var role apikey.Role
	if err := httpx.Decode(r, &role); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	role.Name = chi.URLParam(r, "name")
	if err := s.Keys.SaveRole(r.Context(), role); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatAdmin, Action: "key_role.save",
		KeycloakUsername: identityOf(r).User.Username, Success: true,
		Detail: map[string]any{"role": role.Name, "scopes": role.Scopes},
	})
	out, err := s.Keys.Role(r.Context(), role.Name)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (s *Server) deleteKeyRole(w http.ResponseWriter, r *http.Request) {
	if err := s.Keys.DeleteRole(r.Context(), chi.URLParam(r, "name")); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- audit & sessions ----------

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := audit.Query{
		Category: r.URL.Query().Get("category"),
		Username: r.URL.Query().Get("username"),
		Tool:     r.URL.Query().Get("tool"),
		Project:  r.URL.Query().Get("project"),
		Success:  queryBoolPtr(r, "success"),
		Limit:    queryInt(r, "limit", 100),
		Offset:   queryInt(r, "offset", 0),
	}
	if since := strings.TrimSpace(r.URL.Query().Get("since")); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			q.Since = &t
		}
	}
	entries, total, err := s.Audit.List(r.Context(), q)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"values": entries, "total": total})
}

func (s *Server) purgeAudit(w http.ResponseWriter, r *http.Request) {
	sec, _ := s.Store.Security(r.Context())
	if err := s.Audit.Purge(r.Context(), sec.AuditRetainDays); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "retainDays": sec.AuditRetainDays})
}

func (s *Server) listMCPSessions(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Pool.Query(r.Context(), `
		SELECT id, username, client_name, auth_mode, COALESCE(ip,''),
		       created_at, last_seen_at, closed_at
		FROM mcp_sessions ORDER BY last_seen_at DESC LIMIT $1`, queryInt(r, "limit", 100))
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var username, client, mode, ip string
		var created, lastSeen time.Time
		var closed *time.Time
		if err := rows.Scan(&id, &username, &client, &mode, &ip, &created, &lastSeen, &closed); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "username": username, "client": client, "authMode": mode,
			"ip": ip, "createdAt": created, "lastSeenAt": lastSeen, "closedAt": closed,
		})
	}
	httpx.JSON(w, http.StatusOK, out)
}

var _ = identity.ErrUnmapped
