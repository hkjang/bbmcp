package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hkjang/bbmcp/internal/apikey"
	"github.com/hkjang/bbmcp/internal/approval"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/auth"
	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/httpx"
	"github.com/hkjang/bbmcp/internal/tools"
	"github.com/hkjang/bbmcp/internal/version"
)

// Prefs are the per-user preferences of the personal pages.
type Prefs struct {
	PreferUserPAT bool    `json:"preferUserPat"`
	Theme         string  `json:"theme"`
	FontScale     float64 `json:"fontScale"`
	Locale        string  `json:"locale"`
}

func defaultPrefs() Prefs {
	return Prefs{Theme: "system", FontScale: 1.0, Locale: "ko"}
}

func (s *Server) prefs(ctx context.Context, userID int64) Prefs {
	p := defaultPrefs()
	_ = s.Pool.QueryRow(ctx,
		`SELECT prefer_user_pat, theme, font_scale, locale FROM user_prefs WHERE user_id=$1`,
		userID).Scan(&p.PreferUserPAT, &p.Theme, &p.FontScale, &p.Locale)
	return p
}

func (s *Server) preferUserPAT(ctx context.Context, userID int64) bool {
	if userID == 0 {
		return false
	}
	return s.prefs(ctx, userID).PreferUserPAT
}

// decorate builds the payload the SPA uses to render a signed-in user.
func (s *Server) decorate(r *http.Request, id *auth.Identity) map[string]any {
	ctx := r.Context()
	ui, _ := s.Store.UI(ctx)
	bb, _ := s.Store.Bitbucket(ctx)
	return map[string]any{
		"user":             id.User,
		"bitbucket":        id.Mapping,
		"scopes":           id.Scopes,
		"authMode":         id.AuthMode,
		"isServiceAdmin":   id.User.IsServiceAdmin,
		"prefs":            s.prefs(ctx, id.User.ID),
		"ui":               ui,
		"version":          version.Current(),
		"allowUserPatMode": bb.AllowUserPATMode,
		"defaultAuthMode":  bb.DefaultAuthMode,
	}
}

// mountPersonal registers the self-service routes available to every user.
func (s *Server) mountPersonal(r chi.Router) {
	r.Route("/me", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			httpx.JSON(w, http.StatusOK, s.decorate(r, identityOf(r)))
		})

		r.Put("/prefs", s.savePrefs)
		r.Post("/password", s.changePassword)

		r.Get("/keys", s.myKeys)
		r.Post("/keys", s.createMyKey)
		r.Post("/keys/{id}/rotate", s.rotateMyKey)
		r.Patch("/keys/{id}", s.patchMyKey)
		r.Delete("/keys/{id}", s.revokeMyKey)
		r.Get("/key-roles", s.keyRoles)
		r.Get("/key-scopes", func(w http.ResponseWriter, r *http.Request) {
			httpx.JSON(w, http.StatusOK, apikey.AllScopes())
		})

		r.Get("/bitbucket-pat", s.myPAT)
		r.Put("/bitbucket-pat", s.saveMyPAT)
		r.Delete("/bitbucket-pat", s.deleteMyPAT)
		r.Post("/bitbucket-pat/verify", s.verifyMyPAT)

		r.Get("/approvals", s.myApprovals)
		r.Post("/approvals/{id}/decide", s.decideMyApproval)

		r.Get("/audit", s.myAudit)
		r.Get("/tools", s.myTools)
		r.Get("/permissions", s.myPermissions)
	})
}

func (s *Server) savePrefs(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body Prefs
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	if body.FontScale < 0.8 || body.FontScale > 1.6 {
		body.FontScale = 1.0
	}
	if body.Theme == "" {
		body.Theme = "system"
	}
	if body.Locale == "" {
		body.Locale = "ko"
	}
	if _, err := s.Pool.Exec(r.Context(), `
		INSERT INTO user_prefs(user_id, prefer_user_pat, theme, font_scale, locale, updated_at)
		VALUES ($1,$2,$3,$4,$5,NOW())
		ON CONFLICT (user_id) DO UPDATE
		   SET prefer_user_pat=EXCLUDED.prefer_user_pat, theme=EXCLUDED.theme,
		       font_scale=EXCLUDED.font_scale, locale=EXCLUDED.locale, updated_at=NOW()`,
		id.User.ID, body.PreferUserPAT, body.Theme, body.FontScale, body.Locale); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, body)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Current string `json:"currentPassword"`
		New     string `json:"newPassword"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	if len(body.New) < 10 {
		httpx.Fail(w, http.StatusBadRequest, "새 비밀번호는 10자 이상이어야 합니다")
		return
	}
	if !id.User.HasPassword {
		httpx.Fail(w, http.StatusBadRequest, "SSO 전용 계정은 비밀번호를 사용하지 않습니다")
		return
	}
	if _, _, _, err := s.Auth.LoginLocal(r.Context(), id.User.Username, body.Current, "", ""); err != nil {
		httpx.Fail(w, http.StatusForbidden, "현재 비밀번호가 올바르지 않습니다")
		return
	}
	if err := s.Users.SetPassword(r.Context(), id.User.ID, body.New); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatAuth, Action: "password.change",
		KeycloakUsername: id.User.Username, Success: true,
	})
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) myKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Keys.List(r.Context(), identityOf(r).User.ID)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, keys)
}

func (s *Server) createMyKey(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	pol, _ := s.Store.KeyPolicy(r.Context())
	if !pol.AllowSelfCreate && !id.User.IsServiceAdmin {
		httpx.Fail(w, http.StatusForbidden, "관리자 정책으로 개인 키 발급이 제한되어 있습니다")
		return
	}
	var body struct {
		Name    string   `json:"name"`
		Role    string   `json:"role"`
		Scopes  []string `json:"scopes"`
		TTLDays int      `json:"ttlDays"`
	}
	if err := httpx.Decode(r, &body); err != nil || strings.TrimSpace(body.Name) == "" {
		httpx.Fail(w, http.StatusBadRequest, "키 이름이 필요합니다")
		return
	}
	issued, err := s.Keys.Create(r.Context(), id.User.ID, body.Name, body.Role, body.Scopes, body.TTLDays)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatKey, Action: "key.create", KeycloakUsername: id.User.Username,
		Success: true, Detail: map[string]any{"keyId": issued.Key.ID, "role": issued.Key.Role},
	})
	httpx.JSON(w, http.StatusCreated, issued)
}

// ownedKey loads a key and verifies the caller owns it (or is an admin).
func (s *Server) ownedKey(r *http.Request) (*apikey.Key, error) {
	id := identityOf(r)
	keyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return nil, errBadRequest("키 ID 형식이 올바르지 않습니다")
	}
	key, err := s.Keys.ByID(r.Context(), keyID)
	if err != nil {
		return nil, errBadRequest("키를 찾을 수 없습니다")
	}
	if key.UserID != id.User.ID && !id.User.IsServiceAdmin {
		return nil, errForbidden("다른 사용자의 키입니다")
	}
	return key, nil
}

func (s *Server) rotateMyKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.ownedKey(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	issued, err := s.Keys.Rotate(r.Context(), key.ID)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatKey, Action: "key.rotate",
		KeycloakUsername: identityOf(r).User.Username, Success: true,
		Detail: map[string]any{"from": key.ID, "to": issued.Key.ID},
	})
	httpx.JSON(w, http.StatusOK, issued)
}

func (s *Server) patchMyKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.ownedKey(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Role   string   `json:"role"`
		Scopes []string `json:"scopes"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	role := body.Role
	if role == "" {
		role = key.Role
	}
	if err := s.Keys.UpdateScopes(r.Context(), key.ID, role, body.Scopes); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, _ := s.Keys.ByID(r.Context(), key.ID)
	httpx.JSON(w, http.StatusOK, updated)
}

func (s *Server) revokeMyKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.ownedKey(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.Keys.Revoke(r.Context(), key.ID, "사용자 폐기"); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Audit.Write(r.Context(), audit.Entry{
		Category: audit.CatKey, Action: "key.revoke",
		KeycloakUsername: identityOf(r).User.Username, Success: true,
		Detail: map[string]any{"keyId": key.ID},
	})
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) keyRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.Keys.Roles(r.Context())
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, roles)
}

func (s *Server) myPAT(w http.ResponseWriter, r *http.Request) {
	info, err := s.Provider.UserPATInfo(r.Context(), identityOf(r).User.ID)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, info)
}

func (s *Server) saveMyPAT(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityOf(r)
	bb, _ := s.Store.Bitbucket(ctx)
	if !bb.AllowUserPATMode {
		httpx.Fail(w, http.StatusForbidden, "관리자가 사용자 PAT 모드를 허용하지 않았습니다")
		return
	}
	var body struct {
		BitbucketUser string `json:"bitbucketUser"`
		Token         string `json:"token"`
	}
	if err := httpx.Decode(r, &body); err != nil || strings.TrimSpace(body.Token) == "" {
		httpx.Fail(w, http.StatusBadRequest, "토큰이 필요합니다")
		return
	}
	bbUser := strings.TrimSpace(body.BitbucketUser)
	if bbUser == "" && id.Mapping != nil {
		bbUser = id.Mapping.BitbucketUsername
	}
	if bbUser == "" {
		httpx.Fail(w, http.StatusBadRequest, "Bitbucket 사용자명을 확인할 수 없습니다")
		return
	}
	if err := s.Provider.SaveUserPAT(ctx, id.User.ID, bbUser, strings.TrimSpace(body.Token)); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatKey, Action: "user_pat.save",
		KeycloakUsername: id.User.Username, BitbucketUsername: bbUser, Success: true,
	})
	info, _ := s.Provider.UserPATInfo(ctx, id.User.ID)
	httpx.JSON(w, http.StatusOK, info)
}

func (s *Server) deleteMyPAT(w http.ResponseWriter, r *http.Request) {
	if err := s.Provider.DeleteUserPAT(r.Context(), identityOf(r).User.ID); err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) verifyMyPAT(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityOf(r)
	cred, err := s.Provider.UserCredential(ctx, id.User.ID)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	adapter, _, err := s.Provider.Adapter(ctx)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := adapter.Ping(ctx, cred); err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	user, err := adapter.FindUserByUsername(ctx, cred, cred.Username)
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = s.Provider.MarkUserPATVerified(ctx, id.User.ID)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "user": user})
}

func (s *Server) myApprovals(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	list, err := s.Approvals.List(r.Context(), r.URL.Query().Get("status"), id.KeycloakSub, 100)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, list)
}

// decideMyApproval lets a requester confirm their own WRITE-risk action.
// EXECUTE-risk actions always need a separate administrator decision.
func (s *Server) decideMyApproval(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityOf(r)
	reqID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 ID 형식이 올바르지 않습니다")
		return
	}
	var body struct {
		Approve bool   `json:"approve"`
		Note    string `json:"note"`
	}
	_ = httpx.Decode(r, &body)

	req, err := s.Approvals.ByID(ctx, reqID)
	if err != nil {
		httpx.Fail(w, http.StatusNotFound, err.Error())
		return
	}
	if req.KeycloakSub != id.KeycloakSub {
		httpx.Fail(w, http.StatusForbidden, "본인의 승인 요청이 아닙니다")
		return
	}
	_, rec, err := s.Registry.Get(ctx, req.ToolName)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Approve && rec.Risk != tools.RiskWrite && !id.User.IsServiceAdmin {
		httpx.FailCode(w, http.StatusForbidden, "STRONG_APPROVAL_REQUIRED",
			"실행 등급 작업은 서비스 관리자의 승인이 필요합니다")
		return
	}
	out, err := s.Approvals.Decide(ctx, reqID, body.Approve, id.User.Username, body.Note)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatApproval, Action: "approval.decide",
		KeycloakUsername: id.User.Username, ToolName: req.ToolName,
		ApprovalID: &reqID, Success: true,
		Detail: map[string]any{"approve": body.Approve, "self": true},
	})
	httpx.JSON(w, http.StatusOK, out)
}

func (s *Server) myAudit(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	entries, total, err := s.Audit.List(r.Context(), audit.Query{
		Username: id.User.Username,
		Limit:    queryInt(r, "limit", 50),
		Offset:   queryInt(r, "offset", 0),
	})
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"values": entries, "total": total})
}

func (s *Server) myTools(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	sec, _ := s.Store.Security(r.Context())
	p := id.Principal("web", httpx.ClientIP(r, sec.TrustProxyHeaders),
		s.preferUserPAT(r.Context(), id.User.ID))
	recs, err := s.Executor.Available(r.Context(), p)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, recs)
}

func (s *Server) myPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityOf(r)
	if id.Mapping == nil {
		httpx.FailCode(w, http.StatusConflict, "IDENTITY_UNMAPPED",
			"Bitbucket 사용자 매핑이 없습니다")
		return
	}
	project := strings.TrimSpace(r.URL.Query().Get("project"))
	repo := strings.TrimSpace(r.URL.Query().Get("repository"))
	if project == "" {
		httpx.Fail(w, http.StatusBadRequest, "project 파라미터가 필요합니다")
		return
	}
	out := map[string]any{"username": id.Mapping.BitbucketUsername}
	dec, err := s.Resolver.Project(ctx, id.Mapping.BitbucketUsername, project)
	if err != nil {
		httpx.Fail(w, http.StatusBadGateway, err.Error())
		return
	}
	out["project"] = dec
	if repo != "" {
		repoDec, err := s.Resolver.Repository(ctx, id.Mapping.BitbucketUsername, project, repo)
		if err != nil {
			httpx.Fail(w, http.StatusBadGateway, err.Error())
			return
		}
		out["repository"] = repoDec
	}
	if v, err := s.Policy.Evaluate(ctx, project, repo, ""); err == nil {
		out["policy"] = v
	}
	httpx.JSON(w, http.StatusOK, out)
}

// aiChat relays a streaming AI completion as server-sent events.
func (s *Server) aiChat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityOf(r)
	if !apikey.HasScope(id.Scopes, apikey.ScopeAIInvoke) {
		httpx.FailCode(w, http.StatusForbidden, "SCOPE_DENIED", "ai:invoke 스코프가 필요합니다")
		return
	}
	var body aiRequest
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		httpx.Fail(w, http.StatusInternalServerError, "스트리밍을 지원하지 않습니다")
		return
	}
	httpx.NoCache(w)
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(event string, payload any) {
		writeSSE(w, event, payload)
		flusher.Flush()
	}
	err := s.AI.Stream(ctx, body.toProxyRequest(), func(e aiEvent) error {
		send("message", e)
		return nil
	})
	if err != nil {
		send("message", aiEvent{Type: "error", Error: err.Error()})
	}
	send("message", aiEvent{Type: "end"})
	s.Audit.Write(ctx, audit.Entry{
		Category: audit.CatAI, Action: "ai.chat", KeycloakUsername: id.User.Username,
		Success: err == nil, Message: errString(err),
	})
}

func (s *Server) aiModels(w http.ResponseWriter, r *http.Request) {
	cfg, _, err := s.AI.Config(r.Context())
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"enabled":       cfg.Enabled,
		"provider":      cfg.Provider,
		"model":         cfg.Model,
		"maxTokens":     cfg.MaxTokens,
		"contextLimit":  cfg.ContextLimit,
		"streaming":     cfg.Streaming,
		"maxTokenLimit": maxTokenCeiling(),
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var _ = bitbucket.ErrNoUserPAT
var _ = approval.StatusPending
