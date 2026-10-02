package api

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/hkjang/bbmcp/internal/auth"
	"github.com/hkjang/bbmcp/internal/httpx"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "요청 형식이 올바르지 않습니다")
		return
	}
	sec, _ := s.Store.Security(r.Context())
	ip := httpx.ClientIP(r, sec.TrustProxyHeaders)
	if !s.limiter.Allow("login:"+ip, 20, 10) {
		httpx.FailCode(w, http.StatusTooManyRequests, "RATE_LIMITED", "로그인 시도가 너무 많습니다")
		return
	}

	token, ttl, id, err := s.Auth.LoginLocal(r.Context(),
		strings.TrimSpace(body.Username), body.Password, ip, r.Header.Get("User-Agent"))
	if err != nil {
		httpx.FailCode(w, http.StatusUnauthorized, "BAD_CREDENTIALS", err.Error())
		return
	}
	auth.SetCookie(w, r, token, ttl)
	httpx.JSON(w, http.StatusOK, id)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookie); err == nil && c.Value != "" {
		_ = s.Sessions.Revoke(r.Context(), c.Value)
	}
	auth.ClearCookie(w, r)

	ctx := r.Context()
	kc, _ := s.Store.Keycloak(ctx)
	logout := ""
	if kc.Enabled && kc.Issuer != "" {
		params := url.Values{}
		params.Set("client_id", kc.ClientID)
		// post_logout_redirect_uri must be registered in Keycloak. Sending one
		// that is not registered makes Keycloak refuse the whole logout with
		// "Invalid parameter", so it is only sent when the operator configured
		// it deliberately — and they are told to register it.
		if target := httpx.NormalizeRedirectURI(kc.PostLogoutURL); target != "" {
			params.Set("post_logout_redirect_uri", target)
		}
		logout = strings.TrimRight(kc.Issuer, "/") +
			"/protocol/openid-connect/logout?" + params.Encode()
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "ssoLogoutUrl": logout})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	id, err := s.Auth.Resolve(r.Context(), r)
	if err != nil {
		httpx.FailCode(w, http.StatusUnauthorized, "UNAUTHENTICATED", "로그인이 필요합니다")
		return
	}
	httpx.JSON(w, http.StatusOK, s.decorate(r, id))
}

// CallbackPath is the OIDC redirect path this gateway listens on.
const CallbackPath = "/auth/oidc/callback"

// redirectURI is the callback bbmcp sends to Keycloak.
//
// Keycloak matches it as a string against its registered list, so the value is
// normalised and the operator is shown the exact same string to register. An
// explicit setting wins, because a reverse proxy can make the derived origin
// differ from the public one.
func (s *Server) redirectURI(r *http.Request, configured string) string {
	if normalized := httpx.NormalizeRedirectURI(configured); normalized != "" {
		return normalized
	}
	return s.baseURL(r) + CallbackPath
}

// oidcStart begins an authorization code flow. With silent=1 the request adds
// prompt=none so Keycloak answers immediately from an existing SSO session,
// which is what the hidden iframe on the login screen uses.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.Auth.OIDC.Enabled(ctx) {
		http.Error(w, "Keycloak SSO가 설정되지 않았습니다", http.StatusPreconditionFailed)
		return
	}
	kc, _, err := s.Auth.OIDC.Config(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	silent := r.URL.Query().Get("silent") == "1"
	redirect := s.redirectURI(r, kc.RedirectURL)

	st, err := auth.NewState(silent, safeReturn(r.URL.Query().Get("returnTo")), redirect)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sealed, err := s.Auth.SealState(st)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: auth.StateCookie, Value: sealed, Path: "/", HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})

	cfg, _, err := s.Auth.OIDC.OAuth2Config(ctx, redirect)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", st.Nonce),
		oauth2.S256ChallengeOption(st.Verifier),
	}
	if silent {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "none"))
		if kc.SilentSSOMaxAge > 0 {
			opts = append(opts, oauth2.SetAuthURLParam("max_age", itoa(kc.SilentSSOMaxAge)))
		}
	}
	httpx.NoCache(w)
	http.Redirect(w, r, cfg.AuthCodeURL(st.State, opts...), http.StatusFound)
}

// oidcCallback completes the flow. A silent flow answers through postMessage
// in the iframe; an interactive flow redirects back into the application.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookie, err := r.Cookie(auth.StateCookie)
	if err != nil || cookie.Value == "" {
		s.oidcFailure(w, r, false, "로그인 상태를 확인할 수 없습니다. 다시 시도하십시오.")
		return
	}
	st, err := s.Auth.OpenState(cookie.Value)
	http.SetCookie(w, &http.Cookie{Name: auth.StateCookie, Value: "", Path: "/", MaxAge: -1})
	if err != nil {
		s.oidcFailure(w, r, false, err.Error())
		return
	}

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		// login_required / interaction_required are the normal "no SSO session"
		// answers to prompt=none and must not surface as an error to the user.
		s.oidcFailure(w, r, st.Silent, e+": "+q.Get("error_description"))
		return
	}
	if q.Get("state") != st.State {
		s.oidcFailure(w, r, st.Silent, "state 불일치")
		return
	}
	code := q.Get("code")
	if code == "" {
		s.oidcFailure(w, r, st.Silent, "인가 코드가 없습니다")
		return
	}

	claims, _, err := s.Auth.OIDC.Exchange(ctx, st.Redirect, code, st.Verifier, st.Nonce)
	if err != nil {
		s.oidcFailure(w, r, st.Silent, err.Error())
		return
	}
	sec, _ := s.Store.Security(ctx)
	token, ttl, _, err := s.Auth.CompleteOIDC(ctx, claims,
		httpx.ClientIP(r, sec.TrustProxyHeaders), r.Header.Get("User-Agent"))
	if err != nil {
		s.oidcFailure(w, r, st.Silent, err.Error())
		return
	}
	auth.SetCookie(w, r, token, ttl)

	if st.Silent {
		s.renderBridge(w, map[string]any{"type": "bbmcp-sso", "ok": true})
		return
	}
	target := st.ReturnTo
	if target == "" {
		target = "/"
	}
	httpx.NoCache(w)
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) oidcFailure(w http.ResponseWriter, r *http.Request, silent bool, reason string) {
	if silent {
		s.renderBridge(w, map[string]any{"type": "bbmcp-sso", "ok": false, "reason": reason})
		return
	}
	httpx.NoCache(w)
	http.Redirect(w, r, "/login?sso_error="+url.QueryEscape(reason), http.StatusFound)
}

// oidcSilentFrame is the iframe document that kicks off a prompt=none attempt.
func (s *Server) oidcSilentFrame(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.Auth.OIDC.Enabled(ctx) {
		s.renderBridge(w, map[string]any{"type": "bbmcp-sso", "ok": false, "reason": "sso_disabled"})
		return
	}
	httpx.NoCache(w)
	http.Redirect(w, r, "/auth/oidc/start?silent=1", http.StatusFound)
}

var bridgeTmpl = template.Must(template.New("bridge").Parse(`<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8"><title>SSO</title></head>
<body><script>
(function () {
  var payload = {{.}};
  try { if (window.parent && window.parent !== window) { window.parent.postMessage(payload, window.location.origin); } } catch (e) {}
  try { if (window.opener) { window.opener.postMessage(payload, window.location.origin); window.close(); } } catch (e) {}
})();
</script><noscript>SSO 처리 완료</noscript></body></html>`))

// renderBridge posts the silent SSO outcome to the parent window.
func (s *Server) renderBridge(w http.ResponseWriter, payload map[string]any) {
	httpx.NoCache(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = bridgeTmpl.Execute(w, payload)
}

func safeReturn(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	return raw
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
