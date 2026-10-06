package api

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/hkjang/bbmcp/internal/httpx"
	"github.com/hkjang/bbmcp/internal/settings"
)

// Keycloak compares redirect URIs against the client's Valid redirect URIs
// and, on a mismatch, shows the person signing in a page that only says
// "Invalid parameter: redirect_uri". Nothing on that page tells them, or the
// operator, which address to register. So bbmcp asks Keycloak first, with the
// same authorization request a browser would make, and turns a refusal into a
// message that names the value to add.

// redirectCheck is Keycloak's answer for one client and redirect URI.
type redirectCheck struct {
	URI      string `json:"uri"`
	Accepted bool   `json:"accepted"`
	// Detail is Keycloak's own message when it refused.
	Detail string `json:"detail,omitempty"`
	// Register is what to add to Valid redirect URIs when it refused.
	Register string `json:"register,omitempty"`
	// SendsIssuer reports that Keycloak put iss on the redirect.
	SendsIssuer bool `json:"sendsIssuer,omitempty"`
	// Error is set when Keycloak could not be asked; the answer is unknown.
	Error string `json:"error,omitempty"`
}

// probeChallenge is the RFC 7636 example S256 challenge. The probe never
// exchanges a code, but a client that requires PKCE would otherwise answer
// with an error redirect that reads like a refusal.
const probeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

var keycloakInstruction = regexp.MustCompile(`(?s)<p[^>]*class="instruction"[^>]*>\s*(.*?)\s*</p>`)

// checkRedirect asks Keycloak whether it would send a browser back to
// redirectURI for clientID.
//
// prompt=none makes Keycloak answer at once: it validates the client and the
// redirect URI, and then, finding no session, redirects with login_required
// instead of showing a login page. A redirect to the URI means it is
// registered; an error page means it is not.
func checkRedirect(ctx context.Context, kc settings.Keycloak, authEndpoint, clientID, redirectURI string) redirectCheck {
	out := redirectCheck{URI: redirectURI}
	if authEndpoint == "" {
		out.Error = "Keycloak 메타데이터에 authorization_endpoint 가 없습니다"
		return out
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("prompt", "none")
	q.Set("state", "bbmcp-redirect-check")
	q.Set("code_challenge", probeChallenge)
	q.Set("code_challenge_method", "S256")
	target := authEndpoint
	if strings.Contains(target, "?") {
		target += "&" + q.Encode()
	} else {
		target += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	client := keycloakHTTPClient(kc)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		out.Error = "Keycloak 에 확인할 수 없습니다: " + err.Error()
		return out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		location := resp.Header.Get("Location")
		if !strings.HasPrefix(location, redirectURI) {
			out.Error = "Keycloak 이 예상하지 못한 곳으로 보냈습니다: " + location
			return out
		}
		out.Accepted = true
		if u, err := url.Parse(location); err == nil && u.Query().Get("iss") != "" {
			out.SendsIssuer = true
		}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		out.Detail = keycloakMessage(body)
		if out.Detail == "" {
			out.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		out.Register = registrationFor(redirectURI)
	default:
		out.Error = fmt.Sprintf("Keycloak 응답 %d", resp.StatusCode)
	}
	return out
}

// keycloakMessage pulls the visible message out of Keycloak's error page.
func keycloakMessage(page []byte) string {
	m := keycloakInstruction.FindSubmatch(page)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

// registrationFor is the Valid redirect URIs entry that admits uri.
//
// A loopback callback carries a port the client picks at random, so the entry
// has to be the wildcard for that host; anything else is registered as is.
func registrationFor(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || !httpx.IsLoopbackHost(u.Host) {
		return uri
	}
	return "http://" + hostOnly(u) + ":*"
}

func hostOnly(u *url.URL) string {
	if strings.Contains(u.Hostname(), ":") {
		return "[" + u.Hostname() + "]"
	}
	return u.Hostname()
}

// checkRegistrationRedirects runs checkRedirect over a registration request.
//
// It returns the URIs Keycloak accepts and, when it refuses every one of them,
// a message for the person connecting. A URI that could not be checked is
// kept: the check advises, and an unreachable probe must not block a sign-in
// that would work.
func checkRegistrationRedirects(ctx context.Context, kc settings.Keycloak, authEndpoint, clientID string, uris []string) (kept []string, refused []redirectCheck, refusal string) {
	kept = make([]string, 0, len(uris))
	for _, uri := range uris {
		check := checkRedirect(ctx, kc, authEndpoint, clientID, uri)
		if check.Accepted || check.Error != "" {
			kept = append(kept, uri)
			continue
		}
		refused = append(refused, check)
	}
	if len(kept) == 0 && len(refused) > 0 {
		first := refused[0]
		refusal = fmt.Sprintf("Keycloak 클라이언트 %s 가 리다이렉트 URI %s 를 허용하지 않습니다 (Keycloak: %s). "+
			"관리자가 Keycloak 의 %s 클라이언트 Valid redirect URIs 에 %s 를 추가해야 합니다.",
			clientID, first.URI, first.Detail, clientID, first.Register)
	}
	return kept, refused, refusal
}
