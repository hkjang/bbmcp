package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	// ClientMissing reports that Keycloak has no client with this ID at all.
	ClientMissing bool `json:"clientMissing,omitempty"`
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
	answer, err := askAuthorize(ctx, kc, authEndpoint, clientID, redirectURI)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	switch {
	case answer.status >= 300 && answer.status < 400:
		if !strings.HasPrefix(answer.location, redirectURI) {
			out.Error = "Keycloak 이 예상하지 못한 곳으로 보냈습니다: " + answer.location
			return out
		}
		out.Accepted = true
		if u, err := url.Parse(answer.location); err == nil && u.Query().Get("iss") != "" {
			out.SendsIssuer = true
		}
	case answer.status >= 400 && answer.status < 500:
		out.Detail = answer.detail
		if out.Detail == "" {
			out.Detail = fmt.Sprintf("HTTP %d", answer.status)
		}
		// Keycloak words "Client not found." in the realm's language, so the
		// same request with a client that cannot exist tells the two refusals
		// apart instead of the text.
		if unknown, err := askAuthorize(ctx, kc, authEndpoint, "bbmcp-probe-"+randomHex(8), redirectURI); err == nil &&
			unknown.status == answer.status && unknown.detail == answer.detail {
			out.ClientMissing = true
		} else {
			out.Register = registrationFor(redirectURI)
		}
	default:
		out.Error = fmt.Sprintf("Keycloak 응답 %d", answer.status)
	}
	return out
}

// authorizeAnswer is Keycloak's reply to one prompt=none authorization request.
type authorizeAnswer struct {
	status   int
	location string
	detail   string
}

func askAuthorize(ctx context.Context, kc settings.Keycloak, authEndpoint, clientID, redirectURI string) (authorizeAnswer, error) {
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
		return authorizeAnswer{}, err
	}
	client := keycloakHTTPClient(kc)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return authorizeAnswer{}, fmt.Errorf("Keycloak 에 확인할 수 없습니다: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return authorizeAnswer{status: resp.StatusCode, location: resp.Header.Get("Location"), detail: keycloakMessage(body)}, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// wildcardBypassTargets are redirect URIs that a host-level loopback wildcard
// such as http://127.0.0.1:* admits on a Keycloak that matches wildcards as a
// string prefix: the browser reads "127.0.0.1:" as user info and goes to the
// host after "@". The .invalid domain never resolves.
var wildcardBypassTargets = []string{
	"http://127.0.0.1:@bbmcp-check.invalid/callback",
	"http://localhost:@bbmcp-check.invalid/callback",
}

// checkWildcardBypass returns the bypass targets Keycloak would send a
// sign-in result to for clientID. Any entry means an attacker can make the
// login of a person who follows their link end at the attacker's server.
func checkWildcardBypass(ctx context.Context, kc settings.Keycloak, authEndpoint, clientID string) []string {
	open := []string{}
	for _, target := range wildcardBypassTargets {
		if c := checkRedirect(ctx, kc, authEndpoint, clientID, target); c.Accepted {
			open = append(open, target)
		}
	}
	return open
}

// keycloakMessage pulls the visible message out of Keycloak's error page.
func keycloakMessage(page []byte) string {
	m := keycloakInstruction.FindSubmatch(page)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

// registrationFor is the Valid redirect URIs entry to suggest for uri, or ""
// when nothing should be suggested.
//
// A loopback callback carries a port the client picks at random. Keycloak
// lets a registered loopback URI without a port match any port (Keycloak 10
// only for localhost), so the entry is the URI without its port. It is not a
// host-level wildcard such as http://localhost:*, which a Keycloak that
// compares wildcards as a string prefix (Keycloak 10) also matches for
// http://localhost:@attacker.example/. Any other address is not suggested: an
// anonymous caller chooses it, and an operator copying it into Keycloak would
// send sign-in codes there.
func registrationFor(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || !httpx.IsLoopbackHost(u.Host) || u.User != nil {
		return ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return "http://" + hostOnly(u) + path
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
		refusal = refusalMessage(clientID, refused[0])
	}
	return kept, refused, refusal
}

// refusalMessage explains a refused redirect to the person connecting.
func refusalMessage(clientID string, c redirectCheck) string {
	switch {
	case c.ClientMissing:
		return fmt.Sprintf("Keycloak 에 MCP 클라이언트 %s 가 없습니다 (Keycloak: %s). "+
			"관리자가 Keycloak 에 이 Client ID 로 공개 클라이언트를 만들어야 합니다.", clientID, c.Detail)
	case c.Register != "":
		msg := fmt.Sprintf("Keycloak 클라이언트 %s 가 리다이렉트 URI %s 를 허용하지 않습니다 (Keycloak: %s). "+
			"관리자가 Keycloak 의 %s 클라이언트 Valid redirect URIs 에 %s 를 포트 없이 추가해야 합니다.",
			clientID, clip(c.URI, 300), c.Detail, clientID, c.Register)
		if !strings.Contains(c.Register, "localhost") {
			msg += " 이미 등록했는데도 거부되면, Keycloak 10 처럼 IP 주소(127.0.0.1)의 포트를 무시하지 않는 버전입니다. " +
				"클라이언트가 localhost 로 콜백을 받게 하거나 고정 포트를 쓰게 하고 그 주소를 정확히 등록하십시오."
		}
		return msg
	default:
		return fmt.Sprintf("Keycloak 클라이언트 %s 가 리다이렉트 URI %s 를 허용하지 않습니다 (Keycloak: %s). "+
			"이 주소로 로그인 결과를 받는 클라이언트를 신뢰할 때만, 관리자가 Valid redirect URIs 에 직접 등록하십시오.",
			clientID, clip(c.URI, 300), c.Detail)
	}
}
