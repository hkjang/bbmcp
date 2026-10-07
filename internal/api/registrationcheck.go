package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hkjang/bbmcp/internal/settings"
)

// registrationCheck is what Keycloak's anonymous dynamic client registration
// does with the client an MCP client registers: a public client
// (token_endpoint_auth_method "none").
type registrationCheck struct {
	Endpoint string `json:"endpoint"`
	// AcceptsPublicClients is true when Keycloak would register an MCP client.
	AcceptsPublicClients bool   `json:"acceptsPublicClients"`
	Status               int    `json:"status,omitempty"`
	Code                 string `json:"error,omitempty"`
	Detail               string `json:"detail,omitempty"`
	// Reason explains a refusal in the operator's terms.
	Reason string `json:"reason,omitempty"`
	// Problem is set when Keycloak could not be asked, or when a client the
	// check created could not be removed again.
	Problem string `json:"problem,omitempty"`
	// CreatedClientID is set when Keycloak did create the check's client.
	CreatedClientID string `json:"createdClientId,omitempty"`
	Deleted         bool   `json:"deleted,omitempty"`
}

// keycloakRejectsPublic is the description Keycloak gives when it cannot turn
// the request into a client, which for an MCP client's request means it does
// not know token_endpoint_auth_method "none" (Keycloak 10, for one).
const keycloakRejectsPublic = "Client metadata invalid"

// checkKeycloakRegistration asks Keycloak's registration endpoint whether it
// would register an MCP client, without leaving one behind.
//
// The request is the one MCP clients send, plus a terms-of-service URL that is
// not a URL. Keycloak reads the auth method while converting the request,
// applies its registration policies, and validates URLs only after creating
// the client, rolling the creation back when that fails. So the answer is one
// of: "Client metadata invalid" (public clients are rejected outright), a
// policy refusal (anonymous registration is closed), or the complaint about
// the URL (public clients would be accepted). A Keycloak that creates the
// client anyway gets it deleted again through RFC 7592.
func checkKeycloakRegistration(ctx context.Context, kc settings.Keycloak, endpoint string) registrationCheck {
	out := registrationCheck{Endpoint: endpoint}
	if endpoint == "" {
		out.Reason = "Keycloak 메타데이터에 registration_endpoint 가 없어 동적 등록을 제공하지 않습니다"
		return out
	}
	body, _ := json.Marshal(map[string]any{
		"client_name":                "bbmcp registration check",
		"redirect_uris":              []string{"http://127.0.0.1:9/bbmcp-registration-check"},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"tos_uri":                    "not a url",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		out.Problem = err.Error()
		return out
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := keycloakHTTPClient(kc)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		out.Problem = "Keycloak 에 확인할 수 없습니다: " + err.Error()
		return out
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	out.Status = resp.StatusCode

	var answer struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		ClientID    string `json:"client_id"`
		URI         string `json:"registration_client_uri"`
		Token       string `json:"registration_access_token"`
	}
	_ = json.Unmarshal(raw, &answer)
	out.Code, out.Detail = answer.Error, answer.Description

	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK:
		out.AcceptsPublicClients = true
		out.CreatedClientID = clip(answer.ClientID, 80)
		switch {
		case answer.URI == "" || answer.Token == "":
			out.Problem = "Keycloak 이 시험용 클라이언트를 만들었지만 지울 방법을 알려 주지 않았습니다"
		case !sameOrigin(answer.URI, endpoint):
			// The registration access token only goes back to the server that issued it.
			out.Problem = "Keycloak 이 다른 출처의 관리 주소를 알려 주어 시험용 클라이언트를 지우지 않았습니다"
		default:
			out.Deleted = deleteRegisteredClient(ctx, client, answer.URI, answer.Token)
			if !out.Deleted {
				out.Problem = "시험용 클라이언트를 지우지 못했습니다"
			}
		}
		if out.Problem != "" {
			out.Problem += fmt.Sprintf(". Keycloak 관리 콘솔에서 client_id %q (이름 bbmcp registration check)를 지우십시오", out.CreatedClientID)
		}
	case resp.StatusCode == http.StatusBadRequest && answer.Description == keycloakRejectsPublic:
		out.Reason = "Keycloak 이 공개 클라이언트(token_endpoint_auth_method none) 등록을 받지 않습니다. MCP 클라이언트는 모두 invalid_client_metadata 로 실패합니다"
	case resp.StatusCode == http.StatusBadRequest && strings.Contains(answer.Description, "URL"):
		// It got past the auth method and the policies to URL validation.
		out.AcceptsPublicClients = true
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		out.Reason = "Keycloak 의 익명 등록 정책이 이 요청을 막습니다 (Trusted Hosts 등)"
	default:
		out.Problem = fmt.Sprintf("Keycloak 이 예상하지 못한 응답을 했습니다: %d %s", resp.StatusCode, strings.TrimSpace(answer.Error+" "+answer.Description))
	}
	return out
}

// deleteRegisteredClient removes a client the check created (RFC 7592) and
// reports whether Keycloak confirmed it.
func deleteRegisteredClient(ctx context.Context, client *http.Client, uri, token string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && ua.Scheme != "" &&
		strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}
