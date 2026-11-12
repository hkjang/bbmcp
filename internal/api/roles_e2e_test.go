package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hkjang/bbmcp/internal/tools"
)

// adminDo sends an authenticated console request and decodes the JSON reply.
func (g *gateway) adminDo(t *testing.T, jar *cookiejar.Jar, method, path, body string, out any) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, g.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Jar: jar}).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: 응답을 읽을 수 없습니다 (%d): %s", method, path, resp.StatusCode, raw)
		}
	}
	return resp
}

type consoleUser struct {
	ID             int64    `json:"id"`
	Username       string   `json:"username"`
	Roles          []string `json:"roles"`
	KeycloakRoles  []string `json:"keycloakRoles"`
	EffectiveRoles []string `json:"effectiveRoles"`
	Active         bool     `json:"active"`
}

func (g *gateway) findUser(t *testing.T, jar *cookiejar.Jar, username string) consoleUser {
	t.Helper()
	var users []consoleUser
	g.adminDo(t, jar, http.MethodGet, "/api/admin/users?q="+username, "", &users)
	for _, u := range users {
		if u.Username == username {
			return u
		}
	}
	t.Fatalf("사용자 %s 가 목록에 없습니다: %+v", username, users)
	return consoleUser{}
}

// toolRisks lists the MCP tools a token can see, by risk.
func (g *gateway) toolRisks(t *testing.T, token string) map[string]int {
	t.Helper()
	resp, out := g.post(t, "/mcp", token, `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list 상태 %d: %v", resp.StatusCode, out)
	}
	result, _ := out["result"].(map[string]any)
	list, _ := result["tools"].([]any)
	risks := map[string]int{}
	for _, item := range list {
		tool, _ := item.(map[string]any)
		ann, _ := tool["annotations"].(map[string]any)
		risk, _ := ann["risk"].(string)
		risks[risk]++
	}
	return risks
}

// enableExecuteTool turns on one EXECUTE tool. They ship disabled, and a
// disabled tool is hidden from every role, which would hide what these tests
// are about.
func (g *gateway) enableExecuteTool(t *testing.T, jar *cookiejar.Jar) {
	t.Helper()
	resp := g.adminDo(t, jar, http.MethodPatch, "/api/admin/tools/bitbucket_approve_pull_request",
		`{"enabled":true}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("실행 도구 활성화 상태 %d", resp.StatusCode)
	}
}

// noBbmcpRoles is what Keycloak issues to a user nobody gave a bbmcp realm
// role, and also what a dynamically registered MCP client often receives.
func noBbmcpRoles(c jwt.MapClaims) {
	c["realm_access"] = map[string]any{"roles": []string{"offline_access", "uma_authorization"}}
}

// TestMCPOAuthKeepsAdminGrantedRoles reproduces the report: an administrator
// grants executor in the console, the user's next MCP OAuth request carries a
// token without that role, and the grant used to be overwritten by it.
func TestMCPOAuthKeepsAdminGrantedRoles(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)
	token := kc.token(t, noBbmcpRoles)

	// First request provisions the user. With no role from anywhere the
	// user sees nothing.
	if risks := gw.toolRisks(t, token); len(risks) != 0 {
		t.Fatalf("역할 없는 사용자에게 도구가 보입니다: %v", risks)
	}

	jar := gw.login(t, "admin", "bootstrap-password")
	gw.enableExecuteTool(t, jar)
	user := gw.findUser(t, jar, "hkjang")
	var updated consoleUser
	resp := gw.adminDo(t, jar, http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(user.ID, 10),
		`{"displayName":"장현규","email":"hkjang@example.com","isServiceAdmin":false,"active":true,"roles":["`+tools.RoleExecutor+`"]}`,
		&updated)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("역할 부여 상태 %d", resp.StatusCode)
	}
	if !reflect.DeepEqual(updated.EffectiveRoles, []string{tools.RoleExecutor}) {
		t.Fatalf("부여 직후 실제 역할 = %v", updated.EffectiveRoles)
	}

	// The same token comes back. Each request re-syncs the user from it,
	// which is exactly where the grant used to disappear.
	for i := 0; i < 3; i++ {
		risks := gw.toolRisks(t, token)
		if risks["READ"] == 0 || risks["WRITE"] == 0 || risks["EXECUTE"] == 0 {
			t.Fatalf("요청 %d: 조회·작성·실행 도구가 모두 보여야 합니다: %v", i+1, risks)
		}
	}

	after := gw.findUser(t, jar, "hkjang")
	if !reflect.DeepEqual(after.Roles, []string{tools.RoleExecutor}) {
		t.Fatalf("MCP 요청 뒤 관리자 부여 역할 = %v, executor 가 남아 있어야 합니다", after.Roles)
	}
	if !reflect.DeepEqual(after.KeycloakRoles, []string{"offline_access", "uma_authorization"}) {
		t.Errorf("토큰 역할 = %v", after.KeycloakRoles)
	}

	// bitbucket_me reports the merged roles and the scopes they grant.
	_, out := gw.post(t, "/mcp", token,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bitbucket_me","arguments":{}}}`)
	result, _ := out["result"].(map[string]any)
	me, _ := result["structuredContent"].(map[string]any)
	roles, _ := me["roles"].([]any)
	if len(roles) != 1 || roles[0] != tools.RoleExecutor {
		t.Fatalf("bitbucket_me roles = %v", me["roles"])
	}
	scopes, _ := me["scopes"].([]any)
	hasExecute := false
	for _, s := range scopes {
		if s == "bb:pr:execute" {
			hasExecute = true
		}
	}
	if !hasExecute {
		t.Fatalf("bitbucket_me scopes = %v, bb:pr:execute 가 있어야 합니다", me["scopes"])
	}

	// Revoking the grant in the console takes effect on the next request.
	gw.adminDo(t, jar, http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(user.ID, 10),
		`{"displayName":"장현규","email":"hkjang@example.com","isServiceAdmin":false,"active":true,"roles":[]}`, nil)
	if risks := gw.toolRisks(t, token); len(risks) != 0 {
		t.Fatalf("부여를 회수한 뒤에도 도구가 보입니다: %v", risks)
	}
}

// TestSSODefaultRoleAppliesToMCPOAuth checks the floor every Keycloak user
// gets, and that a token's own bbmcp role still counts above it.
func TestSSODefaultRoleAppliesToMCPOAuth(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)
	jar := gw.login(t, "admin", "bootstrap-password")
	gw.enableExecuteTool(t, jar)

	// Administrator capability is never a default.
	resp := gw.adminDo(t, jar, http.MethodPut, "/api/admin/settings/keycloak",
		`{"value":{"defaultRole":"`+tools.RoleAdmin+`"},"secrets":{}}`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("관리자 역할을 기본으로 저장한 상태 %d, 400 이어야 합니다", resp.StatusCode)
	}
	// Nor is an API key role name, which is what an operator might reach for.
	resp = gw.adminDo(t, jar, http.MethodPut, "/api/admin/settings/keycloak",
		`{"value":{"defaultRole":"executor"},"secrets":{}}`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("키 역할 이름을 기본으로 저장한 상태 %d, 400 이어야 합니다", resp.StatusCode)
	}

	resp = gw.adminDo(t, jar, http.MethodPut, "/api/admin/settings/keycloak",
		`{"value":{"defaultRole":"`+tools.RoleWriter+`"},"secrets":{}}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("기본 역할 저장 상태 %d", resp.StatusCode)
	}

	risks := gw.toolRisks(t, kc.token(t, noBbmcpRoles))
	if risks["READ"] == 0 || risks["WRITE"] == 0 {
		t.Fatalf("기본 역할 writer 로 조회·작성 도구가 보여야 합니다: %v", risks)
	}
	if risks["EXECUTE"] != 0 {
		t.Fatalf("기본 역할 writer 에게 실행 도구가 보입니다: %v", risks)
	}
	user := gw.findUser(t, jar, "hkjang")
	if len(user.Roles) != 0 {
		t.Errorf("기본 역할이 사용자 역할에 기록되었습니다: %v", user.Roles)
	}
	if !reflect.DeepEqual(user.EffectiveRoles, []string{tools.RoleWriter}) {
		t.Errorf("실제 역할 = %v", user.EffectiveRoles)
	}

	// A higher role in the token still wins over the floor.
	risks = gw.toolRisks(t, kc.token(t, func(c jwt.MapClaims) {
		c["realm_access"] = map[string]any{"roles": []string{tools.RoleExecutor}}
	}))
	if risks["EXECUTE"] == 0 {
		t.Fatalf("토큰의 executor 가 기본 역할에 가려졌습니다: %v", risks)
	}
}

// TestMCPOAuthRefusesDeactivatedUser: the console's 활성 switch has to stop
// MCP OAuth too, not only web sessions and API keys.
func TestMCPOAuthRefusesDeactivatedUser(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)
	token := kc.token(t, nil)
	if risks := gw.toolRisks(t, token); risks["READ"] == 0 {
		t.Fatalf("활성 사용자에게 조회 도구가 없습니다: %v", risks)
	}

	jar := gw.login(t, "admin", "bootstrap-password")
	user := gw.findUser(t, jar, "hkjang")
	gw.adminDo(t, jar, http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(user.ID, 10),
		`{"displayName":"장현규","email":"hkjang@example.com","isServiceAdmin":false,"active":false,"roles":[]}`, nil)

	resp, _ := gw.post(t, "/mcp", token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("비활성 사용자의 MCP 요청 상태 %d, 401 이어야 합니다", resp.StatusCode)
	}
}

// TestAdminRejectsUnknownGrantedRole keeps meaningless values out of the
// granted roles, where they would look like access but grant none.
func TestAdminRejectsUnknownGrantedRole(t *testing.T) {
	kc := newKeycloakStub(t, false)
	gw := newGateway(t, kc)
	gw.toolRisks(t, kc.token(t, nil))
	jar := gw.login(t, "admin", "bootstrap-password")
	user := gw.findUser(t, jar, "hkjang")
	resp := gw.adminDo(t, jar, http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(user.ID, 10),
		`{"displayName":"","email":"","isServiceAdmin":false,"active":true,"roles":["executor"]}`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("알 수 없는 역할 부여 상태 %d, 400 이어야 합니다", resp.StatusCode)
	}
}
