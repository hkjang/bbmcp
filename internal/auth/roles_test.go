package auth

import (
	"reflect"
	"testing"

	"github.com/hkjang/bbmcp/internal/settings"
	"github.com/hkjang/bbmcp/internal/tools"
)

func TestEffectiveRolesKeepsGrantWhenTokenHasNone(t *testing.T) {
	// The reported bug: the token carries no bbmcp role, an administrator
	// granted executor, and the grant must survive the token.
	u := &User{
		KeycloakSub:   "sub-1",
		Roles:         []string{tools.RoleExecutor},
		KeycloakRoles: []string{"offline_access", "uma_authorization"},
	}
	got := EffectiveRoles(u, settings.DefaultKeycloak())
	if !reflect.DeepEqual(got, []string{tools.RoleExecutor}) {
		t.Fatalf("EffectiveRoles = %v", got)
	}
	if !tools.RoleSatisfied(got, tools.RoleExecutor) {
		t.Fatal("관리자가 준 executor 로 실행 도구를 쓸 수 없습니다")
	}
}

func TestEffectiveRolesUnionsTokenGrantAndDefault(t *testing.T) {
	kc := settings.DefaultKeycloak()
	kc.DefaultRole = tools.RoleWriter
	u := &User{
		KeycloakSub:   "sub-1",
		Roles:         []string{tools.RoleUser},
		KeycloakRoles: []string{tools.RoleExecutor},
	}
	got := EffectiveRoles(u, kc)
	want := []string{tools.RoleUser, tools.RoleWriter, tools.RoleExecutor}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EffectiveRoles = %v, want %v", got, want)
	}
}

func TestEffectiveRolesDefaultAppliesOnlyToKeycloakAccounts(t *testing.T) {
	kc := settings.DefaultKeycloak()
	kc.DefaultRole = tools.RoleExecutor

	sso := &User{KeycloakSub: "sub-1"}
	if got := EffectiveRoles(sso, kc); !reflect.DeepEqual(got, []string{tools.RoleExecutor}) {
		t.Fatalf("SSO 사용자 = %v, executor 여야 합니다", got)
	}
	local := &User{Username: "ops"}
	if got := EffectiveRoles(local, kc); len(got) != 0 {
		t.Fatalf("로컬 계정 = %v, 기본 역할이 붙으면 안 됩니다", got)
	}
}

func TestEffectiveRolesIgnoresAdminAsDefault(t *testing.T) {
	// The settings handler refuses this value; a stored one written some
	// other way must still not make everyone an administrator.
	kc := settings.DefaultKeycloak()
	kc.DefaultRole = tools.RoleAdmin
	if got := EffectiveRoles(&User{KeycloakSub: "sub-1"}, kc); len(got) != 0 {
		t.Fatalf("EffectiveRoles = %v", got)
	}
}
