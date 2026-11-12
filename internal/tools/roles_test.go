package tools

import (
	"reflect"
	"testing"
)

func TestMergeRolesKeepsOnlyBbmcpRolesRankedAndDeduplicated(t *testing.T) {
	got := MergeRoles(
		[]string{"offline_access", RoleExecutor, "default-roles-company"},
		[]string{RoleUser, RoleExecutor, " " + RoleWriter + " "},
		nil,
	)
	want := []string{RoleUser, RoleWriter, RoleExecutor}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeRoles = %v, want %v", got, want)
	}
}

func TestMergeRolesOfNothingIsEmptyNotNil(t *testing.T) {
	// The JSON for a user without roles must be [] rather than null, which
	// the console would otherwise have to special-case.
	if got := MergeRoles(nil, []string{"uma_authorization"}); got == nil || len(got) != 0 {
		t.Fatalf("MergeRoles = %#v, want empty slice", got)
	}
}

func TestDefaultRoleNeverHandsOutAdmin(t *testing.T) {
	for role, want := range map[string]bool{
		"":             true,
		RoleUser:       true,
		RoleWriter:     true,
		RoleExecutor:   true,
		RoleAdmin:      false,
		"executor":     false, // the API key role name is not a bbmcp role
		"unknown-role": false,
	} {
		if got := DefaultRoleAllowed(role); got != want {
			t.Errorf("DefaultRoleAllowed(%q) = %v, want %v", role, got, want)
		}
	}
}
