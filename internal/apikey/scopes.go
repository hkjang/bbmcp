// Package apikey issues, rotates and verifies personal API keys, and owns the
// editable key permission scheme (roles → scopes).
package apikey

import "strings"

// Scope names. These are the permissions a key can carry; a key can never
// exceed what the owning user is allowed to do in Bitbucket.
const (
	ScopeBitbucketRead = "bb:read"
	ScopePRWrite       = "bb:pr:write"
	ScopePRExecute     = "bb:pr:execute"
	ScopeBranchWrite   = "bb:branch:write"
	ScopeAIInvoke      = "ai:invoke"
	ScopeAdminRead     = "admin:read"
	ScopeAdminWrite    = "admin:write"
)

// ScopeInfo describes a scope for the UI.
type ScopeInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

// AllScopes is the catalogue shown in the key management UI.
func AllScopes() []ScopeInfo {
	return []ScopeInfo{
		{ScopeBitbucketRead, "저장소 조회", "프로젝트·저장소·파일·커밋·PR 읽기", "READ"},
		{ScopePRWrite, "PR 작성", "PR 생성, 댓글, 제목/설명 수정", "WRITE"},
		{ScopePRExecute, "PR 실행", "PR 승인·거절·머지", "EXECUTE"},
		{ScopeBranchWrite, "브랜치 생성", "브랜치 생성", "WRITE"},
		{ScopeAIInvoke, "AI 호출", "AI 리뷰 보조 스트리밍 호출", "WRITE"},
		{ScopeAdminRead, "관리 조회", "관리자 설정·감사 로그 읽기", "ADMIN"},
		{ScopeAdminWrite, "관리 변경", "관리자 설정 변경", "ADMIN"},
	}
}

// BuiltinRoles are seeded on first boot and may be edited afterwards.
func BuiltinRoles() []Role {
	return []Role{
		{Name: "reader", Description: "조회 전용", Scopes: []string{ScopeBitbucketRead}, Builtin: true},
		{Name: "writer", Description: "조회 + PR 작성", Scopes: []string{ScopeBitbucketRead, ScopePRWrite, ScopeAIInvoke}, Builtin: true},
		{Name: "executor", Description: "조회 + 작성 + 머지/승인", Scopes: []string{ScopeBitbucketRead, ScopePRWrite, ScopePRExecute, ScopeBranchWrite, ScopeAIInvoke}, Builtin: true},
		{Name: "admin", Description: "관리 API 포함 전체", Scopes: []string{ScopeBitbucketRead, ScopePRWrite, ScopePRExecute, ScopeBranchWrite, ScopeAIInvoke, ScopeAdminRead, ScopeAdminWrite}, Builtin: true},
	}
}

// ValidScope reports whether name is a known scope.
func ValidScope(name string) bool {
	for _, s := range AllScopes() {
		if s.Name == name {
			return true
		}
	}
	return false
}

// HasScope reports whether scopes contains want.
func HasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
