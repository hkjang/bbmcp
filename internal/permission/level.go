// Package permission answers "what may this Bitbucket user actually do?".
//
// The MCP service account is only a transport for REST calls; it is never
// treated as the caller's authority. Every tool invocation resolves the
// requesting user's own effective Bitbucket permission first.
package permission

import "strings"

// Level is an ordered effective permission.
type Level int

// Permission levels, ordered.
const (
	None Level = iota
	Read
	Write
	Admin
)

// String renders the level for audit and API payloads.
func (l Level) String() string {
	switch l {
	case Read:
		return "READ"
	case Write:
		return "WRITE"
	case Admin:
		return "ADMIN"
	default:
		return "NONE"
	}
}

// AtLeast reports whether l satisfies want.
func (l Level) AtLeast(want Level) bool { return l >= want }

// ParseRequirement maps a tool's required_perm string to a level.
func ParseRequirement(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "REPO_WRITE", "PROJECT_WRITE", "WRITE":
		return Write
	case "REPO_ADMIN", "PROJECT_ADMIN", "ADMIN", "SYS_ADMIN":
		return Admin
	case "", "NONE":
		return None
	default:
		return Read
	}
}

// fromBitbucket maps a Bitbucket permission name to a level.
func fromBitbucket(p string) Level {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "REPO_READ", "PROJECT_READ":
		return Read
	case "REPO_WRITE", "PROJECT_WRITE":
		return Write
	case "REPO_ADMIN", "PROJECT_ADMIN", "ADMIN", "SYS_ADMIN":
		return Admin
	default:
		return None
	}
}

// Decision is the resolved permission for one resource.
type Decision struct {
	Username   string `json:"username"`
	Project    string `json:"project,omitempty"`
	Repository string `json:"repository,omitempty"`
	Level      Level  `json:"-"`
	Effective  string `json:"effective"`
	Read       bool   `json:"read"`
	Write      bool   `json:"write"`
	Admin      bool   `json:"admin"`
	Source     string `json:"source"`
	Note       string `json:"note,omitempty"`
}

func decide(username, project, repo string, lvl Level, source, note string) Decision {
	return Decision{
		Username:   username,
		Project:    project,
		Repository: repo,
		Level:      lvl,
		Effective:  lvl.String(),
		Read:       lvl.AtLeast(Read),
		Write:      lvl.AtLeast(Write),
		Admin:      lvl.AtLeast(Admin),
		Source:     source,
		Note:       note,
	}
}
