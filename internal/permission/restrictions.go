package permission

import (
	"encoding/json"
	"path"
	"strings"
)

// restriction mirrors the branch-permissions/2.0 restriction payload.
type restriction struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Matcher struct {
		ID        string `json:"id"`
		DisplayID string `json:"displayId"`
		Type      struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"type"`
	} `json:"matcher"`
	Users []struct {
		Name string `json:"name"`
	} `json:"users"`
	Groups []string `json:"groups"`
}

// evaluateRestrictions decides whether username may land a change on branch.
//
// "read-only" blocks everyone but the exempted users and groups.
// "pull-request-only" and "fast-forward-only" still permit a pull request
// merge, which is the only write path bbmcp offers, so they do not block.
func evaluateRestrictions(raw any, username string, groups []string, branch string) (bool, string) {
	body, err := json.Marshal(raw)
	if err != nil {
		return false, "브랜치 제한 응답을 해석할 수 없습니다"
	}
	var env struct {
		Values []restriction `json:"values"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return false, "브랜치 제한 응답을 해석할 수 없습니다"
	}

	member := map[string]bool{}
	for _, g := range groups {
		member[strings.ToLower(g)] = true
	}

	for _, rs := range env.Values {
		if !matchesBranch(rs, branch) {
			continue
		}
		if !strings.EqualFold(rs.Type, "read-only") {
			continue
		}
		if exempt(rs, username, member) {
			continue
		}
		label := rs.Matcher.DisplayID
		if label == "" {
			label = rs.Matcher.ID
		}
		return false, "브랜치 제한(read-only)으로 차단됨: " + label
	}
	return true, ""
}

func exempt(rs restriction, username string, member map[string]bool) bool {
	for _, u := range rs.Users {
		if strings.EqualFold(u.Name, username) {
			return true
		}
	}
	for _, g := range rs.Groups {
		if member[strings.ToLower(g)] {
			return true
		}
	}
	return false
}

func matchesBranch(rs restriction, branch string) bool {
	branch = strings.TrimPrefix(branch, "refs/heads/")
	id := strings.TrimPrefix(rs.Matcher.ID, "refs/heads/")
	display := rs.Matcher.DisplayID

	switch strings.ToUpper(rs.Matcher.Type.ID) {
	case "BRANCH":
		return strings.EqualFold(id, branch) || strings.EqualFold(display, branch)
	case "PATTERN":
		pattern := id
		if pattern == "" {
			pattern = display
		}
		if ok, err := path.Match(strings.TrimPrefix(pattern, "refs/heads/"), branch); err == nil && ok {
			return true
		}
		// Bitbucket treats a trailing "/" prefix pattern as "everything under".
		return strings.HasSuffix(pattern, "/") && strings.HasPrefix(branch, strings.TrimPrefix(pattern, "refs/heads/"))
	case "MODEL_CATEGORY":
		prefix := display
		if prefix == "" {
			prefix = id
		}
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		return strings.HasPrefix(branch, prefix)
	case "MODEL_BRANCH":
		return strings.EqualFold(display, branch) || strings.EqualFold(id, branch)
	default:
		return strings.EqualFold(id, branch) || strings.EqualFold(display, branch)
	}
}
