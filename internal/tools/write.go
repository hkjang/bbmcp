package tools

import (
	"context"
	"fmt"
	"strings"
)

// attribution prefixes service-mode writes with the real requester so that a
// comment authored by the service account is never mistaken for its own.
func attribution(c *Call, text string) string {
	if c.Cred.Mode != "service" || !c.Cfg.AttributionNote {
		return text
	}
	requester := c.Principal.BitbucketUsername
	if requester == "" {
		requester = c.Principal.Username
	}
	return fmt.Sprintf("[MCP 요청자: %s]\n\n%s", requester, text)
}

// writeTools are the tier-2 tools: they change Bitbucket state but do not
// decide a pull request's fate.
func writeTools() []Definition {
	return []Definition{
		{
			Name:            "bitbucket_create_pull_request",
			Title:           "PR 생성",
			Description:     "새 풀 리퀘스트를 생성합니다.",
			Group:           "pullrequest",
			Risk:            RiskWrite,
			RequiredPerm:    "REPO_WRITE",
			Scope:           "bb:pr:write",
			Tier:            2,
			DefaultEnabled:  true,
			DefaultApproval: true,
			InputSchema: obj(repoProps(map[string]any{
				"title":       str("PR 제목"),
				"description": str("PR 설명"),
				"fromRef":     str("원본 브랜치 (예: refs/heads/feature/x 또는 feature/x)"),
				"toRef":       str("대상 브랜치 (예: refs/heads/master)"),
				"reviewers":   strArray("리뷰어 Bitbucket 사용자명"),
				"approvalId":  str("승인 요청 ID (승인이 필요한 경우)"),
			}), "project", "repository", "title", "fromRef", "toRef"),
			Resolve: func(a Args) Resource {
				r := resolveRepo(a)
				r.Branch = normalizeRef(a.OptString("toRef", ""))
				return r
			},
			Handle: func(ctx context.Context, c *Call) (any, error) {
				title, err := c.Args.String("title")
				if err != nil {
					return nil, err
				}
				from, err := c.Args.String("fromRef")
				if err != nil {
					return nil, err
				}
				to, err := c.Args.String("toRef")
				if err != nil {
					return nil, err
				}
				pr, err := c.Adapter.CreatePullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					title, attribution(c, c.Args.OptString("description", "")),
					refID(from), refID(to), c.Args.StringSlice("reviewers"))
				if err != nil {
					return nil, err
				}
				return wrap(c, "pull_request", pr.ID, pr), nil
			},
		},
		{
			Name:            "bitbucket_comment_pull_request",
			Title:           "PR 댓글 작성",
			Description:     "풀 리퀘스트에 댓글을 작성합니다. 서비스 모드에서는 요청자가 본문에 표시됩니다.",
			Group:           "pullrequest",
			Risk:            RiskWrite,
			RequiredPerm:    "REPO_READ",
			Scope:           "bb:pr:write",
			Tier:            2,
			DefaultEnabled:  true,
			DefaultApproval: true,
			InputSchema: obj(repoProps(map[string]any{
				"pullRequest": num("PR 번호"),
				"text":        str("댓글 본문"),
				"parentId":    num("상위 댓글 ID (답글인 경우)"),
				"approvalId":  str("승인 요청 ID"),
			}), "project", "repository", "pullRequest", "text"),
			Resolve: resolveRepoPR,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				text, err := c.Args.String("text")
				if err != nil {
					return nil, err
				}
				cm, err := c.Adapter.CommentPullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					c.Resource.PullRequest, attribution(c, text), c.Args.OptInt("parentId", 0))
				if err != nil {
					return nil, err
				}
				return wrap(c, "pr_comment", cm.ID, cm), nil
			},
		},
		{
			Name:            "bitbucket_update_pull_request",
			Title:           "PR 수정",
			Description:     "풀 리퀘스트의 제목과 설명을 수정합니다. version 이 일치해야 합니다.",
			Group:           "pullrequest",
			Risk:            RiskWrite,
			RequiredPerm:    "REPO_WRITE",
			Scope:           "bb:pr:write",
			Tier:            2,
			DefaultEnabled:  true,
			DefaultApproval: true,
			InputSchema: obj(repoProps(map[string]any{
				"pullRequest": num("PR 번호"),
				"version":     num("현재 PR version (생략 시 조회 후 사용)"),
				"title":       str("새 제목"),
				"description": str("새 설명"),
				"approvalId":  str("승인 요청 ID"),
			}), "project", "repository", "pullRequest"),
			Resolve: resolveRepoPR,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				version := c.Args.OptInt("version", -1)
				if version < 0 {
					pr, err := c.Adapter.PullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository, c.Resource.PullRequest)
					if err != nil {
						return nil, err
					}
					version = pr.Version
				}
				title := c.Args.OptString("title", "")
				desc := c.Args.OptString("description", "")
				if title == "" && desc == "" {
					return nil, fmt.Errorf("title 또는 description 중 하나는 필요합니다")
				}
				if desc != "" {
					desc = attribution(c, desc)
				}
				pr, err := c.Adapter.UpdatePullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					c.Resource.PullRequest, version, title, desc)
				if err != nil {
					return nil, err
				}
				return wrap(c, "pull_request", pr.ID, pr), nil
			},
		},
		{
			Name:            "bitbucket_create_branch",
			Title:           "브랜치 생성",
			Description:     "지정한 시작점에서 새 브랜치를 생성합니다.",
			Group:           "refs",
			Risk:            RiskWrite,
			RequiredPerm:    "REPO_WRITE",
			Scope:           "bb:branch:write",
			Tier:            2,
			DefaultEnabled:  true,
			DefaultApproval: true,
			InputSchema: obj(repoProps(map[string]any{
				"name":       str("새 브랜치 이름"),
				"startPoint": str("시작점 ref 또는 커밋"),
				"approvalId": str("승인 요청 ID"),
			}), "project", "repository", "name", "startPoint"),
			Resolve: func(a Args) Resource {
				r := resolveRepo(a)
				r.Branch = normalizeRef(a.OptString("name", ""))
				return r
			},
			Handle: func(ctx context.Context, c *Call) (any, error) {
				name, err := c.Args.String("name")
				if err != nil {
					return nil, err
				}
				start, err := c.Args.String("startPoint")
				if err != nil {
					return nil, err
				}
				br, err := c.Adapter.CreateBranch(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					normalizeRef(name), start)
				if err != nil {
					return nil, err
				}
				return wrap(c, "branch", br.DisplayID, br), nil
			},
		},
	}
}

// executeTools are the tier-3 tools: they decide a pull request's outcome and
// always require approval plus a branch permission check.
func executeTools() []Definition {
	return []Definition{
		{
			Name:            "bitbucket_approve_pull_request",
			Title:           "PR 승인",
			Description:     "풀 리퀘스트를 승인합니다. 사용자 PAT 모드에서만 실제 승인자가 요청자가 됩니다.",
			Group:           "pullrequest",
			Risk:            RiskExecute,
			RequiredPerm:    "REPO_READ",
			Scope:           "bb:pr:execute",
			Tier:            3,
			DefaultEnabled:  false,
			DefaultApproval: true,
			InputSchema: obj(repoProps(map[string]any{
				"pullRequest": num("PR 번호"),
				"status":      enumStr("승인 상태", "APPROVED", "UNAPPROVED", "NEEDS_WORK"),
				"approvalId":  str("승인 요청 ID"),
			}), "project", "repository", "pullRequest", "approvalId"),
			Resolve: resolveRepoPR,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				out, err := c.Adapter.ApprovePullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					c.Resource.PullRequest, c.Args.OptString("status", "APPROVED"))
				if err != nil {
					return nil, err
				}
				return wrap(c, "pr_approval", c.Resource.PullRequest, out), nil
			},
		},
		{
			Name:            "bitbucket_decline_pull_request",
			Title:           "PR 거절",
			Description:     "풀 리퀘스트를 거절합니다.",
			Group:           "pullrequest",
			Risk:            RiskExecute,
			RequiredPerm:    "REPO_WRITE",
			Scope:           "bb:pr:execute",
			Tier:            3,
			DefaultEnabled:  false,
			DefaultApproval: true,
			InputSchema: obj(repoProps(map[string]any{
				"pullRequest": num("PR 번호"),
				"version":     num("현재 PR version"),
				"approvalId":  str("승인 요청 ID"),
			}), "project", "repository", "pullRequest", "approvalId"),
			Resolve: resolveRepoPR,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				pr, err := c.Adapter.PullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository, c.Resource.PullRequest)
				if err != nil {
					return nil, err
				}
				version := c.Args.OptInt("version", pr.Version)
				out, err := c.Adapter.DeclinePullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					c.Resource.PullRequest, version)
				if err != nil {
					return nil, err
				}
				return wrap(c, "pull_request", out.ID, out), nil
			},
		},
		{
			Name:            "bitbucket_merge_pull_request",
			Title:           "PR 머지",
			Description:     "풀 리퀘스트를 머지합니다. 승인, 저장소 쓰기 권한, 브랜치 제한, PR version 을 모두 재검증합니다.",
			Group:           "pullrequest",
			Risk:            RiskExecute,
			RequiredPerm:    "REPO_WRITE",
			Scope:           "bb:pr:execute",
			Tier:            3,
			DefaultEnabled:  false,
			DefaultApproval: true,
			InputSchema: obj(repoProps(map[string]any{
				"pullRequest": num("PR 번호"),
				"version":     num("승인 시점의 PR version"),
				"message":     str("머지 커밋 메시지"),
				"approvalId":  str("승인 요청 ID"),
			}), "project", "repository", "pullRequest", "approvalId"),
			Resolve: resolveRepoPR,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				pr, err := c.Adapter.PullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository, c.Resource.PullRequest)
				if err != nil {
					return nil, err
				}
				if !pr.Open {
					return nil, fmt.Errorf("PR %d 는 열린 상태가 아닙니다 (%s)", pr.ID, pr.State)
				}
				version := c.Args.OptInt("version", pr.Version)
				if version != pr.Version {
					return nil, fmt.Errorf("APPROVAL_STALE: 요청 version %d, 현재 version %d", version, pr.Version)
				}
				out, err := c.Adapter.MergePullRequest(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					c.Resource.PullRequest, pr.Version, attribution(c, c.Args.OptString("message", "")))
				if err != nil {
					return nil, err
				}
				return wrap(c, "pull_request", out.ID, out), nil
			},
		},
	}
}

// normalizeRef strips the refs/heads/ prefix for display-style names.
func normalizeRef(ref string) string {
	return strings.TrimPrefix(strings.TrimSpace(ref), "refs/heads/")
}

// refID expands a display branch name into a full ref id.
func refID(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "refs/") {
		return ref
	}
	return "refs/heads/" + ref
}
