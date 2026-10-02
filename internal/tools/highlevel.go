package tools

import "context"

// highLevelTools aggregate several REST calls into one normalised context
// payload, which is what an AI agent actually needs for a review.
func highLevelTools() []Definition {
	return []Definition{
		{
			Name:           "bitbucket_repository_context",
			Title:          "저장소 컨텍스트",
			Description:    "저장소 메타데이터, 기본 브랜치, 최근 커밋, 브랜치 목록, 루트 트리를 한 번에 수집합니다.",
			Group:          "context",
			Risk:           RiskRead,
			RequiredPerm:   "REPO_READ",
			Scope:          "bb:read",
			Tier:           1,
			DefaultEnabled: true,
			HighLevel:      true,
			InputSchema: obj(repoProps(map[string]any{
				"commitLimit": num("최근 커밋 수 (기본 10)"),
				"treeDepth":   num("루트 트리 항목 수 (기본 50)"),
			}), "project", "repository"),
			Resolve: resolveRepo,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				proj, repo := c.Resource.Project, c.Resource.Repository
				out := map[string]any{}

				r, err := c.Adapter.Repository(ctx, c.Cred, proj, repo)
				if err != nil {
					return nil, err
				}
				out["repository"] = r

				if br, err := c.Adapter.DefaultBranch(ctx, c.Cred, proj, repo); err == nil {
					out["defaultBranch"] = br
				}
				if commits, _, err := c.Adapter.Commits(ctx, c.Cred, proj, repo, "", "",
					0, c.Args.OptInt("commitLimit", 10)); err == nil {
					out["recentCommits"] = commits
				}
				if branches, _, err := c.Adapter.Branches(ctx, c.Cred, proj, repo, "", 0, 50); err == nil {
					out["branches"] = branches
				}
				if tree, _, err := c.Adapter.Tree(ctx, c.Cred, proj, repo, "", "",
					0, c.Args.OptInt("treeDepth", 50)); err == nil {
					out["tree"] = tree
				}
				if prs, _, err := c.Adapter.PullRequests(ctx, c.Cred, proj, repo, "OPEN", "", 0, 10); err == nil {
					out["openPullRequests"] = prs
				}
				return wrap(c, "repository_context", repo, out), nil
			},
		},
		{
			Name:           "bitbucket_pr_review_context",
			Title:          "PR 리뷰 컨텍스트",
			Description:    "PR 정보, diff, 커밋, 댓글, 활동을 하나의 정규화된 컨텍스트로 수집합니다. 리뷰 작업의 기본 도구입니다.",
			Group:          "context",
			Risk:           RiskRead,
			RequiredPerm:   "REPO_READ",
			Scope:          "bb:read",
			Tier:           1,
			DefaultEnabled: true,
			HighLevel:      true,
			InputSchema: obj(repoProps(map[string]any{
				"pullRequest":  num("PR 번호"),
				"contextLines": num("diff 컨텍스트 줄 수 (기본 3)"),
				"includeDiff":  boolean("diff 포함 여부 (기본 true)"),
			}), "project", "repository", "pullRequest"),
			Resolve: resolveRepoPR,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				proj, repo, id := c.Resource.Project, c.Resource.Repository, c.Resource.PullRequest
				out := map[string]any{}

				pr, err := c.Adapter.PullRequest(ctx, c.Cred, proj, repo, id)
				if err != nil {
					return nil, err
				}
				out["pullRequest"] = pr
				out["version"] = pr.Version

				if c.Args.OptBool("includeDiff", true) {
					if diff, err := c.Adapter.PullRequestDiff(ctx, c.Cred, proj, repo, id,
						c.Args.OptInt("contextLines", 3)); err == nil {
						out["diff"] = diff
					}
				}
				if commits, _, err := c.Adapter.PullRequestCommits(ctx, c.Cred, proj, repo, id, 0, 100); err == nil {
					out["commits"] = commits
				}
				if changes, err := c.Adapter.PullRequestChanges(ctx, c.Cred, proj, repo, id, 0, 200); err == nil {
					out["changes"] = changes
				}
				if comments, _, err := c.Adapter.PullRequestComments(ctx, c.Cred, proj, repo, id, 0, 100); err == nil {
					out["comments"] = comments
				}
				if acts, err := c.Adapter.PullRequestActivities(ctx, c.Cred, proj, repo, id, 0, 100); err == nil {
					out["activities"] = acts
				}
				return wrap(c, "pr_review_context", id, out), nil
			},
		},
		{
			Name:           "bitbucket_recent_changes",
			Title:          "최근 변경 요약",
			Description:    "저장소의 최근 커밋과 최근 PR 을 함께 반환합니다.",
			Group:          "context",
			Risk:           RiskRead,
			RequiredPerm:   "REPO_READ",
			Scope:          "bb:read",
			Tier:           1,
			DefaultEnabled: true,
			HighLevel:      true,
			InputSchema: obj(repoProps(map[string]any{
				"limit": num("각 항목 수 (기본 20)"),
				"ref":   str("기준 브랜치"),
			}), "project", "repository"),
			Resolve: resolveRepoRef,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				limit := c.Args.OptInt("limit", 20)
				out := map[string]any{}
				if commits, _, err := c.Adapter.Commits(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					c.Args.OptString("ref", ""), "", 0, limit); err == nil {
					out["commits"] = commits
				}
				if prs, _, err := c.Adapter.PullRequests(ctx, c.Cred, c.Resource.Project, c.Resource.Repository,
					"ALL", "", 0, limit); err == nil {
					out["pullRequests"] = prs
				}
				return wrap(c, "recent_changes", nil, out), nil
			},
		},
		{
			Name:           "bitbucket_change_context",
			Title:          "커밋 변경 컨텍스트",
			Description:    "커밋 한 건의 메타데이터, 변경 파일, diff 를 함께 반환합니다.",
			Group:          "context",
			Risk:           RiskRead,
			RequiredPerm:   "REPO_READ",
			Scope:          "bb:read",
			Tier:           1,
			DefaultEnabled: true,
			HighLevel:      true,
			InputSchema: obj(repoProps(map[string]any{
				"commit":       str("커밋 해시"),
				"contextLines": num("diff 컨텍스트 줄 수 (기본 3)"),
			}), "project", "repository", "commit"),
			Resolve: resolveRepo,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				id, err := c.Args.String("commit")
				if err != nil {
					return nil, err
				}
				proj, repo := c.Resource.Project, c.Resource.Repository
				out := map[string]any{}
				cm, err := c.Adapter.Commit(ctx, c.Cred, proj, repo, id)
				if err != nil {
					return nil, err
				}
				out["commit"] = cm
				if changes, err := c.Adapter.CommitChanges(ctx, c.Cred, proj, repo, id, 0, 200); err == nil {
					out["changes"] = changes
				}
				parent := ""
				if len(cm.Parents) > 0 {
					parent = cm.Parents[0].ID
				}
				if parent != "" {
					if diff, err := c.Adapter.Diff(ctx, c.Cred, proj, repo, parent, id, "",
						c.Args.OptInt("contextLines", 3)); err == nil {
						out["diff"] = diff
					}
				}
				return wrap(c, "change_context", id, out), nil
			},
		},
		{
			Name:           "bitbucket_my_permissions",
			Title:          "내 유효 권한",
			Description:    "요청자의 프로젝트/저장소 유효 권한과 MCP 정책 판정을 함께 반환합니다.",
			Group:          "identity",
			Risk:           RiskRead,
			RequiredPerm:   "NONE",
			Scope:          "bb:read",
			Tier:           1,
			DefaultEnabled: true,
			InputSchema: obj(map[string]any{
				"project":    str("프로젝트 키"),
				"repository": str("저장소 슬러그 (선택)"),
			}, "project"),
			Resolve: resolveRepo,
			Handle: func(ctx context.Context, c *Call) (any, error) {
				out := map[string]any{"username": c.Principal.BitbucketUsername}
				projDec, err := c.Perm.Project(ctx, c.Principal.BitbucketUsername, c.Resource.Project)
				if err != nil {
					return nil, err
				}
				out["project"] = projDec
				if c.Resource.Repository != "" {
					repoDec, err := c.Perm.Repository(ctx, c.Principal.BitbucketUsername,
						c.Resource.Project, c.Resource.Repository)
					if err != nil {
						return nil, err
					}
					out["repository"] = repoDec
				}
				if v, err := c.Policy.Evaluate(ctx, c.Resource.Project, c.Resource.Repository, ""); err == nil {
					out["policy"] = v
				}
				return out, nil
			},
		},
	}
}

// All returns every tool definition shipped with this build.
func All() []Definition {
	out := []Definition{}
	out = append(out, readTools()...)
	out = append(out, highLevelTools()...)
	out = append(out, writeTools()...)
	out = append(out, executeTools()...)
	return out
}
