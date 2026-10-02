package tools

import (
	"context"

	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/permission"
	"github.com/hkjang/bbmcp/internal/policy"
	"github.com/hkjang/bbmcp/internal/settings"
)

// Principal is the authenticated caller of a tool.
type Principal struct {
	UserID            int64    `json:"userId"`
	KeycloakSub       string   `json:"keycloakSub"`
	Username          string   `json:"username"`
	DisplayName       string   `json:"displayName"`
	Roles             []string `json:"roles"`
	Scopes            []string `json:"scopes"`
	IsServiceAdmin    bool     `json:"isServiceAdmin"`
	BitbucketUserID   int64    `json:"bitbucketUserId"`
	BitbucketUsername string   `json:"bitbucketUsername"`
	AuthMode          string   `json:"authMode"` // oauth | apikey | session
	Client            string   `json:"client"`
	IP                string   `json:"ip"`
	PreferUserPAT     bool     `json:"preferUserPat"`
}

// Resource names the Bitbucket objects a call touches, used for policy and
// permission checks before the call runs.
type Resource struct {
	Project     string
	Repository  string
	Branch      string
	PullRequest int
}

// PermissionChecker resolves the requester's own effective Bitbucket
// permission. Listings are filtered through it so the service account's wider
// visibility never leaks to a user who lacks access.
type PermissionChecker interface {
	Project(ctx context.Context, username, projectKey string) (permission.Decision, error)
	Repository(ctx context.Context, username, projectKey, slug string) (permission.Decision, error)
}

// PolicyChecker evaluates the admin-managed MCP ACL.
type PolicyChecker interface {
	Evaluate(ctx context.Context, projectKey, repoSlug, branch string) (policy.Verdict, error)
}

// Call carries everything a tool handler needs.
type Call struct {
	Args      Args
	Principal Principal
	Adapter   bitbucket.Adapter
	Cred      bitbucket.Credential
	Cfg       settings.Bitbucket
	Resource  Resource
	Approved  bool
	Perm      PermissionChecker
	Policy    PolicyChecker
}

// canReadProject reports whether the requester may see a project.
func (c *Call) canReadProject(ctx context.Context, key string) bool {
	if v, err := c.Policy.Evaluate(ctx, key, "", ""); err != nil || !v.Allowed {
		return false
	}
	dec, err := c.Perm.Project(ctx, c.Principal.BitbucketUsername, key)
	return err == nil && dec.Read
}

// canReadRepository reports whether the requester may see a repository.
func (c *Call) canReadRepository(ctx context.Context, key, slug string) bool {
	if v, err := c.Policy.Evaluate(ctx, key, slug, ""); err != nil || !v.Allowed {
		return false
	}
	dec, err := c.Perm.Repository(ctx, c.Principal.BitbucketUsername, key, slug)
	return err == nil && dec.Read
}

// filterProjects keeps only the projects the requester can actually read.
func filterProjects(ctx context.Context, c *Call, in []bitbucket.Project) ([]bitbucket.Project, error) {
	out := make([]bitbucket.Project, 0, len(in))
	for _, p := range in {
		if c.canReadProject(ctx, p.Key) {
			out = append(out, p)
		}
	}
	return out, nil
}

// filterRepositories keeps only the repositories the requester can read.
func filterRepositories(ctx context.Context, c *Call, in []bitbucket.Repository) ([]bitbucket.Repository, error) {
	out := make([]bitbucket.Repository, 0, len(in))
	for _, r := range in {
		if c.canReadRepository(ctx, r.Project.Key, r.Slug) {
			out = append(out, r)
		}
	}
	return out, nil
}

// Definition is one MCP tool.
type Definition struct {
	Name            string
	Title           string
	Description     string
	Group           string
	Risk            string
	RequiredPerm    string
	Scope           string
	Tier            int
	DefaultEnabled  bool
	DefaultApproval bool
	MinRole         string
	HighLevel       bool
	InputSchema     map[string]any
	Resolve         func(Args) Resource
	Handle          func(context.Context, *Call) (any, error)
}

// Result wraps a tool payload with provenance so that a model consuming it can
// tell that repository content is untrusted input, not instructions.
type Result struct {
	Source Source `json:"source"`
	Trust  string `json:"trust"`
	Data   any    `json:"data"`
}

// Source describes where a result came from.
type Source struct {
	Type       string `json:"type"`
	Project    string `json:"project,omitempty"`
	Repository string `json:"repository,omitempty"`
	Resource   string `json:"resource,omitempty"`
	ID         any    `json:"id,omitempty"`
	AuthMode   string `json:"authMode,omitempty"`
	Actor      string `json:"actor,omitempty"`
	Requester  string `json:"requester,omitempty"`
}

// wrap builds an untrusted-data result.
func wrap(c *Call, resource string, id any, data any) Result {
	return Result{
		Source: Source{
			Type:       "bitbucket",
			Project:    c.Resource.Project,
			Repository: c.Resource.Repository,
			Resource:   resource,
			ID:         id,
			AuthMode:   c.Cred.Mode,
			Actor:      c.Cred.Username,
			Requester:  c.Principal.BitbucketUsername,
		},
		Trust: "untrusted",
		Data:  data,
	}
}

// pageOut is the paging envelope returned to clients.
type pageOut struct {
	Size          int  `json:"size"`
	Start         int  `json:"start"`
	Limit         int  `json:"limit"`
	IsLastPage    bool `json:"isLastPage"`
	NextPageStart int  `json:"nextPageStart,omitempty"`
}

func outPage(p bitbucket.Page) pageOut {
	return pageOut{
		Size: p.Size, Start: p.Start, Limit: p.Limit,
		IsLastPage: p.IsLastPage, NextPageStart: p.NextPageStart,
	}
}
