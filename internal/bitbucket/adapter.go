// Package bitbucket adapts Bitbucket Server to the needs of bbmcp.
//
// Every tool talks to the Adapter interface rather than to REST directly, so
// that a Bitbucket upgrade only requires a new Adapter implementation while
// the MCP tools, Keycloak integration and admin UI stay unchanged.
package bitbucket

import "context"

// Credential identifies which identity performs a REST call.
type Credential struct {
	Mode     string // service | user
	Username string // Bitbucket username the token belongs to
	Token    string // personal access token (bearer)
}

// Page is a Bitbucket paged response envelope.
type Page struct {
	Size          int  `json:"size"`
	Limit         int  `json:"limit"`
	Start         int  `json:"start"`
	IsLastPage    bool `json:"isLastPage"`
	NextPageStart int  `json:"nextPageStart"`
}

// User is a Bitbucket user.
type User struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	DisplayName  string `json:"displayName"`
	EmailAddress string `json:"emailAddress"`
	Active       bool   `json:"active"`
	Type         string `json:"type"`
}

// Project is a Bitbucket project.
type Project struct {
	ID          int64  `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Public      bool   `json:"public"`
	Type        string `json:"type"`
}

// Repository is a Bitbucket repository.
type Repository struct {
	ID            int64   `json:"id"`
	Slug          string  `json:"slug"`
	Name          string  `json:"name"`
	ScmID         string  `json:"scmId"`
	State         string  `json:"state"`
	Public        bool    `json:"public"`
	Forkable      bool    `json:"forkable"`
	Project       Project `json:"project"`
	DefaultBranch string  `json:"defaultBranch,omitempty"`
}

// Branch is a repository branch or tag ref.
type Branch struct {
	ID              string `json:"id"`
	DisplayID       string `json:"displayId"`
	Type            string `json:"type"`
	LatestCommit    string `json:"latestCommit"`
	LatestChangeset string `json:"latestChangeset"`
	IsDefault       bool   `json:"isDefault"`
}

// Commit is a repository commit.
type Commit struct {
	ID                 string   `json:"id"`
	DisplayID          string   `json:"displayId"`
	Message            string   `json:"message"`
	Author             Person   `json:"author"`
	AuthorTimestamp    int64    `json:"authorTimestamp"`
	Committer          Person   `json:"committer"`
	CommitterTimestamp int64    `json:"committerTimestamp"`
	Parents            []Commit `json:"parents,omitempty"`
}

// Person is a commit author or committer.
type Person struct {
	Name         string `json:"name"`
	EmailAddress string `json:"emailAddress"`
}

// PullRequest is a pull request summary.
type PullRequest struct {
	ID          int            `json:"id"`
	Version     int            `json:"version"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	State       string         `json:"state"`
	Open        bool           `json:"open"`
	Closed      bool           `json:"closed"`
	CreatedDate int64          `json:"createdDate"`
	UpdatedDate int64          `json:"updatedDate"`
	FromRef     Ref            `json:"fromRef"`
	ToRef       Ref            `json:"toRef"`
	Author      Participant    `json:"author"`
	Reviewers   []Participant  `json:"reviewers"`
	Properties  map[string]any `json:"properties,omitempty"`
	Links       map[string]any `json:"links,omitempty"`
}

// Ref is a pull request source or target ref.
type Ref struct {
	ID           string     `json:"id"`
	DisplayID    string     `json:"displayId"`
	LatestCommit string     `json:"latestCommit"`
	Repository   Repository `json:"repository"`
}

// Participant is a pull request author, reviewer or participant.
type Participant struct {
	User     User   `json:"user"`
	Role     string `json:"role"`
	Approved bool   `json:"approved"`
	Status   string `json:"status"`
}

// Comment is a pull request comment.
type Comment struct {
	ID          int       `json:"id"`
	Version     int       `json:"version"`
	Text        string    `json:"text"`
	Author      User      `json:"author"`
	CreatedDate int64     `json:"createdDate"`
	UpdatedDate int64     `json:"updatedDate"`
	Comments    []Comment `json:"comments,omitempty"`
}

// FileEntry is one node of a repository tree listing.
type FileEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
}

// Adapter is the Bitbucket capability surface bbmcp depends on.
type Adapter interface {
	// Identity
	WhoAmI(ctx context.Context, cred Credential) (*User, error)
	FindUserByUsername(ctx context.Context, cred Credential, username string) (*User, error)

	// Discovery
	Projects(ctx context.Context, cred Credential, filter string, start, limit int) ([]Project, Page, error)
	Project(ctx context.Context, cred Credential, key string) (*Project, error)
	Repositories(ctx context.Context, cred Credential, projectKey, filter string, start, limit int) ([]Repository, Page, error)
	Repository(ctx context.Context, cred Credential, projectKey, slug string) (*Repository, error)
	DefaultBranch(ctx context.Context, cred Credential, projectKey, slug string) (*Branch, error)

	// Content
	Tree(ctx context.Context, cred Credential, projectKey, slug, path, at string, start, limit int) ([]FileEntry, Page, error)
	File(ctx context.Context, cred Credential, projectKey, slug, path, at string, maxBytes int) (string, bool, error)

	// History
	Commits(ctx context.Context, cred Credential, projectKey, slug, until, path string, start, limit int) ([]Commit, Page, error)
	Commit(ctx context.Context, cred Credential, projectKey, slug, id string) (*Commit, error)
	CommitChanges(ctx context.Context, cred Credential, projectKey, slug, id string, start, limit int) (any, error)
	Diff(ctx context.Context, cred Credential, projectKey, slug, from, to, path string, contextLines int) (string, error)

	// Refs
	Branches(ctx context.Context, cred Credential, projectKey, slug, filter string, start, limit int) ([]Branch, Page, error)
	Tags(ctx context.Context, cred Credential, projectKey, slug, filter string, start, limit int) ([]Branch, Page, error)
	CreateBranch(ctx context.Context, cred Credential, projectKey, slug, name, startPoint string) (*Branch, error)
	BranchRestrictions(ctx context.Context, cred Credential, projectKey, slug string) (any, error)

	// Pull requests
	PullRequests(ctx context.Context, cred Credential, projectKey, slug, state, at string, start, limit int) ([]PullRequest, Page, error)
	PullRequest(ctx context.Context, cred Credential, projectKey, slug string, id int) (*PullRequest, error)
	PullRequestCommits(ctx context.Context, cred Credential, projectKey, slug string, id, start, limit int) ([]Commit, Page, error)
	PullRequestChanges(ctx context.Context, cred Credential, projectKey, slug string, id, start, limit int) (any, error)
	PullRequestDiff(ctx context.Context, cred Credential, projectKey, slug string, id, contextLines int) (string, error)
	PullRequestComments(ctx context.Context, cred Credential, projectKey, slug string, id, start, limit int) ([]Comment, Page, error)
	PullRequestActivities(ctx context.Context, cred Credential, projectKey, slug string, id, start, limit int) (any, error)

	// Pull request writes
	CreatePullRequest(ctx context.Context, cred Credential, projectKey, slug, title, description, fromRef, toRef string, reviewers []string) (*PullRequest, error)
	CommentPullRequest(ctx context.Context, cred Credential, projectKey, slug string, id int, text string, parentID int) (*Comment, error)
	UpdatePullRequest(ctx context.Context, cred Credential, projectKey, slug string, id, version int, title, description string) (*PullRequest, error)
	ApprovePullRequest(ctx context.Context, cred Credential, projectKey, slug string, id int, status string) (any, error)
	DeclinePullRequest(ctx context.Context, cred Credential, projectKey, slug string, id, version int) (*PullRequest, error)
	MergePullRequest(ctx context.Context, cred Credential, projectKey, slug string, id, version int, message string) (*PullRequest, error)

	// Permission inspection (REST fallback path)
	GlobalPermission(ctx context.Context, cred Credential, username string) (string, error)
	ProjectPermissionForUser(ctx context.Context, cred Credential, projectKey, username string) (string, error)
	RepoPermissionForUser(ctx context.Context, cred Credential, projectKey, slug, username string) (string, error)
	UserGroups(ctx context.Context, cred Credential, username string) ([]string, error)
	ProjectGroupPermissions(ctx context.Context, cred Credential, projectKey string) (map[string]string, error)
	RepoGroupPermissions(ctx context.Context, cred Credential, projectKey, slug string) (map[string]string, error)

	// Search (implementation may be swapped per Bitbucket deployment)
	SearchCode(ctx context.Context, cred Credential, query, projectKey, slug string, limit int) (any, error)

	// Health
	Ping(ctx context.Context, cred Credential) error
}
