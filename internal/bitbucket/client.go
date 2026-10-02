package bitbucket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hkjang/bbmcp/internal/settings"
)

// APIError carries a Bitbucket REST failure.
type APIError struct {
	Status  int
	Code    string
	Message string
	Body    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("Bitbucket %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("Bitbucket %d", e.Status)
}

// NotFound reports whether the error is a 404.
func (e *APIError) NotFound() bool { return e.Status == http.StatusNotFound }

// Client is the Bitbucket Server 6.9.1 REST adapter.
type Client struct {
	cfg  settings.Bitbucket
	http *http.Client
	base string
}

var _ Adapter = (*Client)(nil)

// NewClient builds a REST client from settings.
func NewClient(cfg settings.Bitbucket) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errors.New("Bitbucket 기본 URL이 설정되지 않았습니다")
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 30
	}
	if cfg.RestPrefix == "" {
		cfg.RestPrefix = "/rest/api/1.0"
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 8,
	}
	if cfg.InsecureSkipTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - operator opt-in for internal CAs
	}
	return &Client{
		cfg:  cfg,
		base: base,
		http: &http.Client{Transport: tr, Timeout: time.Duration(cfg.TimeoutSec) * time.Second},
	}, nil
}

// Config exposes the settings the client was built with.
func (c *Client) Config() settings.Bitbucket { return c.cfg }

func (c *Client) limit(n int) int {
	if n <= 0 {
		if c.cfg.PageSize > 0 {
			return c.cfg.PageSize
		}
		return 50
	}
	if n > 1000 {
		return 1000
	}
	return n
}

// do performs a REST request against an arbitrary path (prefix included).
func (c *Client) do(ctx context.Context, cred Credential, method, path string, query url.Values, body any, accept string) ([]byte, int, error) {
	if cred.Token == "" {
		return nil, 0, errors.New("Bitbucket 접근 토큰이 없습니다 (서비스 계정 PAT 또는 사용자 PAT 필요)")
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+cred.Token)
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-Atlassian-Token", "no-check")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("Bitbucket 요청 실패: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode >= 400 {
		return raw, resp.StatusCode, parseAPIError(resp.StatusCode, raw)
	}
	return raw, resp.StatusCode, nil
}

func parseAPIError(status int, raw []byte) error {
	var env struct {
		Errors []struct {
			Context       string `json:"context"`
			Message       string `json:"message"`
			ExceptionName string `json:"exceptionName"`
		} `json:"errors"`
	}
	e := &APIError{Status: status, Body: truncate(string(raw), 2000)}
	if json.Unmarshal(raw, &env) == nil && len(env.Errors) > 0 {
		e.Message = env.Errors[0].Message
		e.Code = env.Errors[0].ExceptionName
	}
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	return e
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// api performs a request under the configured REST prefix and decodes JSON.
func (c *Client) api(ctx context.Context, cred Credential, method, path string, query url.Values, body, out any) error {
	raw, _, err := c.do(ctx, cred, method, c.cfg.RestPrefix+path, query, body, "")
	if err != nil {
		return err
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func pageQuery(start, limit int) url.Values {
	q := url.Values{}
	if start > 0 {
		q.Set("start", strconv.Itoa(start))
	}
	q.Set("limit", strconv.Itoa(limit))
	return q
}

func repoPath(projectKey, slug string) string {
	return "/projects/" + url.PathEscape(projectKey) + "/repos/" + url.PathEscape(slug)
}

// ---------- identity ----------

// WhoAmI returns the user the credential belongs to.
func (c *Client) WhoAmI(ctx context.Context, cred Credential) (*User, error) {
	// Bitbucket Server has no /me on the 1.0 API; the authenticated username is
	// returned in a response header by the /users endpoint, so resolve by name.
	name := cred.Username
	if name == "" {
		raw, _, err := c.do(ctx, cred, http.MethodGet, c.cfg.RestPrefix+"/users", pageQuery(0, 1), nil, "")
		if err != nil {
			return nil, err
		}
		_ = raw
		return nil, errors.New("자격증명에 연결된 Bitbucket 사용자명을 알 수 없습니다")
	}
	return c.FindUserByUsername(ctx, cred, name)
}

// FindUserByUsername resolves a username to a Bitbucket user, requiring an
// exact (case-insensitive) match so a filter hit is never mistaken for the user.
func (c *Client) FindUserByUsername(ctx context.Context, cred Credential, username string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("사용자명이 비어 있습니다")
	}

	// Direct slug lookup first; it is exact when it succeeds.
	var direct User
	err := c.api(ctx, cred, http.MethodGet, "/users/"+url.PathEscape(strings.ToLower(username)), nil, nil, &direct)
	if err == nil && direct.ID != 0 && strings.EqualFold(direct.Name, username) {
		return &direct, nil
	}

	q := url.Values{}
	q.Set("filter", username)
	q.Set("limit", "100")
	var res struct {
		Page
		Values []User `json:"values"`
	}
	if err := c.api(ctx, cred, http.MethodGet, "/users", q, nil, &res); err != nil {
		return nil, err
	}
	for _, u := range res.Values {
		if strings.EqualFold(u.Name, username) || strings.EqualFold(u.Slug, username) {
			match := u
			return &match, nil
		}
	}
	return nil, fmt.Errorf("Bitbucket 사용자 %q 를 정확히 찾을 수 없습니다", username)
}

// ---------- discovery ----------

// Projects lists projects visible to the credential.
func (c *Client) Projects(ctx context.Context, cred Credential, filter string, start, limit int) ([]Project, Page, error) {
	q := pageQuery(start, c.limit(limit))
	if filter != "" {
		q.Set("name", filter)
	}
	var res struct {
		Page
		Values []Project `json:"values"`
	}
	err := c.api(ctx, cred, http.MethodGet, "/projects", q, nil, &res)
	return res.Values, res.Page, err
}

// Project fetches one project.
func (c *Client) Project(ctx context.Context, cred Credential, key string) (*Project, error) {
	var p Project
	if err := c.api(ctx, cred, http.MethodGet, "/projects/"+url.PathEscape(key), nil, nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Repositories lists repositories, either in one project or across all.
func (c *Client) Repositories(ctx context.Context, cred Credential, projectKey, filter string, start, limit int) ([]Repository, Page, error) {
	q := pageQuery(start, c.limit(limit))
	path := "/repos"
	if projectKey != "" {
		path = "/projects/" + url.PathEscape(projectKey) + "/repos"
	} else if filter != "" {
		q.Set("name", filter)
	}
	var res struct {
		Page
		Values []Repository `json:"values"`
	}
	err := c.api(ctx, cred, http.MethodGet, path, q, nil, &res)
	return res.Values, res.Page, err
}

// Repository fetches one repository.
func (c *Client) Repository(ctx context.Context, cred Credential, projectKey, slug string) (*Repository, error) {
	var r Repository
	if err := c.api(ctx, cred, http.MethodGet, repoPath(projectKey, slug), nil, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// DefaultBranch returns the repository default branch.
func (c *Client) DefaultBranch(ctx context.Context, cred Credential, projectKey, slug string) (*Branch, error) {
	var b Branch
	if err := c.api(ctx, cred, http.MethodGet, repoPath(projectKey, slug)+"/branches/default", nil, nil, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// ---------- content ----------

type browseResponse struct {
	Path     json.RawMessage `json:"path"`
	Revision string          `json:"revision"`
	Children *struct {
		Page
		Values []struct {
			Path struct {
				Components []string `json:"components"`
				Name       string   `json:"name"`
				ToString   string   `json:"toString"`
			} `json:"path"`
			ContentID string `json:"contentId"`
			Type      string `json:"type"`
			Size      int64  `json:"size"`
		} `json:"values"`
	} `json:"children"`
	Lines *struct {
		Page
		Values []struct {
			Text string `json:"text"`
		} `json:"values"`
	} `json:"lines"`
}

// Tree lists the children of a repository path.
func (c *Client) Tree(ctx context.Context, cred Credential, projectKey, slug, path, at string, start, limit int) ([]FileEntry, Page, error) {
	q := pageQuery(start, c.limit(limit))
	if at != "" {
		q.Set("at", at)
	}
	p := repoPath(projectKey, slug) + "/browse"
	if cleaned := strings.Trim(path, "/"); cleaned != "" {
		p += "/" + escapePath(cleaned)
	}
	var res browseResponse
	if err := c.api(ctx, cred, http.MethodGet, p, q, nil, &res); err != nil {
		return nil, Page{}, err
	}
	if res.Children == nil {
		return nil, Page{}, fmt.Errorf("%s 는 디렉터리가 아닙니다", path)
	}
	out := make([]FileEntry, 0, len(res.Children.Values))
	for _, v := range res.Children.Values {
		full := strings.Trim(strings.Trim(path, "/")+"/"+v.Path.ToString, "/")
		out = append(out, FileEntry{Path: full, Type: v.Type, Size: v.Size})
	}
	return out, res.Children.Page, nil
}

// File returns the text content of a file, flagging truncation.
func (c *Client) File(ctx context.Context, cred Credential, projectKey, slug, path, at string, maxBytes int) (string, bool, error) {
	if maxBytes <= 0 {
		maxBytes = 512 * 1024
	}
	cleaned := strings.Trim(path, "/")
	if cleaned == "" {
		return "", false, errors.New("파일 경로가 필요합니다")
	}
	var sb strings.Builder
	start := 0
	truncated := false
	for page := 0; page < 200; page++ {
		q := pageQuery(start, 2000)
		if at != "" {
			q.Set("at", at)
		}
		var res browseResponse
		err := c.api(ctx, cred, http.MethodGet,
			repoPath(projectKey, slug)+"/browse/"+escapePath(cleaned), q, nil, &res)
		if err != nil {
			return "", false, err
		}
		if res.Lines == nil {
			return "", false, fmt.Errorf("%s 는 텍스트 파일이 아니거나 조회할 수 없습니다", path)
		}
		for _, l := range res.Lines.Values {
			if sb.Len()+len(l.Text)+1 > maxBytes {
				truncated = true
				break
			}
			sb.WriteString(l.Text)
			sb.WriteByte('\n')
		}
		if truncated || res.Lines.IsLastPage || len(res.Lines.Values) == 0 {
			break
		}
		start = res.Lines.NextPageStart
	}
	return sb.String(), truncated, nil
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

// ---------- history ----------

// Commits lists commits reachable from until.
func (c *Client) Commits(ctx context.Context, cred Credential, projectKey, slug, until, path string, start, limit int) ([]Commit, Page, error) {
	q := pageQuery(start, c.limit(limit))
	if until != "" {
		q.Set("until", until)
	}
	if path != "" {
		q.Set("path", path)
	}
	var res struct {
		Page
		Values []Commit `json:"values"`
	}
	err := c.api(ctx, cred, http.MethodGet, repoPath(projectKey, slug)+"/commits", q, nil, &res)
	return res.Values, res.Page, err
}

// Commit fetches one commit.
func (c *Client) Commit(ctx context.Context, cred Credential, projectKey, slug, id string) (*Commit, error) {
	var cm Commit
	if err := c.api(ctx, cred, http.MethodGet,
		repoPath(projectKey, slug)+"/commits/"+url.PathEscape(id), nil, nil, &cm); err != nil {
		return nil, err
	}
	return &cm, nil
}

// CommitChanges lists the files touched by a commit.
func (c *Client) CommitChanges(ctx context.Context, cred Credential, projectKey, slug, id string, start, limit int) (any, error) {
	var out any
	err := c.api(ctx, cred, http.MethodGet,
		repoPath(projectKey, slug)+"/commits/"+url.PathEscape(id)+"/changes",
		pageQuery(start, c.limit(limit)), nil, &out)
	return out, err
}

// Diff returns a unified diff between two refs.
func (c *Client) Diff(ctx context.Context, cred Credential, projectKey, slug, from, to, path string, contextLines int) (string, error) {
	q := url.Values{}
	if from != "" {
		q.Set("from", from)
	}
	if to != "" {
		q.Set("to", to)
	}
	if contextLines > 0 {
		q.Set("contextLines", strconv.Itoa(contextLines))
	}
	p := repoPath(projectKey, slug) + "/compare/diff"
	if cleaned := strings.Trim(path, "/"); cleaned != "" {
		p += "/" + escapePath(cleaned)
	}
	raw, _, err := c.do(ctx, cred, http.MethodGet, c.cfg.RestPrefix+p, q, nil, "text/plain")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ---------- refs ----------

// Branches lists branches.
func (c *Client) Branches(ctx context.Context, cred Credential, projectKey, slug, filter string, start, limit int) ([]Branch, Page, error) {
	q := pageQuery(start, c.limit(limit))
	if filter != "" {
		q.Set("filterText", filter)
	}
	q.Set("details", "true")
	var res struct {
		Page
		Values []Branch `json:"values"`
	}
	err := c.api(ctx, cred, http.MethodGet, repoPath(projectKey, slug)+"/branches", q, nil, &res)
	return res.Values, res.Page, err
}

// Tags lists tags.
func (c *Client) Tags(ctx context.Context, cred Credential, projectKey, slug, filter string, start, limit int) ([]Branch, Page, error) {
	q := pageQuery(start, c.limit(limit))
	if filter != "" {
		q.Set("filterText", filter)
	}
	var res struct {
		Page
		Values []Branch `json:"values"`
	}
	err := c.api(ctx, cred, http.MethodGet, repoPath(projectKey, slug)+"/tags", q, nil, &res)
	return res.Values, res.Page, err
}

// CreateBranch creates a branch through the branch-utils API.
func (c *Client) CreateBranch(ctx context.Context, cred Credential, projectKey, slug, name, startPoint string) (*Branch, error) {
	body := map[string]any{"name": name, "startPoint": startPoint}
	raw, _, err := c.do(ctx, cred, http.MethodPost,
		"/rest/branch-utils/1.0"+repoPath(projectKey, slug)+"/branches", nil, body, "")
	if err != nil {
		return nil, err
	}
	var b Branch
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// BranchRestrictions returns the branch permission restrictions of a repository.
func (c *Client) BranchRestrictions(ctx context.Context, cred Credential, projectKey, slug string) (any, error) {
	raw, _, err := c.do(ctx, cred, http.MethodGet,
		"/rest/branch-permissions/2.0"+repoPath(projectKey, slug)+"/restrictions",
		pageQuery(0, 200), nil, "")
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------- pull requests ----------

func prPath(projectKey, slug string, id int) string {
	return repoPath(projectKey, slug) + "/pull-requests/" + strconv.Itoa(id)
}

// PullRequests lists pull requests.
func (c *Client) PullRequests(ctx context.Context, cred Credential, projectKey, slug, state, at string, start, limit int) ([]PullRequest, Page, error) {
	q := pageQuery(start, c.limit(limit))
	if state != "" {
		q.Set("state", strings.ToUpper(state))
	}
	if at != "" {
		q.Set("at", at)
	}
	var res struct {
		Page
		Values []PullRequest `json:"values"`
	}
	err := c.api(ctx, cred, http.MethodGet, repoPath(projectKey, slug)+"/pull-requests", q, nil, &res)
	return res.Values, res.Page, err
}

// PullRequest fetches one pull request.
func (c *Client) PullRequest(ctx context.Context, cred Credential, projectKey, slug string, id int) (*PullRequest, error) {
	var pr PullRequest
	if err := c.api(ctx, cred, http.MethodGet, prPath(projectKey, slug, id), nil, nil, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// PullRequestCommits lists the commits of a pull request.
func (c *Client) PullRequestCommits(ctx context.Context, cred Credential, projectKey, slug string, id, start, limit int) ([]Commit, Page, error) {
	var res struct {
		Page
		Values []Commit `json:"values"`
	}
	err := c.api(ctx, cred, http.MethodGet, prPath(projectKey, slug, id)+"/commits",
		pageQuery(start, c.limit(limit)), nil, &res)
	return res.Values, res.Page, err
}

// PullRequestChanges lists the files changed in a pull request.
func (c *Client) PullRequestChanges(ctx context.Context, cred Credential, projectKey, slug string, id, start, limit int) (any, error) {
	var out any
	err := c.api(ctx, cred, http.MethodGet, prPath(projectKey, slug, id)+"/changes",
		pageQuery(start, c.limit(limit)), nil, &out)
	return out, err
}

// PullRequestDiff returns the unified diff of a pull request.
func (c *Client) PullRequestDiff(ctx context.Context, cred Credential, projectKey, slug string, id, contextLines int) (string, error) {
	q := url.Values{}
	if contextLines > 0 {
		q.Set("contextLines", strconv.Itoa(contextLines))
	}
	raw, _, err := c.do(ctx, cred, http.MethodGet,
		c.cfg.RestPrefix+prPath(projectKey, slug, id)+"/diff", q, nil, "text/plain")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// PullRequestComments lists the top-level comments of a pull request.
func (c *Client) PullRequestComments(ctx context.Context, cred Credential, projectKey, slug string, id, start, limit int) ([]Comment, Page, error) {
	// 6.x exposes comments through the activities feed; filter to COMMENTED.
	var res struct {
		Page
		Values []struct {
			Action  string  `json:"action"`
			Comment Comment `json:"comment"`
		} `json:"values"`
	}
	err := c.api(ctx, cred, http.MethodGet, prPath(projectKey, slug, id)+"/activities",
		pageQuery(start, c.limit(limit)), nil, &res)
	if err != nil {
		return nil, Page{}, err
	}
	out := []Comment{}
	for _, v := range res.Values {
		if v.Action == "COMMENTED" && v.Comment.ID != 0 {
			out = append(out, v.Comment)
		}
	}
	return out, res.Page, nil
}

// PullRequestActivities returns the raw activity feed.
func (c *Client) PullRequestActivities(ctx context.Context, cred Credential, projectKey, slug string, id, start, limit int) (any, error) {
	var out any
	err := c.api(ctx, cred, http.MethodGet, prPath(projectKey, slug, id)+"/activities",
		pageQuery(start, c.limit(limit)), nil, &out)
	return out, err
}

// CreatePullRequest opens a pull request.
func (c *Client) CreatePullRequest(ctx context.Context, cred Credential, projectKey, slug, title, description, fromRef, toRef string, reviewers []string) (*PullRequest, error) {
	revs := make([]map[string]any, 0, len(reviewers))
	for _, r := range reviewers {
		if strings.TrimSpace(r) == "" {
			continue
		}
		revs = append(revs, map[string]any{"user": map[string]any{"name": r}})
	}
	repoRef := map[string]any{
		"slug":    slug,
		"project": map[string]any{"key": projectKey},
	}
	body := map[string]any{
		"title":       title,
		"description": description,
		"state":       "OPEN",
		"open":        true,
		"closed":      false,
		"fromRef":     map[string]any{"id": fromRef, "repository": repoRef},
		"toRef":       map[string]any{"id": toRef, "repository": repoRef},
		"locked":      false,
		"reviewers":   revs,
	}
	var pr PullRequest
	if err := c.api(ctx, cred, http.MethodPost, repoPath(projectKey, slug)+"/pull-requests", nil, body, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// CommentPullRequest adds a comment, optionally as a reply.
func (c *Client) CommentPullRequest(ctx context.Context, cred Credential, projectKey, slug string, id int, text string, parentID int) (*Comment, error) {
	body := map[string]any{"text": text}
	if parentID > 0 {
		body["parent"] = map[string]any{"id": parentID}
	}
	var cm Comment
	if err := c.api(ctx, cred, http.MethodPost, prPath(projectKey, slug, id)+"/comments", nil, body, &cm); err != nil {
		return nil, err
	}
	return &cm, nil
}

// UpdatePullRequest edits a pull request title or description.
func (c *Client) UpdatePullRequest(ctx context.Context, cred Credential, projectKey, slug string, id, version int, title, description string) (*PullRequest, error) {
	body := map[string]any{"version": version}
	if title != "" {
		body["title"] = title
	}
	if description != "" {
		body["description"] = description
	}
	var pr PullRequest
	if err := c.api(ctx, cred, http.MethodPut, prPath(projectKey, slug, id), nil, body, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// ApprovePullRequest sets the participant status of the credential's user.
func (c *Client) ApprovePullRequest(ctx context.Context, cred Credential, projectKey, slug string, id int, status string) (any, error) {
	if status == "" {
		status = "APPROVED"
	}
	if cred.Username != "" {
		var out any
		err := c.api(ctx, cred, http.MethodPut,
			prPath(projectKey, slug, id)+"/participants/"+url.PathEscape(strings.ToLower(cred.Username)),
			nil, map[string]any{"status": strings.ToUpper(status)}, &out)
		if err == nil {
			return out, nil
		}
	}
	var out any
	err := c.api(ctx, cred, http.MethodPost, prPath(projectKey, slug, id)+"/approve", nil, nil, &out)
	return out, err
}

// DeclinePullRequest declines a pull request at a known version.
func (c *Client) DeclinePullRequest(ctx context.Context, cred Credential, projectKey, slug string, id, version int) (*PullRequest, error) {
	q := url.Values{}
	q.Set("version", strconv.Itoa(version))
	var pr PullRequest
	if err := c.api(ctx, cred, http.MethodPost, prPath(projectKey, slug, id)+"/decline", q, nil, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// MergePullRequest merges a pull request at a known version.
func (c *Client) MergePullRequest(ctx context.Context, cred Credential, projectKey, slug string, id, version int, message string) (*PullRequest, error) {
	q := url.Values{}
	q.Set("version", strconv.Itoa(version))
	var body any
	if message != "" {
		body = map[string]any{"message": message}
	}
	var pr PullRequest
	if err := c.api(ctx, cred, http.MethodPost, prPath(projectKey, slug, id)+"/merge", q, body, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// ---------- permission inspection ----------

type permEntry struct {
	User       User                  `json:"user"`
	Group      struct{ Name string } `json:"group"`
	Permission string                `json:"permission"`
}

// GlobalPermission returns the highest global permission of a user.
func (c *Client) GlobalPermission(ctx context.Context, cred Credential, username string) (string, error) {
	q := url.Values{}
	q.Set("filter", username)
	q.Set("limit", "100")
	var res struct {
		Values []permEntry `json:"values"`
	}
	if err := c.api(ctx, cred, http.MethodGet, "/admin/permissions/users", q, nil, &res); err != nil {
		return "", err
	}
	for _, v := range res.Values {
		if strings.EqualFold(v.User.Name, username) {
			return v.Permission, nil
		}
	}
	return "", nil
}

// ProjectPermissionForUser returns a user's direct project permission.
func (c *Client) ProjectPermissionForUser(ctx context.Context, cred Credential, projectKey, username string) (string, error) {
	q := url.Values{}
	q.Set("filter", username)
	q.Set("limit", "100")
	var res struct {
		Values []permEntry `json:"values"`
	}
	if err := c.api(ctx, cred, http.MethodGet,
		"/projects/"+url.PathEscape(projectKey)+"/permissions/users", q, nil, &res); err != nil {
		return "", err
	}
	for _, v := range res.Values {
		if strings.EqualFold(v.User.Name, username) {
			return v.Permission, nil
		}
	}
	return "", nil
}

// RepoPermissionForUser returns a user's direct repository permission.
func (c *Client) RepoPermissionForUser(ctx context.Context, cred Credential, projectKey, slug, username string) (string, error) {
	q := url.Values{}
	q.Set("filter", username)
	q.Set("limit", "100")
	var res struct {
		Values []permEntry `json:"values"`
	}
	if err := c.api(ctx, cred, http.MethodGet,
		repoPath(projectKey, slug)+"/permissions/users", q, nil, &res); err != nil {
		return "", err
	}
	for _, v := range res.Values {
		if strings.EqualFold(v.User.Name, username) {
			return v.Permission, nil
		}
	}
	return "", nil
}

// UserGroups lists the groups a user belongs to.
func (c *Client) UserGroups(ctx context.Context, cred Credential, username string) ([]string, error) {
	q := url.Values{}
	q.Set("context", username)
	q.Set("limit", "200")
	var res struct {
		Values []struct {
			Name string `json:"name"`
		} `json:"values"`
	}
	if err := c.api(ctx, cred, http.MethodGet, "/admin/users/more-members", q, nil, &res); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Values))
	for _, g := range res.Values {
		out = append(out, g.Name)
	}
	return out, nil
}

// ProjectGroupPermissions maps group name to project permission.
func (c *Client) ProjectGroupPermissions(ctx context.Context, cred Credential, projectKey string) (map[string]string, error) {
	return c.groupPerms(ctx, cred, "/projects/"+url.PathEscape(projectKey)+"/permissions/groups")
}

// RepoGroupPermissions maps group name to repository permission.
func (c *Client) RepoGroupPermissions(ctx context.Context, cred Credential, projectKey, slug string) (map[string]string, error) {
	return c.groupPerms(ctx, cred, repoPath(projectKey, slug)+"/permissions/groups")
}

func (c *Client) groupPerms(ctx context.Context, cred Credential, path string) (map[string]string, error) {
	q := url.Values{}
	q.Set("limit", "500")
	var res struct {
		Values []permEntry `json:"values"`
	}
	if err := c.api(ctx, cred, http.MethodGet, path, q, nil, &res); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, v := range res.Values {
		if v.Group.Name != "" {
			out[strings.ToLower(v.Group.Name)] = v.Permission
		}
	}
	return out, nil
}

// Ping verifies connectivity and credential validity.
func (c *Client) Ping(ctx context.Context, cred Credential) error {
	_, _, err := c.do(ctx, cred, http.MethodGet, c.cfg.RestPrefix+"/projects", pageQuery(0, 1), nil, "")
	return err
}

// SearchCode queries the Bitbucket code search API.
//
// Search availability varies by Bitbucket Server deployment, so this is kept
// behind a single adapter method: swapping in a different index (or an
// external one) does not change the MCP tool contract.
func (c *Client) SearchCode(ctx context.Context, cred Credential, query, projectKey, slug string, limit int) (any, error) {
	if strings.TrimSpace(query) == "" {
		return nil, errors.New("검색어가 필요합니다")
	}
	scoped := query
	if projectKey != "" {
		scoped += " project:" + projectKey
	}
	if slug != "" {
		scoped += " repo:" + slug
	}
	body := map[string]any{
		"query": scoped,
		"entities": map[string]any{
			"code": map[string]any{"start": 0, "limit": c.limit(limit)},
		},
	}
	raw, _, err := c.do(ctx, cred, http.MethodPost, "/rest/search/1.0/search", nil, body, "")
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 501) {
			return nil, fmt.Errorf("이 Bitbucket 인스턴스에서 코드 검색 API를 사용할 수 없습니다: %w", err)
		}
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
