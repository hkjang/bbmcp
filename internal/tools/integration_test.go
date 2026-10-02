package tools_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hkjang/bbmcp/internal/approval"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/crypto"
	"github.com/hkjang/bbmcp/internal/database"
	"github.com/hkjang/bbmcp/internal/identity"
	"github.com/hkjang/bbmcp/internal/permission"
	"github.com/hkjang/bbmcp/internal/policy"
	"github.com/hkjang/bbmcp/internal/settings"
	"github.com/hkjang/bbmcp/internal/tools"
)

// fixture wires a real database, a fake Bitbucket and the whole tool pipeline.
type fixture struct {
	db        *database.DB
	store     *settings.Store
	exec      *tools.Executor
	approvals *approval.Engine
	policy    *policy.Engine
	registry  *tools.Registry
	mapper    *identity.Mapper
	bitbucket *fakeBitbucket
	ctx       context.Context
}

// fakeBitbucket records what the gateway asked for and answers like
// Bitbucket Server 6.9.1 would.
type fakeBitbucket struct {
	srv *httptest.Server

	// permissions keyed by "project" or "project/repo" for user hkjang.
	projectPerm map[string]string
	repoPerm    map[string]string
	groups      []string
	readOnly    bool
	prVersion   int
	comments    []string
	merged      bool
}

func newFakeBitbucket(t *testing.T) *fakeBitbucket {
	t.Helper()
	f := &fakeBitbucket{
		projectPerm: map[string]string{},
		repoPerm:    map[string]string{},
		prVersion:   14,
	}
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}

	mux.HandleFunc("/rest/api/1.0/users", func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("filter")
		if filter == "hkjang" || filter == "mcp-service" {
			id := 142
			if filter == "mcp-service" {
				id = 9
			}
			write(w, `{"size":1,"isLastPage":true,"values":[{"id":`+itoa(id)+
				`,"name":"`+filter+`","slug":"`+filter+`","displayName":"`+filter+`","active":true}]}`)
			return
		}
		write(w, `{"size":0,"isLastPage":true,"values":[]}`)
	})
	mux.HandleFunc("/rest/api/1.0/users/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"message":"no direct lookup"}]}`, http.StatusNotFound)
	})

	mux.HandleFunc("/rest/api/1.0/projects", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"size":2,"limit":50,"isLastPage":true,"values":[
			{"id":1,"key":"AI","name":"AI","public":false},
			{"id":2,"key":"HR","name":"HR","public":false}]}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"id":1,"key":"AI","name":"AI","public":false}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/HR", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"id":2,"key":"HR","name":"HR","public":false}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"id":10,"slug":"text2sql","name":"text2sql","public":false,
			"project":{"id":1,"key":"AI","name":"AI"}}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/branches/default", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"id":"refs/heads/master","displayId":"master","isDefault":true}`)
	})

	// Permission inspection.
	mux.HandleFunc("/rest/api/1.0/admin/permissions/users", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"values":[{"user":{"name":"hkjang"},"permission":"LICENSED_USER"}]}`)
	})
	mux.HandleFunc("/rest/api/1.0/admin/users/more-members", func(w http.ResponseWriter, r *http.Request) {
		values := make([]string, 0, len(f.groups))
		for _, g := range f.groups {
			values = append(values, `{"name":"`+g+`"}`)
		}
		write(w, `{"values":[`+strings.Join(values, ",")+`]}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/permissions/users", func(w http.ResponseWriter, r *http.Request) {
		f.writePerm(w, f.projectPerm["AI"])
	})
	mux.HandleFunc("/rest/api/1.0/projects/HR/permissions/users", func(w http.ResponseWriter, r *http.Request) {
		f.writePerm(w, f.projectPerm["HR"])
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/permissions/groups", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"values":[]}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/HR/permissions/groups", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"values":[]}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/permissions/users", func(w http.ResponseWriter, r *http.Request) {
		f.writePerm(w, f.repoPerm["AI/text2sql"])
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/permissions/groups", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"values":[]}`)
	})

	// Branch restrictions.
	mux.HandleFunc("/rest/branch-permissions/2.0/projects/AI/repos/text2sql/restrictions",
		func(w http.ResponseWriter, r *http.Request) {
			if !f.readOnly {
				write(w, `{"values":[]}`)
				return
			}
			write(w, `{"values":[{"id":1,"type":"read-only","matcher":{"id":"refs/heads/master",
				"displayId":"master","type":{"id":"BRANCH"}},"users":[],"groups":[]}]}`)
		})

	// Pull request read and write.
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/pull-requests/7",
		func(w http.ResponseWriter, r *http.Request) {
			write(w, `{"id":7,"version":`+itoa(f.prVersion)+`,"title":"fix","state":"OPEN","open":true,
				"fromRef":{"id":"refs/heads/feature/x"},"toRef":{"id":"refs/heads/master"}}`)
		})
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/pull-requests/7/comments",
		func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			text, _ := body["text"].(string)
			f.comments = append(f.comments, text)
			write(w, `{"id":55,"version":0,"text":`+quote(text)+`,"author":{"name":"mcp-service"}}`)
		})
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/pull-requests/7/merge",
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("version") != itoa(f.prVersion) {
				http.Error(w, `{"errors":[{"message":"out of date"}]}`, http.StatusConflict)
				return
			}
			f.merged = true
			write(w, `{"id":7,"version":`+itoa(f.prVersion+1)+`,"state":"MERGED","open":false}`)
		})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"message":"unhandled `+r.URL.Path+`"}]}`, http.StatusNotFound)
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBitbucket) writePerm(w http.ResponseWriter, perm string) {
	w.Header().Set("Content-Type", "application/json")
	if perm == "" {
		_, _ = w.Write([]byte(`{"values":[]}`))
		return
	}
	_, _ = w.Write([]byte(`{"values":[{"user":{"name":"hkjang"},"permission":"` + perm + `"}]}`))
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL이 설정되지 않아 통합 테스트를 건너뜁니다")
	}
	ctx := context.Background()
	db, err := openTestDB(t, dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `TRUNCATE users, approval_requests, audit_log, policy_rules,
		bitbucket_identity_mapping, identity_mapping_errors, settings, mcp_tools RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	// The requester must exist, since approvals reference the account.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO users(id, username, display_name, keycloak_sub, roles, source)
		VALUES (1, 'hkjang', 'hkjang', 'sub-hkjang', ARRAY['bitbucket-mcp-executor'], 'keycloak')
		ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	fake := newFakeBitbucket(t)
	store := settings.NewStore(db.Pool, sealer)
	pat, _ := store.Seal("service-pat")
	bb := settings.DefaultBitbucket()
	bb.BaseURL = fake.srv.URL
	bb.ServiceUsername = "mcp-service"
	bb.ServicePATEnc = pat
	if err := store.Put(ctx, settings.KeyBitbucket, bb, "test"); err != nil {
		t.Fatalf("settings: %v", err)
	}
	perm := settings.DefaultPermission()
	perm.CacheTTLSec = 0
	if err := store.Put(ctx, settings.KeyPermission, perm, "test"); err != nil {
		t.Fatalf("settings: %v", err)
	}

	provider := bitbucket.NewProvider(store, db.Pool)
	resolver := permission.NewResolver(store, provider)
	policies := policy.NewEngine(db.Pool)
	approvals := approval.NewEngine(db.Pool)
	registry := tools.NewRegistry(db.Pool)
	if err := registry.Sync(ctx); err != nil {
		t.Fatalf("registry sync: %v", err)
	}
	mapper := identity.NewMapper(db.Pool, provider)

	exec := tools.NewExecutor(tools.Deps{
		Registry: registry, Provider: provider, Resolver: resolver, Policy: policies,
		Approvals: approvals, Audit: audit.New(db.Pool), Store: store,
	})
	return &fixture{
		db: db, store: store, exec: exec, approvals: approvals, policy: policies,
		registry: registry, mapper: mapper, bitbucket: fake, ctx: ctx,
	}
}

func (f *fixture) principal() tools.Principal {
	return tools.Principal{
		UserID:            1,
		KeycloakSub:       "sub-hkjang",
		Username:          "hkjang",
		Roles:             []string{tools.RoleExecutor},
		Scopes:            tools.ScopesForRoles([]string{tools.RoleExecutor}),
		BitbucketUserID:   142,
		BitbucketUsername: "hkjang",
		AuthMode:          "oauth",
		Client:            "test",
	}
}

func codeOf(t *testing.T, err error) string {
	t.Helper()
	var te *tools.Error
	if !errors.As(err, &te) {
		t.Fatalf("expected a tools.Error, got %v", err)
	}
	return te.Code
}

func TestReadToolRequiresUserPermissionNotServiceAccount(t *testing.T) {
	f := newFixture(t)

	// The service account can reach the repository; the user cannot.
	if _, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_get_repository", tools.Args{
		"project": "AI", "repository": "text2sql",
	}); codeOf(t, err) != tools.CodePermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED, got %v", err)
	}

	// Granting the user project read is enough to read the repository.
	f.bitbucket.projectPerm["AI"] = "PROJECT_READ"
	f.exec.Resolver.Reset()
	out, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_get_repository", tools.Args{
		"project": "AI", "repository": "text2sql",
	})
	if err != nil {
		t.Fatalf("read after grant: %v", err)
	}
	res, ok := out.(tools.Result)
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if res.Trust != "untrusted" {
		t.Errorf("repository payload not marked untrusted: %+v", res.Source)
	}
	if res.Source.Requester != "hkjang" {
		t.Errorf("provenance lost the requester: %+v", res.Source)
	}
}

func TestProjectListingIsFilteredToTheRequester(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_READ"
	// HR deliberately stays ungranted even though the service account sees it.

	out, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_projects", tools.Args{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	payload := out.(map[string]any)
	projects := payload["values"].([]bitbucket.Project)
	if len(projects) != 1 || projects[0].Key != "AI" {
		t.Fatalf("listing leaked projects: %+v", projects)
	}
}

func TestPolicyDenyOverridesBitbucketPermission(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_ADMIN"
	if _, err := f.policy.Create(f.ctx, policy.Rule{
		Kind: policy.KindProject, Pattern: "AI", Effect: policy.EffectDeny,
		Priority: 10, Note: "감사 중",
	}); err != nil {
		t.Fatalf("policy.Create: %v", err)
	}

	_, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_get_repository", tools.Args{
		"project": "AI", "repository": "text2sql",
	})
	if got := codeOf(t, err); got != tools.CodePolicyDenied {
		t.Fatalf("expected POLICY_DENIED, got %s (%v)", got, err)
	}
}

func TestRiskCapBlocksWriteToolOnReadOnlyProject(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_WRITE"
	f.bitbucket.repoPerm["AI/text2sql"] = "REPO_WRITE"
	if _, err := f.policy.Create(f.ctx, policy.Rule{
		Kind: policy.KindProject, Pattern: "AI", Effect: policy.EffectAllow, RiskCap: "READ",
	}); err != nil {
		t.Fatalf("policy.Create: %v", err)
	}

	_, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_comment_pull_request", tools.Args{
		"project": "AI", "repository": "text2sql", "pullRequest": 7, "text": "검토 의견",
	})
	if got := codeOf(t, err); got != tools.CodePolicyDenied {
		t.Fatalf("expected POLICY_DENIED from the risk cap, got %s (%v)", got, err)
	}
}

func TestWriteToolRequiresApprovalBoundToArguments(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_WRITE"
	f.bitbucket.repoPerm["AI/text2sql"] = "REPO_WRITE"

	args := tools.Args{
		"project": "AI", "repository": "text2sql", "pullRequest": 7, "text": "검토 의견",
	}

	// 1. First call is refused and opens an approval request.
	_, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_comment_pull_request", args)
	var te *tools.Error
	if !errors.As(err, &te) || te.Code != tools.CodeApprovalRequired {
		t.Fatalf("expected APPROVAL_REQUIRED, got %v", err)
	}
	if te.Approval == nil {
		t.Fatal("no approval request was returned")
	}
	reqID := te.Approval.ID

	// 2. An unapproved id still fails.
	withID := cloneArgs(args)
	withID["approvalId"] = reqID.String()
	if _, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_comment_pull_request", withID); err == nil {
		t.Fatal("a pending approval was accepted")
	}

	// 3. After approval the call goes through.
	if _, err := f.approvals.Decide(f.ctx, reqID, true, "admin", "확인"); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if _, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_comment_pull_request", withID); err != nil {
		t.Fatalf("approved call failed: %v", err)
	}
	if len(f.bitbucket.comments) != 1 {
		t.Fatalf("comment count = %d", len(f.bitbucket.comments))
	}
	// Service-mode writes must name the real requester.
	if !strings.Contains(f.bitbucket.comments[0], "hkjang") {
		t.Errorf("attribution missing from comment: %q", f.bitbucket.comments[0])
	}

	// 4. The approval is single use.
	if _, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_comment_pull_request", withID); err == nil {
		t.Fatal("a consumed approval was reused")
	}
}

func TestApprovalGoesStaleWhenArgumentsChange(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_WRITE"
	f.bitbucket.repoPerm["AI/text2sql"] = "REPO_WRITE"

	args := tools.Args{"project": "AI", "repository": "text2sql", "pullRequest": 7, "text": "원래 의견"}
	_, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_comment_pull_request", args)
	var te *tools.Error
	if !errors.As(err, &te) || te.Approval == nil {
		t.Fatalf("expected an approval request, got %v", err)
	}
	if _, err := f.approvals.Decide(f.ctx, te.Approval.ID, true, "admin", ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	tampered := cloneArgs(args)
	tampered["text"] = "전혀 다른 내용"
	tampered["approvalId"] = te.Approval.ID.String()
	_, err = f.exec.Invoke(f.ctx, f.principal(), "bitbucket_comment_pull_request", tampered)
	if got := codeOf(t, err); got != tools.CodeApprovalStale {
		t.Fatalf("expected APPROVAL_STALE, got %s (%v)", got, err)
	}
	if len(f.bitbucket.comments) != 0 {
		t.Fatal("a tampered call reached Bitbucket")
	}
}

func TestMergeApprovalGoesStaleWhenPullRequestAdvances(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_WRITE"
	f.bitbucket.repoPerm["AI/text2sql"] = "REPO_WRITE"
	if err := f.registry.Update(f.ctx, "bitbucket_merge_pull_request", true, true, tools.RoleExecutor); err != nil {
		t.Fatalf("enable merge tool: %v", err)
	}

	args := tools.Args{"project": "AI", "repository": "text2sql", "pullRequest": 7}
	_, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_merge_pull_request", args)
	var te *tools.Error
	if !errors.As(err, &te) || te.Approval == nil {
		t.Fatalf("expected an approval request, got %v", err)
	}
	if te.Approval.PRVersion == nil || *te.Approval.PRVersion != 14 {
		t.Fatalf("approval did not pin the PR version: %+v", te.Approval.PRVersion)
	}
	if _, err := f.approvals.Decide(f.ctx, te.Approval.ID, true, "admin", ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	// A new commit lands on the pull request.
	f.bitbucket.prVersion = 15

	withID := cloneArgs(args)
	withID["approvalId"] = te.Approval.ID.String()
	_, err = f.exec.Invoke(f.ctx, f.principal(), "bitbucket_merge_pull_request", withID)
	if got := codeOf(t, err); got != tools.CodeApprovalStale {
		t.Fatalf("expected APPROVAL_STALE, got %s (%v)", got, err)
	}
	if f.bitbucket.merged {
		t.Fatal("a stale approval merged the pull request")
	}
}

func TestMergeBlockedByBranchRestriction(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_WRITE"
	f.bitbucket.repoPerm["AI/text2sql"] = "REPO_WRITE"
	f.bitbucket.readOnly = true
	if err := f.registry.Update(f.ctx, "bitbucket_merge_pull_request", true, true, tools.RoleExecutor); err != nil {
		t.Fatalf("enable merge tool: %v", err)
	}

	_, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_merge_pull_request", tools.Args{
		"project": "AI", "repository": "text2sql", "pullRequest": 7,
	})
	if got := codeOf(t, err); got != tools.CodeBranchRestricted {
		t.Fatalf("expected BRANCH_RESTRICTED, got %s (%v)", got, err)
	}
	if f.bitbucket.merged {
		t.Fatal("a restricted branch was merged")
	}
}

func TestDisabledToolIsRefused(t *testing.T) {
	f := newFixture(t)
	// Execute-tier tools ship disabled.
	_, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_approve_pull_request", tools.Args{
		"project": "AI", "repository": "text2sql", "pullRequest": 7, "approvalId": "x",
	})
	if got := codeOf(t, err); got != tools.CodeToolDisabled {
		t.Fatalf("expected TOOL_DISABLED, got %s (%v)", got, err)
	}
}

func TestRoleAndScopeGating(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_WRITE"
	f.bitbucket.repoPerm["AI/text2sql"] = "REPO_WRITE"

	reader := f.principal()
	reader.Roles = []string{tools.RoleUser}
	reader.Scopes = tools.ScopesForRoles(reader.Roles)

	_, err := f.exec.Invoke(f.ctx, reader, "bitbucket_comment_pull_request", tools.Args{
		"project": "AI", "repository": "text2sql", "pullRequest": 7, "text": "의견",
	})
	if got := codeOf(t, err); got != tools.CodeRoleDenied {
		t.Fatalf("expected ROLE_DENIED, got %s (%v)", got, err)
	}

	available, err := f.exec.Available(f.ctx, reader)
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	for _, rec := range available {
		if rec.Risk != tools.RiskRead {
			t.Fatalf("a reader was offered %s (%s)", rec.Name, rec.Risk)
		}
	}
}

func TestUnmappedIdentityCannotCallPermissionedTools(t *testing.T) {
	f := newFixture(t)
	p := f.principal()
	p.BitbucketUsername = ""
	p.BitbucketUserID = 0

	if _, err := f.exec.Invoke(f.ctx, p, "bitbucket_get_repository", tools.Args{
		"project": "AI", "repository": "text2sql",
	}); codeOf(t, err) != tools.CodeIdentityMissing {
		t.Fatalf("expected IDENTITY_UNMAPPED, got %v", err)
	}

	// Identity-only tools still work, since they need no Bitbucket permission.
	if _, err := f.exec.Invoke(f.ctx, p, "bitbucket_me", tools.Args{}); err != nil {
		t.Fatalf("bitbucket_me failed for an unmapped user: %v", err)
	}
}

func TestIdentityMappingBindsExactUsernameAndIsStable(t *testing.T) {
	f := newFixture(t)
	m, err := f.mapper.Resolve(f.ctx, "sub-hkjang", "hkjang")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if m.BitbucketUserID != 142 || m.BitbucketUsername != "hkjang" {
		t.Fatalf("mapping = %+v", m)
	}
	if m.MappingType != "auto" {
		t.Errorf("mapping type = %q, want auto", m.MappingType)
	}

	// A second resolve must reuse the stored binding.
	again, err := f.mapper.Resolve(f.ctx, "sub-hkjang", "hkjang")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if again.ID != m.ID {
		t.Error("a new mapping row was created on the second resolve")
	}

	// An unknown Keycloak username must not fall back to a near match.
	if _, err := f.mapper.Resolve(f.ctx, "sub-ghost", "ghost"); err == nil {
		t.Fatal("an unmatched username was mapped")
	}

	// A second subject must not take over an already bound Bitbucket account.
	if _, err := f.mapper.Resolve(f.ctx, "sub-other", "hkjang"); err == nil {
		t.Fatal("a Bitbucket account was bound to two Keycloak subjects")
	}
}

func TestAuditTrailRecordsRequesterAndServiceAccount(t *testing.T) {
	f := newFixture(t)
	f.bitbucket.projectPerm["AI"] = "PROJECT_READ"
	if _, err := f.exec.Invoke(f.ctx, f.principal(), "bitbucket_get_repository", tools.Args{
		"project": "AI", "repository": "text2sql",
	}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	// Audit writes use a detached context; give them a moment to land.
	deadline := time.Now().Add(3 * time.Second)
	var username, service, tool string
	for time.Now().Before(deadline) {
		err := f.db.Pool.QueryRow(f.ctx, `
			SELECT COALESCE(keycloak_username,''), COALESCE(service_account,''), COALESCE(tool_name,'')
			FROM audit_log WHERE tool_name='bitbucket_get_repository' AND success
			ORDER BY id DESC LIMIT 1`).Scan(&username, &service, &tool)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if username != "hkjang" {
		t.Errorf("audit requester = %q", username)
	}
	if service != "mcp-service" {
		t.Errorf("audit service account = %q", service)
	}
}

func cloneArgs(in tools.Args) tools.Args {
	out := tools.Args{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
