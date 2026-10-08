package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hkjang/bbmcp/internal/approval"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/permission"
	"github.com/hkjang/bbmcp/internal/policy"
	"github.com/hkjang/bbmcp/internal/settings"
)

// Error codes returned to MCP clients.
const (
	CodeUnknownTool       = "UNKNOWN_TOOL"
	CodeToolDisabled      = "TOOL_DISABLED"
	CodeRoleDenied        = "ROLE_DENIED"
	CodeScopeDenied       = "SCOPE_DENIED"
	CodePolicyDenied      = "POLICY_DENIED"
	CodePermissionDenied  = "PERMISSION_DENIED"
	CodePermissionUnknown = "PERMISSION_UNKNOWN"
	CodeBranchRestricted  = "BRANCH_RESTRICTED"
	CodeApprovalRequired  = "APPROVAL_REQUIRED"
	CodeApprovalStale     = "APPROVAL_STALE"
	CodeApprovalDenied    = "APPROVAL_DENIED"
	CodeIdentityMissing   = "IDENTITY_UNMAPPED"
	CodeBadArguments      = "BAD_ARGUMENTS"
	CodeUpstream          = "BITBUCKET_ERROR"
	CodeInternal          = "INTERNAL_ERROR"
)

// Error is a structured tool failure.
type Error struct {
	Code     string            `json:"code"`
	Message  string            `json:"message"`
	Approval *approval.Request `json:"approval,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func toolErr(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Deps are the collaborators the executor needs.
type Deps struct {
	Registry  *Registry
	Provider  *bitbucket.Provider
	Resolver  *permission.Resolver
	Policy    *policy.Engine
	Approvals *approval.Engine
	Audit     *audit.Logger
	Store     *settings.Store
}

// Executor authorises and runs tool calls.
type Executor struct{ Deps }

// NewExecutor builds the executor.
func NewExecutor(d Deps) *Executor { return &Executor{Deps: d} }

// Available returns the tools a principal may see and call.
func (e *Executor) Available(ctx context.Context, p Principal) ([]Record, error) {
	all, err := e.Registry.List(ctx)
	if err != nil {
		return nil, err
	}
	mcpCfg, err := e.Store.MCP(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(all))
	for _, rec := range all {
		if !rec.Enabled {
			continue
		}
		if rec.HighLevel && !mcpCfg.ExposeHighLevel {
			continue
		}
		if !p.IsServiceAdmin && !RoleSatisfied(p.Roles, rec.MinRole) {
			continue
		}
		if rec.Scope != "" && !hasScope(p.Scopes, rec.Scope) {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// Invoke runs the full authorisation pipeline and then the tool.
func (e *Executor) Invoke(ctx context.Context, p Principal, name string, args Args) (any, error) {
	started := time.Now()
	if args == nil {
		args = Args{}
	}

	def, rec, err := e.Registry.Get(ctx, name)
	if err != nil {
		if errors.Is(err, ErrUnknownTool) {
			return nil, e.fail(ctx, p, name, Resource{}, started, toolErr(CodeUnknownTool, "%s", err.Error()))
		}
		return nil, e.fail(ctx, p, name, Resource{}, started, toolErr(CodeInternal, "%s", err.Error()))
	}
	if !rec.Enabled {
		return nil, e.fail(ctx, p, name, Resource{}, started,
			toolErr(CodeToolDisabled, "관리자가 비활성화한 도구입니다: %s", name))
	}
	if !p.IsServiceAdmin && !RoleSatisfied(p.Roles, rec.MinRole) {
		return nil, e.fail(ctx, p, name, Resource{}, started,
			toolErr(CodeRoleDenied, "%s 역할이 필요합니다", rec.MinRole))
	}
	if rec.Scope != "" && !hasScope(p.Scopes, rec.Scope) {
		return nil, e.fail(ctx, p, name, Resource{}, started,
			toolErr(CodeScopeDenied, "%s 스코프가 필요합니다", rec.Scope))
	}

	res := Resource{}
	if def.Resolve != nil {
		res = def.Resolve(args)
	}

	// Identity: every call runs as a known Bitbucket user, never as the
	// service account's own authority.
	if p.BitbucketUsername == "" && rec.RequiredPerm != "NONE" {
		return nil, e.fail(ctx, p, name, res, started,
			toolErr(CodeIdentityMissing, "Bitbucket 사용자 매핑이 없어 권한을 확인할 수 없습니다"))
	}

	// MCP ACL.
	if res.Project != "" {
		verdict, err := e.Policy.Evaluate(ctx, res.Project, res.Repository, res.Branch)
		if err != nil {
			return nil, e.fail(ctx, p, name, res, started,
				toolErr(CodeInternal, "정책 평가 실패: %v", err))
		}
		if !verdict.Allowed {
			return nil, e.fail(ctx, p, name, res, started,
				toolErr(CodePolicyDenied, "%s", verdict.Reason))
		}
		if !policy.RiskAllowed(rec.Risk, verdict.RiskCap) {
			return nil, e.fail(ctx, p, name, res, started,
				toolErr(CodePolicyDenied, "정책이 이 리소스에서 %s 등급 도구를 허용하지 않습니다 (상한 %s)",
					rec.Risk, verdict.RiskCap))
		}
	}

	// Effective Bitbucket permission of the requesting user.
	need := permission.ParseRequirement(rec.RequiredPerm)
	if need > permission.None && res.Project != "" {
		var dec permission.Decision
		var perr error
		if res.Repository != "" {
			dec, perr = e.Resolver.Repository(ctx, p.BitbucketUsername, res.Project, res.Repository)
		} else {
			dec, perr = e.Resolver.Project(ctx, p.BitbucketUsername, res.Project)
		}
		if perr != nil {
			code := CodeInternal
			if errors.Is(perr, permission.ErrUnavailable) {
				code = CodePermissionUnknown
			}
			return nil, e.fail(ctx, p, name, res, started,
				toolErr(code, "%v", perr))
		}
		if !dec.Level.AtLeast(need) {
			return nil, e.fail(ctx, p, name, res, started,
				toolErr(CodePermissionDenied, "%s 권한이 필요합니다 (현재 %s)",
					need.String(), dec.Effective))
		}
	}

	// Branch restrictions matter for anything that lands on a branch.
	if rec.Risk == RiskExecute || (rec.Risk == RiskWrite && res.Branch != "") {
		branch := res.Branch
		if branch == "" && res.PullRequest > 0 {
			branch, err = e.prTargetBranch(ctx, p, res)
			if err != nil {
				return nil, e.fail(ctx, p, name, res, started,
					toolErr(CodePermissionUnknown, "PR 대상 브랜치를 확인할 수 없습니다"))
			}
		}
		if branch != "" && res.Repository != "" {
			ok, reason, err := e.Resolver.BranchWritable(ctx, p.BitbucketUsername,
				res.Project, res.Repository, branch)
			if err != nil {
				return nil, e.fail(ctx, p, name, res, started,
					toolErr(CodePermissionUnknown, "%v", err))
			}
			if !ok {
				return nil, e.fail(ctx, p, name, res, started,
					toolErr(CodeBranchRestricted, "브랜치 %s: %s", branch, reason))
			}
		}
	}

	// Approval.
	approved := false
	var usedApproval *approval.Request
	if rec.RequiresApproval {
		req, aerr := e.checkApproval(ctx, p, rec, args, res)
		if aerr != nil {
			return nil, e.fail(ctx, p, name, res, started, aerr)
		}
		approved, usedApproval = true, req
	}

	// Credential: service account by default, the user's own PAT when the
	// deployment and the user opted into User Mode.
	adapter, cfg, err := e.Provider.Adapter(ctx)
	if err != nil {
		return nil, e.fail(ctx, p, name, res, started, toolErr(CodeUpstream, "%v", err))
	}
	cred, err := e.credential(ctx, p, cfg)
	if err != nil {
		return nil, e.fail(ctx, p, name, res, started, toolErr(CodeUpstream, "%v", err))
	}

	call := &Call{
		Args: args, Principal: p, Adapter: adapter, Cred: cred, Cfg: cfg,
		Resource: res, Approved: approved, Perm: e.Resolver, Policy: e.Policy,
	}
	out, err := def.Handle(ctx, call)
	if err != nil {
		code := CodeUpstream
		var apiErr *bitbucket.APIError
		if errors.As(err, &apiErr) {
			if apiErr.Status == 403 || apiErr.Status == 401 {
				code = CodePermissionDenied
			}
		} else if strings.Contains(err.Error(), "필수 인자") || strings.Contains(err.Error(), "비어 있습니다") {
			code = CodeBadArguments
		} else if strings.HasPrefix(err.Error(), "APPROVAL_STALE") {
			code = CodeApprovalStale
		}
		return nil, e.fail(ctx, p, name, res, started, toolErr(code, "%v", err))
	}

	e.record(ctx, p, name, rec, res, started, true, "", "", usedApproval)
	return out, nil
}

// prTargetBranch resolves a pull request's target branch for branch checks.
func (e *Executor) prTargetBranch(ctx context.Context, p Principal, res Resource) (string, error) {
	adapter, cfg, err := e.Provider.Adapter(ctx)
	if err != nil {
		return "", err
	}
	cred, err := e.credential(ctx, p, cfg)
	if err != nil {
		return "", err
	}
	pr, err := adapter.PullRequest(ctx, cred, res.Project, res.Repository, res.PullRequest)
	if err != nil {
		return "", err
	}
	branch := strings.TrimPrefix(pr.ToRef.ID, "refs/heads/")
	if branch == "" {
		return "", errors.New("PR 대상 브랜치가 비어 있습니다")
	}
	return branch, nil
}

// checkApproval validates (or demands) an approval for a risky call.
func (e *Executor) checkApproval(ctx context.Context, p Principal, rec Record, args Args, res Resource) (*approval.Request, *Error) {
	sec, err := e.Store.Security(ctx)
	if err != nil {
		return nil, toolErr(CodeInternal, "%v", err)
	}
	ttl := time.Duration(sec.ApprovalTTLMin) * time.Minute

	raw := args.OptString("approvalId", args.OptString("approval_id", ""))
	if raw == "" {
		req, err := e.newApprovalRequest(ctx, p, rec, args, res, ttl)
		if err != nil {
			return nil, toolErr(CodeInternal, "%v", err)
		}
		return nil, &Error{
			Code: CodeApprovalRequired,
			Message: fmt.Sprintf("이 작업은 승인이 필요합니다. 승인 요청 %s 가 생성되었습니다. "+
				"관리 콘솔에서 승인한 뒤 approvalId 와 함께 다시 호출하십시오.", req.ID),
			Approval: req,
		}
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, toolErr(CodeApprovalDenied, "approvalId 형식이 올바르지 않습니다")
	}

	var currentVersion *int
	if res.PullRequest > 0 && res.Repository != "" {
		if v := e.prVersion(ctx, p, res); v != nil {
			currentVersion = v
		}
	}
	req, err := e.Approvals.Check(ctx, id, p.KeycloakSub, rec.Name, args, currentVersion)
	if err != nil {
		code := CodeApprovalDenied
		switch {
		case errors.Is(err, approval.ErrStale):
			code = CodeApprovalStale
		case errors.Is(err, approval.ErrRequired):
			code = CodeApprovalRequired
		}
		return nil, toolErr(code, "%v", err)
	}
	return req, nil
}

func (e *Executor) newApprovalRequest(ctx context.Context, p Principal, rec Record, args Args, res Resource, ttl time.Duration) (*approval.Request, error) {
	resource := res.Project
	if res.Repository != "" {
		resource += "/" + res.Repository
	}
	if res.PullRequest > 0 {
		resource += fmt.Sprintf("#%d", res.PullRequest)
	}
	var version *int
	if res.PullRequest > 0 && res.Repository != "" {
		version = e.prVersion(ctx, p, res)
	}
	var userID *int64
	if p.UserID != 0 {
		id := p.UserID
		userID = &id
	}
	return e.Approvals.Create(ctx, p.KeycloakSub, userID, p.Username, rec.Name,
		args, resource, version, ttl)
}

func (e *Executor) prVersion(ctx context.Context, p Principal, res Resource) *int {
	adapter, cfg, err := e.Provider.Adapter(ctx)
	if err != nil {
		return nil
	}
	cred, err := e.credential(ctx, p, cfg)
	if err != nil {
		return nil
	}
	pr, err := adapter.PullRequest(ctx, cred, res.Project, res.Repository, res.PullRequest)
	if err != nil {
		return nil
	}
	v := pr.Version
	return &v
}

// credential chooses between Service Mode and User Mode.
func (e *Executor) credential(ctx context.Context, p Principal, cfg settings.Bitbucket) (bitbucket.Credential, error) {
	wantUser := cfg.AllowUserPATMode && (p.PreferUserPAT || cfg.DefaultAuthMode == "user")
	if wantUser && p.UserID != 0 {
		if cred, err := e.Provider.UserCredential(ctx, p.UserID); err == nil {
			return cred, nil
		} else if cfg.DefaultAuthMode == "user" && !errors.Is(err, bitbucket.ErrNoUserPAT) {
			return bitbucket.Credential{}, err
		}
	}
	return e.Provider.ServiceCredential(ctx)
}

// fail audits a denied or failed call and returns the error unchanged.
func (e *Executor) fail(ctx context.Context, p Principal, name string, res Resource, started time.Time, err *Error) error {
	rec := Record{Name: name}
	if _, r, gerr := e.Registry.Get(ctx, name); gerr == nil {
		rec = r
	}
	e.record(ctx, p, name, rec, res, started, false, err.Code, err.Message, nil)
	return err
}

func (e *Executor) record(ctx context.Context, p Principal, name string, rec Record,
	res Resource, started time.Time, success bool, code, message string, appr *approval.Request) {
	category := audit.CatTool
	if rec.Risk == RiskWrite || rec.Risk == RiskExecute {
		category = audit.CatWrite
	}
	if !success {
		if code == CodeApprovalRequired {
			category = audit.CatApproval
		} else if category == audit.CatTool {
			category = audit.CatError
		}
	}
	var bbID *int64
	if p.BitbucketUserID != 0 {
		id := p.BitbucketUserID
		bbID = &id
	}
	var pr *int
	if res.PullRequest > 0 {
		v := res.PullRequest
		pr = &v
	}
	var approvalID *uuid.UUID
	if appr != nil {
		id := appr.ID
		approvalID = &id
	}
	serviceAccount := ""
	if cfg, err := e.Store.Bitbucket(ctx); err == nil {
		serviceAccount = cfg.ServiceUsername
	}
	e.Audit.Write(ctx, audit.Entry{
		Category:          category,
		Action:            "tool.invoke",
		KeycloakSub:       p.KeycloakSub,
		KeycloakUsername:  p.Username,
		BitbucketUserID:   bbID,
		BitbucketUsername: p.BitbucketUsername,
		ServiceAccount:    serviceAccount,
		MCPClient:         p.Client,
		AuthMode:          p.AuthMode,
		ToolName:          name,
		ProjectKey:        res.Project,
		Repository:        res.Repository,
		PullRequest:       pr,
		ApprovalID:        approvalID,
		Success:           success,
		ErrorCode:         code,
		Message:           message,
		LatencyMS:         int(time.Since(started).Milliseconds()),
		IP:                p.IP,
		Detail:            map[string]any{"risk": rec.Risk, "branch": res.Branch},
	})
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
