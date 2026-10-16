// Package approval implements server-side approval for risky MCP tools.
//
// An approval is bound to the exact arguments it was granted for: if the
// arguments change, or the pull request gains a new commit, the approval goes
// stale and the caller has to ask again.
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/bbmcp/internal/crypto"
)

// Statuses of an approval request.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
	StatusExpired  = "expired"
	StatusConsumed = "consumed"
)

// Errors returned to MCP callers.
var (
	ErrRequired = errors.New("APPROVAL_REQUIRED")
	ErrStale    = errors.New("APPROVAL_STALE")
	ErrDenied   = errors.New("APPROVAL_DENIED")
)

// Request is an approval record.
type Request struct {
	ID            uuid.UUID      `json:"id"`
	KeycloakSub   string         `json:"keycloakSub"`
	UserID        *int64         `json:"userId,omitempty"`
	Username      string         `json:"username"`
	ToolName      string         `json:"toolName"`
	ArgumentsHash string         `json:"argumentsHash"`
	Arguments     map[string]any `json:"arguments,omitempty"`
	Resource      string         `json:"resource"`
	PRVersion     *int           `json:"prVersion,omitempty"`
	Status        string         `json:"status"`
	DecidedBy     string         `json:"decidedBy,omitempty"`
	DecisionNote  string         `json:"decisionNote,omitempty"`
	CreatedAt     time.Time      `json:"createdAt"`
	ExpiresAt     time.Time      `json:"expiresAt"`
	ApprovedAt    *time.Time     `json:"approvedAt,omitempty"`
	ConsumedAt    *time.Time     `json:"consumedAt,omitempty"`
}

// Engine stores and checks approvals.
type Engine struct{ pool *pgxpool.Pool }

// NewEngine builds the engine.
func NewEngine(pool *pgxpool.Pool) *Engine { return &Engine{pool: pool} }

// Hash canonicalises tool arguments into a stable digest. The approval id
// itself is excluded so that submitting the approval does not change the hash.
func Hash(toolName string, args map[string]any) string {
	cleaned := map[string]any{}
	for k, v := range args {
		if strings.EqualFold(k, "approvalId") || strings.EqualFold(k, "approval_id") {
			continue
		}
		cleaned[k] = v
	}
	keys := make([]string, 0, len(cleaned))
	for k := range cleaned {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString(toolName)
	for _, k := range keys {
		b, _ := json.Marshal(cleaned[k])
		sb.WriteString("\n")
		sb.WriteString(k)
		sb.WriteString("=")
		sb.Write(b)
	}
	return crypto.SHA256Hex(sb.String())
}

const cols = `id, keycloak_sub, user_id, username, tool_name, arguments_hash,
	arguments_redacted, resource, pr_version, status, COALESCE(decided_by,''),
	COALESCE(decision_note,''), created_at, expires_at, approved_at, consumed_at`

func scan(row pgx.Row) (*Request, error) {
	var r Request
	var args []byte
	if err := row.Scan(&r.ID, &r.KeycloakSub, &r.UserID, &r.Username, &r.ToolName,
		&r.ArgumentsHash, &args, &r.Resource, &r.PRVersion, &r.Status, &r.DecidedBy,
		&r.DecisionNote, &r.CreatedAt, &r.ExpiresAt, &r.ApprovedAt, &r.ConsumedAt); err != nil {
		return nil, err
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &r.Arguments)
	}
	return &r, nil
}

// Create opens a pending approval request.
func (e *Engine) Create(ctx context.Context, sub string, userID *int64, username, toolName string,
	args map[string]any, resource string, prVersion *int, ttl time.Duration) (*Request, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	redacted := redactArgs(args)
	body, _ := json.Marshal(redacted)
	id := uuid.New()
	_, err := e.pool.Exec(ctx, `
		INSERT INTO approval_requests(id, keycloak_sub, user_id, username, tool_name,
			arguments_hash, arguments_redacted, resource, pr_version, status, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		id, sub, userID, username, toolName, Hash(toolName, args), body, resource,
		prVersion, StatusPending, time.Now().Add(ttl))
	if err != nil {
		return nil, err
	}
	return e.ByID(ctx, id)
}

// ByID loads one request.
func (e *Engine) ByID(ctx context.Context, id uuid.UUID) (*Request, error) {
	r, err := scan(e.pool.QueryRow(ctx, `SELECT `+cols+` FROM approval_requests WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("승인 요청을 찾을 수 없습니다")
	}
	return r, err
}

// List returns requests, optionally filtered by status or requester.
func (e *Engine) List(ctx context.Context, status, sub string, limit int) ([]Request, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := e.pool.Query(ctx, `SELECT `+cols+` FROM approval_requests
		WHERE ($1='' OR status=$1) AND ($2='' OR keycloak_sub=$2)
		ORDER BY created_at DESC LIMIT $3`, status, sub, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Request{}
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// Decide approves or rejects a request.
func (e *Engine) Decide(ctx context.Context, id uuid.UUID, approve bool, decidedBy, note string) (*Request, error) {
	req, err := e.ByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.Status != StatusPending {
		return nil, fmt.Errorf("이미 처리된 요청입니다 (%s)", req.Status)
	}
	if time.Now().After(req.ExpiresAt) {
		_, _ = e.pool.Exec(ctx, `UPDATE approval_requests SET status=$2 WHERE id=$1`, id, StatusExpired)
		return nil, fmt.Errorf("만료된 요청입니다")
	}
	status := StatusRejected
	if approve {
		status = StatusApproved
	}
	if _, err := e.pool.Exec(ctx, `
		UPDATE approval_requests
		SET status = $2::VARCHAR,
		    decided_by = $3,
		    decision_note = $4,
		    approved_at = CASE WHEN $2::VARCHAR = 'approved' THEN NOW() ELSE NULL END
		WHERE id = $1`, id, status, decidedBy, note); err != nil {
		return nil, err
	}
	return e.ByID(ctx, id)
}

// Check validates an approval for a tool call and marks it consumed.
//
// currentPRVersion is compared when the approval recorded one, which is how a
// merge approval is invalidated by a new commit on the pull request. A nil
// currentPRVersion against a pinned approval is a refusal, not a pass: the
// version could not be verified. Consumption is a conditional UPDATE, so one
// approval is spent exactly once even under concurrent calls.
func (e *Engine) Check(ctx context.Context, id uuid.UUID, sub, toolName string,
	args map[string]any, currentPRVersion *int) (*Request, error) {
	req, err := e.ByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDenied, err)
	}
	switch {
	case req.KeycloakSub != sub:
		return nil, fmt.Errorf("%w: 승인 요청자가 아닙니다", ErrDenied)
	case req.ToolName != toolName:
		return nil, fmt.Errorf("%w: 다른 도구의 승인입니다", ErrDenied)
	case req.Status == StatusRejected:
		return nil, fmt.Errorf("%w: 승인이 거절되었습니다", ErrDenied)
	case req.Status == StatusConsumed:
		return nil, fmt.Errorf("%w: 이미 사용된 승인입니다", ErrStale)
	case req.Status != StatusApproved:
		return nil, fmt.Errorf("%w: 승인 대기 상태입니다", ErrRequired)
	case time.Now().After(req.ExpiresAt):
		_, _ = e.pool.Exec(ctx, `UPDATE approval_requests SET status=$2 WHERE id=$1`, id, StatusExpired)
		return nil, fmt.Errorf("%w: 승인이 만료되었습니다", ErrStale)
	case req.ArgumentsHash != Hash(toolName, args):
		return nil, fmt.Errorf("%w: 승인 이후 인자가 변경되었습니다", ErrStale)
	}
	// An approval that pinned a PR version is only usable while that version can
	// be confirmed: an unreadable pull request must fail closed, not merge on an
	// unverifiable assumption. The approval itself stays usable for a retry.
	if req.PRVersion != nil && currentPRVersion == nil {
		return nil, fmt.Errorf("%w: 현재 PR 버전을 확인할 수 없습니다", ErrStale)
	}
	if req.PRVersion != nil && currentPRVersion != nil && *req.PRVersion != *currentPRVersion {
		return nil, fmt.Errorf("%w: 승인 시 PR 버전 %d, 현재 %d",
			ErrStale, *req.PRVersion, *currentPRVersion)
	}
	// Consume conditionally so that concurrent calls carrying the same approval
	// id cannot all pass: exactly one UPDATE sees status 'approved'.
	tag, err := e.pool.Exec(ctx,
		`UPDATE approval_requests SET status=$2::VARCHAR, consumed_at=NOW()
		 WHERE id=$1 AND status='approved'`,
		id, StatusConsumed)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("%w: 이미 사용된 승인입니다", ErrStale)
	}
	return req, nil
}

// ExpireStale marks timed-out pending requests as expired.
func (e *Engine) ExpireStale(ctx context.Context) error {
	_, err := e.pool.Exec(ctx,
		`UPDATE approval_requests SET status=$1 WHERE status=$2 AND expires_at < NOW()`,
		StatusExpired, StatusPending)
	return err
}

// sensitiveKeyParts are matched as substrings against the lowercased argument name.
// Each entry must stay specific enough not to swallow a real tool argument: bare
// "key"/"auth"/"pat" would hide "projectKey", "authMode" and "path", so the
// qualified forms are listed instead. Unlike audit.redactKeys this list covers only
// credential-shaped names — an approver has to read "diff", "content" and "text" to
// know what they are approving, and oversized values are truncated below instead.
var sensitiveKeyParts = []string{
	"token", "secret", "password", "passwd",
	"credential", "authorization", "bearer",
	"apikey", "api_key", "accesskey", "access_key",
	"privatekey", "private_key",
}

const (
	redactedMark = "[redacted]"
	// maxValueBytes caps one stored string value.
	maxValueBytes = 2000
	// maxDepth bounds the walk so a deeply nested argument cannot exhaust the
	// stack; maxElements does the same for a wide one.
	maxDepth    = 8
	maxElements = 200
)

// redactArgs strips large or sensitive argument values before storage. It
// returns a fresh map and never writes through to args: Create hashes the
// caller's own argument map, so an in-place scrub would store the digest of the
// redacted copy and invalidate the approval the moment it is submitted.
func redactArgs(args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = redactValue(k, v, 1)
	}
	return out
}

// redactValue copies v, replacing credential-shaped and oversized values.
// Objects and lists are walked rather than copied through, because a secret
// nested inside one reaches the same record and the same admin console
// response as a top-level one. depth counts a top-level argument value as 1.
func redactValue(key string, v any, depth int) any {
	if containsAny(strings.ToLower(key), sensitiveKeyParts) {
		return redactedMark
	}
	// Past the bounds the value is dropped, not passed through: an argument
	// built to outrun the walk must not be the one that escapes scrubbing.
	if depth > maxDepth {
		return redactedMark
	}
	switch t := v.(type) {
	case string:
		if len(t) > maxValueBytes {
			return trimToRune(t[:maxValueBytes]) + "…"
		}
		return t
	case map[string]any:
		if len(t) > maxElements {
			return redactedMark
		}
		out := make(map[string]any, len(t))
		for k, nv := range t {
			out[k] = redactValue(k, nv, depth+1)
		}
		return out
	case []any:
		if len(t) > maxElements {
			return redactedMark
		}
		out := make([]any, len(t))
		for i, nv := range t {
			// List elements have no name of their own, and the enclosing key is
			// not reapplied: a sensitive key was already handled above, so
			// {"tokens":[…]} is gone before the list is ever walked.
			out[i] = redactValue("", nv, depth+1)
		}
		return out
	default:
		return v
	}
}

// trimToRune drops a trailing partial UTF-8 sequence left behind by cutting a
// string at a byte offset. Without it the byte cap splits a multi-byte
// character — the common case for Korean arguments — and json.Marshal replaces
// the broken bytes with U+FFFD, so the approver reads a corrupted value.
// internal/mcp keeps its own copy of this on purpose: that one caps a response
// for MCP clients and is free to change without touching stored approvals.
func trimToRune(s string) string {
	for len(s) > 0 {
		if r, size := utf8.DecodeLastRuneInString(s); r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

func containsAny(s string, parts []string) bool {
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
