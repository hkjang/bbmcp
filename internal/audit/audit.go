// Package audit records every security-relevant action. Secrets, tokens and
// full source/diff bodies are deliberately excluded from the record.
package audit

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Categories used across the service.
const (
	CatAuth     = "auth"
	CatTool     = "tool"
	CatWrite    = "write"
	CatApproval = "approval"
	CatAdmin    = "admin"
	CatKey      = "key"
	CatError    = "error"
	CatAI       = "ai"
)

// Entry is one audit row.
type Entry struct {
	ID                int64          `json:"id"`
	OccurredAt        time.Time      `json:"occurredAt"`
	Category          string         `json:"category"`
	Action            string         `json:"action"`
	KeycloakSub       string         `json:"keycloakSub,omitempty"`
	KeycloakUsername  string         `json:"keycloakUsername,omitempty"`
	BitbucketUserID   *int64         `json:"bitbucketUserId,omitempty"`
	BitbucketUsername string         `json:"bitbucketUsername,omitempty"`
	ServiceAccount    string         `json:"serviceAccount,omitempty"`
	MCPClient         string         `json:"mcpClient,omitempty"`
	AuthMode          string         `json:"authMode,omitempty"`
	ToolName          string         `json:"toolName,omitempty"`
	ProjectKey        string         `json:"projectKey,omitempty"`
	Repository        string         `json:"repository,omitempty"`
	PullRequest       *int           `json:"pullRequest,omitempty"`
	ApprovalID        *uuid.UUID     `json:"approvalId,omitempty"`
	Success           bool           `json:"success"`
	ErrorCode         string         `json:"errorCode,omitempty"`
	Message           string         `json:"message,omitempty"`
	LatencyMS         int            `json:"latencyMs"`
	IP                string         `json:"ip,omitempty"`
	Detail            map[string]any `json:"detail,omitempty"`
}

// Logger writes audit entries.
type Logger struct{ pool *pgxpool.Pool }

// New builds a logger.
func New(pool *pgxpool.Pool) *Logger { return &Logger{pool: pool} }

// redactKeys are never stored, even if a caller passes them in Detail.
var redactKeys = []string{"authorization", "pat", "token", "password", "secret",
	"apikey", "api_key", "diff", "content", "source", "prompt", "messages"}

func redact(detail map[string]any) map[string]any {
	if detail == nil {
		return nil
	}
	out := make(map[string]any, len(detail))
	for k, v := range detail {
		lk := strings.ToLower(k)
		dropped := false
		for _, bad := range redactKeys {
			if strings.Contains(lk, bad) {
				out[k] = "[redacted]"
				dropped = true
				break
			}
		}
		if !dropped {
			out[k] = v
		}
	}
	return out
}

// Write persists an entry. Audit failures never break the request path.
func (l *Logger) Write(ctx context.Context, e Entry) {
	e.Detail = redact(e.Detail)
	var detail []byte
	if e.Detail != nil {
		detail, _ = json.Marshal(e.Detail)
	}
	// Use a detached context so a cancelled request still leaves a trace.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = l.pool.Exec(wctx, `
		INSERT INTO audit_log(category, action, keycloak_sub, keycloak_username,
			bitbucket_user_id, bitbucket_username, service_account, mcp_client,
			auth_mode, tool_name, project_key, repository, pull_request, approval_id,
			success, error_code, message, latency_ms, ip, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		e.Category, e.Action, nz(e.KeycloakSub), nz(e.KeycloakUsername),
		e.BitbucketUserID, nz(e.BitbucketUsername), nz(e.ServiceAccount), nz(e.MCPClient),
		nz(e.AuthMode), nz(e.ToolName), nz(e.ProjectKey), nz(e.Repository),
		e.PullRequest, e.ApprovalID, e.Success, nz(e.ErrorCode), nz(e.Message),
		e.LatencyMS, nz(e.IP), detail)
}

// Query filters audit rows for the admin UI.
type Query struct {
	Category string
	Username string
	Tool     string
	Project  string
	Success  *bool
	Since    *time.Time
	Limit    int
	Offset   int
}

// List returns matching entries, newest first.
func (l *Logger) List(ctx context.Context, q Query) ([]Entry, int, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	where := `WHERE ($1='' OR category=$1)
		AND ($2='' OR keycloak_username ILIKE '%'||$2||'%')
		AND ($3='' OR tool_name=$3)
		AND ($4='' OR project_key=$4)
		AND ($5::BOOLEAN IS NULL OR success=$5)
		AND ($6::TIMESTAMPTZ IS NULL OR occurred_at >= $6)`
	args := []any{q.Category, q.Username, q.Tool, q.Project, q.Success, q.Since}

	var total int
	if err := l.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log `+where, args...).
		Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := l.pool.Query(ctx, `
		SELECT id, occurred_at, category, action, COALESCE(keycloak_sub,''),
		       COALESCE(keycloak_username,''), bitbucket_user_id,
		       COALESCE(bitbucket_username,''), COALESCE(service_account,''),
		       COALESCE(mcp_client,''), COALESCE(auth_mode,''), COALESCE(tool_name,''),
		       COALESCE(project_key,''), COALESCE(repository,''), pull_request,
		       approval_id, success, COALESCE(error_code,''), COALESCE(message,''),
		       COALESCE(latency_ms,0), COALESCE(ip,''), detail
		FROM audit_log `+where+`
		ORDER BY occurred_at DESC, id DESC
		LIMIT `+itoa(q.Limit)+` OFFSET `+itoa(q.Offset), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []Entry{}
	for rows.Next() {
		var e Entry
		var detail []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Category, &e.Action, &e.KeycloakSub,
			&e.KeycloakUsername, &e.BitbucketUserID, &e.BitbucketUsername, &e.ServiceAccount,
			&e.MCPClient, &e.AuthMode, &e.ToolName, &e.ProjectKey, &e.Repository,
			&e.PullRequest, &e.ApprovalID, &e.Success, &e.ErrorCode, &e.Message,
			&e.LatencyMS, &e.IP, &detail); err != nil {
			return nil, 0, err
		}
		if len(detail) > 0 {
			_ = json.Unmarshal(detail, &e.Detail)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Purge deletes entries older than the retention window.
func (l *Logger) Purge(ctx context.Context, retainDays int) error {
	if retainDays <= 0 {
		return nil
	}
	_, err := l.pool.Exec(ctx,
		`DELETE FROM audit_log WHERE occurred_at < NOW() - make_interval(days => $1)`, retainDays)
	return err
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func itoa(n int) string {
	if n < 0 {
		n = 0
	}
	digits := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
