// Package policy narrows what MCP may touch, on top of Bitbucket's own
// permissions. A user can never gain access here — only lose it.
package policy

import (
	"context"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Rule kinds and effects.
const (
	KindProject    = "project"
	KindRepository = "repository"
	KindBranch     = "branch"

	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// Rule is one ACL entry.
type Rule struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Pattern   string    `json:"pattern"`
	Effect    string    `json:"effect"`
	RiskCap   string    `json:"riskCap,omitempty"`
	Priority  int       `json:"priority"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"createdAt"`
}

// Verdict is the outcome of evaluating a resource against the ACL.
type Verdict struct {
	Allowed   bool   `json:"allowed"`
	RiskCap   string `json:"riskCap,omitempty"`
	MatchedBy string `json:"matchedBy,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Engine evaluates ACL rules with a short-lived cache.
type Engine struct {
	pool *pgxpool.Pool

	mu     sync.RWMutex
	rules  []Rule
	loaded time.Time
	ttl    time.Duration
}

// NewEngine builds the engine.
func NewEngine(pool *pgxpool.Pool) *Engine {
	return &Engine{pool: pool, ttl: 15 * time.Second}
}

// Reset forces a reload on the next evaluation.
func (e *Engine) Reset() {
	e.mu.Lock()
	e.loaded = time.Time{}
	e.mu.Unlock()
}

// Rules returns every rule, highest priority first.
func (e *Engine) Rules(ctx context.Context) ([]Rule, error) {
	e.mu.RLock()
	if !e.loaded.IsZero() && time.Since(e.loaded) < e.ttl {
		out := e.rules
		e.mu.RUnlock()
		return out, nil
	}
	e.mu.RUnlock()

	rows, err := e.pool.Query(ctx, `
		SELECT id, kind, pattern, effect, COALESCE(risk_cap,''), priority, note, created_at
		FROM policy_rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Kind, &r.Pattern, &r.Effect, &r.RiskCap,
			&r.Priority, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.rules, e.loaded = out, time.Now()
	e.mu.Unlock()
	return out, nil
}

// Create inserts a rule.
func (e *Engine) Create(ctx context.Context, r Rule) (int64, error) {
	var id int64
	err := e.pool.QueryRow(ctx, `
		INSERT INTO policy_rules(kind, pattern, effect, risk_cap, priority, note)
		VALUES ($1,$2,$3,NULLIF($4,''),$5,$6) RETURNING id`,
		r.Kind, r.Pattern, r.Effect, r.RiskCap, r.Priority, r.Note).Scan(&id)
	e.Reset()
	return id, err
}

// Update replaces a rule.
func (e *Engine) Update(ctx context.Context, r Rule) error {
	_, err := e.pool.Exec(ctx, `
		UPDATE policy_rules SET kind=$2, pattern=$3, effect=$4,
		       risk_cap=NULLIF($5,''), priority=$6, note=$7 WHERE id=$1`,
		r.ID, r.Kind, r.Pattern, r.Effect, r.RiskCap, r.Priority, r.Note)
	e.Reset()
	return err
}

// Delete removes a rule.
func (e *Engine) Delete(ctx context.Context, id int64) error {
	_, err := e.pool.Exec(ctx, `DELETE FROM policy_rules WHERE id=$1`, id)
	e.Reset()
	return err
}

// Evaluate checks a project/repository/branch triple against the ACL.
//
// Semantics, applied per kind: an explicit deny always wins; if at least one
// allow rule exists for a kind, the resource must match one of them.
func (e *Engine) Evaluate(ctx context.Context, projectKey, repoSlug, branch string) (Verdict, error) {
	rules, err := e.Rules(ctx)
	if err != nil {
		return Verdict{}, err
	}

	targets := []struct {
		kind  string
		value string
	}{
		{KindProject, projectKey},
		{KindRepository, projectKey + "/" + repoSlug},
		{KindBranch, branch},
	}

	cap := ""
	for _, t := range targets {
		if t.value == "" || t.value == "/" {
			continue
		}
		hasAllow := false
		matchedAllow := false
		for _, r := range rules {
			if r.Kind != t.kind {
				continue
			}
			if r.Effect == EffectAllow {
				hasAllow = true
			}
			if !matchPattern(r.Pattern, t.value) {
				continue
			}
			if r.Effect == EffectDeny {
				return Verdict{
					Allowed:   false,
					MatchedBy: r.Kind + ":" + r.Pattern,
					Reason:    denyReason(r),
				}, nil
			}
			matchedAllow = true
			if r.RiskCap != "" && (cap == "" || riskRank(r.RiskCap) < riskRank(cap)) {
				cap = r.RiskCap
			}
		}
		if hasAllow && !matchedAllow {
			return Verdict{
				Allowed:   false,
				MatchedBy: t.kind + ":허용목록",
				Reason:    "MCP 허용 목록에 포함되지 않은 " + koKind(t.kind) + "입니다: " + t.value,
			}, nil
		}
	}
	return Verdict{Allowed: true, RiskCap: cap}, nil
}

func denyReason(r Rule) string {
	if r.Note != "" {
		return "정책으로 차단됨: " + r.Note
	}
	return "정책으로 차단됨 (" + koKind(r.Kind) + " " + r.Pattern + ")"
}

func koKind(kind string) string {
	switch kind {
	case KindProject:
		return "프로젝트"
	case KindRepository:
		return "저장소"
	case KindBranch:
		return "브랜치"
	default:
		return kind
	}
}

// matchPattern supports glob patterns, "PREFIX/*" and exact matches,
// case-insensitively because Bitbucket keys are case-insensitive.
func matchPattern(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "**" {
		return true
	}
	p := strings.ToLower(pattern)
	v := strings.ToLower(value)
	if p == v {
		return true
	}
	if strings.HasSuffix(p, "/**") {
		return strings.HasPrefix(v, strings.TrimSuffix(p, "**"))
	}
	if ok, err := path.Match(p, v); err == nil && ok {
		return true
	}
	// A project pattern such as "AI/*" should also match the bare project key.
	if strings.HasSuffix(p, "/*") && v == strings.TrimSuffix(p, "/*") {
		return true
	}
	return false
}

func riskRank(level string) int {
	switch strings.ToUpper(level) {
	case "READ":
		return 1
	case "WRITE":
		return 2
	case "EXECUTE":
		return 3
	case "ADMIN":
		return 4
	default:
		return 99
	}
}

// RiskAllowed reports whether a tool's risk level fits within a cap.
func RiskAllowed(toolRisk, cap string) bool {
	if cap == "" {
		return true
	}
	return riskRank(toolRisk) <= riskRank(cap)
}
