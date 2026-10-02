package policy

import (
	"testing"
	"time"
)

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"AI", "AI", true},
		{"ai", "AI", true},
		{"AI/*", "AI/text2sql", true},
		{"AI/*", "AI", true},
		{"AI/*", "ALM/text2sql", false},
		{"*", "anything", true},
		{"SECURITY/**", "SECURITY/deep/nested", true},
		{"release/*", "release/1.0", true},
		{"release/*", "main", false},
	}
	for _, c := range cases {
		if got := matchPattern(c.pattern, c.value); got != c.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
	if matchPattern("", "AI") {
		t.Error("empty pattern matched")
	}
}

func TestRiskAllowed(t *testing.T) {
	if !RiskAllowed("EXECUTE", "") {
		t.Error("empty cap should allow any risk")
	}
	if !RiskAllowed("READ", "WRITE") {
		t.Error("READ should fit under a WRITE cap")
	}
	if RiskAllowed("EXECUTE", "READ") {
		t.Error("EXECUTE must not fit under a READ cap")
	}
	if !RiskAllowed("WRITE", "WRITE") {
		t.Error("equal risk and cap should be allowed")
	}
}

// evaluateRules exercises the ACL semantics without a database.
func evaluateRules(rules []Rule, project, repo, branch string) Verdict {
	e := &Engine{rules: rules, ttl: time.Minute, loaded: forcedLoad()}
	v, err := e.Evaluate(ctxBackground(), project, repo, branch)
	if err != nil {
		panic(err)
	}
	return v
}

func TestEvaluateDenyWins(t *testing.T) {
	rules := []Rule{
		{Kind: KindProject, Pattern: "AI", Effect: EffectAllow, Priority: 10},
		{Kind: KindProject, Pattern: "AI", Effect: EffectDeny, Priority: 20, Note: "점검 중"},
	}
	v := evaluateRules(rules, "AI", "text2sql", "")
	if v.Allowed {
		t.Fatal("deny rule did not win over allow")
	}
	if v.Reason == "" {
		t.Error("deny verdict carried no reason")
	}
}

func TestEvaluateAllowlistIsExclusive(t *testing.T) {
	rules := []Rule{{Kind: KindProject, Pattern: "AI", Effect: EffectAllow}}
	if v := evaluateRules(rules, "AI", "", ""); !v.Allowed {
		t.Error("allowlisted project was denied")
	}
	if v := evaluateRules(rules, "HR", "", ""); v.Allowed {
		t.Error("project outside the allowlist was permitted")
	}
}

func TestEvaluateNoRulesAllowsEverything(t *testing.T) {
	if v := evaluateRules(nil, "ANY", "repo", "main"); !v.Allowed {
		t.Error("empty ACL should allow")
	}
}

func TestEvaluateRiskCapPropagates(t *testing.T) {
	rules := []Rule{
		{Kind: KindProject, Pattern: "AI", Effect: EffectAllow, RiskCap: "WRITE"},
		{Kind: KindRepository, Pattern: "AI/legacy", Effect: EffectAllow, RiskCap: "READ"},
	}
	v := evaluateRules(rules, "AI", "legacy", "")
	if !v.Allowed {
		t.Fatal("resource should be allowed")
	}
	if v.RiskCap != "READ" {
		t.Fatalf("risk cap = %q, want the most restrictive (READ)", v.RiskCap)
	}
}

func TestEvaluateBranchDeny(t *testing.T) {
	rules := []Rule{{Kind: KindBranch, Pattern: "master", Effect: EffectDeny}}
	if v := evaluateRules(rules, "AI", "repo", "master"); v.Allowed {
		t.Error("denied branch was permitted")
	}
	if v := evaluateRules(rules, "AI", "repo", "feature/x"); !v.Allowed {
		t.Error("unrelated branch was denied")
	}
}
