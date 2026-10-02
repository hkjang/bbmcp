package permission

import (
	"encoding/json"
	"testing"
)

func restrictions(t *testing.T, body string) any {
	t.Helper()
	var out any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return out
}

func TestReadOnlyBranchBlocksNonExemptUser(t *testing.T) {
	raw := restrictions(t, `{"values":[{"id":1,"type":"read-only",
		"matcher":{"id":"refs/heads/master","displayId":"master","type":{"id":"BRANCH"}},
		"users":[{"name":"release-manager"}],"groups":["release-team"]}]}`)

	if ok, reason := evaluateRestrictions(raw, "hkjang", nil, "master"); ok {
		t.Error("read-only master allowed a non-exempt user")
	} else if reason == "" {
		t.Error("block carried no reason")
	}
	if ok, _ := evaluateRestrictions(raw, "release-manager", nil, "master"); !ok {
		t.Error("exempt user was blocked")
	}
	if ok, _ := evaluateRestrictions(raw, "hkjang", []string{"release-team"}, "master"); !ok {
		t.Error("user in an exempt group was blocked")
	}
	if ok, _ := evaluateRestrictions(raw, "hkjang", nil, "feature/x"); !ok {
		t.Error("unrelated branch was blocked")
	}
}

func TestPullRequestOnlyDoesNotBlockMerge(t *testing.T) {
	// bbmcp only ever lands changes through a pull request, so a
	// pull-request-only restriction must not stop a merge.
	raw := restrictions(t, `{"values":[{"id":2,"type":"pull-request-only",
		"matcher":{"id":"refs/heads/master","displayId":"master","type":{"id":"BRANCH"}},
		"users":[],"groups":[]}]}`)
	if ok, reason := evaluateRestrictions(raw, "hkjang", nil, "master"); !ok {
		t.Errorf("pull-request-only blocked a merge: %s", reason)
	}
}

func TestPatternAndCategoryMatchers(t *testing.T) {
	raw := restrictions(t, `{"values":[
		{"id":3,"type":"read-only","matcher":{"id":"release/*","displayId":"release/*","type":{"id":"PATTERN"}},"users":[],"groups":[]},
		{"id":4,"type":"read-only","matcher":{"id":"production","displayId":"production","type":{"id":"MODEL_CATEGORY"}},"users":[],"groups":[]}]}`)

	if ok, _ := evaluateRestrictions(raw, "hkjang", nil, "release/1.2"); ok {
		t.Error("pattern matcher did not block release/1.2")
	}
	if ok, _ := evaluateRestrictions(raw, "hkjang", nil, "production/eu"); ok {
		t.Error("category matcher did not block production/eu")
	}
	if ok, _ := evaluateRestrictions(raw, "hkjang", nil, "develop"); !ok {
		t.Error("unmatched branch was blocked")
	}
}

func TestRefsHeadsPrefixIsNormalised(t *testing.T) {
	raw := restrictions(t, `{"values":[{"id":5,"type":"read-only",
		"matcher":{"id":"refs/heads/master","displayId":"master","type":{"id":"BRANCH"}},
		"users":[],"groups":[]}]}`)
	if ok, _ := evaluateRestrictions(raw, "hkjang", nil, "refs/heads/master"); ok {
		t.Error("fully qualified ref bypassed the restriction")
	}
}

func TestMalformedPayloadFailsClosed(t *testing.T) {
	if ok, _ := evaluateRestrictions(func() {}, "hkjang", nil, "master"); ok {
		t.Error("unparseable restrictions were treated as permissive")
	}
}

func TestLevelOrdering(t *testing.T) {
	if !Admin.AtLeast(Write) || !Write.AtLeast(Read) || Read.AtLeast(Write) {
		t.Error("level ordering is wrong")
	}
	if ParseRequirement("REPO_WRITE") != Write {
		t.Error("REPO_WRITE did not parse to Write")
	}
	if ParseRequirement("NONE") != None {
		t.Error("NONE did not parse to None")
	}
	if ParseRequirement("unknown") != Read {
		t.Error("unknown requirement should default to Read")
	}
	if fromBitbucket("PROJECT_ADMIN") != Admin {
		t.Error("PROJECT_ADMIN should map to Admin")
	}
}
