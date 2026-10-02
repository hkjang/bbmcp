package bitbucket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hkjang/bbmcp/internal/settings"
)

// fakeBitbucket is a minimal stand-in for Bitbucket Server 6.9.1 REST.
func fakeBitbucket(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()

	write := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}

	mux.HandleFunc("/rest/api/1.0/users", func(w http.ResponseWriter, r *http.Request) {
		// A filter search deliberately returns a near-miss first, so a client
		// that takes the first hit binds the wrong account.
		switch r.URL.Query().Get("filter") {
		case "hkjang":
			write(w, `{"size":2,"isLastPage":true,"values":[
				{"id":999,"name":"hkjang2","slug":"hkjang2","displayName":"Other","active":true},
				{"id":142,"name":"hkjang","slug":"hkjang","displayName":"Jang","emailAddress":"h@x.io","active":true}]}`)
		case "ghost":
			write(w, `{"size":0,"isLastPage":true,"values":[]}`)
		default:
			write(w, `{"size":0,"isLastPage":true,"values":[]}`)
		}
	})
	mux.HandleFunc("/rest/api/1.0/users/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"message":"not found"}]}`, http.StatusNotFound)
	})

	mux.HandleFunc("/rest/api/1.0/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") == "" {
			t.Error("projects request did not carry a limit")
		}
		write(w, `{"size":1,"limit":50,"isLastPage":true,"values":[
			{"id":1,"key":"AI","name":"AI","public":false}]}`)
	})

	// browse: directory listing and paged file lines.
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/browse", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"children":{"size":2,"isLastPage":true,"values":[
			{"path":{"toString":"src","name":"src"},"type":"DIRECTORY"},
			{"path":{"toString":"README.md","name":"README.md"},"type":"FILE","size":12}]}}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/browse/README.md", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("start") == "2" {
			write(w, `{"lines":{"size":1,"start":2,"isLastPage":true,"values":[{"text":"third"}]}}`)
			return
		}
		write(w, `{"lines":{"size":2,"start":0,"isLastPage":false,"nextPageStart":2,
			"values":[{"text":"first"},{"text":"second"}]}}`)
	})

	// Pull request with an explicit version, and a merge that enforces it.
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/pull-requests/7", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"id":7,"version":14,"title":"fix","state":"OPEN","open":true,
			"fromRef":{"id":"refs/heads/feature/x"},"toRef":{"id":"refs/heads/master"}}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/pull-requests/7/merge", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("version") != "14" {
			http.Error(w, `{"errors":[{"message":"PR has been modified","exceptionName":"com.atlassian.bitbucket.pull.PullRequestOutOfDateException"}]}`,
				http.StatusConflict)
			return
		}
		write(w, `{"id":7,"version":15,"state":"MERGED","open":false,"closed":true}`)
	})

	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/pull-requests/7/activities", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"size":3,"isLastPage":true,"values":[
			{"action":"OPENED"},
			{"action":"COMMENTED","comment":{"id":11,"text":"보완 필요","author":{"name":"kim"}}},
			{"action":"COMMENTED","comment":{"id":12,"text":"확인","author":{"name":"lee"}}}]}`)
	})

	mux.HandleFunc("/rest/api/1.0/projects/AI/repos/text2sql/compare/diff", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "text/plain" {
			t.Errorf("diff Accept header = %q, want text/plain", got)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new\n"))
	})

	mux.HandleFunc("/rest/api/1.0/admin/permissions/users", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"values":[{"user":{"name":"hkjang"},"permission":"LICENSED_USER"}]}`)
	})
	mux.HandleFunc("/rest/api/1.0/projects/AI/permissions/users", func(w http.ResponseWriter, r *http.Request) {
		write(w, `{"values":[{"user":{"name":"hkjang"},"permission":"PROJECT_READ"}]}`)
	})
	mux.HandleFunc("/rest/branch-utils/1.0/projects/AI/repos/text2sql/branches", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "feature/new" {
			t.Errorf("branch name = %v", body["name"])
		}
		write(w, `{"id":"refs/heads/feature/new","displayId":"feature/new","type":"BRANCH"}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"message":"unhandled `+r.URL.Path+`"}]}`, http.StatusNotFound)
	})

	srv := httptest.NewServer(authGuard(t, mux))
	t.Cleanup(srv.Close)

	client, err := NewClient(settings.Bitbucket{
		BaseURL: srv.URL, RestPrefix: "/rest/api/1.0", TimeoutSec: 10, PageSize: 50,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return srv, client
}

// authGuard asserts every call carries the bearer credential.
func authGuard(t *testing.T, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer service-pat" {
			t.Errorf("Authorization = %q", got)
			http.Error(w, `{"errors":[{"message":"unauthorized"}]}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func testCred() Credential {
	return Credential{Mode: "service", Username: "mcp-bitbucket-service", Token: "service-pat"}
}

func TestFindUserByUsernameRequiresExactMatch(t *testing.T) {
	_, client := fakeBitbucket(t)
	ctx := context.Background()

	user, err := client.FindUserByUsername(ctx, testCred(), "hkjang")
	if err != nil {
		t.Fatalf("FindUserByUsername: %v", err)
	}
	if user.Name != "hkjang" || user.ID != 142 {
		t.Fatalf("bound the wrong account: %+v", user)
	}

	if _, err := client.FindUserByUsername(ctx, testCred(), "ghost"); err == nil {
		t.Fatal("a username with no exact match was accepted")
	}
}

func TestMissingCredentialIsRejectedBeforeCall(t *testing.T) {
	_, client := fakeBitbucket(t)
	if err := client.Ping(context.Background(), Credential{}); err == nil {
		t.Fatal("a call without a token was attempted")
	}
}

func TestFilePagingConcatenatesLines(t *testing.T) {
	_, client := fakeBitbucket(t)
	content, truncated, err := client.File(context.Background(), testCred(),
		"AI", "text2sql", "README.md", "master", 0)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if truncated {
		t.Error("small file reported as truncated")
	}
	if content != "first\nsecond\nthird\n" {
		t.Fatalf("content = %q", content)
	}
}

func TestFileRespectsMaxBytes(t *testing.T) {
	_, client := fakeBitbucket(t)
	content, truncated, err := client.File(context.Background(), testCred(),
		"AI", "text2sql", "README.md", "", 8)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if !truncated {
		t.Error("truncation was not reported")
	}
	if len(content) > 8 {
		t.Fatalf("content exceeded maxBytes: %q", content)
	}
}

func TestTreeListsChildren(t *testing.T) {
	_, client := fakeBitbucket(t)
	entries, _, err := client.Tree(context.Background(), testCred(), "AI", "text2sql", "", "", 0, 0)
	if err != nil {
		t.Fatalf("Tree: %v", err)
	}
	if len(entries) != 2 || entries[0].Type != "DIRECTORY" || entries[1].Path != "README.md" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestMergeSendsApprovedVersionAndSurfacesConflict(t *testing.T) {
	_, client := fakeBitbucket(t)
	ctx := context.Background()

	merged, err := client.MergePullRequest(ctx, testCred(), "AI", "text2sql", 7, 14, "ok")
	if err != nil {
		t.Fatalf("MergePullRequest: %v", err)
	}
	if merged.State != "MERGED" {
		t.Fatalf("state = %q", merged.State)
	}

	_, err = client.MergePullRequest(ctx, testCred(), "AI", "text2sql", 7, 13, "stale")
	if err == nil {
		t.Fatal("merge with a stale version succeeded")
	}
	var apiErr *APIError
	if !asAPIError(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("expected a 409 APIError, got %v", err)
	}
	if !strings.Contains(apiErr.Message, "modified") {
		t.Errorf("conflict message not surfaced: %q", apiErr.Message)
	}
}

func TestPullRequestCommentsFilterActivities(t *testing.T) {
	_, client := fakeBitbucket(t)
	comments, _, err := client.PullRequestComments(context.Background(), testCred(), "AI", "text2sql", 7, 0, 0)
	if err != nil {
		t.Fatalf("PullRequestComments: %v", err)
	}
	if len(comments) != 2 {
		t.Fatalf("got %d comments, want 2", len(comments))
	}
	if comments[0].Text != "보완 필요" {
		t.Errorf("comment text = %q", comments[0].Text)
	}
}

func TestDiffRequestsPlainText(t *testing.T) {
	_, client := fakeBitbucket(t)
	diff, err := client.Diff(context.Background(), testCred(), "AI", "text2sql", "a", "b", "", 3)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !strings.Contains(diff, "+new") {
		t.Fatalf("diff = %q", diff)
	}
}

func TestCreateBranchUsesBranchUtils(t *testing.T) {
	_, client := fakeBitbucket(t)
	br, err := client.CreateBranch(context.Background(), testCred(), "AI", "text2sql",
		"feature/new", "refs/heads/master")
	if err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	if br.DisplayID != "feature/new" {
		t.Fatalf("branch = %+v", br)
	}
}

func TestUnhandledPathBecomesAPIError(t *testing.T) {
	_, client := fakeBitbucket(t)
	_, err := client.Repository(context.Background(), testCred(), "NOPE", "nope")
	var apiErr *APIError
	if !asAPIError(err, &apiErr) || !apiErr.NotFound() {
		t.Fatalf("expected a 404 APIError, got %v", err)
	}
}
