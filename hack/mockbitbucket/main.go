//go:build ignore
// +build ignore

// Command mockbitbucket is a development stand-in for Bitbucket Server 6.9.1.
//
// It implements the subset of the REST API bbmcp uses, with a small fixed
// dataset, so the gateway can be exercised and screenshotted without a real
// Bitbucket instance. It is not part of the shipped image.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type page struct {
	Size       int   `json:"size"`
	Limit      int   `json:"limit"`
	Start      int   `json:"start"`
	IsLastPage bool  `json:"isLastPage"`
	Values     []any `json:"values"`
}

func paged(values ...any) page {
	return page{Size: len(values), Limit: 50, Start: 0, IsLastPage: true, Values: values}
}

func user(id int, name, display, email string) map[string]any {
	return map[string]any{
		"id": id, "name": name, "slug": name, "displayName": display,
		"emailAddress": email, "active": true, "type": "NORMAL",
	}
}

func project(id int, key, name, desc string) map[string]any {
	return map[string]any{"id": id, "key": key, "name": name, "description": desc, "public": false, "type": "NORMAL"}
}

func repo(id int, slug, name string, proj map[string]any) map[string]any {
	return map[string]any{
		"id": id, "slug": slug, "name": name, "scmId": "git", "state": "AVAILABLE",
		"public": false, "forkable": true, "project": proj,
	}
}

func commit(id, msg, author, email string, ts int64) map[string]any {
	return map[string]any{
		"id": id, "displayId": id[:11], "message": msg,
		"author":          map[string]any{"name": author, "emailAddress": email},
		"authorTimestamp": ts,
		"committer":       map[string]any{"name": author, "emailAddress": email},
		"committerTimestamp": ts,
		"parents": []any{map[string]any{"id": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5", "displayId": "b2c3d4e5f60"}},
	}
}

func main() {
	addr := flag.String("addr", ":19200", "수신 주소")
	flag.Parse()

	projAI := project(1, "AI", "AI 플랫폼", "사내 AI 서비스")
	projALM := project(2, "ALM", "ALM", "애플리케이션 생애주기 관리")
	projDEV := project(3, "DEVOPS", "DevOps", "배포 자동화")
	projHR := project(4, "HR", "인사", "인사 시스템 (MCP 차단 대상)")

	repoText2SQL := repo(10, "text2sql", "text2sql", projAI)
	repoRag := repo(11, "rag-gateway", "rag-gateway", projAI)
	repoPipeline := repo(12, "deploy-pipeline", "deploy-pipeline", projDEV)

	users := map[string]map[string]any{
		"hkjang":      user(142, "hkjang", "장현규", "hkjang@example.com"),
		"kim":         user(271, "kim", "김도형", "kim@example.com"),
		"mcp-service": user(9, "mcp-service", "bbmcp 서비스 계정", "mcp@example.com"),
	}

	// Effective permissions the mock grants to hkjang.
	projectPerms := map[string]string{"AI": "PROJECT_WRITE", "ALM": "PROJECT_READ", "DEVOPS": "PROJECT_READ"}
	repoPerms := map[string]string{"AI/text2sql": "REPO_WRITE", "DEVOPS/deploy-pipeline": "REPO_READ"}

	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, body any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}

	mux.HandleFunc("/rest/api/1.0/users", func(w http.ResponseWriter, r *http.Request) {
		filter := strings.ToLower(r.URL.Query().Get("filter"))
		out := []any{}
		for name, u := range users {
			if filter == "" || strings.Contains(name, filter) {
				out = append(out, u)
			}
		}
		write(w, paged(out...))
	})

	mux.HandleFunc("/rest/api/1.0/projects", func(w http.ResponseWriter, r *http.Request) {
		write(w, paged(projAI, projALM, projDEV, projHR))
	})

	mux.HandleFunc("/rest/api/1.0/repos", func(w http.ResponseWriter, r *http.Request) {
		write(w, paged(repoText2SQL, repoRag, repoPipeline))
	})

	mux.HandleFunc("/rest/api/1.0/admin/permissions/users", func(w http.ResponseWriter, r *http.Request) {
		write(w, paged(map[string]any{"user": users["hkjang"], "permission": "LICENSED_USER"}))
	})

	mux.HandleFunc("/rest/api/1.0/admin/users/more-members", func(w http.ResponseWriter, r *http.Request) {
		write(w, paged(map[string]any{"name": "ai-developers"}))
	})

	// Project and repository scoped routes are resolved by path parsing so the
	// mock stays short.
	mux.HandleFunc("/rest/api/1.0/projects/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/rest/api/1.0/projects/"), "/"), "/")
		key := parts[0]
		projects := map[string]map[string]any{"AI": projAI, "ALM": projALM, "DEVOPS": projDEV, "HR": projHR}
		proj, ok := projects[key]
		if !ok {
			http.Error(w, `{"errors":[{"message":"project not found"}]}`, http.StatusNotFound)
			return
		}

		switch {
		case len(parts) == 1:
			write(w, proj)

		case len(parts) == 3 && parts[1] == "permissions" && parts[2] == "users":
			if perm, ok := projectPerms[key]; ok {
				write(w, paged(map[string]any{"user": users["hkjang"], "permission": perm}))
				return
			}
			write(w, paged())

		case len(parts) == 3 && parts[1] == "permissions" && parts[2] == "groups":
			write(w, paged(map[string]any{"group": map[string]any{"name": "ai-developers"}, "permission": "PROJECT_READ"}))

		case len(parts) == 2 && parts[1] == "repos":
			switch key {
			case "AI":
				write(w, paged(repoText2SQL, repoRag))
			case "DEVOPS":
				write(w, paged(repoPipeline))
			default:
				write(w, paged())
			}

		case len(parts) >= 3 && parts[1] == "repos":
			repoRoutes(w, r, key, parts[2], parts[3:], proj, repoPerms, users)

		default:
			http.Error(w, `{"errors":[{"message":"unhandled"}]}`, http.StatusNotFound)
		}
	})

	mux.HandleFunc("/rest/branch-permissions/2.0/", func(w http.ResponseWriter, r *http.Request) {
		write(w, paged(map[string]any{
			"id": 1, "type": "read-only",
			"matcher": map[string]any{
				"id": "refs/heads/master", "displayId": "master",
				"type": map[string]any{"id": "BRANCH", "name": "Branch"},
			},
			"users":  []any{},
			"groups": []string{"release-managers"},
		}))
	})

	mux.HandleFunc("/rest/branch-utils/1.0/", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"id": "refs/heads/feature/new", "displayId": "feature/new", "type": "BRANCH"})
	})

	mux.HandleFunc("/rest/search/1.0/search", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{
			"code": map[string]any{
				"count": 1,
				"values": []any{map[string]any{
					"repository": repoText2SQL,
					"file":       "src/main/java/App.java",
					"hitContexts": []any{[]any{map[string]any{"line": 42, "text": "public void run() {"}}},
				}},
			},
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("미처리 경로: %s %s", r.Method, r.URL.Path)
		http.Error(w, `{"errors":[{"message":"unhandled `+r.URL.Path+`"}]}`, http.StatusNotFound)
	})

	log.Printf("모의 Bitbucket 수신: %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
	_ = fmt.Sprint()
}

func repoRoutes(w http.ResponseWriter, r *http.Request, projectKey, slug string, rest []string,
	proj map[string]any, repoPerms map[string]string, users map[string]map[string]any) {

	write := func(body any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
	plain := func(body string) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}

	repoBody := repo(10, slug, slug, proj)
	prOne := map[string]any{
		"id": 7, "version": 14, "title": "스트리밍 응답 처리 보강",
		"description": "AI 응답 스트리밍에서 부분 프레임 처리 오류를 수정했습니다.",
		"state":       "OPEN", "open": true, "closed": false,
		"createdDate": int64(1759300000000), "updatedDate": int64(1759380000000),
		"fromRef": map[string]any{"id": "refs/heads/feature/stream-fix", "displayId": "feature/stream-fix",
			"latestCommit": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4", "repository": repoBody},
		"toRef": map[string]any{"id": "refs/heads/master", "displayId": "master",
			"latestCommit": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5", "repository": repoBody},
		"author":    map[string]any{"user": users["hkjang"], "role": "AUTHOR", "approved": false, "status": "UNAPPROVED"},
		"reviewers": []any{map[string]any{"user": users["kim"], "role": "REVIEWER", "approved": false, "status": "NEEDS_WORK"}},
	}
	prTwo := map[string]any{
		"id": 6, "version": 3, "title": "권한 캐시 TTL 설정 추가",
		"state": "MERGED", "open": false, "closed": true,
		"createdDate": int64(1759100000000), "updatedDate": int64(1759200000000),
		"fromRef": map[string]any{"id": "refs/heads/feature/perm-cache", "displayId": "feature/perm-cache", "repository": repoBody},
		"toRef":   map[string]any{"id": "refs/heads/master", "displayId": "master", "repository": repoBody},
		"author":  map[string]any{"user": users["kim"], "role": "AUTHOR", "approved": true, "status": "APPROVED"},
	}

	key := strings.Join(rest, "/")
	switch {
	case key == "":
		write(repoBody)

	case key == "branches/default":
		write(map[string]any{"id": "refs/heads/master", "displayId": "master", "type": "BRANCH",
			"latestCommit": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5", "isDefault": true})

	case key == "branches":
		write(paged(
			map[string]any{"id": "refs/heads/master", "displayId": "master", "type": "BRANCH", "isDefault": true,
				"latestCommit": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5"},
			map[string]any{"id": "refs/heads/develop", "displayId": "develop", "type": "BRANCH",
				"latestCommit": "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6"},
			map[string]any{"id": "refs/heads/feature/stream-fix", "displayId": "feature/stream-fix", "type": "BRANCH",
				"latestCommit": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"},
		))

	case key == "tags":
		write(paged(map[string]any{"id": "refs/tags/v1.4.0", "displayId": "v1.4.0", "type": "TAG",
			"latestCommit": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5"}))

	case key == "commits":
		write(paged(
			commit("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4", "스트리밍 프레임 경계 처리 수정", "hkjang", "hkjang@example.com", 1759380000000),
			commit("b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5", "권한 캐시 TTL 설정 추가", "kim", "kim@example.com", 1759200000000),
			commit("c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6", "초기 커밋", "hkjang", "hkjang@example.com", 1759000000000),
		))

	case strings.HasPrefix(key, "commits/") && strings.HasSuffix(key, "/changes"):
		write(paged(map[string]any{
			"path":     map[string]any{"toString": "src/main/java/App.java"},
			"type":     "MODIFY",
			"nodeType": "FILE",
		}))

	case strings.HasPrefix(key, "commits/"):
		id := strings.TrimPrefix(key, "commits/")
		write(commit(id, "스트리밍 프레임 경계 처리 수정", "hkjang", "hkjang@example.com", 1759380000000))

	case key == "browse" || key == "browse/":
		write(map[string]any{"children": map[string]any{
			"size": 3, "isLastPage": true,
			"values": []any{
				map[string]any{"path": map[string]any{"toString": "src", "name": "src"}, "type": "DIRECTORY"},
				map[string]any{"path": map[string]any{"toString": "README.md", "name": "README.md"}, "type": "FILE", "size": 842},
				map[string]any{"path": map[string]any{"toString": "pom.xml", "name": "pom.xml"}, "type": "FILE", "size": 1931},
			}}})

	case strings.HasPrefix(key, "browse/"):
		write(map[string]any{"lines": map[string]any{
			"size": 4, "isLastPage": true,
			"values": []any{
				map[string]any{"text": "# text2sql"},
				map[string]any{"text": ""},
				map[string]any{"text": "자연어 질의를 SQL 로 변환하는 서비스입니다."},
				map[string]any{"text": "빌드: ./gradlew build"},
			}}})

	case key == "compare/diff" || strings.HasPrefix(key, "compare/diff"):
		plain("--- a/src/main/java/App.java\n+++ b/src/main/java/App.java\n@@ -39,7 +39,11 @@\n-    buffer.append(chunk);\n+    if (chunk != null) {\n+        buffer.append(chunk);\n+    }\n")

	case key == "pull-requests":
		if r.URL.Query().Get("state") == "MERGED" {
			write(paged(prTwo))
			return
		}
		if strings.EqualFold(r.URL.Query().Get("state"), "ALL") {
			write(paged(prOne, prTwo))
			return
		}
		write(paged(prOne))

	case key == "pull-requests/7":
		write(prOne)

	case key == "pull-requests/7/commits":
		write(paged(commit("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4", "스트리밍 프레임 경계 처리 수정", "hkjang", "hkjang@example.com", 1759380000000)))

	case key == "pull-requests/7/changes":
		write(paged(map[string]any{
			"path": map[string]any{"toString": "src/main/java/App.java"}, "type": "MODIFY", "nodeType": "FILE",
		}))

	case key == "pull-requests/7/diff":
		plain("--- a/src/main/java/App.java\n+++ b/src/main/java/App.java\n@@ -39,7 +39,11 @@\n-    buffer.append(chunk);\n+    if (chunk != null) {\n+        buffer.append(chunk);\n+    }\n")

	case key == "pull-requests/7/activities":
		write(paged(
			map[string]any{"id": 100, "action": "OPENED", "user": users["hkjang"], "createdDate": int64(1759300000000)},
			map[string]any{"id": 101, "action": "COMMENTED", "user": users["kim"], "createdDate": int64(1759340000000),
				"comment": map[string]any{"id": 11, "version": 0, "text": "부분 프레임에서 널 검사가 필요해 보입니다.",
					"author": users["kim"], "createdDate": int64(1759340000000)}},
		))

	case key == "pull-requests/7/comments":
		write(map[string]any{"id": 55, "version": 0, "text": "확인했습니다.", "author": users["mcp-service"]})

	case key == "permissions/users":
		if perm, ok := repoPerms[projectKey+"/"+slug]; ok {
			write(paged(map[string]any{"user": users["hkjang"], "permission": perm}))
			return
		}
		write(paged())

	case key == "permissions/groups":
		write(paged())

	default:
		log.Printf("미처리 저장소 경로: %s", key)
		http.Error(w, `{"errors":[{"message":"unhandled repo path `+key+`"}]}`, http.StatusNotFound)
	}
}
