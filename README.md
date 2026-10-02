<div align="center">

<img src="docs/assets/logo-192.png" alt="bbmcp" width="96" height="96">

# bbmcp

**Bitbucket MCP 게이트웨이** — AI 가 Bitbucket 을 보더라도, 사용자가 볼 수 있는 것만 봅니다.

[문서](https://hkjang.github.io/bbmcp/) ·
[사용자 가이드](https://hkjang.github.io/bbmcp/guide-user.html) ·
[관리자 가이드](https://hkjang.github.io/bbmcp/guide-admin.html) ·
[릴리스](https://github.com/hkjang/bbmcp/releases)

</div>

---

bbmcp 는 **Bitbucket Server 6.9.1** 앞에 두는 MCP(Model Context Protocol) 게이트웨이입니다.
Keycloak 으로 사용자를 인증하고, **요청자 본인의 Bitbucket 유효 권한**을 매 호출마다 확인한 뒤에만
저장소와 풀 리퀘스트에 접근합니다. 서비스 계정의 넓은 권한은 데이터를 가져오는 수단일 뿐,
사용자의 권한으로 간주하지 않습니다.

```
유효 권한 = Bitbucket 사용자 권한
          ∩ MCP 접근 정책(프로젝트/저장소/브랜치)
          ∩ 도구 역할·스코프
          ∩ 승인(쓰기·실행 등급)
```

## 왜 필요한가

Bitbucket Server 6.9.1 에는 GitLab 의 `sudo` 같은 범용 impersonation 이 없고, 관리자가 사용자를 대신해
개인 액세스 토큰을 만들어 줄 수도 없습니다. 그래서 흔히 쓰는 "관리자 PAT 하나로 모든 REST 호출" 방식은
AI 에게 사용자가 볼 수 없는 저장소까지 노출합니다. bbmcp 는 그 사이에 서서 요청자 권한을 강제합니다.

## 주요 기능

| 영역 | 내용 |
|---|---|
| 인증 | Keycloak OIDC, 사일런트 SSO(`prompt=none`), 로컬 계정 비상 로그인 |
| 식별 | 최초 1회 `preferred_username` 정확 일치 → 이후 `Keycloak sub ↔ Bitbucket user.id` 고정 |
| 권한 | Bitbucket 권한 플러그인(권장) 또는 REST 폴백, fail-closed 기본 |
| 정책 | 프로젝트·저장소·브랜치 허용/차단, 리소스별 위험도 상한 |
| 승인 | 인자 해시와 PR version 에 묶인 1회용 승인, 변경 시 `APPROVAL_STALE` |
| 도구 | 33종 (조회 / 작성 / 실행 3단계 + 고수준 컨텍스트 도구) |
| 키 | 개인 API 키 발급·회전(유예 포함)·폐기, 변경 가능한 역할·스코프 체계 |
| AI | Anthropic · OpenAI 호환, 항상 스트리밍, 최대 256k 토큰 |
| 감사 | 요청자·Bitbucket 사용자·서비스 계정·도구·대상·결과, 비밀값 제외 |
| 배포 | 환경변수 4개, 단일 도커 이미지, 오프라인망 지원 |

## 빠른 시작 (오프라인)

```bash
# 1) 릴리스 이미지 적재
docker load -i bbmcp-v0.1.0.tar.gz

# 2) 환경변수 (네 개뿐입니다)
cp deploy/.env.example deploy/.env
$EDITOR deploy/.env          # ENCRYPTION_KEY=$(openssl rand -base64 32)

# 3) 기동
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
curl -fsS http://localhost:8080/healthz
```

| 환경변수 | 설명 |
|---|---|
| `DATABASE_URL` | PostgreSQL DSN |
| `BOOTSTRAP_ADMIN` | 최초 관리자 아이디 |
| `BOOTSTRAP_ADMIN_PASSWORD` | 최초 관리자 비밀번호 |
| `ENCRYPTION_KEY` | 저장 비밀값 암호화 키(32바이트) |

나머지 설정(Keycloak, Bitbucket 서비스 계정, 권한 해석기, AI, 정책, 도구)은 **모두 관리자 콘솔**에서
입력하며, 비밀값은 AES-256-GCM 으로 암호화되어 PostgreSQL 에 저장됩니다.

> `ENCRYPTION_KEY` 를 분실하면 저장된 Client Secret·서비스 PAT·사용자 PAT 을 복호화할 수 없습니다.
> 데이터베이스 백업과 반드시 함께 보관하십시오.

## MCP 클라이언트 연결

```json
{
  "mcpServers": {
    "bbmcp": {
      "type": "http",
      "url": "https://bbmcp.company.local/mcp",
      "headers": { "Authorization": "Bearer bbmcp_xxx_yyy" }
    }
  }
}
```

Keycloak OAuth 를 쓰는 클라이언트는 `/.well-known/oauth-protected-resource` 메타데이터로 인가 서버를
자동 발견합니다.

## MCP 도구

<details>
<summary><strong>조회 (1차) — 기본 활성</strong></summary>

`bitbucket_me` `bitbucket_my_permissions` `bitbucket_projects` `bitbucket_get_project`
`bitbucket_repositories` `bitbucket_get_repository` `bitbucket_repository_tree` `bitbucket_get_file`
`bitbucket_commits` `bitbucket_get_commit` `bitbucket_commit_changes` `bitbucket_diff`
`bitbucket_branches` `bitbucket_tags` `bitbucket_pull_requests` `bitbucket_get_pull_request`
`bitbucket_pr_commits` `bitbucket_pr_changes` `bitbucket_pr_diff` `bitbucket_pr_comments`
`bitbucket_pr_activities` `bitbucket_search_code`

**고수준 컨텍스트**: `bitbucket_pr_review_context` `bitbucket_repository_context`
`bitbucket_recent_changes` `bitbucket_change_context`

</details>

<details>
<summary><strong>작성 (2차) — 기본 활성 · 승인 필요</strong></summary>

`bitbucket_create_pull_request` `bitbucket_comment_pull_request` `bitbucket_update_pull_request`
`bitbucket_create_branch`

</details>

<details>
<summary><strong>실행 (3차) — 기본 비활성 · 승인 필수</strong></summary>

`bitbucket_merge_pull_request` `bitbucket_approve_pull_request` `bitbucket_decline_pull_request`

</details>

삭제·권한 변경·사용자 관리 도구는 의도적으로 제공하지 않습니다.

## 아키텍처

```mermaid
flowchart TB
    USER[사용자] --> CLIENT[MCP 클라이언트 / AI 에이전트]
    CLIENT --> KC[Keycloak]
    CLIENT --> MCP[bbmcp 게이트웨이]

    MCP --> AUTH[토큰 · API 키 검증]
    AUTH --> ID[식별 매핑]
    ID --> POLICY[접근 정책]
    POLICY --> PERM[권한 해석기]
    PERM --> PLUGIN[Bitbucket 권한 플러그인]
    PLUGIN --> BB[Bitbucket Server 6.9.1]
    POLICY --> APPROVAL[승인 엔진]
    APPROVAL --> TOOLS[MCP 도구]
    TOOLS -->|서비스 계정 PAT| REST[Bitbucket REST]
    REST --> BB
    MCP --> AUDIT[(감사 로그)]

    style MCP fill:#dcfce7
    style PERM fill:#e9d5ff
    style APPROVAL fill:#fecaca
    style BB fill:#fca5a5
```

## 저장소 구조

```
cmd/server/            서버 진입점
internal/
  auth/                로컬 계정, 세션, Keycloak OIDC, 사일런트 SSO
  identity/            Keycloak sub ↔ Bitbucket user.id 매핑
  bitbucket/           BitbucketAdapter 인터페이스와 6.9.1 REST 구현
  permission/          유효 권한 해석기(플러그인 / REST 폴백), 브랜치 제한
  policy/              프로젝트·저장소·브랜치 ACL
  approval/            인자 바인딩 승인 엔진
  tools/               MCP 도구 정의와 인가 파이프라인
  mcp/                 Streamable HTTP MCP 엔드포인트
  api/                 관리자 · 개인 API, 인증 핸들러
  aiproxy/             AI 스트리밍 중계
  apikey/              개인 키와 변경 가능한 권한 체계
  audit/ crypto/ settings/ database/ httpx/ webui/
web/                   React + Mantine 콘솔
plugin/                Bitbucket Server 권한 플러그인 (Java)
deploy/                docker-compose 와 환경변수 예시
docs/                  GitHub Pages 문서와 화면 캡처
hack/                  개발용 모의 Bitbucket, 시드, 화면 검증 스크립트
```

## 개발

```bash
# PostgreSQL + 모의 Bitbucket + 서버를 한 번에 기동하고 샘플 데이터까지 넣습니다
scripts/dev.sh up
# 콘솔: http://localhost:18411  (admin / bbmcpAdmin!2026)

# 테스트 (통합 테스트는 TEST_DATABASE_URL 이 있을 때만 수행)
go test ./... -count=1 -p 1
TEST_DATABASE_URL="postgres://bbmcp:bbmcp@127.0.0.1:15457/bbmcp_test?sslmode=disable" \
  go test ./... -count=1 -p 1

# 모든 화면을 실제 브라우저로 돌며 콘솔 오류를 검사하고 캡처를 갱신합니다
node hack/screenshots.mjs

scripts/dev.sh down
```

## 빌드와 릴리스

```bash
scripts/build.sh                # 로컬 바이너리 (웹 콘솔 포함)
scripts/build.sh --image        # bbmcp:v<버전> 이미지
scripts/build.sh --image --save # + bbmcp-v<버전>.tar.gz
scripts/release.sh              # 태그 + GitHub 릴리스 업로드
```

릴리스 산출물은 **오프라인망에서 운영 가능한 서비스 도커 이미지 하나**입니다.
이미지 이름은 `bbmcp:v<버전>`, 파일명은 `bbmcp-v<버전>.tar.gz` 입니다.

## 라이선스

Apache License 2.0
