# bbmcp Permission Resolver (Bitbucket Server 6.9.1 플러그인)

bbmcp 게이트웨이가 **Bitbucket 자체 권한 판정**을 그대로 사용할 수 있도록, 유효 권한
조회 전용 REST 엔드포인트를 제공하는 작은 플러그인입니다.

이 플러그인이 없어도 bbmcp 는 REST 폴백 모드로 동작하지만, 그룹 권한·상속·공개 저장소
조합을 Bitbucket 과 100% 동일하게 맞추려면 플러그인 모드를 권장합니다.

## 제공 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/rest/mcp-permission/1.0/health` | 플러그인 상태 |
| GET | `/rest/mcp-permission/1.0/users/{username}/projects/{projectKey}` | 프로젝트 유효 권한 |
| GET | `/rest/mcp-permission/1.0/users/{username}/repositories/{projectKey}/{repositorySlug}` | 저장소 유효 권한 |

응답 예:

```json
{
  "username": "hkjang",
  "userId": 142,
  "project": "AI",
  "repository": "text2sql",
  "public": false,
  "permissions": { "read": true, "write": true, "admin": false },
  "effective": "WRITE",
  "global": { "licensedUser": true, "projectCreate": false, "admin": false, "sysAdmin": false }
}
```

**권한을 변경하는 기능은 의도적으로 제공하지 않습니다.** 조회 전용입니다.

## 빌드

Atlassian SDK(또는 Maven + Atlassian 저장소 접근)가 있는 환경에서 빌드합니다.

```bash
cd plugin
atlas-package          # 또는: mvn clean package
# target/bbmcp-permission-plugin-1.0.0.jar
```

오프라인망에서는 외부망 빌드 머신에서 jar 를 만들어 반입하십시오.

## 설치

1. Bitbucket 관리 → 애플리케이션 관리 → 앱 업로드로 jar 를 업로드합니다.
2. `bitbucket.properties` 에 공유 비밀값을 설정하고 Bitbucket 을 재시작합니다.

   ```properties
   bbmcp.permission.secret=<충분히 긴 임의 문자열>
   ```

   또는 환경변수 `BBMCP_PERMISSION_SECRET` 로 지정할 수 있습니다.

3. bbmcp 관리 콘솔 → **권한 해석기** 에서
   - 모드: `Bitbucket 권한 플러그인`
   - 플러그인 기본 URL: Bitbucket 주소
   - 플러그인 공유 비밀값: 위에서 설정한 값

   을 입력하고 **판정 시험** 으로 확인합니다.

## 접근 통제

모든 요청은 서블릿 필터에서 다음을 검증합니다.

- `X-BBMCP-Token`: 공유 비밀값 (상수 시간 비교)
- `X-BBMCP-Timestamp`: 유닉스 초, ±5분 허용
- `X-BBMCP-Signature`: `HMAC-SHA256(secret, "<timestamp>\n<path>")` 의 hex

비밀값이 설정되지 않으면 **모든 요청을 거부**합니다(기본 차단).
추가로 네트워크 계층에서 bbmcp 서버 IP 만 허용하는 것을 권장합니다.
