-- Keycloak 토큰에서 온 역할과 관리자가 bbmcp 에서 부여한 역할을 따로 보관합니다.
--
-- 이전에는 Keycloak 로그인과 MCP OAuth 요청이 올 때마다 users.roles 를 토큰의
-- 역할로 통째로 덮어써서, 관리자가 사용자 화면에서 준 역할이 다음 요청에서
-- 사라졌습니다. 이제 토큰 역할은 keycloak_roles 에만 쓰고, roles 는 관리자가
-- 부여한 역할만 담습니다. 실제 적용 역할은 두 값과 SSO 기본 역할의 합집합입니다.
ALTER TABLE users ADD COLUMN IF NOT EXISTS keycloak_roles TEXT[] NOT NULL DEFAULT '{}';

-- Keycloak 에 연결된 계정의 roles 는 마지막으로 본 토큰의 역할이었습니다. 그 값은
-- keycloak_roles 로 옮기고 roles 는 비웁니다. 토큰에서 온 역할을 관리자 부여로
-- 남겨 두면, 나중에 Keycloak 에서 그 역할을 회수해도 bbmcp 에서는 계속 유지되어
-- 허용 범위가 넓어집니다.
UPDATE users
   SET keycloak_roles = roles,
       roles = '{}'
 WHERE keycloak_sub IS NOT NULL;
