import { Alert, Button, Code, Group, List, Stack, Text } from '@mantine/core'
import { IconPlugConnected } from '@tabler/icons-react'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import { ErrorBlock, JsonBlock, LoadingBlock, PageHeader, SaveBar, Section } from '../../components/ui'
import type { KeycloakSettings } from '../../lib/api'
import { useConnectivityTest, useSettingsGroup } from '../../lib/useSettingsGroup'

const fields: Field<KeycloakSettings>[] = [
  { kind: 'switch', key: 'enabled', label: 'Keycloak SSO 사용', description: '끄면 로컬 계정 로그인만 허용합니다.' },
  { kind: 'switch', key: 'silentSso', label: '사일런트 SSO 사용', description: '로그인 화면에서 숨은 iframe 으로 기존 SSO 세션을 자동 확인합니다.' },
  {
    kind: 'text',
    key: 'issuer',
    label: 'Issuer URL',
    description: 'realm 까지 포함합니다. 예: https://sso.company.local/realms/company',
    placeholder: 'https://sso.company.local/realms/company',
    span: 12,
  },
  { kind: 'text', key: 'clientId', label: 'Client ID', placeholder: 'bbmcp' },
  { kind: 'secret', secretKey: 'clientSecret', label: 'Client Secret' },
  {
    kind: 'text',
    key: 'redirectUrl',
    label: 'Redirect URI',
    description: '비워 두면 요청 호스트 기준 /auth/oidc/callback 을 사용합니다.',
    placeholder: 'https://bbmcp.company.local/auth/oidc/callback',
    span: 12,
  },
  {
    kind: 'text',
    key: 'postLogoutUrl',
    label: '로그아웃 후 이동 URL',
    placeholder: 'https://bbmcp.company.local/',
    span: 12,
  },
  { kind: 'tags', key: 'scopes', label: '스코프', placeholder: 'openid, profile, email' },
  { kind: 'text', key: 'usernameClaim', label: '사용자명 클레임', description: '기본값 preferred_username' },
  { kind: 'text', key: 'roleClaimPath', label: '역할 클레임 경로', description: '기본값 realm_access.roles' },
  { kind: 'text', key: 'adminRole', label: '서비스 관리자 역할', description: '이 역할을 가진 사용자는 관리 메뉴를 사용할 수 있습니다.' },
  { kind: 'text', key: 'requireRole', label: '로그인 필수 역할', description: '비워 두면 역할 제한 없이 로그인할 수 있습니다.' },
  { kind: 'number', key: 'silentSsoMaxAgeSec', label: '사일런트 SSO max_age (초)', description: '0 이면 사용하지 않습니다.', min: 0, max: 86400 },
  { kind: 'switch', key: 'autoProvision', label: '첫 로그인 시 계정 자동 생성' },
  { kind: 'switch', key: 'insecureSkipTls', label: 'TLS 인증서 검증 생략', description: '사설 CA 환경에서만 사용하십시오.' },
]

export function AdminAuthPage() {
  const { query, draft, setDraft, secrets, setSecrets, secretPresence, save } =
    useSettingsGroup<KeycloakSettings>('keycloak')
  const test = useConnectivityTest('keycloak')

  return (
    <>
      <PageHeader
        title="인증 (Keycloak)"
        description="Client ID 와 Client Secret 만 입력하면 디스커버리 문서로 엔드포인트를 자동 구성합니다."
        actions={
          <Button
            variant="default"
            leftSection={<IconPlugConnected size={18} />}
            loading={test.isPending}
            onClick={() => test.mutate(undefined)}
          >
            연결 점검
          </Button>
        }
      />

      {query.isLoading ? <LoadingBlock /> : null}
      {query.error ? <ErrorBlock error={query.error} /> : null}

      {test.data ? (
        <Alert color={test.data.ok ? 'teal' : 'red'} variant="light" mb="lg" title={test.data.ok ? '연결 정상' : '연결 실패'}>
          <JsonBlock value={test.data} maxHeight={220} />
        </Alert>
      ) : null}

      {draft ? (
        <Section title="OIDC 구성">
          <SettingsForm
            fields={fields}
            value={draft}
            onChange={setDraft}
            secrets={secrets}
            onSecretChange={setSecrets}
            secretPresence={secretPresence}
          />
          <SaveBar onSave={() => save.mutate()} saving={save.isPending} />
        </Section>
      ) : null}

      <Section title="Keycloak 쪽 설정 안내">
        <Stack gap="sm">
          <Text>클라이언트를 아래와 같이 구성하십시오.</Text>
          <List spacing="xs" size="sm">
            <List.Item>Client type: <Code>OpenID Connect</Code>, Client authentication: <Code>On</Code> (confidential)</List.Item>
            <List.Item>Valid redirect URIs: <Code>https://&lt;bbmcp 주소&gt;/auth/oidc/callback</Code></List.Item>
            <List.Item>Web origins: <Code>https://&lt;bbmcp 주소&gt;</Code></List.Item>
            <List.Item>Valid post logout redirect URIs: <Code>https://&lt;bbmcp 주소&gt;/*</Code></List.Item>
            <List.Item>
              Realm roles: <Code>bitbucket-mcp-user</Code>, <Code>bitbucket-mcp-writer</Code>,{' '}
              <Code>bitbucket-mcp-executor</Code>, <Code>bitbucket-mcp-admin</Code>
            </List.Item>
            <List.Item>사일런트 SSO 는 <Code>prompt=none</Code> 요청을 사용하므로 추가 설정이 필요하지 않습니다.</List.Item>
          </List>
          <Group gap="xs">
            <Text size="sm" c="dimmed">MCP 클라이언트용 보호 리소스 메타데이터:</Text>
            <Code>/.well-known/oauth-protected-resource</Code>
          </Group>
        </Stack>
      </Section>
    </>
  )
}
