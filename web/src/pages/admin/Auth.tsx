import { Alert, Badge, Button, Code, List, Stack, Table, Text } from '@mantine/core'
import { IconAlertTriangle, IconPlugConnected, IconShieldLock } from '@tabler/icons-react'
import { useMutation } from '@tanstack/react-query'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import {
  CopyField,
  ErrorBlock,
  JsonBlock,
  LoadingBlock,
  PageHeader,
  SaveBar,
  Section,
  StatList,
  TableScroll,
} from '../../components/ui'
import { api, type KeycloakSettings, type KeycloakTestReport, type MCPOAuthReport } from '../../lib/api'
import { useSettingsGroup } from '../../lib/useSettingsGroup'

const loginFields: Field<KeycloakSettings>[] = [
  { kind: 'switch', key: 'enabled', label: 'Keycloak SSO 사용', description: '끄면 로컬 계정 로그인만 허용합니다.' },
  {
    kind: 'switch',
    key: 'silentSso',
    label: '사일런트 SSO 사용',
    description: '로그인 화면에서 숨은 프레임으로 기존 SSO 세션을 자동 확인합니다.',
  },
  {
    kind: 'text',
    key: 'issuer',
    label: 'Issuer URL',
    description: 'realm 까지 포함합니다. 예: https://sso.company.local/realms/company',
    placeholder: 'https://sso.company.local/realms/company',
    span: 12,
  },
  { kind: 'text', key: 'clientId', label: 'Client ID (웹 콘솔)', placeholder: 'bbmcp' },
  { kind: 'secret', secretKey: 'clientSecret', label: 'Client Secret (웹 콘솔)' },
  {
    kind: 'text',
    key: 'redirectUrl',
    label: 'Redirect URI',
    description: '비워 두면 접속 주소 기준 /auth/oidc/callback 을 사용합니다. 여기 값과 Keycloak 등록값이 정확히 같아야 합니다.',
    placeholder: 'https://bbmcp.company.local/auth/oidc/callback',
    span: 12,
  },
  {
    kind: 'text',
    key: 'postLogoutUrl',
    label: '로그아웃 후 이동 URL',
    description:
      '비워 두면 로그아웃 시 이 값을 보내지 않습니다(오류 없음). 값을 넣으면 Keycloak 의 Valid post logout redirect URIs 에도 같은 값을 등록해야 합니다.',
    placeholder: 'https://bbmcp.company.local',
    span: 12,
  },
  { kind: 'tags', key: 'scopes', label: '웹 로그인 스코프', placeholder: 'openid, profile, email' },
  { kind: 'text', key: 'usernameClaim', label: '사용자명 클레임', description: '기본값 preferred_username' },
  { kind: 'text', key: 'roleClaimPath', label: '역할 클레임 경로', description: '기본값 realm_access.roles' },
  {
    kind: 'text',
    key: 'adminRole',
    label: '서비스 관리자 역할',
    description: '이 역할을 가진 사용자는 관리 메뉴를 사용할 수 있습니다.',
  },
  {
    kind: 'text',
    key: 'requireRole',
    label: '로그인 필수 역할',
    description: '비워 두면 역할 제한 없이 로그인할 수 있습니다.',
  },
  {
    kind: 'number',
    key: 'silentSsoMaxAgeSec',
    label: '사일런트 SSO max_age (초)',
    description: '0 이면 사용하지 않습니다.',
    min: 0,
    max: 86400,
  },
  { kind: 'switch', key: 'autoProvision', label: '첫 로그인 시 계정 자동 생성' },
  {
    kind: 'switch',
    key: 'insecureSkipTls',
    label: 'TLS 인증서 검증 생략',
    description: '사설 CA 환경에서만 사용하십시오.',
  },
]

const mcpFields: Field<KeycloakSettings>[] = [
  {
    kind: 'switch',
    key: 'mcpOauthEnabled',
    label: 'MCP OAuth 사용',
    description: '끄면 MCP 클라이언트는 개인 API 키로만 연결할 수 있습니다.',
  },
  {
    kind: 'switch',
    key: 'mcpAllowDynamicRegistration',
    label: '게이트웨이 동적 등록 대행',
    description: 'Keycloak 의 동적 등록이 막혀 있어도 아래 클라이언트 ID 를 내려 줍니다.',
  },
  {
    kind: 'text',
    key: 'mcpClientId',
    label: 'MCP 클라이언트 ID (공개 클라이언트)',
    description: 'Keycloak 에 PKCE 공개 클라이언트로 따로 만들어 두십시오.',
    placeholder: 'bbmcp-mcp',
  },
  {
    kind: 'text',
    key: 'mcpRequiredScope',
    label: '필수 스코프',
    description: '비워 두면 스코프를 검사하지 않습니다. 예: mcp',
  },
  {
    kind: 'tags',
    key: 'mcpScopes',
    label: 'MCP 스코프',
    description: '클라이언트에게 요청하도록 안내할 스코프입니다.',
    placeholder: 'openid, profile, email, offline_access',
  },
  {
    kind: 'tags',
    key: 'mcpAudiences',
    label: '허용 클라이언트 (aud / azp)',
    description: '비워 두면 위의 MCP 클라이언트 ID 와 웹 콘솔 Client ID 를 허용합니다.',
  },
]

export function AdminAuthPage() {
  const { query, draft, setDraft, secrets, setSecrets, secretPresence, save } =
    useSettingsGroup<KeycloakSettings>('keycloak')
  const test = useMutation({
    mutationFn: () => api.post<KeycloakTestReport>('/api/admin/test/keycloak'),
  })
  const oauthTest = useMutation({
    mutationFn: () => api.post<MCPOAuthReport>('/api/admin/test/mcp-oauth'),
  })

  const origin = window.location.origin

  return (
    <>
      <PageHeader
        title="인증 (Keycloak)"
        description="웹 콘솔 로그인과 MCP 클라이언트 OAuth 를 함께 설정합니다. Client ID 와 Secret 만 입력하면 엔드포인트는 디스커버리 문서에서 자동으로 읽습니다."
        actions={
          <Button
            variant="default"
            leftSection={<IconPlugConnected size={18} />}
            loading={test.isPending}
            onClick={() => test.mutate()}
          >
            연결 점검
          </Button>
        }
      />

      {query.isLoading ? <LoadingBlock /> : null}
      {query.error ? <ErrorBlock error={query.error} /> : null}

      {test.data ? <KeycloakReport report={test.data} /> : null}

      {draft ? (
        <>
          <Section title="웹 콘솔 로그인" description="사람이 브라우저로 접속할 때 사용하는 기밀 클라이언트입니다.">
            <SettingsForm
              fields={loginFields}
              value={draft}
              onChange={setDraft}
              secrets={secrets}
              onSecretChange={setSecrets}
              secretPresence={secretPresence}
            />
          </Section>

          <Section
            title="MCP OAuth"
            description="MCP 클라이언트는 공개 클라이언트로 PKCE 로그인합니다. 웹 콘솔과 같은 클라이언트를 쓰지 마십시오."
            actions={
              <Button
                variant="default"
                size="compact-sm"
                leftSection={<IconShieldLock size={16} />}
                loading={oauthTest.isPending}
                onClick={() => oauthTest.mutate()}
              >
                MCP OAuth 점검
              </Button>
            }
          >
            <SettingsForm
              fields={mcpFields}
              value={draft}
              onChange={setDraft}
              secrets={secrets}
              onSecretChange={setSecrets}
              secretPresence={secretPresence}
            />
            <SaveBar onSave={() => save.mutate()} saving={save.isPending} />
          </Section>
        </>
      ) : null}

      {oauthTest.error ? <ErrorBlock error={oauthTest.error} /> : null}
      {oauthTest.data ? <OAuthReport report={oauthTest.data} /> : null}

      <Section title="Keycloak 쪽 설정 안내">
        <Text mb="sm">클라이언트를 두 개 만듭니다. 용도가 다르고 보안 등급도 다릅니다.</Text>
        <TableScroll minWidth={720}>
          <Table striped withTableBorder={false}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>항목</Table.Th>
                <Table.Th>웹 콘솔용</Table.Th>
                <Table.Th>MCP 클라이언트용</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              <Table.Tr>
                <Table.Td>Client ID 예시</Table.Td>
                <Table.Td><Code>bbmcp</Code></Table.Td>
                <Table.Td><Code>bbmcp-mcp</Code></Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Td>Client authentication</Table.Td>
                <Table.Td>On (기밀)</Table.Td>
                <Table.Td>Off (공개)</Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Td>PKCE</Table.Td>
                <Table.Td>선택</Table.Td>
                <Table.Td><strong>S256 필수</strong></Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Td>Standard flow</Table.Td>
                <Table.Td>On</Table.Td>
                <Table.Td>On</Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Td>Valid redirect URIs</Table.Td>
                <Table.Td><Code>{origin}/auth/oidc/callback</Code></Table.Td>
                <Table.Td>
                  <Code>http://127.0.0.1:*</Code> / <Code>http://localhost:*</Code>
                  <Text size="xs" c="dimmed" mt={4}>
                    MCP 클라이언트는 로컬 루프백 포트로 콜백을 받습니다.
                  </Text>
                </Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Td>Web origins</Table.Td>
                <Table.Td><Code>{origin}</Code></Table.Td>
                <Table.Td><Code>+</Code> 또는 비움</Table.Td>
              </Table.Tr>
            </Table.Tbody>
          </Table>
        </TableScroll>

        <Text fw={600} mt="lg" mb="xs">
          공통
        </Text>
        <List spacing="xs" size="sm">
          <List.Item>
            Realm 역할: <Code>bitbucket-mcp-user</Code>, <Code>bitbucket-mcp-writer</Code>,{' '}
            <Code>bitbucket-mcp-executor</Code>, <Code>bitbucket-mcp-admin</Code>
          </List.Item>
          <List.Item>
            두 클라이언트 모두 사용자 역할이 토큰에 실리도록 기본 매퍼를 유지하십시오.
          </List.Item>
          <List.Item>
            필수 스코프를 지정했다면 Keycloak 에 같은 이름의 client scope 를 만들고 MCP 클라이언트에
            기본 스코프로 추가하십시오.
          </List.Item>
        </List>
      </Section>
    </>
  )
}

function KeycloakReport({ report }: { report: KeycloakTestReport }) {
  return (
    <Section
      title="Keycloak 연결 점검 결과"
      actions={
        <Badge color={report.ok ? 'teal' : 'red'} variant="light">
          {report.ok ? '연결 정상' : '연결 실패'}
        </Badge>
      }
    >
      {report.error ? (
        <Alert color="red" variant="light" icon={<IconAlertTriangle size={20} />} mb="md">
          {report.error}
        </Alert>
      ) : null}

      {report.warnings?.length ? (
        <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={20} />} mb="md" title="확인하십시오">
          <Stack gap={4}>
            {report.warnings.map((w) => (
              <Text key={w} size="sm">
                • {w}
              </Text>
            ))}
          </Stack>
        </Alert>
      ) : null}

      <StatList
        items={[
          { label: '인가 엔드포인트', value: report.authUrl || '—' },
          { label: '토큰 엔드포인트', value: report.tokenUrl || '—' },
          { label: '요청 스코프', value: report.scopes?.join(', ') || '—' },
        ]}
      />

      <Alert variant="light" color="bbblue" mt="lg" title="Keycloak 에 그대로 등록하십시오">
        <Text size="sm" mb="sm">
          아래 값은 bbmcp 가 실제로 보내는 문자열입니다. 한 글자라도 다르면 Keycloak 이
          <Code>Invalid parameter: redirect_uri</Code> 로 거부합니다.
        </Text>
        <Stack gap="sm">
          <div>
            <Text size="sm" fw={600} mb={4}>
              Valid redirect URIs
            </Text>
            {report.register.validRedirectUris.map((uri) => (
              <CopyField key={uri} value={uri} />
            ))}
          </div>
          <div>
            <Text size="sm" fw={600} mb={4}>
              Web origins
            </Text>
            {report.register.webOrigins.map((uri) => (
              <CopyField key={uri} value={uri} />
            ))}
          </div>
          <div>
            <Text size="sm" fw={600} mb={4}>
              Valid post logout redirect URIs
            </Text>
            {report.register.validPostLogoutRedirectUris.length > 0 ? (
              report.register.validPostLogoutRedirectUris.map((uri) => <CopyField key={uri} value={uri} />)
            ) : (
              <Text size="sm" c="dimmed">
                설정하지 않았습니다. bbmcp 는 로그아웃 시 이 값을 보내지 않으므로 오류는 나지 않고,
                로그아웃 후 Keycloak 화면에 머무릅니다.
              </Text>
            )}
          </div>
        </Stack>
      </Alert>
    </Section>
  )
}

function OAuthReport({ report }: { report: MCPOAuthReport }) {
  const as = report.authorizationServer ?? {}
  return (
    <Section
      title="MCP OAuth 점검 결과"
      actions={
        <Badge color={report.ok ? 'teal' : 'red'} variant="light">
          {report.ok ? '연결 가능' : '확인 필요'}
        </Badge>
      }
    >
      {report.error ? (
        <Alert color="red" variant="light" icon={<IconAlertTriangle size={20} />} mb="md">
          {report.error}
        </Alert>
      ) : null}

      {report.warnings?.length ? (
        <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={20} />} mb="md" title="확인하십시오">
          <Stack gap={4}>
            {report.warnings.map((w) => (
              <Text key={w} size="sm">
                • {w}
              </Text>
            ))}
          </Stack>
        </Alert>
      ) : null}

      <StatList
        items={[
          { label: '리소스 URL', value: report.resourceUrl },
          { label: 'Issuer', value: report.issuer || '—' },
          { label: '인가 엔드포인트', value: as.authorizationEndpoint || '—' },
          { label: '토큰 엔드포인트', value: as.tokenEndpoint || '—' },
          { label: 'JWKS', value: as.jwksUri || '—' },
          {
            label: 'Keycloak 동적 등록',
            value: report.keycloakSupportsDynamicRegistration ? '지원' : '미지원',
          },
          { label: '게이트웨이 등록 대행', value: report.gatewayRegistrationEndpoint || '사용 안 함' },
          { label: 'MCP 클라이언트 ID', value: report.mcpClientId || '미설정' },
          { label: '허용 클라이언트', value: report.acceptedAudiences.join(', ') || '—' },
          { label: '필수 스코프', value: report.requiredScope || '없음' },
        ]}
      />

      <Text fw={600} mt="lg" mb="xs">
        클라이언트가 처음 읽는 주소
      </Text>
      <CopyField value={report.resourceMetadataUrl} />

      {report.loopbackRedirectUris?.length ? (
        <Alert variant="light" color="bbblue" mt="lg" title="MCP 공개 클라이언트에 등록할 리다이렉트 URI">
          <Text size="sm" mb="sm">
            MCP 클라이언트는 매번 다른 루프백 포트로 콜백을 받습니다. 아래 와일드카드를 Keycloak 공개
            클라이언트의 Valid redirect URIs 에 넣지 않으면 로그인 창에서
            <Code>Invalid parameter: redirect_uri</Code> 가 납니다.
          </Text>
          <Stack gap={6}>
            {report.loopbackRedirectUris.map((uri) => (
              <CopyField key={uri} value={uri} />
            ))}
          </Stack>
        </Alert>
      ) : null}

      <Text fw={600} mt="lg" mb="xs">
        클라이언트 설정 예시
      </Text>
      <JsonBlock value={report.clientConfigExample} maxHeight={200} />
      <Text size="sm" c="dimmed" mt="xs">
        OAuth 를 지원하는 MCP 클라이언트는 위 설정만으로 충분합니다. 연결하면 브라우저가 열리고
        Keycloak 로그인 후 자동으로 토큰을 받습니다.
      </Text>
    </Section>
  )
}
