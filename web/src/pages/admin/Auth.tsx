import { Alert, Badge, Button, Code, Group, List, Stack, Table, Text } from '@mantine/core'
import { IconAlertTriangle, IconPlugConnected, IconShieldLock } from '@tabler/icons-react'
import { useMutation } from '@tanstack/react-query'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import {
  CopyField,
  ErrorBlock,
  JsonBlock,
  TextBlock,
  LoadingBlock,
  PageHeader,
  SaveBar,
  Section,
  StatList,
  TableScroll,
} from '../../components/ui'
import {
  api,
  type DiscoveryTrace,
  type KeycloakRegistrationReport,
  type KeycloakSettings,
  type KeycloakTestReport,
  type MCPOAuthReport,
  type RedirectCheck,
} from '../../lib/api'
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
    description:
      'realm 까지 포함합니다. 예: https://sso.company.local/realms/company (구버전 WildFly 배포판, 예: Keycloak 10 은 https://sso.company.local/auth/realms/company)',
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
      '비워 두면 로그아웃 시 이 값을 보내지 않습니다(오류 없음). 값을 넣으면 Keycloak 의 Valid post logout redirect URIs 에도 같은 값을 등록해야 합니다. 그 항목이 없는 구버전(예: Keycloak 10)은 Valid Redirect URIs 에 등록합니다.',
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
    description:
      '켜 두십시오(권장). MCP 클라이언트에 이 게이트웨이를 인가 서버로 알리고 아래 클라이언트 ID 를 내려 줍니다. 끄면 클라이언트가 Keycloak 에 직접 등록하는데, Keycloak 13 이하(예: 10)는 이를 invalid_client_metadata 로 거부합니다.',
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
  const registrationTest = useMutation({
    mutationFn: () => api.post<KeycloakRegistrationReport>('/api/admin/test/keycloak-registration'),
  })
  const trace = useMutation({
    mutationFn: () => api.get<DiscoveryTrace>('/api/admin/mcp-oauth/trace'),
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

      {query.data ? (
        <Section
          title="MCP 클라이언트 진단"
          description="에이전트가 로그인에서 실패할 때, 실제로 어디까지 왔는지 확인합니다."
        >
          <Stack gap="lg">
            <div>
              <Group justify="space-between" mb="xs">
                <Text fw={600}>최근 클라이언트 탐색 기록</Text>
                <Button size="compact-sm" variant="default" loading={trace.isPending} onClick={() => trace.mutate()}>
                  기록 보기
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                정상이면 401 → 보호 리소스 메타데이터 → 인가 서버 메타데이터 → 등록 순서로 보입니다. 401 만 있고 그 뒤가
                없다면 클라이언트가 이 게이트웨이가 아니라 다른 곳(예: Keycloak)을 인가 서버로 쓰고 있습니다. 옛 bbmcp 가
                응답했거나, 클라이언트가 예전 정보를 기억하거나, 설정에 고정되어 있는 경우입니다.
              </Text>
              {trace.error ? <ErrorBlock error={trace.error} /> : null}
              {trace.data ? <TraceTable trace={trace.data} /> : null}
            </div>

            <div>
              <Text fw={600} mb="xs">
                에이전트 PC 에서 확인
              </Text>
              <Text size="sm" c="dimmed" mb="xs">
                에이전트가 쓰는 주소로 바꿔 실행하십시오. 첫 줄이 버전, 둘째 줄이 클라이언트가 받는 인가 서버, 셋째 줄이 등록
                주소입니다. 버전이 비어 있거나 인가 서버·등록 주소가 Keycloak 이면, 그 주소에 응답하는 것은 옛 bbmcp
                이거나 등록 대행이 꺼진 bbmcp 입니다.
              </Text>
              <TextBlock text={probeCommands(oauthTest.data?.resourceUrl || origin)} maxHeight={260} />
            </div>

            <div>
              <Text fw={600} mb="xs">
                등록 없이 연결 (클라이언트 ID 고정)
              </Text>
              <Text size="sm" c="dimmed" mb="xs">
                클라이언트에 MCP 클라이언트 ID 를 고정하면 동적 등록을 아예 하지 않으므로, 서버 버전·설정과 무관하게
                invalid_client_metadata 가 나지 않습니다.
              </Text>
              <TextBlock text={fixedClientExamples(oauthTest.data?.resourceUrl || origin, draft?.mcpClientId || 'bbmcp-mcp')} maxHeight={260} />
            </div>

            <div>
              <Group justify="space-between" mb="xs">
                <Text fw={600}>Keycloak 동적 등록 시험</Text>
                <Button
                  size="compact-sm"
                  variant="default"
                  loading={registrationTest.isPending}
                  onClick={() => registrationTest.mutate()}
                >
                  시험
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                MCP 클라이언트가 보내는 것과 같은 등록 요청을 Keycloak 에 한 번 보내, Keycloak 이 받아 주는지 확인합니다.
                시험용 클라이언트는 만들어지지 않거나, 만들어지면 즉시 지웁니다.
              </Text>
              {registrationTest.error ? <ErrorBlock error={registrationTest.error} /> : null}
              {registrationTest.data ? <RegistrationResult report={registrationTest.data} /> : null}
            </div>
          </Stack>
        </Section>
      ) : null}

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
                  <Code>http://localhost/callback</Code> / <Code>http://127.0.0.1/callback</Code>
                  <Text size="xs" c="dimmed" mt={4}>
                    포트 없이 등록하면 클라이언트가 고른 임의 포트가 허용됩니다(Keycloak 26 에서 확인). Keycloak 10 처럼 MCP OAuth
                    점검이 보안 경고를 내는 구버전에서는 이 방식과 http://localhost:* 같은 와일드카드가 공격자 주소까지 통과하므로,
                    고정 포트 주소를 정확히 등록하고(예: http://localhost:33333/callback) 클라이언트에 그 포트를 설정하십시오.
                  </Text>
                </Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Td>Web origins</Table.Td>
                <Table.Td><Code>{origin}</Code></Table.Td>
                <Table.Td><Code>+</Code> 또는 비움</Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Td>Exclude Issuer From Authentication Response (Advanced)</Table.Td>
                <Table.Td>Off</Table.Td>
                <Table.Td>
                  <strong>On</strong>
                  <Text size="xs" c="dimmed" mt={4}>
                    MCP 클라이언트에는 bbmcp 가 인가 서버로 알려지므로 Keycloak 의 issuer 를 붙이지 않습니다. 이
                    옵션이 없는 구버전(예: Keycloak 10)은 issuer 를 붙이지 않으므로 할 일이 없습니다.
                  </Text>
                </Table.Td>
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
            {report.redirectCheck ? <RedirectCheckLine check={report.redirectCheck} /> : null}
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
              Valid post logout redirect URIs{' '}
              <Text span size="xs" c="dimmed" fw={400}>
                (이 항목이 없는 구버전 Keycloak 은 Valid Redirect URIs)
              </Text>
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

      {report.keycloakRegisters ? (
        <Alert color="red" variant="light" icon={<IconAlertTriangle size={20} />} mb="md" title="MCP 클라이언트가 Keycloak 에 직접 등록합니다">
          게이트웨이 동적 등록 대행이 꺼져 있습니다. Keycloak 13 이하(예: 10)에서는 모든 MCP 클라이언트가
          invalid_client_metadata 로 실패합니다. 위 설정에서 등록 대행을 켜고 저장하십시오.
        </Alert>
      ) : null}

      {report.unsafeRedirects?.length ? (
        <Alert color="red" variant="light" icon={<IconAlertTriangle size={20} />} mb="md" title="보안: 공격자 주소로 로그인 결과가 갈 수 있습니다">
          Keycloak 이 <Code>{report.unsafeRedirects[0]}</Code> 로도 로그인 결과를 보냅니다. MCP 클라이언트의 Valid redirect
          URIs 에서 와일드카드(<Code>http://localhost:*</Code> 등)와 포트 없는 localhost 주소를 지우고, 고정 포트 주소를 정확히
          등록한 뒤(예: <Code>http://localhost:33333/callback</Code>) 클라이언트에 그 포트를 설정하십시오(Claude Code:{' '}
          <Code>--callback-port 33333</Code>).
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
          {
            label: '실행 중인 버전',
            value: report.version ? `v${report.version.version} (${report.version.commit.slice(0, 7)})` : '—',
          },
          { label: '리소스 URL', value: report.resourceUrl },
          { label: '클라이언트에 알리는 인가 서버', value: report.advertisedAuthorizationServer || '—' },
          { label: 'Keycloak Issuer', value: report.issuer || '—' },
          { label: '인가 엔드포인트', value: as.authorizationEndpoint || '—' },
          { label: '토큰 엔드포인트', value: as.tokenEndpoint || '—' },
          { label: 'JWKS', value: as.jwksUri || '—' },
          {
            label: 'Keycloak 등록 엔드포인트',
            value: report.keycloakSupportsDynamicRegistration ? '있음 (받아 주는지는 아래 시험으로 확인)' : '없음',
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
        <Alert variant="light" color="bbblue" mt="lg" title="MCP 공개 클라이언트에 할 설정">
          <Text size="sm" mb="sm">
            MCP 클라이언트는 매번 다른 루프백 포트로 콜백을 받습니다. 아래 주소를 포트 없이 Keycloak 공개
            클라이언트의 Valid redirect URIs 에 넣으면 임의 포트가 허용됩니다. 없으면 로그인 창에서
            <Code>Invalid parameter: redirect_uri</Code> 가 납니다. 이 점검이 보안 경고를 낸다면(Keycloak 10 등 구버전) 포트 없는
            주소와 와일드카드를 지우고, 고정 포트 주소(예: <Code>http://localhost:33333/callback</Code>)를 정확히 등록한 뒤 클라이언트에
            그 포트를 설정하십시오(Claude Code: <Code>--callback-port 33333</Code>).
          </Text>
          <Stack gap={6}>
            {report.loopbackRedirectUris.map((uri) => (
              <CopyField key={uri} value={uri} />
            ))}
          </Stack>
          {report.redirectChecks?.length ? (
            <Stack gap={6} mt="md">
              <Text size="sm" fw={600}>
                Keycloak 에 실제로 확인한 결과
              </Text>
              {report.redirectChecks.map((check) => (
                <RedirectCheckLine key={check.uri} check={check} />
              ))}
            </Stack>
          ) : null}
          {report.gatewayRegistrationEndpoint && report.redirectChecks?.some((check) => check.sendsIssuer) ? (
            <Text size="sm" mt="md">
              같은 클라이언트의 Advanced 탭에서 <Code>Exclude Issuer From Authentication Response</Code> 를
              켜십시오. 클라이언트에는 이 게이트웨이가 인가 서버로 알려지므로, Keycloak 이 로그인 응답에
              자기 issuer 를 붙이면 이를 검사하는 클라이언트(Python MCP SDK 등)가 로그인을 거부합니다.
            </Text>
          ) : null}
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

/** One redirect URI and what Keycloak answered when bbmcp asked about it. */
function RedirectCheckLine({ check }: { check: RedirectCheck }) {
  const [color, label] = check.error
    ? ['gray', '확인 불가']
    : check.accepted
      ? ['teal', 'Keycloak 허용']
      : check.clientMissing
        ? ['red', '클라이언트 없음']
        : ['red', 'Keycloak 거부']
  return (
    <Stack gap={4} mt={6}>
      <Group gap="xs" wrap="nowrap">
        <Badge color={color} variant="light" style={{ flexShrink: 0 }}>
          {label}
        </Badge>
        <Code style={{ overflowWrap: 'anywhere' }}>{check.uri}</Code>
      </Group>
      {check.error ? (
        <Text size="xs" c="dimmed">
          {check.error}
        </Text>
      ) : null}
      {!check.accepted && !check.error && check.clientMissing ? (
        <Text size="xs" c="dimmed">
          Keycloak: {check.detail}. Keycloak 에 이 Client ID 의 공개 클라이언트가 없습니다.
        </Text>
      ) : null}
      {!check.accepted && !check.error && !check.clientMissing ? (
        <>
          <Text size="xs" c="dimmed">
            Keycloak: {check.detail}. 아래 값을 Valid redirect URIs 에 추가하십시오.
          </Text>
          {check.register ? <CopyField value={check.register} /> : null}
        </>
      ) : null}
    </Stack>
  )
}

/** Commands an operator runs on the agent's PC, reading what a client reads. */
function probeCommands(base: string): string {
  return [
    '# PowerShell',
    `$u = "${base}"`,
    `$r = Invoke-WebRequest -UseBasicParsing "$u/.well-known/oauth-protected-resource/mcp"`,
    `"version: " + $r.Headers["X-Bbmcp-Version"]`,
    `$as = ($r.Content | ConvertFrom-Json).authorization_servers[0]; "authorization server: $as"`,
    `"registration: " + (Invoke-RestMethod "$as/.well-known/openid-configuration").registration_endpoint`,
    '',
    '# bash',
    `u=${base}`,
    `curl -sD - "$u/.well-known/oauth-protected-resource/mcp" | grep -i -E 'x-bbmcp-version|authorization_servers'`,
    `as=$(curl -s "$u/.well-known/oauth-protected-resource/mcp" | sed -E 's/.*"authorization_servers":\\["([^"]*)".*/\\1/')`,
    `curl -s "$as/.well-known/openid-configuration" | grep -o '"registration_endpoint":"[^"]*"'`,
  ].join('\n')
}

/** Client configurations that skip dynamic registration altogether. */
function fixedClientExamples(base: string, clientId: string): string {
  return [
    '# Claude Code',
    `claude mcp add --transport http --client-id ${clientId} bbmcp ${base}/mcp`,
    '',
    '# Keycloak 10 등 고정 포트가 필요한 경우: http://localhost:33333/callback 을 정확히 등록하고',
    `claude mcp add --transport http --client-id ${clientId} --callback-port 33333 bbmcp ${base}/mcp`,
    '',
    '# .mcp.json 또는 Claude Code 설정 (사용자 범위)',
    JSON.stringify({ mcpServers: { bbmcp: { type: 'http', url: `${base}/mcp`, oauth: { clientId, callbackPort: 33333 } } } }, null, 2),
  ].join('\n')
}

function TraceTable({ trace }: { trace: DiscoveryTrace }) {
  if (!trace.events.length) {
    return (
      <Text size="sm" mt="xs">
        v{trace.version.version} 이 {new Date(trace.since).toLocaleString()} 에 시작한 뒤 기록된 탐색이 없습니다.
      </Text>
    )
  }
  return (
    <TableScroll>
      <Table striped mt="xs" fz="xs">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>시각</Table.Th>
            <Table.Th>단계</Table.Th>
            <Table.Th>상태</Table.Th>
            <Table.Th>주소{trace.trustProxyHeaders ? ' (프록시 헤더 기준)' : ''}</Table.Th>
            <Table.Th>클라이언트</Table.Th>
            <Table.Th>내용</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {trace.events.map((e, i) => (
            <Table.Tr key={`${e.at}-${i}`}>
              <Table.Td>{new Date(e.at).toLocaleTimeString()}</Table.Td>
              <Table.Td>{traceKindLabel[e.kind] ?? e.kind}</Table.Td>
              <Table.Td>{e.status}</Table.Td>
              <Table.Td>{e.ip}</Table.Td>
              <Table.Td style={{ maxWidth: 220, overflowWrap: 'anywhere' }}>{e.userAgent}</Table.Td>
              <Table.Td style={{ maxWidth: 320, overflowWrap: 'anywhere' }}>{e.detail}</Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </TableScroll>
  )
}

const traceKindLabel: Record<string, string> = {
  challenge: '401 인증 요구',
  'resource-metadata': '보호 리소스 메타데이터',
  'server-metadata': '인가 서버 메타데이터',
  register: '클라이언트 등록',
  'unknown-well-known': '알 수 없는 well-known',
}

function RegistrationResult({ report }: { report: KeycloakRegistrationReport }) {
  const check = report.check
  if (!check) {
    return (
      <Alert color="red" variant="light" mt="xs">
        {report.error}
      </Alert>
    )
  }
  const [color, title] = check.problem
    ? ['red', '확인 필요']
    : check.acceptsPublicClients
      ? ['teal', 'Keycloak 이 MCP 클라이언트 등록을 받아 줍니다']
      : ['orange', 'Keycloak 이 MCP 클라이언트 등록을 받지 않습니다']
  return (
    <Alert color={color} variant="light" mt="xs" title={title}>
      <Stack gap={4}>
        {check.reason ? <Text size="sm">{check.reason}</Text> : null}
        {check.problem ? <Text size="sm">{check.problem}</Text> : null}
        <Text size="xs" c="dimmed">
          {check.endpoint} → {check.status ?? '—'} {check.error ?? ''} {check.detail ?? ''}
        </Text>
        {!check.acceptsPublicClients ? (
          <Text size="sm">
            그래서 등록 대행을 켜 두어야 합니다. 에이전트에 invalid_client_metadata 가 보인다면, 그 에이전트는 bbmcp 가 아니라
            Keycloak 에 등록하러 간 것입니다.
          </Text>
        ) : null}
        {report.note ? (
          <Text size="xs" c="dimmed">
            {report.note}
          </Text>
        ) : null}
      </Stack>
    </Alert>
  )
}
