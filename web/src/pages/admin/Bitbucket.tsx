import { Alert, Button, Code, List, Text } from '@mantine/core'
import { IconPlugConnected } from '@tabler/icons-react'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import { ErrorBlock, JsonBlock, LoadingBlock, PageHeader, SaveBar, Section } from '../../components/ui'
import type { BitbucketSettings } from '../../lib/api'
import { useConnectivityTest, useSettingsGroup } from '../../lib/useSettingsGroup'

const fields: Field<BitbucketSettings>[] = [
  {
    kind: 'text',
    key: 'baseUrl',
    label: 'Bitbucket 기본 URL',
    description: '컨텍스트 경로까지 포함합니다. 예: https://bitbucket.company.local',
    placeholder: 'https://bitbucket.company.local',
    span: 12,
  },
  { kind: 'text', key: 'restPrefix', label: 'REST 경로 접두사', description: 'Bitbucket Server 6.x 는 /rest/api/1.0' },
  { kind: 'text', key: 'serviceUsername', label: '서비스 계정 사용자명', placeholder: 'mcp-bitbucket-service' },
  { kind: 'secret', secretKey: 'servicePat', label: '서비스 계정 PAT', description: 'Bearer 인증에 사용됩니다. AES-256-GCM 으로 암호화 저장됩니다.' },
  {
    kind: 'select',
    key: 'defaultAuthMode',
    label: '기본 인증 모드',
    description: '서비스 계정 모드를 권장합니다. 사용자 모드는 개인 PAT 이 등록된 사용자에게만 적용됩니다.',
    options: [
      { value: 'service', label: '서비스 계정 (Service Mode)' },
      { value: 'user', label: '사용자 PAT (User Mode)' },
    ],
  },
  { kind: 'switch', key: 'allowUserPatMode', label: '사용자 PAT 모드 허용', description: '사용자가 개인 토큰을 등록해 본인 명의로 쓰기 작업을 할 수 있습니다.' },
  { kind: 'switch', key: 'attributionNote', label: '요청자 표기 추가', description: '서비스 계정으로 작성한 PR·댓글 본문에 [MCP 요청자: …] 를 붙입니다.' },
  { kind: 'number', key: 'timeoutSec', label: '요청 제한 시간 (초)', min: 5, max: 300 },
  { kind: 'number', key: 'pageSize', label: '기본 페이지 크기', min: 10, max: 1000 },
  { kind: 'switch', key: 'insecureSkipTls', label: 'TLS 인증서 검증 생략', description: '사설 CA 환경에서만 사용하십시오.' },
]

export function AdminBitbucketPage() {
  const { query, draft, setDraft, secrets, setSecrets, secretPresence, save } =
    useSettingsGroup<BitbucketSettings>('bitbucket')
  const test = useConnectivityTest('bitbucket')

  return (
    <>
      <PageHeader
        title="Bitbucket 연결"
        description="Bitbucket Server 6.9.1 REST 와 MCP 전용 서비스 계정을 설정합니다."
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
        <Alert
          color={test.data.ok ? 'teal' : 'red'}
          variant="light"
          mb="lg"
          title={test.data.ok ? '연결 정상' : '연결 실패'}
        >
          <JsonBlock value={test.data} maxHeight={260} />
        </Alert>
      ) : null}

      {draft ? (
        <Section title="연결 · 서비스 계정">
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

      <Section title="서비스 계정 권한 권고">
        <Text mb="sm">
          서비스 계정은 REST 호출 수단일 뿐이며, 요청자의 권한으로 간주되지 않습니다. 그래도 토큰 탈취 시
          영향을 줄이려면 전역 관리자 대신 필요한 프로젝트에만 권한을 부여하십시오.
        </Text>
        <List spacing="xs" size="sm">
          <List.Item>서비스 계정을 <Code>SYS_ADMIN</Code> 으로 두지 않는 것을 권장합니다.</List.Item>
          <List.Item>REST 폴백 권한 해석 모드는 그룹·전역 권한 조회를 위해 관리자 권한을 요구할 수 있습니다. 권한 플러그인 모드를 사용하면 그 요구가 사라집니다.</List.Item>
          <List.Item>Bitbucket 은 관리자가 사용자를 대신해 PAT 을 만들 수 없으므로, 사용자 명의 작성이 필요하면 사용자 본인이 토큰을 등록해야 합니다.</List.Item>
        </List>
      </Section>
    </>
  )
}
