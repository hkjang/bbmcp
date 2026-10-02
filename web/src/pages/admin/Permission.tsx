import { Alert, Button, Code, Group, List, Text, TextInput } from '@mantine/core'
import { IconPlugConnected } from '@tabler/icons-react'
import { useState } from 'react'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import { ErrorBlock, JsonBlock, LoadingBlock, PageHeader, SaveBar, Section } from '../../components/ui'
import type { PermissionSettings } from '../../lib/api'
import { useConnectivityTest, useSettingsGroup } from '../../lib/useSettingsGroup'

const fields: Field<PermissionSettings>[] = [
  {
    kind: 'select',
    key: 'mode',
    label: '권한 해석 모드',
    description: '플러그인 모드는 Bitbucket 자체 PermissionService 판정을 그대로 사용합니다.',
    options: [
      { value: 'rest', label: 'REST 폴백 (플러그인 없이 동작)' },
      { value: 'plugin', label: 'Bitbucket 권한 플러그인 (권장)' },
    ],
    span: 12,
  },
  {
    kind: 'text',
    key: 'pluginBaseUrl',
    label: '플러그인 기본 URL',
    description: '보통 Bitbucket 과 동일한 호스트입니다.',
    placeholder: 'https://bitbucket.company.local',
    span: 12,
  },
  { kind: 'secret', secretKey: 'pluginSecret', label: '플러그인 공유 비밀값', description: 'HMAC 서명과 서비스 토큰에 사용됩니다.' },
  { kind: 'number', key: 'cacheTtlSec', label: '판정 캐시 TTL (초)', description: '0 이면 캐시하지 않습니다.', min: 0, max: 3600 },
  { kind: 'number', key: 'timeoutSec', label: '요청 제한 시간 (초)', min: 1, max: 120 },
  {
    kind: 'switch',
    key: 'failClosed',
    label: '판정 실패 시 차단 (fail-closed)',
    description: '권한을 확인할 수 없을 때 요청을 거부합니다. 끄면 권한 없음으로 처리합니다.',
  },
]

export function AdminPermissionPage() {
  const { query, draft, setDraft, secrets, setSecrets, secretPresence, save } =
    useSettingsGroup<PermissionSettings>('permission_plugin')
  const test = useConnectivityTest('permission')
  const [username, setUsername] = useState('')
  const [project, setProject] = useState('')

  return (
    <>
      <PageHeader
        title="권한 해석기"
        description="요청자의 Bitbucket 유효 권한을 판정하는 경로를 설정합니다. 이 판정이 모든 도구 호출의 기준입니다."
      />

      {query.isLoading ? <LoadingBlock /> : null}
      {query.error ? <ErrorBlock error={query.error} /> : null}

      {draft ? (
        <Section title="해석 모드">
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

      <Section title="판정 시험" description="실제 사용자와 프로젝트로 판정 결과를 확인합니다.">
        <Group align="flex-end" gap="md" wrap="wrap">
          <TextInput
            label="Bitbucket 사용자명"
            placeholder="hkjang"
            value={username}
            onChange={(event) => setUsername(event.currentTarget.value)}
            w={220}
          />
          <TextInput
            label="프로젝트 키"
            placeholder="AI"
            value={project}
            onChange={(event) => setProject(event.currentTarget.value)}
            w={180}
          />
          <Button
            leftSection={<IconPlugConnected size={18} />}
            loading={test.isPending}
            onClick={() =>
              test.mutate(
                username && project
                  ? `?username=${encodeURIComponent(username)}&project=${encodeURIComponent(project)}`
                  : undefined,
              )
            }
          >
            판정 시험
          </Button>
        </Group>

        {test.data ? (
          <Alert
            mt="md"
            color={test.data.ok ? 'teal' : 'red'}
            variant="light"
            title={test.data.ok ? '판정 성공' : '판정 실패'}
          >
            <JsonBlock value={test.data} maxHeight={260} />
          </Alert>
        ) : null}
      </Section>

      <Section title="권한 플러그인 안내">
        <Text mb="sm">
          플러그인은 <Code>plugin/</Code> 디렉터리에 Bitbucket Server 6.9.1 API 기준으로 포함되어 있습니다.
          빌드한 jar 를 Bitbucket 관리 → 애플리케이션 관리에서 업로드한 뒤 아래 엔드포인트가 응답하면 됩니다.
        </Text>
        <List spacing="xs" size="sm">
          <List.Item><Code>GET /rest/mcp-permission/1.0/health</Code></List.Item>
          <List.Item><Code>GET /rest/mcp-permission/1.0/users/&#123;username&#125;/projects/&#123;project&#125;</Code></List.Item>
          <List.Item><Code>GET /rest/mcp-permission/1.0/users/&#123;username&#125;/repositories/&#123;project&#125;/&#123;repo&#125;</Code></List.Item>
        </List>
        <Text size="sm" c="dimmed" mt="sm">
          플러그인은 bbmcp 가 보내는 공유 비밀값과 HMAC 서명을 검증하며, 일반 사용자가 직접 호출할 수 없습니다.
          추가로 네트워크 계층에서 bbmcp 서버 IP 만 허용하는 것을 권장합니다.
        </Text>
      </Section>
    </>
  )
}
