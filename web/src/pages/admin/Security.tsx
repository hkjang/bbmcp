import { Text } from '@mantine/core'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import { ErrorBlock, LoadingBlock, PageHeader, SaveBar, Section } from '../../components/ui'
import type { SecuritySettings } from '../../lib/api'
import { useSettingsGroup } from '../../lib/useSettingsGroup'

const fields: Field<SecuritySettings>[] = [
  {
    kind: 'tags',
    key: 'ipAllowlist',
    label: 'IP 허용 목록',
    description: '비워 두면 모든 주소를 허용합니다. 개별 IP 또는 CIDR 을 입력하십시오.',
    placeholder: '10.0.0.0/8',
    span: 12,
  },
  { kind: 'number', key: 'rateLimitPerMin', label: '분당 요청 허용량', description: 'MCP 엔드포인트에 적용됩니다.', min: 0, max: 100000 },
  { kind: 'number', key: 'rateLimitBurst', label: '버스트 허용량', min: 0, max: 100000 },
  { kind: 'number', key: 'sessionTtlMinutes', label: '웹 세션 유지 시간 (분)', min: 5, max: 10080 },
  { kind: 'number', key: 'approvalTtlMinutes', label: '승인 유효 시간 (분)', description: '만료되면 다시 승인을 받아야 합니다.', min: 1, max: 1440 },
  { kind: 'number', key: 'auditRetainDays', label: '감사 로그 보존 (일)', min: 0, max: 3650 },
  {
    kind: 'switch',
    key: 'trustProxyHeaders',
    label: '프록시 헤더 신뢰',
    description: 'X-Forwarded-For 로 클라이언트 주소를 판별합니다. 리버스 프록시 뒤에서만 켜십시오.',
  },
]

export function AdminSecurityPage() {
  const { query, draft, setDraft, secrets, setSecrets, save } = useSettingsGroup<SecuritySettings>('security')

  return (
    <>
      <PageHeader
        title="보안"
        description="접근 주소 제한, 요청 한도, 세션과 승인 유효 시간, 감사 로그 보존 기간을 설정합니다."
      />

      {query.isLoading ? <LoadingBlock /> : null}
      {query.error ? <ErrorBlock error={query.error} /> : null}

      {draft ? (
        <Section title="네트워크 · 세션">
          <SettingsForm
            fields={fields}
            value={draft}
            onChange={setDraft}
            secrets={secrets}
            onSecretChange={setSecrets}
          />
          <SaveBar onSave={() => save.mutate()} saving={save.isPending} />
        </Section>
      ) : null}

      <Section title="비밀값 보관">
        <Text size="sm">
          Keycloak Client Secret, Bitbucket 서비스 PAT, 권한 플러그인 비밀값, AI API 키, 사용자 개인 PAT 은 모두
          <code> ENCRYPTION_KEY </code> 로 파생한 AES-256-GCM 봉투에 담겨 PostgreSQL 에 저장됩니다. 관리 API 는
          저장 여부만 반환하고 평문을 돌려주지 않으며, 감사 로그에서도 제외됩니다.
        </Text>
      </Section>
    </>
  )
}
