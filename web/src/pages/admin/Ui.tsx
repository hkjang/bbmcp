import { Text } from '@mantine/core'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import { ErrorBlock, LoadingBlock, PageHeader, SaveBar, Section } from '../../components/ui'
import type { UISettings } from '../../lib/api'
import { useSettingsGroup } from '../../lib/useSettingsGroup'

const fields: Field<UISettings>[] = [
  { kind: 'text', key: 'serviceName', label: '서비스 이름', description: '머리글과 로그인 화면에 표시됩니다.' },
  { kind: 'text', key: 'tagline', label: '부제' },
  {
    kind: 'select',
    key: 'defaultTheme',
    label: '기본 테마',
    options: [
      { value: 'light', label: '밝게' },
      { value: 'dark', label: '어둡게' },
      { value: 'system', label: '시스템 설정' },
    ],
  },
  {
    kind: 'number',
    key: 'fontScale',
    label: '기본 글자 배율',
    description: '1.0 = 본문 16px. 사용자가 개인 설정에서 덮어쓸 수 있습니다.',
    min: 0.9,
    max: 1.4,
    step: 0.05,
    decimal: true,
  },
  {
    kind: 'select',
    key: 'locale',
    label: '기본 언어',
    options: [
      { value: 'ko', label: '한국어' },
      { value: 'en', label: 'English' },
    ],
  },
  {
    kind: 'textarea',
    key: 'loginNotice',
    label: '로그인 화면 공지',
    description: '사내 이용 안내나 보안 공지를 표시할 수 있습니다. 비워 두면 표시하지 않습니다.',
    minRows: 3,
    span: 12,
  },
]

export function AdminUiPage() {
  const { query, draft, setDraft, secrets, setSecrets, save } = useSettingsGroup<UISettings>('ui')

  return (
    <>
      <PageHeader title="화면 설정" description="서비스 이름, 테마, 글자 크기 기본값과 로그인 공지를 설정합니다." />

      {query.isLoading ? <LoadingBlock /> : null}
      {query.error ? <ErrorBlock error={query.error} /> : null}

      {draft ? (
        <Section title="표시">
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

      <Section title="버전 표시">
        <Text size="sm">
          서비스 버전은 로그인 화면 하단과 우측 상단 프로필 메뉴, 그리고 좌측 메뉴 하단에 항상 표시됩니다.
          별도 설정이 필요하지 않습니다.
        </Text>
      </Section>
    </>
  )
}
