import { Alert, Button, Text } from '@mantine/core'
import { IconRobot } from '@tabler/icons-react'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import { ErrorBlock, JsonBlock, LoadingBlock, PageHeader, SaveBar, Section } from '../../components/ui'
import type { AISettings } from '../../lib/api'
import { formatNumber } from '../../lib/format'
import { useConnectivityTest, useSettingsGroup } from '../../lib/useSettingsGroup'

export function AdminAiPage() {
  const { query, draft, setDraft, secrets, setSecrets, secretPresence, limits, save } =
    useSettingsGroup<AISettings>('ai')
  const test = useConnectivityTest('ai')
  const ceiling = limits.maxTokenCeiling ?? 262144

  const fields: Field<AISettings>[] = [
    { kind: 'switch', key: 'enabled', label: 'AI 기능 사용' },
    {
      kind: 'switch',
      key: 'streaming',
      label: '스트리밍 응답',
      description: '기본값입니다. 끄더라도 서버는 스트리밍으로 호출한 뒤 모아서 전달합니다.',
    },
    {
      kind: 'select',
      key: 'provider',
      label: '제공자',
      options: [
        { value: 'anthropic', label: 'Anthropic Messages API' },
        { value: 'openai-compatible', label: 'OpenAI 호환 (vLLM, Ollama, 사내 게이트웨이 등)' },
      ],
    },
    {
      kind: 'text',
      key: 'baseUrl',
      label: '기본 URL',
      description: '오프라인망에서는 사내 추론 게이트웨이 주소를 입력하십시오.',
      placeholder: 'https://api.anthropic.com',
    },
    { kind: 'text', key: 'model', label: '모델', placeholder: 'claude-sonnet-5' },
    { kind: 'secret', secretKey: 'apiKey', label: 'API 키' },
    {
      kind: 'number',
      key: 'maxTokens',
      label: '기본 최대 출력 토큰',
      description: `상한 ${formatNumber(ceiling)} (256k)`,
      min: 256,
      max: ceiling,
      step: 1024,
    },
    {
      kind: 'number',
      key: 'contextLimit',
      label: '최대 토큰 상한',
      description: '사용자가 요청할 수 있는 최대값입니다. 256k 를 초과할 수 없습니다.',
      min: 1024,
      max: ceiling,
      step: 1024,
    },
    { kind: 'number', key: 'temperature', label: 'temperature', min: 0, max: 2, step: 0.1, decimal: true },
    { kind: 'number', key: 'topP', label: 'top_p', min: 0, max: 1, step: 0.05, decimal: true },
    { kind: 'number', key: 'timeoutSec', label: '응답 제한 시간 (초)', min: 10, max: 1800 },
    {
      kind: 'textarea',
      key: 'systemPrompt',
      label: '시스템 프롬프트',
      description: '저장소 내용을 신뢰할 수 없는 데이터로 다루도록 지시하는 문장을 유지하십시오.',
      minRows: 4,
      span: 12,
    },
  ]

  return (
    <>
      <PageHeader
        title="AI 설정"
        description="AI 호출은 항상 스트리밍으로 수행하며, 최대 출력 토큰은 256k 까지 설정할 수 있습니다."
        actions={
          <Button
            variant="default"
            leftSection={<IconRobot size={18} />}
            loading={test.isPending}
            onClick={() => test.mutate(undefined)}
          >
            호출 점검
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
          title={test.data.ok ? '호출 성공' : '호출 실패'}
        >
          <JsonBlock value={test.data} maxHeight={200} />
        </Alert>
      ) : null}

      {draft ? (
        <Section title="모델 · 파라미터">
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

      <Section title="오프라인망 참고">
        <Text size="sm">
          외부 인터넷이 없는 환경에서는 사내 추론 게이트웨이를 OpenAI 호환 모드로 연결하십시오. bbmcp 는
          <code> /v1/chat/completions </code> 와 Anthropic <code> /v1/messages </code> 두 형식을 모두 지원하며,
          두 경우 모두 서버-전송 이벤트로 중계합니다.
        </Text>
      </Section>
    </>
  )
}
