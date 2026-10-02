import {
  Alert,
  Badge,
  Box,
  Button,
  Group,
  NumberInput,
  Paper,
  ScrollArea,
  Stack,
  Text,
  Textarea,
} from '@mantine/core'
import { IconPlayerStop, IconRobot, IconSend, IconTrash } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { useCallback, useEffect, useRef, useState } from 'react'

import { PageHeader, Section } from '../components/ui'
import { api } from '../lib/api'
import { formatNumber } from '../lib/format'

interface AIModelInfo {
  enabled: boolean
  provider: string
  model: string
  maxTokens: number
  contextLimit: number
  streaming: boolean
  maxTokenLimit: number
}

interface ChatTurn {
  role: 'user' | 'assistant'
  content: string
}

export function MyAiPage() {
  const info = useQuery({ queryKey: ['ai', 'models'], queryFn: () => api.get<AIModelInfo>('/api/ai/models') })
  const [turns, setTurns] = useState<ChatTurn[]>([])
  const [input, setInput] = useState('')
  const [maxTokens, setMaxTokens] = useState<number | ''>('')
  const [streaming, setStreaming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const viewportRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (info.data && maxTokens === '') setMaxTokens(info.data.maxTokens)
  }, [info.data, maxTokens])

  useEffect(() => {
    viewportRef.current?.scrollTo({ top: viewportRef.current.scrollHeight, behavior: 'smooth' })
  }, [turns])

  // The AI endpoint is server-sent events: responses are streamed by default so
  // a long review answer renders progressively instead of blocking.
  const send = useCallback(async () => {
    const prompt = input.trim()
    if (!prompt || streaming) return

    const history: ChatTurn[] = [...turns, { role: 'user', content: prompt }]
    setTurns([...history, { role: 'assistant', content: '' }])
    setInput('')
    setError(null)
    setStreaming(true)

    const controller = new AbortController()
    abortRef.current = controller

    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
        body: JSON.stringify({
          messages: history.map((t) => ({ role: t.role, content: t.content })),
          maxTokens: typeof maxTokens === 'number' ? maxTokens : undefined,
        }),
        signal: controller.signal,
      })

      if (!res.ok || !res.body) {
        const text = await res.text()
        throw new Error(text || `AI 호출이 실패했습니다 (${res.status})`)
      }

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        let boundary = buffer.indexOf('\n\n')
        while (boundary !== -1) {
          const chunk = buffer.slice(0, boundary)
          buffer = buffer.slice(boundary + 2)
          boundary = buffer.indexOf('\n\n')

          const dataLine = chunk
            .split('\n')
            .find((line) => line.startsWith('data:'))
          if (!dataLine) continue
          const payload = dataLine.slice(5).trim()
          if (!payload) continue

          try {
            const event = JSON.parse(payload) as { type: string; text?: string; error?: string }
            if (event.type === 'delta' && event.text) {
              setTurns((prev) => {
                const next = [...prev]
                const last = next[next.length - 1]
                if (last && last.role === 'assistant') {
                  next[next.length - 1] = { ...last, content: last.content + event.text }
                }
                return next
              })
            } else if (event.type === 'error') {
              setError(event.error ?? 'AI 오류가 발생했습니다.')
            }
          } catch {
            // Ignore keep-alive and malformed frames.
          }
        }
      }
    } catch (err) {
      if ((err as Error).name !== 'AbortError') {
        setError(err instanceof Error ? err.message : 'AI 호출에 실패했습니다.')
      }
    } finally {
      setStreaming(false)
      abortRef.current = null
    }
  }, [input, maxTokens, streaming, turns])

  return (
    <>
      <PageHeader
        title="AI 리뷰 보조"
        description="관리자가 설정한 모델로 스트리밍 응답을 받습니다. 저장소 내용은 MCP 도구로 수집한 뒤 이곳에 붙여 사용하십시오."
        actions={
          <Group gap="xs">
            <Badge variant="light" color={info.data?.enabled ? 'teal' : 'gray'}>
              {info.data?.enabled ? '활성' : '비활성'}
            </Badge>
            <Badge variant="light" color="bbblue">
              {info.data?.model ?? '—'}
            </Badge>
            <Badge variant="light" color="gray">
              최대 {formatNumber(info.data?.maxTokenLimit ?? 262144)} 토큰
            </Badge>
          </Group>
        }
      />

      {info.data && !info.data.enabled ? (
        <Alert color="orange" variant="light" mb="lg" icon={<IconRobot size={20} />}>
          AI 기능이 비활성화되어 있습니다. 서비스 관리자가 AI 설정에서 활성화할 수 있습니다.
        </Alert>
      ) : null}

      <Section>
        <ScrollArea
          h={420}
          viewportRef={viewportRef}
          type="auto"
          scrollbarSize={10}
          offsetScrollbars
          mb="md"
        >
          <Stack gap="md" p="xs">
            {turns.length === 0 ? (
              <Text c="dimmed" ta="center" py="xl">
                질문을 입력하면 응답이 실시간으로 표시됩니다.
              </Text>
            ) : null}
            {turns.map((turn, index) => (
              <Paper
                key={index}
                withBorder
                radius="md"
                p="md"
                bg={turn.role === 'user' ? 'var(--mantine-color-default-hover)' : undefined}
              >
                <Badge variant="light" color={turn.role === 'user' ? 'gray' : 'bbblue'} mb="xs">
                  {turn.role === 'user' ? '나' : 'AI'}
                </Badge>
                <Box className="bbmcp-code" style={{ whiteSpace: 'pre-wrap' }}>
                  {turn.content || (streaming && index === turns.length - 1 ? '응답을 생성하고 있습니다…' : '')}
                </Box>
              </Paper>
            ))}
          </Stack>
        </ScrollArea>

        {error ? (
          <Alert color="red" variant="light" mb="md">
            {error}
          </Alert>
        ) : null}

        <Stack gap="sm">
          <Textarea
            label="질문"
            placeholder="예: 아래 diff 에서 널 포인터 위험이 있는 부분을 지적해 주십시오."
            autosize
            minRows={3}
            maxRows={14}
            value={input}
            onChange={(event) => setInput(event.currentTarget.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
                event.preventDefault()
                void send()
              }
            }}
          />
          <Group justify="space-between" wrap="wrap" gap="sm">
            <NumberInput
              label="최대 출력 토큰"
              description={`상한 ${formatNumber(info.data?.maxTokenLimit ?? 262144)}`}
              min={256}
              max={info.data?.maxTokenLimit ?? 262144}
              step={1024}
              clampBehavior="strict"
              value={maxTokens}
              onChange={(next) => setMaxTokens(typeof next === 'number' ? next : '')}
              w={240}
            />
            <Group gap="sm">
              <Button
                variant="default"
                leftSection={<IconTrash size={18} />}
                onClick={() => {
                  setTurns([])
                  setError(null)
                }}
                disabled={streaming || turns.length === 0}
              >
                대화 지우기
              </Button>
              {streaming ? (
                <Button
                  color="red"
                  variant="light"
                  leftSection={<IconPlayerStop size={18} />}
                  onClick={() => abortRef.current?.abort()}
                >
                  중단
                </Button>
              ) : (
                <Button
                  leftSection={<IconSend size={18} />}
                  onClick={() => void send()}
                  disabled={!input.trim() || !info.data?.enabled}
                >
                  보내기 (Ctrl+Enter)
                </Button>
              )}
            </Group>
          </Group>
        </Stack>
      </Section>
    </>
  )
}
