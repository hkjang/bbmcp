import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  NumberInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconPlus, IconTestPipe, IconTrash } from '@tabler/icons-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import {
  EmptyState,
  ErrorBlock,
  JsonBlock,
  LoadingBlock,
  PageHeader,
  Section,
  TableScroll,
} from '../../components/ui'
import { api, type PolicyRule } from '../../lib/api'

const kindOptions = [
  { value: 'project', label: '프로젝트' },
  { value: 'repository', label: '저장소 (프로젝트/저장소)' },
  { value: 'branch', label: '브랜치' },
]

const effectOptions = [
  { value: 'allow', label: '허용 (allow)' },
  { value: 'deny', label: '차단 (deny)' },
]

const riskOptions = [
  { value: '', label: '제한 없음' },
  { value: 'READ', label: '조회까지만' },
  { value: 'WRITE', label: '작성까지' },
  { value: 'EXECUTE', label: '실행까지' },
]

const emptyRule: PolicyRule = {
  id: 0,
  kind: 'project',
  pattern: '',
  effect: 'allow',
  riskCap: '',
  priority: 100,
  note: '',
}

export function AdminPolicyPage() {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<PolicyRule | null>(null)

  const rules = useQuery({ queryKey: ['admin', 'policy'], queryFn: () => api.get<PolicyRule[]>('/api/admin/policy/rules') })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['admin', 'policy'] })

  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/api/admin/policy/rules/${id}`),
    onSuccess: () => {
      invalidate()
      notifications.show({ color: 'teal', title: '삭제했습니다', message: '규칙이 제거되었습니다.' })
    },
  })

  return (
    <>
      <PageHeader
        title="접근 정책"
        description="Bitbucket 권한 위에 MCP 사용 범위를 더 좁힙니다. 권한을 넓히는 용도로는 사용할 수 없습니다."
        actions={
          <Button leftSection={<IconPlus size={18} />} onClick={() => setEditing({ ...emptyRule })}>
            규칙 추가
          </Button>
        }
      />

      <Alert variant="light" color="bbblue" mb="lg">
        판정 순서: 같은 종류에 차단 규칙이 하나라도 일치하면 즉시 차단합니다. 허용 규칙이 하나 이상 있으면
        허용 목록에 포함된 대상만 통과합니다. 패턴은 <code>AI</code>, <code>AI/*</code>, <code>SECURITY/**</code>,{' '}
        <code>release/*</code> 형태를 지원합니다.
      </Alert>

      <Section title="규칙">
        {rules.isLoading ? <LoadingBlock /> : null}
        {rules.error ? <ErrorBlock error={rules.error} /> : null}
        {rules.data && rules.data.length === 0 ? (
          <EmptyState label="규칙이 없습니다. 규칙이 없으면 Bitbucket 권한만으로 판정합니다." />
        ) : null}

        {rules.data && rules.data.length > 0 ? (
          <TableScroll minWidth={880}>
            <Table highlightOnHover striped stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th ta="right">우선순위</Table.Th>
                  <Table.Th>종류</Table.Th>
                  <Table.Th>패턴</Table.Th>
                  <Table.Th>효과</Table.Th>
                  <Table.Th>위험도 상한</Table.Th>
                  <Table.Th>메모</Table.Th>
                  <Table.Th ta="right">작업</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rules.data.map((rule) => (
                  <Table.Tr key={rule.id}>
                    <Table.Td ta="right">{rule.priority}</Table.Td>
                    <Table.Td>{kindOptions.find((k) => k.value === rule.kind)?.label ?? rule.kind}</Table.Td>
                    <Table.Td>
                      <Text ff="monospace">{rule.pattern}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge color={rule.effect === 'deny' ? 'red' : 'teal'} variant="light">
                        {rule.effect === 'deny' ? '차단' : '허용'}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{rule.riskCap || '—'}</Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed" lineClamp={2} maw={280}>
                        {rule.note || '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end" wrap="nowrap">
                        <Button size="compact-sm" variant="default" onClick={() => setEditing(rule)}>
                          편집
                        </Button>
                        <Button
                          size="compact-sm"
                          variant="light"
                          color="red"
                          leftSection={<IconTrash size={16} />}
                          onClick={() => {
                            if (window.confirm(`규칙 ${rule.pattern} 을 삭제하시겠습니까?`)) remove.mutate(rule.id)
                          }}
                        >
                          삭제
                        </Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </TableScroll>
        ) : null}
      </Section>

      <PolicyTester />

      <RuleModal rule={editing} onClose={() => setEditing(null)} onSaved={invalidate} />
    </>
  )
}

function RuleModal({
  rule,
  onClose,
  onSaved,
}: {
  rule: PolicyRule | null
  onClose: () => void
  onSaved: () => void
}) {
  const [draft, setDraft] = useState<PolicyRule>(rule ?? emptyRule)

  // Reset the draft whenever a different rule is opened.
  const key = rule?.id ?? 'new'
  const [lastKey, setLastKey] = useState<number | string>(key)
  if (lastKey !== key) {
    setLastKey(key)
    setDraft(rule ?? emptyRule)
  }

  const save = useMutation({
    mutationFn: () =>
      draft.id
        ? api.put<PolicyRule>(`/api/admin/policy/rules/${draft.id}`, draft)
        : api.post<PolicyRule>('/api/admin/policy/rules', draft),
    onSuccess: () => {
      onSaved()
      onClose()
      notifications.show({ color: 'teal', title: '저장했습니다', message: '정책이 적용되었습니다.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '저장 실패',
        message: err instanceof Error ? err.message : '규칙을 저장할 수 없습니다.',
      }),
  })

  return (
    <Modal opened={Boolean(rule)} onClose={onClose} title={draft.id ? '규칙 편집' : '규칙 추가'} size="lg">
      <Stack gap="md">
        <Select
          label="종류"
          data={kindOptions}
          value={draft.kind}
          onChange={(value) => setDraft({ ...draft, kind: (value ?? 'project') as PolicyRule['kind'] })}
          allowDeselect={false}
          comboboxProps={{ withinPortal: true }}
        />
        <TextInput
          label="패턴"
          description="프로젝트는 키, 저장소는 프로젝트/저장소, 브랜치는 브랜치 이름 기준입니다."
          placeholder={draft.kind === 'repository' ? 'AI/*' : draft.kind === 'branch' ? 'release/*' : 'AI'}
          required
          value={draft.pattern}
          onChange={(event) => setDraft({ ...draft, pattern: event.currentTarget.value })}
        />
        <Select
          label="효과"
          data={effectOptions}
          value={draft.effect}
          onChange={(value) => setDraft({ ...draft, effect: (value ?? 'allow') as PolicyRule['effect'] })}
          allowDeselect={false}
          comboboxProps={{ withinPortal: true }}
        />
        <Select
          label="위험도 상한"
          description="허용 규칙에만 적용됩니다. 예: 특정 프로젝트는 조회만 허용."
          data={riskOptions}
          value={draft.riskCap ?? ''}
          onChange={(value) => setDraft({ ...draft, riskCap: value ?? '' })}
          allowDeselect={false}
          comboboxProps={{ withinPortal: true }}
        />
        <NumberInput
          label="우선순위"
          description="작을수록 먼저 평가됩니다."
          min={1}
          max={10000}
          value={draft.priority}
          onChange={(value) => setDraft({ ...draft, priority: typeof value === 'number' ? value : 100 })}
        />
        <TextInput
          label="메모"
          placeholder="차단 사유나 담당자"
          value={draft.note}
          onChange={(event) => setDraft({ ...draft, note: event.currentTarget.value })}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            취소
          </Button>
          <Button loading={save.isPending} disabled={!draft.pattern.trim()} onClick={() => save.mutate()}>
            저장
          </Button>
        </Group>
      </Stack>
    </Modal>
  )
}

function PolicyTester() {
  const [project, setProject] = useState('')
  const [repository, setRepository] = useState('')
  const [branch, setBranch] = useState('')
  const [username, setUsername] = useState('')

  const evaluate = useMutation({
    mutationFn: () =>
      api.post<Record<string, unknown>>('/api/admin/policy/evaluate', {
        project: project.trim(),
        repository: repository.trim(),
        branch: branch.trim(),
        username: username.trim(),
      }),
  })

  return (
    <Section
      title="정책 시험"
      description="실제 판정 경로로 정책과 사용자 권한을 함께 확인합니다."
    >
      <Group align="flex-end" gap="md" wrap="wrap">
        <TextInput label="프로젝트" placeholder="AI" value={project} onChange={(e) => setProject(e.currentTarget.value)} w={160} />
        <TextInput label="저장소" placeholder="text2sql" value={repository} onChange={(e) => setRepository(e.currentTarget.value)} w={180} />
        <TextInput label="브랜치" placeholder="master" value={branch} onChange={(e) => setBranch(e.currentTarget.value)} w={160} />
        <TextInput label="Bitbucket 사용자 (선택)" placeholder="hkjang" value={username} onChange={(e) => setUsername(e.currentTarget.value)} w={200} />
        <Button
          leftSection={<IconTestPipe size={18} />}
          loading={evaluate.isPending}
          disabled={!project.trim()}
          onClick={() => evaluate.mutate()}
        >
          평가
        </Button>
      </Group>
      {evaluate.error ? <ErrorBlock error={evaluate.error} /> : null}
      {evaluate.data ? <JsonBlock value={evaluate.data} maxHeight={280} /> : null}
    </Section>
  )
}
