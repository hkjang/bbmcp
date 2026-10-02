import { Badge, Button, Group, Modal, Pagination, Select, Table, Text, TextInput } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconSearch, IconTrash } from '@tabler/icons-react'
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
import { api, type AuditEntry, type Paged } from '../../lib/api'
import { auditCategoryLabels, formatDateTime, resultLabel } from '../../lib/format'

const PAGE_SIZE = 50

const categoryOptions = [
  { value: 'all', label: '전체 분류' },
  ...Object.entries(auditCategoryLabels).map(([value, label]) => ({ value, label })),
]

const resultOptions = [
  { value: 'all', label: '전체 결과' },
  { value: 'true', label: '성공만' },
  { value: 'false', label: '실패만' },
]

export function AdminAuditPage() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [category, setCategory] = useState('all')
  const [result, setResult] = useState('all')
  const [username, setUsername] = useState('')
  const [tool, setTool] = useState('')
  const [detail, setDetail] = useState<AuditEntry | null>(null)

  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String((page - 1) * PAGE_SIZE),
  })
  if (category !== 'all') params.set('category', category)
  if (result !== 'all') params.set('success', result)
  if (username.trim()) params.set('username', username.trim())
  if (tool.trim()) params.set('tool', tool.trim())

  const audit = useQuery({
    queryKey: ['admin', 'audit', params.toString()],
    queryFn: () => api.get<Paged<AuditEntry>>(`/api/admin/audit?${params.toString()}`),
  })

  const purge = useMutation({
    mutationFn: () => api.post<{ retainDays: number }>('/api/admin/audit/purge'),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'audit'] })
      notifications.show({
        color: 'teal',
        title: '정리했습니다',
        message: `보존 기간 ${res.retainDays}일을 초과한 기록을 삭제했습니다.`,
      })
    },
  })

  const totalPages = Math.max(1, Math.ceil((audit.data?.total ?? 0) / PAGE_SIZE))

  return (
    <>
      <PageHeader
        title="감사 로그"
        description="요청자(Keycloak), 매핑된 Bitbucket 사용자, 서비스 계정, 도구, 대상, 결과를 모두 기록합니다. 토큰과 소스·diff 본문은 기록하지 않습니다."
        actions={
          <Button
            variant="light"
            color="red"
            leftSection={<IconTrash size={18} />}
            loading={purge.isPending}
            onClick={() => {
              if (window.confirm('보존 기간이 지난 감사 로그를 삭제하시겠습니까?')) purge.mutate()
            }}
          >
            보존 기간 적용
          </Button>
        }
      />

      <Section>
        <Group gap="md" wrap="wrap" mb="md">
          <Select
            data={categoryOptions}
            value={category}
            onChange={(value) => {
              setCategory(value ?? 'all')
              setPage(1)
            }}
            allowDeselect={false}
            comboboxProps={{ withinPortal: true }}
            w={180}
          />
          <Select
            data={resultOptions}
            value={result}
            onChange={(value) => {
              setResult(value ?? 'all')
              setPage(1)
            }}
            allowDeselect={false}
            comboboxProps={{ withinPortal: true }}
            w={150}
          />
          <TextInput
            placeholder="요청자"
            leftSection={<IconSearch size={18} />}
            value={username}
            onChange={(event) => {
              setUsername(event.currentTarget.value)
              setPage(1)
            }}
            w={180}
          />
          <TextInput
            placeholder="도구 이름"
            value={tool}
            onChange={(event) => {
              setTool(event.currentTarget.value)
              setPage(1)
            }}
            w={240}
          />
          <Text size="sm" c="dimmed">
            총 {audit.data?.total ?? 0}건
          </Text>
        </Group>

        {audit.isLoading ? <LoadingBlock /> : null}
        {audit.error ? <ErrorBlock error={audit.error} /> : null}
        {audit.data && audit.data.values.length === 0 ? <EmptyState label="조건에 맞는 기록이 없습니다." /> : null}

        {audit.data && audit.data.values.length > 0 ? (
          <>
            <TableScroll minWidth={1100}>
              <Table highlightOnHover striped stickyHeader>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>시각</Table.Th>
                    <Table.Th>분류</Table.Th>
                    <Table.Th>요청자</Table.Th>
                    <Table.Th>Bitbucket</Table.Th>
                    <Table.Th>동작</Table.Th>
                    <Table.Th>대상</Table.Th>
                    <Table.Th>결과</Table.Th>
                    <Table.Th ta="right">소요</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {audit.data.values.map((entry) => (
                    <Table.Tr key={entry.id}>
                      <Table.Td>{formatDateTime(entry.occurredAt)}</Table.Td>
                      <Table.Td>
                        <Badge variant="light" color="gray">
                          {auditCategoryLabels[entry.category] ?? entry.category}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Text>{entry.keycloakUsername ?? '—'}</Text>
                        {entry.mcpClient ? (
                          <Text size="xs" c="dimmed" lineClamp={1} maw={160}>
                            {entry.mcpClient}
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm">{entry.bitbucketUsername ?? '—'}</Text>
                        {entry.serviceAccount ? (
                          <Text size="xs" c="dimmed">
                            대리: {entry.serviceAccount}
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td>
                        <Text ff={entry.toolName ? 'monospace' : undefined} size="sm">
                          {entry.toolName || entry.action}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        {entry.projectKey ? (
                          <Text size="sm">
                            {entry.projectKey}
                            {entry.repository ? `/${entry.repository}` : ''}
                            {entry.pullRequest ? ` #${entry.pullRequest}` : ''}
                          </Text>
                        ) : (
                          <Text c="dimmed">—</Text>
                        )}
                      </Table.Td>
                      <Table.Td>
                        <Badge color={entry.success ? 'teal' : 'red'} variant="light">
                          {resultLabel(entry.success, entry.errorCode)}
                        </Badge>
                      </Table.Td>
                      <Table.Td ta="right">{entry.latencyMs}ms</Table.Td>
                      <Table.Td>
                        <Button size="compact-xs" variant="subtle" onClick={() => setDetail(entry)}>
                          상세
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </TableScroll>

            {totalPages > 1 ? (
              <Group justify="center" mt="lg">
                <Pagination total={totalPages} value={page} onChange={setPage} />
              </Group>
            ) : null}
          </>
        ) : null}
      </Section>

      <Modal opened={Boolean(detail)} onClose={() => setDetail(null)} title="감사 기록 상세" size="lg">
        {detail ? <JsonBlock value={detail} maxHeight={520} /> : null}
      </Modal>
    </>
  )
}
