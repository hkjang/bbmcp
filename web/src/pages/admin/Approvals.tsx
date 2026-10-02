import { Badge, Button, Group, Modal, SegmentedControl, Stack, Table, Text, Textarea } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconCheck, IconX } from '@tabler/icons-react'
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
import { api, type ApprovalRequest } from '../../lib/api'
import { approvalStatusColors, approvalStatusLabels, formatDateTime, formatRelative } from '../../lib/format'

export function AdminApprovalsPage() {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState('pending')
  const [detail, setDetail] = useState<ApprovalRequest | null>(null)
  const [note, setNote] = useState('')

  const approvals = useQuery({
    queryKey: ['admin', 'approvals', status],
    queryFn: () =>
      api.get<ApprovalRequest[]>(`/api/admin/approvals?status=${status === 'all' ? '' : status}`),
    refetchInterval: 30_000,
  })

  const decide = useMutation({
    mutationFn: ({ id, approve }: { id: string; approve: boolean }) =>
      api.post<ApprovalRequest>(`/api/admin/approvals/${id}/decide`, { approve, note }),
    onSuccess: (_data, variables) => {
      setDetail(null)
      setNote('')
      void queryClient.invalidateQueries({ queryKey: ['admin', 'approvals'] })
      void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      notifications.show({
        color: variables.approve ? 'teal' : 'gray',
        title: variables.approve ? '승인했습니다' : '거절했습니다',
        message: '처리 결과가 감사 로그에 기록되었습니다.',
      })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '처리 실패',
        message: err instanceof Error ? err.message : '승인을 처리할 수 없습니다.',
      }),
  })

  return (
    <>
      <PageHeader
        title="승인 관리"
        description="쓰기·실행 등급 도구 호출에 대한 승인 요청입니다. 승인은 요청 당시의 인자와 PR version 에 묶여 있습니다."
        actions={
          <SegmentedControl
            value={status}
            onChange={setStatus}
            data={[
              { label: '대기', value: 'pending' },
              { label: '승인', value: 'approved' },
              { label: '거절', value: 'rejected' },
              { label: '전체', value: 'all' },
            ]}
          />
        }
      />

      <Section>
        {approvals.isLoading ? <LoadingBlock /> : null}
        {approvals.error ? <ErrorBlock error={approvals.error} /> : null}
        {approvals.data && approvals.data.length === 0 ? (
          <EmptyState label="표시할 승인 요청이 없습니다." />
        ) : null}

        {approvals.data && approvals.data.length > 0 ? (
          <TableScroll minWidth={980}>
            <Table highlightOnHover striped stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>요청자</Table.Th>
                  <Table.Th>도구</Table.Th>
                  <Table.Th>대상</Table.Th>
                  <Table.Th>상태</Table.Th>
                  <Table.Th>요청</Table.Th>
                  <Table.Th>만료</Table.Th>
                  <Table.Th ta="right">작업</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {approvals.data.map((req) => (
                  <Table.Tr key={req.id}>
                    <Table.Td>
                      <Text fw={600}>{req.username}</Text>
                      <Text size="xs" c="dimmed" style={{ overflowWrap: 'anywhere' }}>
                        {req.keycloakSub}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text ff="monospace" size="sm">
                        {req.toolName}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text>{req.resource || '—'}</Text>
                      {req.prVersion !== undefined ? (
                        <Text size="xs" c="dimmed">
                          PR version {req.prVersion}
                        </Text>
                      ) : null}
                    </Table.Td>
                    <Table.Td>
                      <Badge color={approvalStatusColors[req.status] ?? 'gray'} variant="light">
                        {approvalStatusLabels[req.status] ?? req.status}
                      </Badge>
                      {req.decidedBy ? (
                        <Text size="xs" c="dimmed">
                          {req.decidedBy}
                        </Text>
                      ) : null}
                    </Table.Td>
                    <Table.Td>{formatRelative(req.createdAt)}</Table.Td>
                    <Table.Td>{formatDateTime(req.expiresAt)}</Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end" wrap="nowrap">
                        <Button size="compact-sm" variant="default" onClick={() => setDetail(req)}>
                          상세
                        </Button>
                        {req.status === 'pending' ? (
                          <>
                            <Button
                              size="compact-sm"
                              leftSection={<IconCheck size={16} />}
                              onClick={() => decide.mutate({ id: req.id, approve: true })}
                            >
                              승인
                            </Button>
                            <Button
                              size="compact-sm"
                              variant="light"
                              color="red"
                              leftSection={<IconX size={16} />}
                              onClick={() => decide.mutate({ id: req.id, approve: false })}
                            >
                              거절
                            </Button>
                          </>
                        ) : null}
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </TableScroll>
        ) : null}
      </Section>

      <Modal opened={Boolean(detail)} onClose={() => setDetail(null)} title="승인 요청 상세" size="lg">
        {detail ? (
          <Stack gap="md">
            <Text>
              <strong>{detail.username}</strong> 님이 <strong>{detail.toolName}</strong> 실행을 요청했습니다.
            </Text>
            <Text size="sm" c="dimmed">
              대상 {detail.resource || '—'} · 인자 해시 {detail.argumentsHash.slice(0, 16)}…
            </Text>
            <JsonBlock value={detail.arguments ?? {}} />
            {detail.status === 'pending' ? (
              <>
                <Textarea
                  label="메모"
                  placeholder="승인/거절 사유"
                  value={note}
                  onChange={(event) => setNote(event.currentTarget.value)}
                  autosize
                  minRows={2}
                />
                <Group justify="flex-end">
                  <Button variant="light" color="red" onClick={() => decide.mutate({ id: detail.id, approve: false })}>
                    거절
                  </Button>
                  <Button onClick={() => decide.mutate({ id: detail.id, approve: true })}>승인</Button>
                </Group>
              </>
            ) : detail.decisionNote ? (
              <Text size="sm">메모: {detail.decisionNote}</Text>
            ) : null}
          </Stack>
        ) : null}
      </Modal>
    </>
  )
}
