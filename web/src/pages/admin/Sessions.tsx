import { Badge, Table, Text } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'

import { EmptyState, ErrorBlock, LoadingBlock, PageHeader, Section, TableScroll } from '../../components/ui'
import { api, type MCPSession } from '../../lib/api'
import { formatDateTime, formatRelative } from '../../lib/format'

export function AdminSessionsPage() {
  const sessions = useQuery({
    queryKey: ['admin', 'sessions'],
    queryFn: () => api.get<MCPSession[]>('/api/admin/sessions'),
    refetchInterval: 30_000,
  })

  return (
    <>
      <PageHeader
        title="MCP 세션"
        description="MCP 클라이언트가 초기화한 세션 기록입니다. 어떤 클라이언트가 어떤 인증 수단으로 접속했는지 확인할 수 있습니다."
      />

      <Section>
        {sessions.isLoading ? <LoadingBlock /> : null}
        {sessions.error ? <ErrorBlock error={sessions.error} /> : null}
        {sessions.data && sessions.data.length === 0 ? <EmptyState label="세션 기록이 없습니다." /> : null}

        {sessions.data && sessions.data.length > 0 ? (
          <TableScroll minWidth={880}>
            <Table highlightOnHover striped stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>사용자</Table.Th>
                  <Table.Th>클라이언트</Table.Th>
                  <Table.Th>인증</Table.Th>
                  <Table.Th>주소</Table.Th>
                  <Table.Th>시작</Table.Th>
                  <Table.Th>마지막 활동</Table.Th>
                  <Table.Th>상태</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {sessions.data.map((session) => (
                  <Table.Tr key={session.id}>
                    <Table.Td>
                      <Text fw={600}>{session.username}</Text>
                      <Text size="xs" c="dimmed">
                        {session.id.slice(0, 8)}…
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" lineClamp={2} maw={320}>
                        {session.client || '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={session.authMode === 'apikey' ? 'blue' : 'grape'}>
                        {session.authMode === 'apikey' ? 'API 키' : session.authMode}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{session.ip || '—'}</Table.Td>
                    <Table.Td>{formatDateTime(session.createdAt)}</Table.Td>
                    <Table.Td>{formatRelative(session.lastSeenAt)}</Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={session.closedAt ? 'gray' : 'teal'}>
                        {session.closedAt ? '종료' : '활성'}
                      </Badge>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </TableScroll>
        ) : null}
      </Section>
    </>
  )
}
