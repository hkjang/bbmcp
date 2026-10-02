import { Badge, Group, Pagination, Table, Text } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { EmptyState, ErrorBlock, LoadingBlock, PageHeader, Section, TableScroll } from '../components/ui'
import { api, type AuditEntry, type Paged } from '../lib/api'
import { auditCategoryLabels, formatDateTime, resultLabel } from '../lib/format'

const PAGE_SIZE = 25

export function MyAuditPage() {
  const [page, setPage] = useState(1)
  const audit = useQuery({
    queryKey: ['me', 'audit', page],
    queryFn: () =>
      api.get<Paged<AuditEntry>>(`/api/me/audit?limit=${PAGE_SIZE}&offset=${(page - 1) * PAGE_SIZE}`),
  })

  const totalPages = Math.max(1, Math.ceil((audit.data?.total ?? 0) / PAGE_SIZE))

  return (
    <>
      <PageHeader
        title="내 활동 기록"
        description="내 계정으로 수행된 도구 호출과 인증 기록입니다. 토큰과 소스 본문은 기록되지 않습니다."
      />

      <Section>
        {audit.isLoading ? <LoadingBlock /> : null}
        {audit.error ? <ErrorBlock error={audit.error} /> : null}
        {audit.data && audit.data.values.length === 0 ? <EmptyState label="기록이 없습니다." /> : null}

        {audit.data && audit.data.values.length > 0 ? (
          <>
            <TableScroll minWidth={900}>
              <Table highlightOnHover striped stickyHeader>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>시각</Table.Th>
                    <Table.Th>분류</Table.Th>
                    <Table.Th>동작</Table.Th>
                    <Table.Th>대상</Table.Th>
                    <Table.Th>결과</Table.Th>
                    <Table.Th ta="right">소요</Table.Th>
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
                        <Text>{entry.toolName || entry.action}</Text>
                        {entry.authMode ? (
                          <Text size="xs" c="dimmed">
                            {entry.authMode}
                          </Text>
                        ) : null}
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
                        <Group gap="xs" wrap="nowrap">
                          <Badge color={entry.success ? 'teal' : 'red'} variant="light">
                            {resultLabel(entry.success, entry.errorCode)}
                          </Badge>
                        </Group>
                        {entry.message && !entry.success ? (
                          <Text size="xs" c="dimmed" lineClamp={2}>
                            {entry.message}
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td ta="right">{entry.latencyMs}ms</Table.Td>
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
    </>
  )
}
