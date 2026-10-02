import { Alert, Badge, Button, Grid, Group, SimpleGrid, Table, Text, Title } from '@mantine/core'
import { IconAlertTriangle, IconRefresh } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import {
  EmptyState,
  ErrorBlock,
  HealthBadge,
  LoadingBlock,
  PageHeader,
  Section,
  StatList,
  TableScroll,
} from '../../components/ui'
import { api, type Dashboard } from '../../lib/api'
import {
  auditCategoryLabels,
  formatDateTime,
  formatNumber,
  healthLabels,
  resultLabel,
} from '../../lib/format'

const countLabels: Record<string, string> = {
  users: '활성 사용자',
  mappings: '식별 매핑',
  mappingErrors: '매핑 실패',
  activeKeys: '활성 API 키',
  rotationDue: '회전 필요 키',
  pendingApprovals: '대기 승인',
  enabledTools: '활성 도구',
  policyRules: '정책 규칙',
  mcpSessions: '최근 MCP 세션',
}

export function AdminDashboardPage() {
  const dashboard = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<Dashboard>('/api/admin/dashboard'),
    refetchInterval: 60_000,
  })

  const health = dashboard.data?.health ?? {}
  const unhealthy = Object.entries(health).filter(([, v]) => !v.ok && !v.skipped)

  return (
    <>
      <PageHeader
        title="관리 대시보드"
        description="서비스 상태와 최근 활동을 한눈에 확인합니다."
        actions={
          <Button
            variant="default"
            leftSection={<IconRefresh size={18} />}
            loading={dashboard.isFetching}
            onClick={() => void dashboard.refetch()}
          >
            새로고침
          </Button>
        }
      />

      {dashboard.isLoading ? <LoadingBlock /> : null}
      {dashboard.error ? <ErrorBlock error={dashboard.error} /> : null}

      {unhealthy.length > 0 ? (
        <Alert
          color="red"
          variant="light"
          icon={<IconAlertTriangle size={20} />}
          title="확인이 필요한 구성 요소가 있습니다"
          mb="lg"
        >
          {unhealthy.map(([key, value]) => (
            <Text key={key} size="sm">
              • {healthLabels[key] ?? key}: {value.detail}
            </Text>
          ))}
        </Alert>
      ) : null}

      {dashboard.data ? (
        <>
          <Section title="상태">
            <Group gap="sm" wrap="wrap">
              {Object.entries(health).map(([key, value]) => (
                <HealthBadge key={key} name={healthLabels[key] ?? key} value={value} />
              ))}
            </Group>
          </Section>

          <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }} mb="lg">
            {Object.entries(dashboard.data.counts).map(([key, value]) => (
              <Section key={key}>
                <Text size="sm" c="dimmed">
                  {countLabels[key] ?? key}
                </Text>
                <Title order={3}>{formatNumber(value)}</Title>
              </Section>
            ))}
          </SimpleGrid>

          <Grid gutter="lg">
            <Grid.Col span={{ base: 12, lg: 4 }}>
              <Section title="24시간 요약">
                <StatList
                  items={[
                    { label: '도구 호출', value: formatNumber(dashboard.data.toolCalls24h) },
                    { label: '실패', value: formatNumber(dashboard.data.failures24h) },
                    { label: '서비스 버전', value: `v${dashboard.data.version.version}` },
                    { label: '빌드', value: dashboard.data.version.commit },
                  ]}
                />
              </Section>

              <Section title="많이 쓰인 도구 (7일)">
                {dashboard.data.topTools && dashboard.data.topTools.length > 0 ? (
                  <StatList
                    items={dashboard.data.topTools.map((t) => ({
                      label: t.tool,
                      value: formatNumber(t.calls),
                    }))}
                  />
                ) : (
                  <EmptyState label="호출 기록이 없습니다." />
                )}
              </Section>
            </Grid.Col>

            <Grid.Col span={{ base: 12, lg: 8 }}>
              <Section
                title="최근 활동"
                actions={
                  <Button component={Link} to="/admin/audit" variant="subtle" size="compact-sm">
                    전체 감사 로그
                  </Button>
                }
              >
                {dashboard.data.recentAudit && dashboard.data.recentAudit.length > 0 ? (
                  <TableScroll minWidth={760}>
                    <Table highlightOnHover striped>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>시각</Table.Th>
                          <Table.Th>분류</Table.Th>
                          <Table.Th>요청자</Table.Th>
                          <Table.Th>동작</Table.Th>
                          <Table.Th>결과</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {dashboard.data.recentAudit.map((entry) => (
                          <Table.Tr key={entry.id}>
                            <Table.Td>{formatDateTime(entry.occurredAt)}</Table.Td>
                            <Table.Td>
                              <Badge variant="light" color="gray">
                                {auditCategoryLabels[entry.category] ?? entry.category}
                              </Badge>
                            </Table.Td>
                            <Table.Td>{entry.keycloakUsername ?? '—'}</Table.Td>
                            <Table.Td>{entry.toolName || entry.action}</Table.Td>
                            <Table.Td>
                              <Badge color={entry.success ? 'teal' : 'red'} variant="light">
                                {resultLabel(entry.success, entry.errorCode)}
                              </Badge>
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </TableScroll>
                ) : (
                  <EmptyState label="기록이 없습니다." />
                )}
              </Section>
            </Grid.Col>
          </Grid>
        </>
      ) : null}
    </>
  )
}
