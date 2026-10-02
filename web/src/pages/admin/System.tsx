import { Badge, Button, Code, Grid, Group, Table, Text } from '@mantine/core'
import { IconRefresh } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'

import {
  ErrorBlock,
  HealthBadge,
  LoadingBlock,
  PageHeader,
  Section,
  StatList,
  TableScroll,
} from '../../components/ui'
import { api, type SystemInfo } from '../../lib/api'
import { formatDateTime, healthLabels } from '../../lib/format'

export function AdminSystemPage() {
  const system = useQuery({ queryKey: ['admin', 'system'], queryFn: () => api.get<SystemInfo>('/api/admin/system') })

  return (
    <>
      <PageHeader
        title="시스템"
        description="버전, 데이터베이스, 마이그레이션, 구성 요소 상태를 확인합니다."
        actions={
          <Button
            variant="default"
            leftSection={<IconRefresh size={18} />}
            loading={system.isFetching}
            onClick={() => void system.refetch()}
          >
            새로고침
          </Button>
        }
      />

      {system.isLoading ? <LoadingBlock /> : null}
      {system.error ? <ErrorBlock error={system.error} /> : null}

      {system.data ? (
        <>
          <Section title="구성 요소 상태">
            <Group gap="sm" wrap="wrap">
              {Object.entries(system.data.health).map(([key, value]) => (
                <HealthBadge key={key} name={healthLabels[key] ?? key} value={value} />
              ))}
            </Group>
            <Text size="sm" c="dimmed" mt="md">
              준비 상태 점검 엔드포인트: <Code>/readyz</Code> · 메트릭: <Code>/metrics</Code> · 상태:{' '}
              <Code>/healthz</Code>
            </Text>
          </Section>

          <Grid gutter="lg">
            <Grid.Col span={{ base: 12, md: 6 }}>
              <Section title="서비스">
                <StatList
                  items={[
                    { label: '이름', value: system.data.version.name },
                    { label: '버전', value: `v${system.data.version.version}` },
                    { label: '빌드 커밋', value: system.data.version.commit },
                    { label: '빌드 시각', value: system.data.version.buildDate },
                  ]}
                />
              </Section>
            </Grid.Col>

            <Grid.Col span={{ base: 12, md: 6 }}>
              <Section title="데이터베이스">
                <StatList
                  items={[
                    { label: '데이터베이스', value: system.data.database.name },
                    { label: '크기', value: system.data.database.size },
                    {
                      label: '연결 풀',
                      value: `사용 ${system.data.pool.acquired ?? 0} / 유휴 ${system.data.pool.idle ?? 0} / 전체 ${
                        system.data.pool.total ?? 0
                      }`,
                    },
                  ]}
                />
                <Text size="xs" c="dimmed" mt="md" style={{ overflowWrap: 'anywhere' }}>
                  {system.data.database.version}
                </Text>
              </Section>
            </Grid.Col>
          </Grid>

          <Section title="스키마 마이그레이션">
            {system.data.migrations && system.data.migrations.length > 0 ? (
              <TableScroll minWidth={520}>
                <Table striped>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>버전</Table.Th>
                      <Table.Th>적용 시각</Table.Th>
                      <Table.Th>상태</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {system.data.migrations.map((m) => (
                      <Table.Tr key={m.version}>
                        <Table.Td>
                          <Code>{m.version}</Code>
                        </Table.Td>
                        <Table.Td>{formatDateTime(m.appliedAt)}</Table.Td>
                        <Table.Td>
                          <Badge variant="light" color="teal">
                            적용됨
                          </Badge>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </TableScroll>
            ) : (
              <Text c="dimmed">마이그레이션 기록이 없습니다.</Text>
            )}
          </Section>

          <Section title="백업 안내">
            <Text size="sm">
              bbmcp 의 모든 설정과 감사 기록은 PostgreSQL 에 있습니다. 백업은 데이터베이스 덤프와{' '}
              <Code>ENCRYPTION_KEY</Code> 두 가지를 함께 보관해야 복원할 수 있습니다. 키를 분실하면 저장된
              비밀값(서비스 PAT, Client Secret, 사용자 PAT)을 복호화할 수 없습니다.
            </Text>
            <Code block mt="md">{`pg_dump "$DATABASE_URL" --format=custom --file=bbmcp-$(date +%Y%m%d).dump`}</Code>
          </Section>
        </>
      ) : null}
    </>
  )
}
