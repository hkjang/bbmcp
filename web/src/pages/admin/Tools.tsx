import {
  Alert,
  Badge,
  Button,
  Group,
  Select,
  Switch,
  Table,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconRefresh, IconSearch } from '@tabler/icons-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'

import { ErrorBlock, LoadingBlock, PageHeader, Section, TableScroll } from '../../components/ui'
import { api, type ToolRecord } from '../../lib/api'
import { riskColors, riskLabels, roleLabels } from '../../lib/format'

const roleOptions = [
  { value: 'bitbucket-mcp-user', label: roleLabels['bitbucket-mcp-user'] },
  { value: 'bitbucket-mcp-writer', label: roleLabels['bitbucket-mcp-writer'] },
  { value: 'bitbucket-mcp-executor', label: roleLabels['bitbucket-mcp-executor'] },
  { value: 'bitbucket-mcp-admin', label: roleLabels['bitbucket-mcp-admin'] },
]

export function AdminToolsPage() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [groupFilter, setGroupFilter] = useState<string>('all')

  const tools = useQuery({ queryKey: ['admin', 'tools'], queryFn: () => api.get<ToolRecord[]>('/api/admin/tools') })

  const patch = useMutation({
    mutationFn: ({ name, body }: { name: string; body: Record<string, unknown> }) =>
      api.patch<ToolRecord>(`/api/admin/tools/${name}`, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'tools'] })
      void queryClient.invalidateQueries({ queryKey: ['me', 'tools'] })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '변경 실패',
        message: err instanceof Error ? err.message : '도구 설정을 변경할 수 없습니다.',
      }),
  })

  const sync = useMutation({
    mutationFn: () => api.post<ToolRecord[]>('/api/admin/tools/sync'),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'tools'] })
      notifications.show({ color: 'teal', title: '동기화했습니다', message: '빌드에 포함된 도구 목록을 반영했습니다.' })
    },
  })

  const groups = useMemo(() => {
    const set = new Set((tools.data ?? []).map((t) => t.group))
    return ['all', ...[...set].sort()]
  }, [tools.data])

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return (tools.data ?? []).filter((tool) => {
      if (groupFilter !== 'all' && tool.group !== groupFilter) return false
      if (!needle) return true
      return (
        tool.name.toLowerCase().includes(needle) ||
        tool.title.toLowerCase().includes(needle) ||
        tool.description.toLowerCase().includes(needle)
      )
    })
  }, [tools.data, search, groupFilter])

  return (
    <>
      <PageHeader
        title="MCP 도구"
        description="도구별 활성화, 승인 필요 여부, 최소 역할을 조정합니다. 실행 등급 도구는 승인을 해제할 수 없습니다."
        actions={
          <Group gap="sm">
            <TextInput
              placeholder="도구 검색"
              leftSection={<IconSearch size={18} />}
              value={search}
              onChange={(event) => setSearch(event.currentTarget.value)}
              w={220}
            />
            <Select
              data={groups.map((g) => ({ value: g, label: g === 'all' ? '전체 그룹' : g }))}
              value={groupFilter}
              onChange={(value) => setGroupFilter(value ?? 'all')}
              allowDeselect={false}
              comboboxProps={{ withinPortal: true }}
              w={180}
            />
            <Button
              variant="default"
              leftSection={<IconRefresh size={18} />}
              loading={sync.isPending}
              onClick={() => sync.mutate()}
            >
              목록 동기화
            </Button>
          </Group>
        }
      />

      <Alert variant="light" color="bbblue" mb="lg">
        도구를 활성화해도 요청자의 Bitbucket 유효 권한과 접근 정책을 통과하지 못하면 호출은 거부됩니다.
        실행 등급(머지·승인·거절) 도구는 기본적으로 비활성 상태로 배포됩니다.
      </Alert>

      <Section>
        {tools.isLoading ? <LoadingBlock /> : null}
        {tools.error ? <ErrorBlock error={tools.error} /> : null}

        {tools.data ? (
          <TableScroll minWidth={1040}>
            <Table highlightOnHover striped stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>도구</Table.Th>
                  <Table.Th>그룹</Table.Th>
                  <Table.Th>위험도</Table.Th>
                  <Table.Th>필요 권한</Table.Th>
                  <Table.Th>최소 역할</Table.Th>
                  <Table.Th ta="center">활성</Table.Th>
                  <Table.Th ta="center">승인 필요</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rows.map((tool) => (
                  <Table.Tr key={tool.name}>
                    <Table.Td>
                      <Text fw={600}>{tool.title}</Text>
                      <Text size="xs" ff="monospace" c="dimmed">
                        {tool.name}
                      </Text>
                      <Text size="xs" c="dimmed" lineClamp={2} maw={420}>
                        {tool.description}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color="gray">
                        {tool.group}
                      </Badge>
                      {tool.highLevel ? (
                        <Badge variant="light" color="grape" mt={4}>
                          고수준
                        </Badge>
                      ) : null}
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={riskColors[tool.risk]}>
                        {riskLabels[tool.risk] ?? tool.risk}
                      </Badge>
                      <Text size="xs" c="dimmed" mt={2}>
                        {tool.tier}차
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace">
                        {tool.requiredPermission}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Select
                        data={roleOptions}
                        value={tool.minRole}
                        onChange={(value) =>
                          value && patch.mutate({ name: tool.name, body: { minRole: value } })
                        }
                        allowDeselect={false}
                        comboboxProps={{ withinPortal: true }}
                        size="sm"
                        w={190}
                      />
                    </Table.Td>
                    <Table.Td ta="center">
                      <Switch
                        checked={tool.enabled}
                        onChange={(event) =>
                          patch.mutate({ name: tool.name, body: { enabled: event.currentTarget.checked } })
                        }
                        aria-label={`${tool.name} 활성화`}
                      />
                    </Table.Td>
                    <Table.Td ta="center">
                      <Tooltip
                        label={tool.risk === 'EXECUTE' ? '실행 등급은 승인을 해제할 수 없습니다' : '승인 필요 여부'}
                        disabled={tool.risk !== 'EXECUTE'}
                      >
                        <Switch
                          checked={tool.requiresApproval}
                          disabled={tool.risk === 'EXECUTE'}
                          onChange={(event) =>
                            patch.mutate({
                              name: tool.name,
                              body: { requiresApproval: event.currentTarget.checked },
                            })
                          }
                          aria-label={`${tool.name} 승인 필요`}
                        />
                      </Tooltip>
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
