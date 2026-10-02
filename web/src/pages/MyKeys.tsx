import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconKey, IconPlus, IconRefresh, IconTrash } from '@tabler/icons-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'

import {
  CopyField,
  EmptyState,
  ErrorBlock,
  LoadingBlock,
  PageHeader,
  Section,
  TableScroll,
} from '../components/ui'
import { api, type ApiKey, type IssuedKey, type KeyRole, type ScopeInfo } from '../lib/api'
import { useAuth } from '../lib/auth'
import { formatDateTime, formatRelative, keyStatusColors, keyStatusLabels } from '../lib/format'

export function MyKeysPage() {
  const queryClient = useQueryClient()
  const { me } = useAuth()
  const [createOpen, setCreateOpen] = useState(false)
  const [issued, setIssued] = useState<IssuedKey | null>(null)

  const keys = useQuery({ queryKey: ['me', 'keys'], queryFn: () => api.get<ApiKey[]>('/api/me/keys') })
  const roles = useQuery({ queryKey: ['me', 'key-roles'], queryFn: () => api.get<KeyRole[]>('/api/me/key-roles') })
  const scopes = useQuery({ queryKey: ['me', 'key-scopes'], queryFn: () => api.get<ScopeInfo[]>('/api/me/key-scopes') })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['me', 'keys'] })
  }

  const rotate = useMutation({
    mutationFn: (id: string) => api.post<IssuedKey>(`/api/me/keys/${id}/rotate`),
    onSuccess: (data) => {
      setIssued(data)
      invalidate()
      notifications.show({ color: 'teal', title: '키를 회전했습니다', message: '새 키를 안전하게 보관하십시오.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '회전 실패',
        message: err instanceof Error ? err.message : '키를 회전할 수 없습니다.',
      }),
  })

  const revoke = useMutation({
    mutationFn: (id: string) => api.del(`/api/me/keys/${id}`),
    onSuccess: () => {
      invalidate()
      notifications.show({ color: 'teal', title: '폐기했습니다', message: '해당 키는 더 이상 사용할 수 없습니다.' })
    },
  })

  return (
    <>
      <PageHeader
        title="내 API 키"
        description="MCP 클라이언트와 REST API 호출에 사용하는 개인 키입니다. 키는 발급 시 한 번만 전체 값을 확인할 수 있습니다."
        actions={
          <Button leftSection={<IconPlus size={18} />} onClick={() => setCreateOpen(true)}>
            키 발급
          </Button>
        }
      />

      {!me?.allowUserPatMode && me?.defaultAuthMode === 'user' ? (
        <Alert color="orange" variant="light" mb="lg">
          관리자가 사용자 PAT 모드를 비활성화했습니다. 쓰기 작업의 Bitbucket 작성자는 서비스 계정이 됩니다.
        </Alert>
      ) : null}

      <Section>
        {keys.isLoading ? <LoadingBlock /> : null}
        {keys.error ? <ErrorBlock error={keys.error} /> : null}
        {keys.data && keys.data.length === 0 ? <EmptyState label="발급된 키가 없습니다." /> : null}

        {keys.data && keys.data.length > 0 ? (
          <TableScroll minWidth={900}>
            <Table highlightOnHover striped stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>이름</Table.Th>
                  <Table.Th>접두사</Table.Th>
                  <Table.Th>역할 · 스코프</Table.Th>
                  <Table.Th>상태</Table.Th>
                  <Table.Th>회전 예정</Table.Th>
                  <Table.Th>만료</Table.Th>
                  <Table.Th>마지막 사용</Table.Th>
                  <Table.Th ta="right">작업</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {keys.data.map((key) => (
                  <Table.Tr key={key.id}>
                    <Table.Td>
                      <Text fw={600}>{key.name}</Text>
                      <Text size="xs" c="dimmed">
                        생성 {formatRelative(key.createdAt)}
                        {key.rotatedFrom ? ' · 회전으로 생성' : ''}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text ff="monospace" size="sm">
                        bbmcp_{key.prefix}…
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" mb={4}>
                        {key.role || '—'}
                      </Badge>
                      <Group gap={4}>
                        {key.scopes.map((scope) => (
                          <Badge key={scope} size="xs" variant="outline" color="gray">
                            {scope}
                          </Badge>
                        ))}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Badge color={keyStatusColors[key.status]} variant="light">
                        {keyStatusLabels[key.status] ?? key.status}
                      </Badge>
                      {key.revokedReason ? (
                        <Text size="xs" c="dimmed">
                          {key.revokedReason}
                        </Text>
                      ) : null}
                    </Table.Td>
                    <Table.Td>{formatDateTime(key.rotationDueAt)}</Table.Td>
                    <Table.Td>{formatDateTime(key.expiresAt)}</Table.Td>
                    <Table.Td>{formatRelative(key.lastUsedAt)}</Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end" wrap="nowrap">
                        <Tooltip label="회전 (새 키 발급 후 기존 키는 유예 시간 뒤 만료)">
                          <Button
                            size="compact-sm"
                            variant="light"
                            leftSection={<IconRefresh size={16} />}
                            loading={rotate.isPending}
                            disabled={key.status === 'revoked'}
                            onClick={() => rotate.mutate(key.id)}
                          >
                            회전
                          </Button>
                        </Tooltip>
                        <Tooltip label="즉시 폐기">
                          <Button
                            size="compact-sm"
                            variant="light"
                            color="red"
                            leftSection={<IconTrash size={16} />}
                            disabled={key.status === 'revoked'}
                            onClick={() => {
                              if (window.confirm(`키 "${key.name}" 을 폐기하시겠습니까? 되돌릴 수 없습니다.`)) {
                                revoke.mutate(key.id)
                              }
                            }}
                          >
                            폐기
                          </Button>
                        </Tooltip>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </TableScroll>
        ) : null}
      </Section>

      <CreateKeyModal
        opened={createOpen}
        onClose={() => setCreateOpen(false)}
        roles={roles.data ?? []}
        scopes={scopes.data ?? []}
        onIssued={(next) => {
          setIssued(next)
          invalidate()
        }}
      />

      <Modal opened={Boolean(issued)} onClose={() => setIssued(null)} title="발급된 키" size="lg">
        <Stack gap="md">
          <Alert color="yellow" variant="light" icon={<IconKey size={20} />}>
            이 값은 지금 한 번만 표시됩니다. 복사해 안전한 곳에 보관하십시오.
          </Alert>
          {issued ? <CopyField value={issued.secret} label="키 복사" /> : null}
          <Text size="sm" c="dimmed">
            역할 {issued?.key.role} · 스코프 {issued?.key.scopes.join(', ')}
            {issued?.key.expiresAt ? ` · 만료 ${formatDateTime(issued.key.expiresAt)}` : ''}
          </Text>
          <Group justify="flex-end">
            <Button onClick={() => setIssued(null)}>확인</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}

function CreateKeyModal({
  opened,
  onClose,
  roles,
  scopes,
  onIssued,
}: {
  opened: boolean
  onClose: () => void
  roles: KeyRole[]
  scopes: ScopeInfo[]
  onIssued: (issued: IssuedKey) => void
}) {
  const [name, setName] = useState('')
  const [role, setRole] = useState<string | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [ttl, setTtl] = useState<number | ''>(365)

  const roleOptions = useMemo(
    () => roles.map((r) => ({ value: r.name, label: `${r.name}${r.description ? ` — ${r.description}` : ''}` })),
    [roles],
  )

  const activeRole = roles.find((r) => r.name === role)
  const scopeOptions = useMemo(() => {
    const allowed = activeRole?.scopes ?? []
    return scopes
      .filter((s) => allowed.length === 0 || allowed.includes(s.name))
      .map((s) => ({ value: s.name, label: `${s.label} (${s.name})` }))
  }, [activeRole, scopes])

  const create = useMutation({
    mutationFn: () =>
      api.post<IssuedKey>('/api/me/keys', {
        name: name.trim(),
        role,
        scopes: selected,
        ttlDays: typeof ttl === 'number' ? ttl : 0,
      }),
    onSuccess: (data) => {
      onIssued(data)
      onClose()
      setName('')
      setSelected([])
      notifications.show({ color: 'teal', title: '키를 발급했습니다', message: '값을 복사해 보관하십시오.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '발급 실패',
        message: err instanceof Error ? err.message : '키를 발급할 수 없습니다.',
      }),
  })

  return (
    <Modal opened={opened} onClose={onClose} title="API 키 발급" size="lg">
      <Stack gap="md">
        <TextInput
          label="키 이름"
          description="용도를 알 수 있게 적으십시오 (예: Claude Code, CI 리뷰 봇)"
          placeholder="Claude Code"
          required
          value={name}
          onChange={(event) => setName(event.currentTarget.value)}
        />
        <Select
          label="권한 역할"
          description="역할이 허용한 범위 안에서만 스코프를 선택할 수 있습니다."
          data={roleOptions}
          value={role}
          onChange={(next) => {
            setRole(next)
            setSelected([])
          }}
          placeholder="역할을 선택하십시오"
          allowDeselect={false}
          comboboxProps={{ withinPortal: true }}
          nothingFoundMessage="역할이 없습니다"
        />
        <MultiSelect
          label="스코프 (선택)"
          description="비워 두면 역할의 전체 스코프가 부여됩니다."
          data={scopeOptions}
          value={selected}
          onChange={setSelected}
          disabled={!role}
          clearable
          searchable
          comboboxProps={{ withinPortal: true }}
          nothingFoundMessage="선택 가능한 스코프가 없습니다"
        />
        <NumberInput
          label="유효 기간 (일)"
          description="0 을 입력하면 관리자 정책의 기본값을 사용합니다."
          min={0}
          max={3650}
          value={ttl}
          onChange={(next) => setTtl(typeof next === 'number' ? next : '')}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            취소
          </Button>
          <Button
            loading={create.isPending}
            disabled={!name.trim() || !role}
            onClick={() => create.mutate()}
          >
            발급
          </Button>
        </Group>
      </Stack>
    </Modal>
  )
}
