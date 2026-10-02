import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  MultiSelect,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconPlus, IconRefresh, IconTrash } from '@tabler/icons-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { SettingsForm, type Field } from '../../components/SettingsForm'
import {
  CopyField,
  EmptyState,
  ErrorBlock,
  LoadingBlock,
  PageHeader,
  SaveBar,
  Section,
  TableScroll,
} from '../../components/ui'
import {
  api,
  type ApiKey,
  type IssuedKey,
  type KeyPolicySettings,
  type KeyRole,
  type ScopeInfo,
} from '../../lib/api'
import { formatDateTime, formatRelative, keyStatusColors, keyStatusLabels } from '../../lib/format'
import { useSettingsGroup } from '../../lib/useSettingsGroup'

export function AdminKeysPage() {
  const queryClient = useQueryClient()
  const [editingRole, setEditingRole] = useState<KeyRole | null>(null)
  const [issued, setIssued] = useState<IssuedKey | null>(null)

  const keys = useQuery({ queryKey: ['admin', 'keys'], queryFn: () => api.get<ApiKey[]>('/api/admin/keys') })
  const roles = useQuery({ queryKey: ['admin', 'key-roles'], queryFn: () => api.get<KeyRole[]>('/api/admin/key-roles') })
  const scopes = useQuery({ queryKey: ['admin', 'key-scopes'], queryFn: () => api.get<ScopeInfo[]>('/api/admin/key-scopes') })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['admin', 'keys'] })
    void queryClient.invalidateQueries({ queryKey: ['admin', 'key-roles'] })
    void queryClient.invalidateQueries({ queryKey: ['me'] })
  }

  const revoke = useMutation({
    mutationFn: (id: string) => api.post(`/api/admin/keys/${id}/revoke`, { reason: '관리자 폐기' }),
    onSuccess: () => {
      invalidate()
      notifications.show({ color: 'teal', title: '폐기했습니다', message: '해당 키는 즉시 무효화되었습니다.' })
    },
  })

  const rotate = useMutation({
    mutationFn: (id: string) => api.post<IssuedKey>(`/api/admin/keys/${id}/rotate`),
    onSuccess: (data) => {
      setIssued(data)
      invalidate()
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '회전 실패',
        message: err instanceof Error ? err.message : '키를 회전할 수 없습니다.',
      }),
  })

  const deleteRole = useMutation({
    mutationFn: (name: string) => api.del(`/api/admin/key-roles/${name}`),
    onSuccess: () => {
      invalidate()
      notifications.show({ color: 'teal', title: '삭제했습니다', message: '역할이 제거되었습니다.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '삭제 실패',
        message: err instanceof Error ? err.message : '역할을 삭제할 수 없습니다.',
      }),
  })

  return (
    <>
      <PageHeader
        title="키 · 권한 체계"
        description="개인 API 키의 권한 역할(스코프 묶음)과 발급 정책을 정의합니다. 역할의 스코프를 바꾸면 이미 발급된 키에도 즉시 적용됩니다."
        actions={
          <Button
            leftSection={<IconPlus size={18} />}
            onClick={() => setEditingRole({ name: '', description: '', scopes: [], builtin: false })}
          >
            역할 추가
          </Button>
        }
      />

      <KeyPolicySection />

      <Section title="권한 역할" description="역할은 키가 가질 수 있는 스코프의 상한입니다.">
        {roles.isLoading ? <LoadingBlock /> : null}
        {roles.error ? <ErrorBlock error={roles.error} /> : null}

        {roles.data ? (
          <TableScroll minWidth={760}>
            <Table highlightOnHover striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>역할</Table.Th>
                  <Table.Th>설명</Table.Th>
                  <Table.Th>스코프</Table.Th>
                  <Table.Th ta="right">작업</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {roles.data.map((role) => (
                  <Table.Tr key={role.name}>
                    <Table.Td>
                      <Group gap="xs">
                        <Text fw={600}>{role.name}</Text>
                        {role.builtin ? (
                          <Badge size="sm" variant="light" color="gray">
                            기본
                          </Badge>
                        ) : null}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed">
                        {role.description || '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {role.scopes.map((scope) => (
                          <Badge key={scope} size="xs" variant="outline" color="gray">
                            {scope}
                          </Badge>
                        ))}
                        {role.scopes.length === 0 ? <Text c="dimmed">없음</Text> : null}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end" wrap="nowrap">
                        <Button size="compact-sm" variant="default" onClick={() => setEditingRole(role)}>
                          편집
                        </Button>
                        <Tooltip label={role.builtin ? '기본 역할은 삭제할 수 없습니다' : '역할 삭제'}>
                          <Button
                            size="compact-sm"
                            variant="light"
                            color="red"
                            disabled={role.builtin}
                            leftSection={<IconTrash size={16} />}
                            onClick={() => {
                              if (window.confirm(`역할 ${role.name} 을 삭제하시겠습니까?`)) deleteRole.mutate(role.name)
                            }}
                          >
                            삭제
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

      <Section title="발급된 키" description="전체 사용자의 키입니다. 유출이 의심되면 즉시 폐기하거나 회전하십시오.">
        {keys.isLoading ? <LoadingBlock /> : null}
        {keys.error ? <ErrorBlock error={keys.error} /> : null}
        {keys.data && keys.data.length === 0 ? <EmptyState label="발급된 키가 없습니다." /> : null}

        {keys.data && keys.data.length > 0 ? (
          <TableScroll minWidth={1000}>
            <Table highlightOnHover striped stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>소유자</Table.Th>
                  <Table.Th>이름 · 접두사</Table.Th>
                  <Table.Th>역할</Table.Th>
                  <Table.Th>상태</Table.Th>
                  <Table.Th>회전 예정</Table.Th>
                  <Table.Th>마지막 사용</Table.Th>
                  <Table.Th ta="right">작업</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {keys.data.map((key) => (
                  <Table.Tr key={key.id}>
                    <Table.Td>
                      <Text fw={600}>{key.username ?? key.userId}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text>{key.name}</Text>
                      <Text size="xs" ff="monospace" c="dimmed">
                        bbmcp_{key.prefix}…
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light">{key.role || '—'}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Badge color={keyStatusColors[key.status]} variant="light">
                        {keyStatusLabels[key.status] ?? key.status}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{formatDateTime(key.rotationDueAt)}</Table.Td>
                    <Table.Td>{formatRelative(key.lastUsedAt)}</Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end" wrap="nowrap">
                        <Button
                          size="compact-sm"
                          variant="light"
                          leftSection={<IconRefresh size={16} />}
                          disabled={key.status === 'revoked'}
                          loading={rotate.isPending}
                          onClick={() => rotate.mutate(key.id)}
                        >
                          회전
                        </Button>
                        <Button
                          size="compact-sm"
                          variant="light"
                          color="red"
                          disabled={key.status === 'revoked'}
                          onClick={() => {
                            if (window.confirm(`${key.username} 의 키 "${key.name}" 을 폐기하시겠습니까?`)) {
                              revoke.mutate(key.id)
                            }
                          }}
                        >
                          폐기
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

      <RoleModal
        role={editingRole}
        scopes={scopes.data ?? []}
        onClose={() => setEditingRole(null)}
        onSaved={invalidate}
      />

      <Modal opened={Boolean(issued)} onClose={() => setIssued(null)} title="회전된 키" size="lg">
        <Stack gap="md">
          <Alert color="yellow" variant="light">
            새 키 값은 지금 한 번만 표시됩니다. 소유자에게 안전한 경로로 전달하십시오.
          </Alert>
          {issued ? <CopyField value={issued.secret} /> : null}
          <Group justify="flex-end">
            <Button onClick={() => setIssued(null)}>확인</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}

function KeyPolicySection() {
  const { query, draft, setDraft, secrets, setSecrets, save } = useSettingsGroup<KeyPolicySettings>('key_policy')
  const roles = useQuery({ queryKey: ['admin', 'key-roles'], queryFn: () => api.get<KeyRole[]>('/api/admin/key-roles') })

  const fields: Field<KeyPolicySettings>[] = [
    {
      kind: 'select',
      key: 'defaultRole',
      label: '기본 역할',
      description: '사용자가 역할을 지정하지 않고 키를 발급할 때 사용됩니다.',
      options: (roles.data ?? []).map((r) => ({ value: r.name, label: r.name })),
    },
    { kind: 'number', key: 'rotationDays', label: '회전 주기 (일)', description: '0 이면 회전 안내를 하지 않습니다.', min: 0, max: 3650 },
    { kind: 'number', key: 'keyTtlDays', label: '키 유효 기간 (일)', description: '0 이면 만료 없음', min: 0, max: 3650 },
    { kind: 'number', key: 'maxKeysPerUser', label: '사용자당 최대 활성 키', min: 0, max: 50 },
    { kind: 'number', key: 'graceHours', label: '회전 유예 시간 (시간)', description: '회전 후 기존 키가 유지되는 시간입니다.', min: 0, max: 720 },
    { kind: 'switch', key: 'allowSelfCreate', label: '사용자 직접 발급 허용' },
  ]

  if (query.isLoading) return <LoadingBlock />
  if (query.error) return <ErrorBlock error={query.error} />
  if (!draft) return null

  return (
    <Section title="키 발급 정책">
      <SettingsForm
        fields={fields}
        value={draft}
        onChange={setDraft}
        secrets={secrets}
        onSecretChange={setSecrets}
      />
      <SaveBar onSave={() => save.mutate()} saving={save.isPending} />
    </Section>
  )
}

function RoleModal({
  role,
  scopes,
  onClose,
  onSaved,
}: {
  role: KeyRole | null
  scopes: ScopeInfo[]
  onClose: () => void
  onSaved: () => void
}) {
  const [draft, setDraft] = useState<KeyRole>(role ?? { name: '', description: '', scopes: [], builtin: false })
  const key = role?.name ?? 'new'
  const [lastKey, setLastKey] = useState(key)
  if (lastKey !== key) {
    setLastKey(key)
    setDraft(role ?? { name: '', description: '', scopes: [], builtin: false })
  }

  const save = useMutation({
    mutationFn: () =>
      api.put<KeyRole>(`/api/admin/key-roles/${draft.name}`, {
        description: draft.description,
        scopes: draft.scopes,
      }),
    onSuccess: () => {
      onSaved()
      onClose()
      notifications.show({
        color: 'teal',
        title: '저장했습니다',
        message: '역할 변경은 기존 키에도 즉시 적용됩니다.',
      })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '저장 실패',
        message: err instanceof Error ? err.message : '역할을 저장할 수 없습니다.',
      }),
  })

  return (
    <Modal opened={Boolean(role)} onClose={onClose} title={role?.name ? `역할 편집: ${role.name}` : '역할 추가'} size="lg">
      <Stack gap="md">
        <TextInput
          label="역할 이름"
          description="영문 소문자와 하이픈을 권장합니다."
          placeholder="reviewer"
          required
          disabled={Boolean(role?.name)}
          value={draft.name}
          onChange={(event) => setDraft({ ...draft, name: event.currentTarget.value })}
        />
        <TextInput
          label="설명"
          placeholder="조회 + PR 댓글"
          value={draft.description}
          onChange={(event) => setDraft({ ...draft, description: event.currentTarget.value })}
        />
        <MultiSelect
          label="스코프"
          description="이 역할로 발급한 키가 가질 수 있는 최대 권한입니다."
          data={scopes.map((s) => ({ value: s.name, label: `${s.label} — ${s.description}` }))}
          value={draft.scopes}
          onChange={(value) => setDraft({ ...draft, scopes: value })}
          searchable
          clearable
          comboboxProps={{ withinPortal: true }}
          nothingFoundMessage="스코프가 없습니다"
        />
        <Alert variant="light" color="bbblue">
          스코프를 줄이면 이미 발급된 키의 권한도 함께 줄어듭니다. 키를 다시 발급할 필요는 없습니다.
        </Alert>
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            취소
          </Button>
          <Button loading={save.isPending} disabled={!draft.name.trim()} onClick={() => save.mutate()}>
            저장
          </Button>
        </Group>
      </Stack>
    </Modal>
  )
}
