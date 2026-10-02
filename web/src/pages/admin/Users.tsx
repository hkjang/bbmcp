import {
  Badge,
  Button,
  Group,
  Modal,
  MultiSelect,
  PasswordInput,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconKey, IconPlus, IconSearch, IconTrash } from '@tabler/icons-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { EmptyState, ErrorBlock, LoadingBlock, PageHeader, Section, TableScroll } from '../../components/ui'
import { api, type User } from '../../lib/api'
import { formatDateTime, formatRelative, roleLabels } from '../../lib/format'

const roleOptions = Object.entries(roleLabels).map(([value, label]) => ({ value, label }))

export function AdminUsersPage() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<User | null>(null)
  const [passwordFor, setPasswordFor] = useState<User | null>(null)

  const users = useQuery({
    queryKey: ['admin', 'users', search],
    queryFn: () => api.get<User[]>(`/api/admin/users?q=${encodeURIComponent(search)}`),
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })

  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/api/admin/users/${id}`),
    onSuccess: () => {
      invalidate()
      notifications.show({ color: 'teal', title: '삭제했습니다', message: '사용자를 제거했습니다.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '삭제 실패',
        message: err instanceof Error ? err.message : '사용자를 삭제할 수 없습니다.',
      }),
  })

  return (
    <>
      <PageHeader
        title="사용자"
        description="Keycloak 로그인 사용자는 첫 로그인 시 자동 등록됩니다. 로컬 계정은 SSO 장애 시 접속용으로 사용하십시오."
        actions={
          <Group gap="sm">
            <TextInput
              placeholder="사용자 검색"
              leftSection={<IconSearch size={18} />}
              value={search}
              onChange={(event) => setSearch(event.currentTarget.value)}
              w={220}
            />
            <Button leftSection={<IconPlus size={18} />} onClick={() => setCreateOpen(true)}>
              로컬 계정 추가
            </Button>
          </Group>
        }
      />

      <Section>
        {users.isLoading ? <LoadingBlock /> : null}
        {users.error ? <ErrorBlock error={users.error} /> : null}
        {users.data && users.data.length === 0 ? <EmptyState label="사용자가 없습니다." /> : null}

        {users.data && users.data.length > 0 ? (
          <TableScroll minWidth={980}>
            <Table highlightOnHover striped stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>사용자</Table.Th>
                  <Table.Th>출처</Table.Th>
                  <Table.Th>역할</Table.Th>
                  <Table.Th>상태</Table.Th>
                  <Table.Th>마지막 로그인</Table.Th>
                  <Table.Th>생성</Table.Th>
                  <Table.Th ta="right">작업</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {users.data.map((user) => (
                  <Table.Tr key={user.id}>
                    <Table.Td>
                      <Text fw={600}>{user.username}</Text>
                      <Text size="xs" c="dimmed">
                        {user.displayName || '—'} {user.email ? `· ${user.email}` : ''}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge
                        variant="light"
                        color={user.source === 'keycloak' ? 'grape' : user.source === 'bootstrap' ? 'orange' : 'gray'}
                      >
                        {user.source === 'keycloak' ? 'Keycloak' : user.source === 'bootstrap' ? '부트스트랩' : '로컬'}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {user.isServiceAdmin ? (
                          <Badge variant="light" color="grape">
                            서비스 관리자
                          </Badge>
                        ) : null}
                        {user.roles.map((role) => (
                          <Badge key={role} size="xs" variant="outline" color="gray">
                            {role}
                          </Badge>
                        ))}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={user.active ? 'teal' : 'gray'}>
                        {user.active ? '활성' : '비활성'}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{formatRelative(user.lastLoginAt)}</Table.Td>
                    <Table.Td>{formatDateTime(user.createdAt)}</Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end" wrap="nowrap">
                        <Button size="compact-sm" variant="default" onClick={() => setEditing(user)}>
                          편집
                        </Button>
                        <Button
                          size="compact-sm"
                          variant="light"
                          leftSection={<IconKey size={16} />}
                          onClick={() => setPasswordFor(user)}
                        >
                          비밀번호
                        </Button>
                        <Button
                          size="compact-sm"
                          variant="light"
                          color="red"
                          leftSection={<IconTrash size={16} />}
                          onClick={() => {
                            if (window.confirm(`${user.username} 계정을 삭제하시겠습니까?`)) remove.mutate(user.id)
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

      <CreateUserModal opened={createOpen} onClose={() => setCreateOpen(false)} onSaved={invalidate} />
      <EditUserModal user={editing} onClose={() => setEditing(null)} onSaved={invalidate} />
      <PasswordModal user={passwordFor} onClose={() => setPasswordFor(null)} />
    </>
  )
}

function CreateUserModal({
  opened,
  onClose,
  onSaved,
}: {
  opened: boolean
  onClose: () => void
  onSaved: () => void
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)
  const [roles, setRoles] = useState<string[]>(['bitbucket-mcp-user'])

  const create = useMutation({
    mutationFn: () =>
      api.post<User>('/api/admin/users', {
        username: username.trim(),
        password,
        displayName: displayName.trim(),
        email: email.trim(),
        isServiceAdmin: isAdmin,
        roles,
      }),
    onSuccess: () => {
      onSaved()
      onClose()
      setUsername('')
      setPassword('')
      setDisplayName('')
      setEmail('')
      notifications.show({ color: 'teal', title: '생성했습니다', message: '로컬 계정이 추가되었습니다.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '생성 실패',
        message: err instanceof Error ? err.message : '계정을 만들 수 없습니다.',
      }),
  })

  return (
    <Modal opened={opened} onClose={onClose} title="로컬 계정 추가" size="lg">
      <Stack gap="md">
        <TextInput
          label="아이디"
          required
          value={username}
          onChange={(event) => setUsername(event.currentTarget.value)}
        />
        <PasswordInput
          label="비밀번호"
          description="10자 이상"
          required
          value={password}
          onChange={(event) => setPassword(event.currentTarget.value)}
        />
        <TextInput label="표시 이름" value={displayName} onChange={(event) => setDisplayName(event.currentTarget.value)} />
        <TextInput label="이메일" type="email" value={email} onChange={(event) => setEmail(event.currentTarget.value)} />
        <MultiSelect
          label="역할"
          data={roleOptions}
          value={roles}
          onChange={setRoles}
          comboboxProps={{ withinPortal: true }}
        />
        <Switch
          label="서비스 관리자"
          description="관리 메뉴 전체에 접근할 수 있습니다."
          checked={isAdmin}
          onChange={(event) => setIsAdmin(event.currentTarget.checked)}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            취소
          </Button>
          <Button
            loading={create.isPending}
            disabled={!username.trim() || password.length < 10}
            onClick={() => create.mutate()}
          >
            생성
          </Button>
        </Group>
      </Stack>
    </Modal>
  )
}

function EditUserModal({
  user,
  onClose,
  onSaved,
}: {
  user: User | null
  onClose: () => void
  onSaved: () => void
}) {
  const [draft, setDraft] = useState<User | null>(user)
  const key = user?.id ?? 0
  const [lastKey, setLastKey] = useState(key)
  if (lastKey !== key) {
    setLastKey(key)
    setDraft(user)
  }

  const save = useMutation({
    mutationFn: () =>
      api.patch<User>(`/api/admin/users/${draft?.id}`, {
        displayName: draft?.displayName ?? '',
        email: draft?.email ?? '',
        isServiceAdmin: draft?.isServiceAdmin ?? false,
        active: draft?.active ?? true,
        roles: draft?.roles ?? [],
      }),
    onSuccess: () => {
      onSaved()
      onClose()
      notifications.show({ color: 'teal', title: '저장했습니다', message: '사용자 정보를 변경했습니다.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '저장 실패',
        message: err instanceof Error ? err.message : '사용자를 변경할 수 없습니다.',
      }),
  })

  if (!draft) return null

  return (
    <Modal opened={Boolean(user)} onClose={onClose} title={`사용자 편집: ${draft.username}`} size="lg">
      <Stack gap="md">
        <TextInput
          label="표시 이름"
          value={draft.displayName}
          onChange={(event) => setDraft({ ...draft, displayName: event.currentTarget.value })}
        />
        <TextInput
          label="이메일"
          type="email"
          value={draft.email}
          onChange={(event) => setDraft({ ...draft, email: event.currentTarget.value })}
        />
        <MultiSelect
          label="역할"
          description="Keycloak 사용자는 다음 로그인 시 토큰의 역할로 덮어써집니다."
          data={roleOptions}
          value={draft.roles}
          onChange={(value) => setDraft({ ...draft, roles: value })}
          comboboxProps={{ withinPortal: true }}
        />
        <Switch
          label="서비스 관리자"
          checked={draft.isServiceAdmin}
          onChange={(event) => setDraft({ ...draft, isServiceAdmin: event.currentTarget.checked })}
        />
        <Switch
          label="활성"
          description="비활성화하면 모든 세션이 즉시 종료됩니다."
          checked={draft.active}
          onChange={(event) => setDraft({ ...draft, active: event.currentTarget.checked })}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            취소
          </Button>
          <Button loading={save.isPending} onClick={() => save.mutate()}>
            저장
          </Button>
        </Group>
      </Stack>
    </Modal>
  )
}

function PasswordModal({ user, onClose }: { user: User | null; onClose: () => void }) {
  const [password, setPassword] = useState('')

  const save = useMutation({
    mutationFn: () => api.post(`/api/admin/users/${user?.id}/password`, { password }),
    onSuccess: () => {
      onClose()
      setPassword('')
      notifications.show({
        color: 'teal',
        title: '변경했습니다',
        message: '해당 사용자의 모든 세션이 종료되었습니다.',
      })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '변경 실패',
        message: err instanceof Error ? err.message : '비밀번호를 변경할 수 없습니다.',
      }),
  })

  return (
    <Modal opened={Boolean(user)} onClose={onClose} title={`비밀번호 재설정: ${user?.username}`}>
      <Stack gap="md">
        <PasswordInput
          label="새 비밀번호"
          description="10자 이상"
          value={password}
          onChange={(event) => setPassword(event.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            취소
          </Button>
          <Button loading={save.isPending} disabled={password.length < 10} onClick={() => save.mutate()}>
            변경
          </Button>
        </Group>
      </Stack>
    </Modal>
  )
}
