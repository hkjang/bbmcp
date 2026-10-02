import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconPlus, IconRefresh, IconSearch, IconTrash } from '@tabler/icons-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import {
  EmptyState,
  ErrorBlock,
  LoadingBlock,
  PageHeader,
  Section,
  TableScroll,
} from '../../components/ui'
import { api, type Mapping, type MappingError } from '../../lib/api'
import { formatDateTime, formatRelative } from '../../lib/format'

export function AdminIdentityPage() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [createOpen, setCreateOpen] = useState(false)

  const mappings = useQuery({
    queryKey: ['admin', 'mappings', search],
    queryFn: () => api.get<Mapping[]>(`/api/admin/identity/mappings?q=${encodeURIComponent(search)}`),
  })
  const errors = useQuery({
    queryKey: ['admin', 'mapping-errors'],
    queryFn: () => api.get<MappingError[]>('/api/admin/identity/errors'),
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['admin', 'mappings'] })
    void queryClient.invalidateQueries({ queryKey: ['admin', 'mapping-errors'] })
  }

  const verify = useMutation({
    mutationFn: (sub: string) =>
      api.post<{ ok: boolean; error?: string }>(
        `/api/admin/identity/mappings/${encodeURIComponent(sub)}/verify`,
      ),
    onSuccess: (res) => {
      invalidate()
      notifications.show({
        color: res.ok ? 'teal' : 'red',
        title: res.ok ? '재검증 완료' : '재검증 실패',
        message: res.ok ? 'Bitbucket 사용자 ID 가 일치합니다.' : (res.error ?? '확인할 수 없습니다.'),
      })
    },
  })

  const setActive = useMutation({
    mutationFn: ({ sub, active }: { sub: string; active: boolean }) =>
      api.post(`/api/admin/identity/mappings/${encodeURIComponent(sub)}/active`, { active }),
    onSuccess: invalidate,
  })

  const remove = useMutation({
    mutationFn: (sub: string) => api.del(`/api/admin/identity/mappings/${encodeURIComponent(sub)}`),
    onSuccess: () => {
      invalidate()
      notifications.show({ color: 'teal', title: '삭제했습니다', message: '다음 로그인 시 다시 매핑됩니다.' })
    },
  })

  const clearErrors = useMutation({
    mutationFn: () => api.del('/api/admin/identity/errors'),
    onSuccess: invalidate,
  })

  return (
    <>
      <PageHeader
        title="식별 매핑"
        description="Keycloak 주체(sub)와 Bitbucket 사용자 ID 를 고정하는 영구 매핑입니다. 최초 1회만 사용자명으로 찾고, 이후에는 ID 기준으로 판정합니다."
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
              수동 매핑
            </Button>
          </Group>
        }
      />

      <Section title="매핑 목록">
        {mappings.isLoading ? <LoadingBlock /> : null}
        {mappings.error ? <ErrorBlock error={mappings.error} /> : null}
        {mappings.data && mappings.data.length === 0 ? (
          <EmptyState label="등록된 매핑이 없습니다. 사용자가 처음 로그인하면 자동으로 생성됩니다." />
        ) : null}

        {mappings.data && mappings.data.length > 0 ? (
          <TableScroll minWidth={980}>
            <Table highlightOnHover striped stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Keycloak</Table.Th>
                  <Table.Th>Bitbucket</Table.Th>
                  <Table.Th ta="right">BB ID</Table.Th>
                  <Table.Th>방식</Table.Th>
                  <Table.Th>상태</Table.Th>
                  <Table.Th>확인</Table.Th>
                  <Table.Th ta="right">작업</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {mappings.data.map((m) => (
                  <Table.Tr key={m.keycloakSub}>
                    <Table.Td>
                      <Text fw={600}>{m.keycloakUsername}</Text>
                      <Text size="xs" c="dimmed" style={{ overflowWrap: 'anywhere' }}>
                        {m.keycloakSub}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text fw={600}>{m.bitbucketUsername}</Text>
                      <Text size="xs" c="dimmed">
                        {m.bitbucketDisplay || m.bitbucketEmail || '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td ta="right">{m.bitbucketUserId}</Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={m.mappingType === 'manual' ? 'grape' : 'bbblue'}>
                        {m.mappingType === 'manual' ? '수동' : '자동'}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={m.active ? (m.lastError ? 'orange' : 'teal') : 'gray'}>
                        {m.active ? (m.lastError ? '주의' : '정상') : '비활성'}
                      </Badge>
                      {m.lastError ? (
                        <Text size="xs" c="dimmed" lineClamp={2}>
                          {m.lastError}
                        </Text>
                      ) : null}
                    </Table.Td>
                    <Table.Td>{formatRelative(m.verifiedAt)}</Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end" wrap="nowrap">
                        <Tooltip label="Bitbucket 사용자 ID 재검증">
                          <Button
                            size="compact-sm"
                            variant="light"
                            leftSection={<IconRefresh size={16} />}
                            loading={verify.isPending}
                            onClick={() => verify.mutate(m.keycloakSub)}
                          >
                            재검증
                          </Button>
                        </Tooltip>
                        <Button
                          size="compact-sm"
                          variant="light"
                          color={m.active ? 'orange' : 'teal'}
                          onClick={() => setActive.mutate({ sub: m.keycloakSub, active: !m.active })}
                        >
                          {m.active ? '비활성' : '활성'}
                        </Button>
                        <Tooltip label="매핑 삭제 (다음 로그인 시 재생성)">
                          <Button
                            size="compact-sm"
                            variant="light"
                            color="red"
                            leftSection={<IconTrash size={16} />}
                            onClick={() => {
                              if (window.confirm(`${m.keycloakUsername} 의 매핑을 삭제하시겠습니까?`)) {
                                remove.mutate(m.keycloakSub)
                              }
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

      <Section
        title="매핑 실패"
        description="자동 매핑이 실패한 주체입니다. 사용자명이 다르면 수동 매핑으로 연결하십시오."
        actions={
          errors.data && errors.data.length > 0 ? (
            <Button variant="subtle" size="compact-sm" onClick={() => clearErrors.mutate()}>
              목록 지우기
            </Button>
          ) : null
        }
      >
        {errors.data && errors.data.length === 0 ? <EmptyState label="실패 기록이 없습니다." /> : null}
        {errors.data && errors.data.length > 0 ? (
          <TableScroll minWidth={720}>
            <Table striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Keycloak 사용자</Table.Th>
                  <Table.Th>원인</Table.Th>
                  <Table.Th ta="right">횟수</Table.Th>
                  <Table.Th>최근</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {errors.data.map((e) => (
                  <Table.Tr key={e.id}>
                    <Table.Td>
                      <Text fw={600}>{e.keycloakUsername}</Text>
                      <Text size="xs" c="dimmed" style={{ overflowWrap: 'anywhere' }}>
                        {e.keycloakSub}
                      </Text>
                    </Table.Td>
                    <Table.Td>{e.reason}</Table.Td>
                    <Table.Td ta="right">{e.occurrences}</Table.Td>
                    <Table.Td>{formatDateTime(e.occurredAt)}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </TableScroll>
        ) : null}
      </Section>

      <ManualMappingModal opened={createOpen} onClose={() => setCreateOpen(false)} onDone={invalidate} />
    </>
  )
}

function ManualMappingModal({
  opened,
  onClose,
  onDone,
}: {
  opened: boolean
  onClose: () => void
  onDone: () => void
}) {
  const [sub, setSub] = useState('')
  const [keycloakUser, setKeycloakUser] = useState('')
  const [bitbucketUser, setBitbucketUser] = useState('')

  const create = useMutation({
    mutationFn: () =>
      api.post<Mapping>('/api/admin/identity/mappings', {
        keycloakSub: sub.trim(),
        keycloakUsername: keycloakUser.trim(),
        bitbucketUsername: bitbucketUser.trim(),
      }),
    onSuccess: () => {
      onDone()
      onClose()
      setSub('')
      setKeycloakUser('')
      setBitbucketUser('')
      notifications.show({ color: 'teal', title: '매핑했습니다', message: '수동 매핑이 등록되었습니다.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '매핑 실패',
        message: err instanceof Error ? err.message : '매핑을 등록할 수 없습니다.',
      }),
  })

  return (
    <Modal opened={opened} onClose={onClose} title="수동 매핑" size="lg">
      <Stack gap="md">
        <Alert variant="light" color="bbblue">
          Keycloak 사용자명과 Bitbucket 사용자명이 다른 경우 사용합니다. Bitbucket 사용자명은 정확히 일치해야 하며,
          존재하지 않으면 등록되지 않습니다.
        </Alert>
        <TextInput
          label="Keycloak 사용자명"
          placeholder="hong"
          required
          value={keycloakUser}
          onChange={(event) => setKeycloakUser(event.currentTarget.value)}
        />
        <TextInput
          label="Keycloak 주체 (sub)"
          description="비워 두면 로컬 계정 형식(local:사용자명)으로 등록합니다."
          placeholder="5fcad5e8-…"
          value={sub}
          onChange={(event) => setSub(event.currentTarget.value)}
        />
        <TextInput
          label="Bitbucket 사용자명"
          placeholder="hong01"
          required
          value={bitbucketUser}
          onChange={(event) => setBitbucketUser(event.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            취소
          </Button>
          <Button
            loading={create.isPending}
            disabled={!keycloakUser.trim() || !bitbucketUser.trim()}
            onClick={() => create.mutate()}
          >
            매핑
          </Button>
        </Group>
      </Stack>
    </Modal>
  )
}
