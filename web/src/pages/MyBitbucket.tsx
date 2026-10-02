import {
  Alert,
  Badge,
  Button,
  Group,
  PasswordInput,
  Stack,
  Switch,
  Text,
  TextInput,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconPlugConnected, IconShieldCheck, IconTrash } from '@tabler/icons-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { PageHeader, Section, StatList } from '../components/ui'
import { api, type Prefs } from '../lib/api'
import { useAuth } from '../lib/auth'
import { formatDateTime } from '../lib/format'

interface UserPatInfo {
  userId: number
  bitbucketUser: string
  hasToken: boolean
  verifiedAt?: number
}

export function MyBitbucketPage() {
  const { me, refresh } = useAuth()
  const queryClient = useQueryClient()
  const [token, setToken] = useState('')
  const [bbUser, setBbUser] = useState('')

  const pat = useQuery({
    queryKey: ['me', 'pat'],
    queryFn: () => api.get<UserPatInfo>('/api/me/bitbucket-pat'),
  })

  const save = useMutation({
    mutationFn: () =>
      api.put<UserPatInfo>('/api/me/bitbucket-pat', {
        bitbucketUser: bbUser.trim() || me?.bitbucket?.bitbucketUsername || '',
        token: token.trim(),
      }),
    onSuccess: () => {
      setToken('')
      void queryClient.invalidateQueries({ queryKey: ['me', 'pat'] })
      notifications.show({
        color: 'teal',
        title: '토큰을 저장했습니다',
        message: '토큰은 AES-256-GCM 으로 암호화되어 저장됩니다.',
      })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '저장 실패',
        message: err instanceof Error ? err.message : '토큰을 저장할 수 없습니다.',
      }),
  })

  const verify = useMutation({
    mutationFn: () => api.post<{ ok: boolean; error?: string; user?: { name: string; id: number } }>('/api/me/bitbucket-pat/verify'),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ['me', 'pat'] })
      notifications.show({
        color: res.ok ? 'teal' : 'red',
        title: res.ok ? '연결을 확인했습니다' : '확인 실패',
        message: res.ok ? `Bitbucket 사용자 ${res.user?.name} 로 인증됩니다.` : (res.error ?? '토큰을 확인할 수 없습니다.'),
      })
    },
  })

  const remove = useMutation({
    mutationFn: () => api.del('/api/me/bitbucket-pat'),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['me', 'pat'] })
      notifications.show({ color: 'teal', title: '삭제했습니다', message: '저장된 토큰을 제거했습니다.' })
    },
  })

  const savePrefs = useMutation({
    mutationFn: (next: Partial<Prefs>) =>
      api.put<Prefs>('/api/me/prefs', { ...me?.prefs, ...next }),
    onSuccess: async () => {
      await refresh()
      notifications.show({ color: 'teal', title: '적용했습니다', message: '인증 모드를 변경했습니다.' })
    },
  })

  return (
    <>
      <PageHeader
        title="Bitbucket 토큰 · 인증 모드"
        description="기본값은 서비스 계정 모드입니다. Bitbucket 에 남는 작성자를 본인 계정으로 만들려면 개인 액세스 토큰을 등록하십시오."
      />

      <Section title="현재 상태">
        <StatList
          items={[
            { label: 'Bitbucket 사용자', value: me?.bitbucket?.bitbucketUsername ?? '매핑 없음' },
            { label: 'Bitbucket 사용자 ID', value: me?.bitbucket?.bitbucketUserId ?? '—' },
            {
              label: '등록된 개인 토큰',
              value: pat.data?.hasToken ? (
                <Badge color="teal" variant="light">
                  있음
                </Badge>
              ) : (
                <Badge color="gray" variant="light">
                  없음
                </Badge>
              ),
            },
            {
              label: '토큰 확인 시각',
              value: pat.data?.verifiedAt ? formatDateTime(new Date(pat.data.verifiedAt * 1000).toISOString()) : '—',
            },
            { label: '서비스 기본 모드', value: me?.defaultAuthMode === 'user' ? '사용자 PAT' : '서비스 계정' },
          ]}
        />
      </Section>

      <Section
        title="인증 모드"
        description="사용자 PAT 모드를 켜면 내 요청은 등록한 토큰으로 Bitbucket 을 호출합니다. 토큰이 없으면 자동으로 서비스 계정으로 대체됩니다."
      >
        <Switch
          label="내 요청에 개인 토큰을 우선 사용"
          description={
            me?.allowUserPatMode
              ? '쓰기 작업의 Bitbucket 작성자가 본인으로 기록됩니다.'
              : '관리자가 사용자 PAT 모드를 비활성화했습니다.'
          }
          checked={Boolean(me?.prefs.preferUserPat)}
          disabled={!me?.allowUserPatMode || savePrefs.isPending}
          onChange={(event) => savePrefs.mutate({ preferUserPat: event.currentTarget.checked })}
        />
      </Section>

      <Section
        title="개인 액세스 토큰 등록"
        description="Bitbucket 에서 직접 발급한 토큰만 사용하십시오. bbmcp 는 Bitbucket 비밀번호를 수집하지 않습니다."
      >
        <Stack gap="md" maw={620}>
          <TextInput
            label="Bitbucket 사용자명"
            description="비워 두면 식별 매핑에 저장된 사용자명을 사용합니다."
            placeholder={me?.bitbucket?.bitbucketUsername ?? 'hkjang'}
            value={bbUser}
            onChange={(event) => setBbUser(event.currentTarget.value)}
          />
          <PasswordInput
            label="개인 액세스 토큰 (PAT)"
            description="Bitbucket → 프로필 → Personal access tokens 에서 발급합니다. 읽기 전용 권한이면 조회만 가능합니다."
            placeholder="BBDC-…"
            value={token}
            onChange={(event) => setToken(event.currentTarget.value)}
          />
          <Alert variant="light" color="bbblue">
            토큰은 서버에서 AES-256-GCM 으로 암호화되어 저장되며, 감사 로그와 API 응답에 평문으로 노출되지 않습니다.
          </Alert>
          <Group>
            <Button
              leftSection={<IconPlugConnected size={18} />}
              loading={save.isPending}
              disabled={!token.trim()}
              onClick={() => save.mutate()}
            >
              저장
            </Button>
            <Button
              variant="default"
              leftSection={<IconShieldCheck size={18} />}
              loading={verify.isPending}
              disabled={!pat.data?.hasToken}
              onClick={() => verify.mutate()}
            >
              연결 확인
            </Button>
            <Button
              variant="light"
              color="red"
              leftSection={<IconTrash size={18} />}
              loading={remove.isPending}
              disabled={!pat.data?.hasToken}
              onClick={() => {
                if (window.confirm('저장된 Bitbucket 토큰을 삭제하시겠습니까?')) remove.mutate()
              }}
            >
              삭제
            </Button>
          </Group>
          <Text size="sm" c="dimmed">
            서비스 계정 모드에서 작성한 댓글과 PR 본문에는 [MCP 요청자: {me?.user.username}] 표기가 자동으로 붙습니다.
          </Text>
        </Stack>
      </Section>
    </>
  )
}
