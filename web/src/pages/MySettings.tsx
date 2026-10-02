import {
  Button,
  Group,
  PasswordInput,
  SegmentedControl,
  Select,
  Slider,
  Stack,
  Text,
  useMantineColorScheme,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'

import { PageHeader, Section, StatList } from '../components/ui'
import { api, type Prefs } from '../lib/api'
import { useAuth } from '../lib/auth'
import { formatDateTime } from '../lib/format'

export function MySettingsPage() {
  const { me, refresh } = useAuth()
  const { setColorScheme } = useMantineColorScheme()
  const [prefs, setPrefs] = useState<Prefs>(
    me?.prefs ?? { preferUserPat: false, theme: 'system', fontScale: 1, locale: 'ko' },
  )
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')

  const savePrefs = useMutation({
    mutationFn: () => api.put<Prefs>('/api/me/prefs', prefs),
    onSuccess: async (data) => {
      document.documentElement.style.setProperty('--bbmcp-font-scale', String(data.fontScale))
      setColorScheme(data.theme === 'system' ? 'auto' : (data.theme as 'light' | 'dark'))
      await refresh()
      notifications.show({ color: 'teal', title: '저장했습니다', message: '개인 설정이 적용되었습니다.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '저장 실패',
        message: err instanceof Error ? err.message : '설정을 저장할 수 없습니다.',
      }),
  })

  const changePassword = useMutation({
    mutationFn: () => api.post('/api/me/password', { currentPassword: current, newPassword: next }),
    onSuccess: () => {
      setCurrent('')
      setNext('')
      setConfirm('')
      notifications.show({ color: 'teal', title: '변경했습니다', message: '비밀번호가 변경되었습니다.' })
    },
    onError: (err: unknown) =>
      notifications.show({
        color: 'red',
        title: '변경 실패',
        message: err instanceof Error ? err.message : '비밀번호를 변경할 수 없습니다.',
      }),
  })

  const passwordValid = next.length >= 10 && next === confirm && current.length > 0

  return (
    <>
      <PageHeader title="개인 설정" description="화면 표시와 계정 보안을 개인별로 설정합니다." />

      <Section title="계정">
        <StatList
          items={[
            { label: '아이디', value: me?.user.username ?? '—' },
            { label: '표시 이름', value: me?.user.displayName || '—' },
            { label: '이메일', value: me?.user.email || '—' },
            { label: '계정 출처', value: me?.user.source === 'keycloak' ? 'Keycloak SSO' : '로컬' },
            { label: '역할', value: me?.user.roles.join(', ') || '—' },
            { label: '생성', value: formatDateTime(me?.user.createdAt) },
            { label: '마지막 로그인', value: formatDateTime(me?.user.lastLoginAt) },
          ]}
        />
      </Section>

      <Section title="화면" description="글자 크기는 이 브라우저뿐 아니라 내 계정으로 접속하는 모든 화면에 적용됩니다.">
        <Stack gap="lg" maw={560}>
          <div>
            <Text fw={600} mb="xs">
              테마
            </Text>
            <SegmentedControl
              value={prefs.theme}
              onChange={(value) => setPrefs({ ...prefs, theme: value })}
              data={[
                { label: '시스템 설정', value: 'system' },
                { label: '밝게', value: 'light' },
                { label: '어둡게', value: 'dark' },
              ]}
              fullWidth
            />
          </div>

          <div>
            <Text fw={600} mb={4}>
              글자 크기 ({Math.round(prefs.fontScale * 100)}%)
            </Text>
            <Text size="sm" c="dimmed" mb="md">
              기본값 100% 는 본문 16px 입니다. 큰 화면이나 공유 모니터에서는 110~125% 를 권장합니다.
            </Text>
            <Slider
              value={prefs.fontScale}
              onChange={(value) => setPrefs({ ...prefs, fontScale: value })}
              min={0.9}
              max={1.4}
              step={0.05}
              marks={[
                { value: 0.9, label: '90%' },
                { value: 1, label: '100%' },
                { value: 1.15, label: '115%' },
                { value: 1.4, label: '140%' },
              ]}
              mb="xl"
            />
          </div>

          <Select
            label="표시 언어"
            description="현재 버전은 한국어를 기본으로 제공합니다."
            data={[
              { value: 'ko', label: '한국어' },
              { value: 'en', label: 'English (일부 미번역)' },
            ]}
            value={prefs.locale}
            onChange={(value) => setPrefs({ ...prefs, locale: value ?? 'ko' })}
            allowDeselect={false}
            comboboxProps={{ withinPortal: true }}
          />

          <Group justify="flex-end">
            <Button loading={savePrefs.isPending} onClick={() => savePrefs.mutate()}>
              저장
            </Button>
          </Group>
        </Stack>
      </Section>

      {me?.user.hasPassword ? (
        <Section title="비밀번호 변경" description="변경하면 다른 모든 세션이 즉시 로그아웃됩니다.">
          <Stack gap="md" maw={480}>
            <PasswordInput
              label="현재 비밀번호"
              value={current}
              onChange={(event) => setCurrent(event.currentTarget.value)}
              autoComplete="current-password"
            />
            <PasswordInput
              label="새 비밀번호"
              description="10자 이상"
              value={next}
              onChange={(event) => setNext(event.currentTarget.value)}
              autoComplete="new-password"
              error={next.length > 0 && next.length < 10 ? '10자 이상이어야 합니다' : undefined}
            />
            <PasswordInput
              label="새 비밀번호 확인"
              value={confirm}
              onChange={(event) => setConfirm(event.currentTarget.value)}
              autoComplete="new-password"
              error={confirm.length > 0 && confirm !== next ? '비밀번호가 일치하지 않습니다' : undefined}
            />
            <Group justify="flex-end">
              <Button
                loading={changePassword.isPending}
                disabled={!passwordValid}
                onClick={() => changePassword.mutate()}
              >
                비밀번호 변경
              </Button>
            </Group>
          </Stack>
        </Section>
      ) : (
        <Section title="비밀번호">
          <Text c="dimmed">
            이 계정은 Keycloak SSO 로 인증합니다. 비밀번호는 Keycloak 에서 변경하십시오.
          </Text>
        </Section>
      )}
    </>
  )
}
