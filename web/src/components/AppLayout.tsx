import {
  ActionIcon,
  AppShell,
  Avatar,
  Badge,
  Box,
  Burger,
  Divider,
  Group,
  Menu,
  NavLink,
  ScrollArea,
  Stack,
  Text,
  Tooltip,
  UnstyledButton,
  useComputedColorScheme,
  useMantineColorScheme,
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import {
  IconActivity,
  IconAdjustmentsAlt,
  IconApi,
  IconBrandGithub,
  IconChecklist,
  IconChevronDown,
  IconDashboard,
  IconDatabase,
  IconFileText,
  IconFingerprint,
  IconKey,
  IconLogout,
  IconMoon,
  IconPlugConnected,
  IconRobot,
  IconServer2,
  IconShieldLock,
  IconSun,
  IconToolsKitchen2,
  IconUserCog,
  IconUsers,
  IconVersions,
} from '@tabler/icons-react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../lib/auth'
import { BrandMark } from './BrandMark'

interface NavItem {
  label: string
  to: string
  icon: typeof IconDashboard
  admin?: boolean
}

interface NavGroup {
  label: string
  items: NavItem[]
  admin?: boolean
}

const navGroups: NavGroup[] = [
  {
    label: '내 작업 공간',
    items: [
      { label: '개요', to: '/', icon: IconDashboard },
      { label: 'API 키', to: '/me/keys', icon: IconKey },
      { label: 'Bitbucket 토큰', to: '/me/bitbucket', icon: IconPlugConnected },
      { label: '승인 요청', to: '/me/approvals', icon: IconChecklist },
      { label: '사용 가능한 도구', to: '/me/tools', icon: IconToolsKitchen2 },
      { label: '내 권한 조회', to: '/me/permissions', icon: IconFingerprint },
      { label: 'AI 리뷰 보조', to: '/me/ai', icon: IconRobot },
      { label: '내 활동 기록', to: '/me/audit', icon: IconActivity },
      { label: '개인 설정', to: '/me/settings', icon: IconUserCog },
    ],
  },
  {
    label: '서비스 관리',
    admin: true,
    items: [
      { label: '관리 대시보드', to: '/admin', icon: IconDashboard },
      { label: '인증 (Keycloak)', to: '/admin/auth', icon: IconShieldLock },
      { label: 'Bitbucket 연결', to: '/admin/bitbucket', icon: IconPlugConnected },
      { label: '권한 해석기', to: '/admin/permission', icon: IconFingerprint },
      { label: '식별 매핑', to: '/admin/identity', icon: IconUsers },
      { label: 'MCP 도구', to: '/admin/tools', icon: IconToolsKitchen2 },
      { label: '접근 정책', to: '/admin/policy', icon: IconAdjustmentsAlt },
      { label: '승인 관리', to: '/admin/approvals', icon: IconChecklist },
      { label: 'MCP 세션', to: '/admin/sessions', icon: IconApi },
      { label: '키 · 권한 체계', to: '/admin/keys', icon: IconKey },
      { label: '사용자', to: '/admin/users', icon: IconUsers },
      { label: 'AI 설정', to: '/admin/ai', icon: IconRobot },
      { label: '보안', to: '/admin/security', icon: IconShieldLock },
      { label: '화면 설정', to: '/admin/ui', icon: IconAdjustmentsAlt },
      { label: '감사 로그', to: '/admin/audit', icon: IconFileText },
      { label: '시스템', to: '/admin/system', icon: IconServer2 },
    ],
  },
]

export function AppLayout() {
  const [mobileOpened, { toggle: toggleMobile, close: closeMobile }] = useDisclosure(false)
  const [desktopOpened, { toggle: toggleDesktop }] = useDisclosure(true)
  const { me, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const { setColorScheme } = useMantineColorScheme()
  const computed = useComputedColorScheme('light', { getInitialValueInEffect: true })

  const isAdmin = Boolean(me?.isServiceAdmin)
  const serviceName = me?.ui.serviceName || 'bbmcp'
  const version = me?.version

  const isActive = (to: string) =>
    to === '/' ? location.pathname === '/' : location.pathname.startsWith(to)

  return (
    <AppShell
      header={{ height: 64 }}
      navbar={{
        width: 290,
        breakpoint: 'sm',
        collapsed: { mobile: !mobileOpened, desktop: !desktopOpened },
      }}
      padding="lg"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={mobileOpened} onClick={toggleMobile} hiddenFrom="sm" size="sm" aria-label="메뉴 열기" />
            <Burger opened={desktopOpened} onClick={toggleDesktop} visibleFrom="sm" size="sm" aria-label="메뉴 접기" />
            <UnstyledButton component={Link} to="/" aria-label="홈으로">
              <Group gap="xs" wrap="nowrap">
                <BrandMark size={30} />
                <Box>
                  <Text fw={800} size="lg" lh={1.1}>
                    {serviceName}
                  </Text>
                  <Text size="xs" c="dimmed" lh={1.1} visibleFrom="xs">
                    {me?.ui.tagline || 'Bitbucket MCP 게이트웨이'}
                  </Text>
                </Box>
              </Group>
            </UnstyledButton>
          </Group>

          <Group gap="xs" wrap="nowrap">
            <Tooltip label={computed === 'dark' ? '밝은 테마로' : '어두운 테마로'}>
              <ActionIcon
                variant="default"
                size="lg"
                aria-label="테마 전환"
                onClick={() => setColorScheme(computed === 'dark' ? 'light' : 'dark')}
              >
                {computed === 'dark' ? <IconSun size={20} /> : <IconMoon size={20} />}
              </ActionIcon>
            </Tooltip>

            <Menu shadow="md" width={290} position="bottom-end" withinPortal>
              <Menu.Target>
                <UnstyledButton aria-label="프로필 메뉴">
                  <Group gap="xs" wrap="nowrap">
                    <Avatar color="bbblue" radius="xl" size={34}>
                      {(me?.user.displayName || me?.user.username || '?').slice(0, 2).toUpperCase()}
                    </Avatar>
                    <Box visibleFrom="sm">
                      <Text size="sm" fw={600} lh={1.15}>
                        {me?.user.displayName || me?.user.username}
                      </Text>
                      <Text size="xs" c="dimmed" lh={1.15}>
                        {isAdmin ? '서비스 관리자' : '사용자'}
                      </Text>
                    </Box>
                    <IconChevronDown size={16} />
                  </Group>
                </UnstyledButton>
              </Menu.Target>

              <Menu.Dropdown>
                <Menu.Label>계정</Menu.Label>
                <Menu.Item disabled style={{ opacity: 1, cursor: 'default' }}>
                  <Stack gap={2}>
                    <Text size="sm" fw={600}>
                      {me?.user.username}
                    </Text>
                    {me?.user.email ? (
                      <Text size="xs" c="dimmed">
                        {me.user.email}
                      </Text>
                    ) : null}
                    <Group gap={6} mt={4}>
                      <Badge size="sm" variant="light" color={isAdmin ? 'grape' : 'bbblue'}>
                        {isAdmin ? '관리자' : '사용자'}
                      </Badge>
                      <Badge size="sm" variant="light" color="gray">
                        {me?.authMode === 'session' ? '세션' : me?.authMode}
                      </Badge>
                    </Group>
                    <Text size="xs" c="dimmed" mt={4}>
                      Bitbucket: {me?.bitbucket?.bitbucketUsername ?? '매핑 없음'}
                    </Text>
                  </Stack>
                </Menu.Item>

                <Menu.Divider />
                <Menu.Label>서비스 버전</Menu.Label>
                <Menu.Item
                  leftSection={<IconVersions size={18} />}
                  disabled
                  style={{ opacity: 1, cursor: 'default' }}
                >
                  <Stack gap={2}>
                    <Text size="sm" fw={600}>
                      v{version?.version ?? '—'}
                    </Text>
                    <Text size="xs" c="dimmed">
                      빌드 {version?.commit ?? '—'} · {version?.buildDate ?? '—'}
                    </Text>
                  </Stack>
                </Menu.Item>

                <Menu.Divider />
                <Menu.Item
                  leftSection={<IconUserCog size={18} />}
                  onClick={() => navigate('/me/settings')}
                >
                  개인 설정
                </Menu.Item>
                <Menu.Item
                  leftSection={<IconDatabase size={18} />}
                  onClick={() => navigate('/me/keys')}
                >
                  내 API 키
                </Menu.Item>
                <Menu.Item
                  leftSection={<IconBrandGithub size={18} />}
                  component="a"
                  href="https://hkjang.github.io/bbmcp/"
                  target="_blank"
                  rel="noreferrer"
                >
                  사용 안내
                </Menu.Item>
                <Menu.Divider />
                <Menu.Item color="red" leftSection={<IconLogout size={18} />} onClick={() => void logout()}>
                  로그아웃
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="xs">
        <AppShell.Section
          grow
          component={ScrollArea}
          type="hover"
          scrollbarSize={10}
          scrollHideDelay={400}
          className="bbmcp-nav-scroll"
        >
          <Stack gap="lg" py="xs">
            {navGroups
              .filter((group) => !group.admin || isAdmin)
              .map((group) => (
                <Box key={group.label}>
                  <Text size="xs" fw={700} c="dimmed" tt="uppercase" px="sm" mb={6} lts={0.6}>
                    {group.label}
                  </Text>
                  <Stack gap={2}>
                    {group.items.map((item) => (
                      <NavLink
                        key={item.to}
                        component={Link}
                        to={item.to}
                        label={item.label}
                        leftSection={<item.icon size={19} stroke={1.7} />}
                        active={isActive(item.to)}
                        onClick={closeMobile}
                        fz="sm"
                        style={{ borderRadius: 'var(--mantine-radius-sm)' }}
                      />
                    ))}
                  </Stack>
                </Box>
              ))}
          </Stack>
        </AppShell.Section>

        <AppShell.Section>
          <Divider mb="xs" />
          <Group justify="space-between" px="sm" pb="xs" wrap="nowrap">
            <Text size="xs" c="dimmed">
              {serviceName} v{version?.version ?? '—'}
            </Text>
            <Badge size="xs" variant="light" color="gray">
              {version?.commit?.slice(0, 7) ?? 'dev'}
            </Badge>
          </Group>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <Outlet />
      </AppShell.Main>
    </AppShell>
  )
}
