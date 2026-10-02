import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Center,
  Divider,
  Group,
  Loader,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import { IconAlertTriangle, IconKey, IconShieldLock } from '@tabler/icons-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import { BrandMark } from '../components/BrandMark'
import { useAuth } from '../lib/auth'

export function LoginPage() {
  const { config, login, startSso, silentChecking, ssoError } = useAuth()
  const [params] = useSearchParams()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const version = config?.version
  const ui = config?.ui
  const keycloakEnabled = config?.auth.keycloakEnabled ?? false
  const returnTo = params.get('returnTo') ?? '/'

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username.trim(), password)
      // The router sends the user on once `me` is populated.
      if (returnTo && returnTo !== '/') window.location.href = returnTo
    } catch (err) {
      setError(err instanceof Error ? err.message : '로그인에 실패했습니다.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box className="bbmcp-login-hero" mih="100vh">
      <Center mih="100vh" p="md">
        <Stack w="100%" maw={460} gap="lg">
          <Stack align="center" gap="xs">
            <BrandMark size={64} />
            <Title order={1} ta="center">
              {ui?.serviceName ?? 'bbmcp'}
            </Title>
            <Text c="dimmed" ta="center" size="lg">
              {ui?.tagline ?? 'Bitbucket MCP 게이트웨이'}
            </Text>
          </Stack>

          <Card withBorder radius="md" p="xl" shadow="sm">
            <Stack gap="md">
              {ui?.loginNotice ? (
                <Alert variant="light" color="bbblue">
                  {ui.loginNotice}
                </Alert>
              ) : null}

              {silentChecking ? (
                <Group gap="xs" justify="center">
                  <Loader size="xs" />
                  <Text size="sm" c="dimmed">
                    기존 SSO 세션을 확인하고 있습니다…
                  </Text>
                </Group>
              ) : null}

              {ssoError ? (
                <Alert
                  variant="light"
                  color="orange"
                  icon={<IconAlertTriangle size={20} />}
                  title="SSO 안내"
                >
                  {ssoError}
                </Alert>
              ) : null}

              {keycloakEnabled ? (
                <>
                  <Button
                    size="md"
                    fullWidth
                    leftSection={<IconShieldLock size={20} />}
                    onClick={() => startSso(returnTo)}
                  >
                    Keycloak 계정으로 로그인
                  </Button>
                  <Divider label="또는 로컬 계정" labelPosition="center" />
                </>
              ) : null}

              <form onSubmit={submit}>
                <Stack gap="md">
                  <TextInput
                    label="아이디"
                    placeholder="관리자 또는 로컬 계정"
                    autoComplete="username"
                    required
                    value={username}
                    onChange={(event) => setUsername(event.currentTarget.value)}
                  />
                  <PasswordInput
                    label="비밀번호"
                    placeholder="비밀번호"
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(event) => setPassword(event.currentTarget.value)}
                  />
                  {error ? (
                    <Alert color="red" variant="light" icon={<IconAlertTriangle size={20} />}>
                      {error}
                    </Alert>
                  ) : null}
                  <Button
                    type="submit"
                    size="md"
                    fullWidth
                    loading={busy}
                    variant={keycloakEnabled ? 'default' : 'filled'}
                    leftSection={<IconKey size={20} />}
                  >
                    로그인
                  </Button>
                </Stack>
              </form>
            </Stack>
          </Card>

          {/* The running version is visible before sign-in, so an operator can
              confirm which build an environment is on without logging in. */}
          <Group justify="center" gap="xs">
            <Badge variant="light" color="gray" size="lg">
              버전 v{version?.version ?? '—'}
            </Badge>
            <Badge variant="light" color="gray" size="lg">
              빌드 {version?.commit?.slice(0, 7) ?? '—'}
            </Badge>
            <Badge variant="light" color="gray" size="lg">
              {version?.buildDate ?? '—'}
            </Badge>
          </Group>
        </Stack>
      </Center>
    </Box>
  )
}
