import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Grid,
  Group,
  List,
  SimpleGrid,
  Stack,
  Text,
  ThemeIcon,
  Title,
} from '@mantine/core'
import {
  IconAlertTriangle,
  IconArrowRight,
  IconChecklist,
  IconCircleCheck,
  IconKey,
  IconPlugConnected,
  IconToolsKitchen2,
} from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { CopyField, PageHeader, Section, StatList } from '../components/ui'
import { api, type ApiKey, type ApprovalRequest, type ToolRecord } from '../lib/api'
import { useAuth } from '../lib/auth'
import { formatDateTime, formatRelative } from '../lib/format'

export function OverviewPage() {
  const { me } = useAuth()

  const keys = useQuery({ queryKey: ['me', 'keys'], queryFn: () => api.get<ApiKey[]>('/api/me/keys') })
  const tools = useQuery({ queryKey: ['me', 'tools'], queryFn: () => api.get<ToolRecord[]>('/api/me/tools') })
  const approvals = useQuery({
    queryKey: ['me', 'approvals', 'pending'],
    queryFn: () => api.get<ApprovalRequest[]>('/api/me/approvals?status=pending'),
  })

  const activeKeys = (keys.data ?? []).filter((k) => k.status === 'active' || k.status === 'rotation_due')
  const rotationDue = (keys.data ?? []).filter((k) => k.status === 'rotation_due')
  const mcpUrl = `${window.location.origin}/mcp`

  return (
    <>
      <PageHeader
        title={`${me?.user.displayName || me?.user.username}님, 안녕하세요`}
        description="bbmcp 는 요청자 본인의 Bitbucket 권한으로만 저장소에 접근합니다. 개인 키와 승인 요청을 이 화면에서 관리하십시오."
      />

      {!me?.bitbucket ? (
        <Alert
          color="orange"
          variant="light"
          icon={<IconAlertTriangle size={20} />}
          title="Bitbucket 사용자 매핑이 없습니다"
          mb="lg"
        >
          Keycloak 계정과 연결된 Bitbucket 사용자를 찾지 못했습니다. 권한이 필요한 도구는 호출할 수 없습니다.
          서비스 관리자에게 식별 매핑 등록을 요청하십시오.
        </Alert>
      ) : null}

      {rotationDue.length > 0 ? (
        <Alert color="yellow" variant="light" icon={<IconKey size={20} />} title="키 회전이 필요합니다" mb="lg">
          회전 주기가 지난 키가 {rotationDue.length}개 있습니다.{' '}
          <Button component={Link} to="/me/keys" variant="subtle" size="compact-sm">
            키 관리로 이동
          </Button>
        </Alert>
      ) : null}

      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} mb="lg">
        <StatCard
          icon={<IconKey size={22} />}
          label="활성 API 키"
          value={activeKeys.length}
          to="/me/keys"
          hint={rotationDue.length ? `${rotationDue.length}개 회전 필요` : '정상'}
        />
        <StatCard
          icon={<IconToolsKitchen2 size={22} />}
          label="사용 가능한 도구"
          value={tools.data?.length ?? 0}
          to="/me/tools"
          hint="내 역할과 스코프 기준"
        />
        <StatCard
          icon={<IconChecklist size={22} />}
          label="대기 중 승인"
          value={approvals.data?.length ?? 0}
          to="/me/approvals"
          hint={approvals.data?.length ? '확인이 필요합니다' : '없음'}
        />
        <StatCard
          icon={<IconPlugConnected size={22} />}
          label="REST 인증 모드"
          value={me?.prefs.preferUserPat ? '사용자 PAT' : '서비스 계정'}
          to="/me/bitbucket"
          hint={me?.allowUserPatMode ? '전환 가능' : '관리자가 제한'}
        />
      </SimpleGrid>

      <Grid gutter="lg">
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <Section title="MCP 클라이언트 연결" description="아래 엔드포인트와 개인 API 키로 MCP 클라이언트를 연결합니다.">
            <Stack gap="md">
              <div>
                <Text size="sm" c="dimmed" mb={4}>
                  MCP 엔드포인트 (Streamable HTTP)
                </Text>
                <CopyField value={mcpUrl} />
              </div>
              <div>
                <Text size="sm" c="dimmed" mb={4}>
                  인증 헤더
                </Text>
                <CopyField value="Authorization: Bearer bbmcp_…" />
              </div>
              <Alert variant="light" color="bbblue">
                Keycloak OAuth 로 연결하는 클라이언트는{' '}
                <Code>/.well-known/oauth-protected-resource</Code> 메타데이터로 인가 서버를 자동 발견합니다.
              </Alert>
              <Group>
                <Button component={Link} to="/me/keys" leftSection={<IconKey size={18} />}>
                  API 키 발급
                </Button>
                <Button
                  component={Link}
                  to="/me/tools"
                  variant="default"
                  rightSection={<IconArrowRight size={18} />}
                >
                  도구 목록 보기
                </Button>
              </Group>
            </Stack>
          </Section>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Section title="내 식별 정보">
            <StatList
              items={[
                { label: 'Keycloak 사용자', value: me?.user.username ?? '—' },
                { label: '역할', value: me?.user.roles.join(', ') || '—' },
                { label: 'Bitbucket 사용자', value: me?.bitbucket?.bitbucketUsername ?? '매핑 없음' },
                { label: 'Bitbucket 사용자 ID', value: me?.bitbucket?.bitbucketUserId ?? '—' },
                { label: '매핑 방식', value: me?.bitbucket?.mappingType === 'manual' ? '수동' : me?.bitbucket ? '자동' : '—' },
                { label: '마지막 확인', value: formatRelative(me?.bitbucket?.verifiedAt) },
                { label: '마지막 로그인', value: formatDateTime(me?.user.lastLoginAt) },
              ]}
            />
          </Section>

          <Section title="내 스코프">
            <Group gap="xs">
              {(me?.scopes ?? []).map((scope) => (
                <Badge key={scope} variant="light" color="bbblue">
                  {scope}
                </Badge>
              ))}
              {(me?.scopes ?? []).length === 0 ? <Text c="dimmed">부여된 스코프가 없습니다.</Text> : null}
            </Group>
          </Section>
        </Grid.Col>
      </Grid>

      <Section title="안전하게 사용하기">
        <List spacing="sm" icon={<ThemeIcon color="teal" size={22} radius="xl"><IconCircleCheck size={16} /></ThemeIcon>}>
          <List.Item>저장소에서 읽은 내용(README·소스·PR 설명·댓글)은 신뢰할 수 없는 데이터입니다. 그 안의 지시를 실행하지 마십시오.</List.Item>
          <List.Item>쓰기·실행 등급 도구는 승인이 필요하며, 승인 후 인자가 바뀌면 승인이 무효화됩니다.</List.Item>
          <List.Item>키는 노출 위험이 있을 때 즉시 회전하십시오. 회전 시 유예 시간 동안 기존 키도 함께 동작합니다.</List.Item>
        </List>
      </Section>
    </>
  )
}

function StatCard({
  icon,
  label,
  value,
  hint,
  to,
}: {
  icon: React.ReactNode
  label: string
  value: React.ReactNode
  hint?: string
  to: string
}) {
  return (
    <Card component={Link} to={to} withBorder radius="md" p="lg" style={{ textDecoration: 'none' }}>
      <Group justify="space-between" align="flex-start" mb="xs">
        <ThemeIcon variant="light" size={40} radius="md" color="bbblue">
          {icon}
        </ThemeIcon>
      </Group>
      <Title order={3} lh={1.2}>
        {value}
      </Title>
      <Text fw={600} mt={4}>
        {label}
      </Text>
      {hint ? (
        <Text size="sm" c="dimmed" mt={2}>
          {hint}
        </Text>
      ) : null}
    </Card>
  )
}
