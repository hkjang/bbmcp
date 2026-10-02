import { Alert, Badge, Button, Group, Stack, Text, TextInput } from '@mantine/core'
import { IconSearch } from '@tabler/icons-react'
import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'

import { ErrorBlock, PageHeader, Section, StatList } from '../components/ui'
import { api, type PermissionDecision } from '../lib/api'
import { useAuth } from '../lib/auth'

interface PermissionResult {
  username: string
  project?: PermissionDecision
  repository?: PermissionDecision
  policy?: { allowed: boolean; riskCap?: string; reason?: string; matchedBy?: string }
}

export function MyPermissionsPage() {
  const { me } = useAuth()
  const [project, setProject] = useState('')
  const [repository, setRepository] = useState('')

  const check = useMutation({
    mutationFn: () => {
      const params = new URLSearchParams({ project: project.trim() })
      if (repository.trim()) params.set('repository', repository.trim())
      return api.get<PermissionResult>(`/api/me/permissions?${params.toString()}`)
    },
  })

  return (
    <>
      <PageHeader
        title="내 유효 권한 조회"
        description="특정 프로젝트·저장소에 대해 bbmcp 가 판정하는 내 유효 권한과 접근 정책 결과를 확인합니다."
      />

      {!me?.bitbucket ? (
        <Alert color="orange" variant="light" mb="lg">
          Bitbucket 사용자 매핑이 없어 권한을 조회할 수 없습니다.
        </Alert>
      ) : null}

      <Section>
        <Group align="flex-end" gap="md" wrap="wrap">
          <TextInput
            label="프로젝트 키"
            placeholder="AI"
            value={project}
            onChange={(event) => setProject(event.currentTarget.value)}
            w={200}
          />
          <TextInput
            label="저장소 슬러그 (선택)"
            placeholder="text2sql"
            value={repository}
            onChange={(event) => setRepository(event.currentTarget.value)}
            w={240}
          />
          <Button
            leftSection={<IconSearch size={18} />}
            loading={check.isPending}
            disabled={!project.trim() || !me?.bitbucket}
            onClick={() => check.mutate()}
          >
            조회
          </Button>
        </Group>
      </Section>

      {check.error ? <ErrorBlock error={check.error} /> : null}

      {check.data ? (
        <>
          <Section title="판정 결과">
            <Stack gap="lg">
              <DecisionBlock title="프로젝트" decision={check.data.project} />
              {check.data.repository ? (
                <DecisionBlock title="저장소" decision={check.data.repository} />
              ) : null}
              {check.data.policy ? (
                <div>
                  <Text fw={600} mb="xs">
                    MCP 접근 정책
                  </Text>
                  <Group gap="xs" mb="xs">
                    <Badge color={check.data.policy.allowed ? 'teal' : 'red'} variant="light">
                      {check.data.policy.allowed ? '허용' : '차단'}
                    </Badge>
                    {check.data.policy.riskCap ? (
                      <Badge color="yellow" variant="light">
                        위험도 상한 {check.data.policy.riskCap}
                      </Badge>
                    ) : null}
                  </Group>
                  {check.data.policy.reason ? (
                    <Text size="sm" c="dimmed">
                      {check.data.policy.reason}
                    </Text>
                  ) : null}
                </div>
              ) : null}
            </Stack>
          </Section>
        </>
      ) : null}
    </>
  )
}

function DecisionBlock({ title, decision }: { title: string; decision?: PermissionDecision }) {
  if (!decision) return null
  return (
    <div>
      <Group gap="xs" mb="xs">
        <Text fw={600}>{title}</Text>
        <Badge color={decision.read ? 'teal' : 'gray'} variant="light">
          유효 권한 {decision.effective}
        </Badge>
      </Group>
      <StatList
        items={[
          { label: '조회', value: decision.read ? '가능' : '불가' },
          { label: '쓰기', value: decision.write ? '가능' : '불가' },
          { label: '관리', value: decision.admin ? '가능' : '불가' },
          { label: '판정 출처', value: decision.source },
          ...(decision.note ? [{ label: '비고', value: decision.note }] : []),
        ]}
      />
    </div>
  )
}
