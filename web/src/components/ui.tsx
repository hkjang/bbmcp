import {
  ActionIcon,
  Alert,
  Badge,
  Box,
  Button,
  Code,
  CopyButton,
  Group,
  Loader,
  Paper,
  ScrollArea,
  Stack,
  Text,
  Title,
  Tooltip,
} from '@mantine/core'
import {
  IconAlertTriangle,
  IconCheck,
  IconCircleCheck,
  IconCircleX,
  IconCopy,
  IconMinus,
} from '@tabler/icons-react'
import type { ReactNode } from 'react'
import type { HealthComponent } from '../lib/api'

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <Group justify="space-between" align="flex-start" wrap="wrap" gap="md" mb="lg">
      <Box style={{ flex: '1 1 320px', minWidth: 0 }}>
        <Title order={2}>{title}</Title>
        {description ? (
          <Text c="dimmed" mt={6} size="md">
            {description}
          </Text>
        ) : null}
      </Box>
      {actions ? <Group gap="sm">{actions}</Group> : null}
    </Group>
  )
}

export function Section({
  title,
  description,
  actions,
  children,
}: {
  title?: string
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <Paper withBorder radius="md" p="lg" mb="lg">
      {title || actions ? (
        <Group justify="space-between" align="flex-start" mb={description ? 4 : 'md'} wrap="wrap">
          {title ? <Title order={4}>{title}</Title> : <span />}
          {actions ? <Group gap="xs">{actions}</Group> : null}
        </Group>
      ) : null}
      {description ? (
        <Text c="dimmed" size="sm" mb="md">
          {description}
        </Text>
      ) : null}
      {children}
    </Paper>
  )
}

export function LoadingBlock({ label = '불러오는 중입니다…' }: { label?: string }) {
  return (
    <Group justify="center" py="xl" gap="sm">
      <Loader size="sm" />
      <Text c="dimmed">{label}</Text>
    </Group>
  )
}

export function ErrorBlock({ error, title = '오류' }: { error: unknown; title?: string }) {
  const message = error instanceof Error ? error.message : String(error ?? '알 수 없는 오류')
  return (
    <Alert color="red" icon={<IconAlertTriangle size={20} />} title={title} variant="light">
      {message}
    </Alert>
  )
}

export function EmptyState({ label }: { label: string }) {
  return (
    <Text c="dimmed" ta="center" py="xl">
      {label}
    </Text>
  )
}

export function HealthBadge({ name, value }: { name: string; value: HealthComponent }) {
  const color = value.skipped ? 'gray' : value.ok ? 'teal' : 'red'
  const icon = value.skipped ? (
    <IconMinus size={16} />
  ) : value.ok ? (
    <IconCircleCheck size={16} />
  ) : (
    <IconCircleX size={16} />
  )
  return (
    <Tooltip label={value.detail || name} multiline maw={360}>
      <Badge color={color} variant="light" leftSection={icon} style={{ cursor: 'help' }}>
        {name}
      </Badge>
    </Tooltip>
  )
}

export function CopyField({ value, label }: { value: string; label?: string }) {
  return (
    <Group gap="xs" wrap="nowrap" align="center">
      <Code style={{ overflowWrap: 'anywhere' }}>{value}</Code>
      <CopyButton value={value} timeout={1500}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? '복사했습니다' : (label ?? '복사')}>
            <ActionIcon variant="subtle" color={copied ? 'teal' : 'gray'} onClick={copy} aria-label="복사">
              {copied ? <IconCheck size={18} /> : <IconCopy size={18} />}
            </ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </Group>
  )
}

export function TableScroll({ children, minWidth = 720 }: { children: ReactNode; minWidth?: number }) {
  return (
    <ScrollArea type="auto" offsetScrollbars scrollbarSize={10}>
      <Box miw={minWidth}>{children}</Box>
    </ScrollArea>
  )
}

/** Preformatted text such as shell commands, shown as written. */
export function TextBlock({ text, maxHeight = 420 }: { text: string; maxHeight?: number }) {
  return (
    <Box
      component="pre"
      className="bbmcp-code bbmcp-scroll-surface"
      p="sm"
      m={0}
      style={{
        maxHeight,
        overflow: 'auto',
        whiteSpace: 'pre',
        borderRadius: 'var(--mantine-radius-sm)',
        background: 'var(--mantine-color-default-hover)',
      }}
    >
      {text}
    </Box>
  )
}

export function JsonBlock({ value, maxHeight = 420 }: { value: unknown; maxHeight?: number }) {
  return (
    <Box
      className="bbmcp-code bbmcp-scroll-surface"
      p="sm"
      style={{
        maxHeight,
        overflow: 'auto',
        borderRadius: 'var(--mantine-radius-sm)',
        background: 'var(--mantine-color-default-hover)',
      }}
    >
      {JSON.stringify(value, null, 2)}
    </Box>
  )
}

export function SaveBar({
  onSave,
  saving,
  dirty,
  extra,
}: {
  onSave: () => void
  saving?: boolean
  dirty?: boolean
  extra?: ReactNode
}) {
  return (
    <Group justify="flex-end" mt="lg" gap="sm">
      {extra}
      <Button onClick={onSave} loading={saving} disabled={dirty === false}>
        저장
      </Button>
    </Group>
  )
}

export function StatList({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <Stack gap="xs">
      {items.map((item) => (
        <Group key={item.label} justify="space-between" wrap="nowrap" gap="md">
          <Text c="dimmed" size="sm">
            {item.label}
          </Text>
          <Text size="sm" fw={600} style={{ textAlign: 'right', overflowWrap: 'anywhere' }}>
            {item.value}
          </Text>
        </Group>
      ))}
    </Stack>
  )
}
