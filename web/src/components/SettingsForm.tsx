import {
  Grid,
  NumberInput,
  PasswordInput,
  Select,
  Switch,
  TagsInput,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from '@mantine/core'
import { IconLock } from '@tabler/icons-react'

export interface SelectOption {
  value: string
  label: string
}

export type Field<T extends object> =
  | { kind: 'text'; key: keyof T & string; label: string; description?: string; placeholder?: string; span?: number }
  | { kind: 'textarea'; key: keyof T & string; label: string; description?: string; minRows?: number; span?: number }
  | {
      kind: 'number'
      key: keyof T & string
      label: string
      description?: string
      min?: number
      max?: number
      step?: number
      decimal?: boolean
      span?: number
    }
  | { kind: 'switch'; key: keyof T & string; label: string; description?: string; span?: number }
  | {
      kind: 'select'
      key: keyof T & string
      label: string
      description?: string
      options: SelectOption[]
      span?: number
    }
  | { kind: 'tags'; key: keyof T & string; label: string; description?: string; placeholder?: string; span?: number }
  | {
      kind: 'secret'
      secretKey: string
      label: string
      description?: string
      hasValue?: boolean
      span?: number
    }

interface Props<T extends object> {
  fields: Field<T>[]
  value: T
  onChange: (next: T) => void
  secrets: Record<string, string>
  onSecretChange: (next: Record<string, string>) => void
  secretPresence?: Record<string, boolean>
}

/**
 * SettingsForm renders an admin settings group from a declarative spec.
 *
 * Selects are always given a value that exists in their option list: an
 * unexpected stored value is surfaced as its own option rather than silently
 * rendering an empty control that cannot be reopened.
 */
export function SettingsForm<T extends object>({
  fields,
  value,
  onChange,
  secrets,
  onSecretChange,
  secretPresence,
}: Props<T>) {
  const set = (key: string, next: unknown) => onChange({ ...value, [key]: next } as T)
  const read = (key: string): unknown => (value as Record<string, unknown>)[key]

  return (
    <Grid gutter="lg">
      {fields.map((field) => {
        const span = field.span ?? 6
        const key = field.kind === 'secret' ? `secret:${field.secretKey}` : `field:${field.key}`

        return (
          <Grid.Col key={key} span={{ base: 12, md: span }}>
            {renderField(field, read, set, secrets, onSecretChange, secretPresence)}
          </Grid.Col>
        )
      })}
    </Grid>
  )
}

function renderField<T extends object>(
  field: Field<T>,
  read: (key: string) => unknown,
  set: (key: string, next: unknown) => void,
  secrets: Record<string, string>,
  onSecretChange: (next: Record<string, string>) => void,
  secretPresence?: Record<string, boolean>,
) {
  switch (field.kind) {
    case 'text':
      return (
        <TextInput
          label={field.label}
          description={field.description}
          placeholder={field.placeholder}
          value={asString(read(field.key))}
          onChange={(event) => set(field.key, event.currentTarget.value)}
        />
      )

    case 'textarea':
      return (
        <Textarea
          label={field.label}
          description={field.description}
          autosize
          minRows={field.minRows ?? 3}
          maxRows={12}
          value={asString(read(field.key))}
          onChange={(event) => set(field.key, event.currentTarget.value)}
        />
      )

    case 'number':
      return (
        <NumberInput
          label={field.label}
          description={field.description}
          min={field.min}
          max={field.max}
          step={field.step}
          decimalScale={field.decimal ? 2 : 0}
          allowDecimal={Boolean(field.decimal)}
          clampBehavior="strict"
          value={asNumber(read(field.key))}
          onChange={(next) => set(field.key, typeof next === 'number' ? next : Number(next) || 0)}
        />
      )

    case 'switch':
      return (
        <Switch
          label={field.label}
          description={field.description}
          mt={field.description ? 0 : 'xl'}
          checked={Boolean(read(field.key))}
          onChange={(event) => set(field.key, event.currentTarget.checked)}
        />
      )

    case 'select': {
      const current = asString(read(field.key))
      const options = ensureOption(field.options, current)
      return (
        <Select
          label={field.label}
          description={field.description}
          data={options}
          value={current === '' ? null : current}
          onChange={(next) => set(field.key, next ?? '')}
          allowDeselect={false}
          searchable={options.length > 8}
          nothingFoundMessage="일치하는 항목이 없습니다"
          comboboxProps={{ withinPortal: true }}
        />
      )
    }

    case 'tags':
      return (
        <TagsInput
          label={field.label}
          description={field.description}
          placeholder={field.placeholder}
          value={asStringArray(read(field.key))}
          onChange={(next) => set(field.key, next)}
          clearable
        />
      )

    case 'secret': {
      const present = secretPresence?.[field.secretKey] ?? field.hasValue
      return (
        <PasswordInput
          label={field.label}
          description={
            field.description ??
            (present
              ? '저장된 값이 있습니다. 비워 두면 기존 값을 유지합니다.'
              : '아직 저장된 값이 없습니다.')
          }
          placeholder={present ? '••••••••  (변경할 때만 입력)' : '값을 입력하십시오'}
          value={secrets[field.secretKey] ?? ''}
          onChange={(event) =>
            onSecretChange({ ...secrets, [field.secretKey]: event.currentTarget.value })
          }
          leftSection={
            <Tooltip label={present ? '암호화 저장됨 (AES-256-GCM)' : '미설정'}>
              <IconLock size={18} color={present ? 'var(--mantine-color-teal-6)' : undefined} />
            </Tooltip>
          }
        />
      )
    }
  }
}

/** ensureOption guarantees the current value is selectable. */
function ensureOption(options: SelectOption[], current: string): SelectOption[] {
  if (current === '' || options.some((o) => o.value === current)) return options
  return [...options, { value: current, label: `${current} (저장된 값)` }]
}

function asString(value: unknown): string {
  if (value === null || value === undefined) return ''
  return typeof value === 'string' ? value : String(value)
}

function asNumber(value: unknown): number | '' {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value !== '' && Number.isFinite(Number(value))) return Number(value)
  return ''
}

function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string')
  return []
}

export function FieldHint({ children }: { children: React.ReactNode }) {
  return (
    <Text c="dimmed" size="sm" mt="xs">
      {children}
    </Text>
  )
}
