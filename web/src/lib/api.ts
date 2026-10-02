// Thin typed wrapper over the bbmcp HTTP API.

export class ApiError extends Error {
  status: number
  code?: string

  constructor(status: number, message: string, code?: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(init?.headers ?? {}),
    },
    ...init,
  })

  if (res.status === 204) return undefined as T

  const text = await res.text()
  let body: unknown = undefined
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = { error: text }
    }
  }

  if (!res.ok) {
    const envelope = body as { error?: string; code?: string } | undefined
    throw new ApiError(res.status, envelope?.error ?? `요청이 실패했습니다 (${res.status})`, envelope?.code)
  }
  return body as T
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: body === undefined ? undefined : JSON.stringify(body) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PATCH', body: body === undefined ? undefined : JSON.stringify(body) }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}

// ---------- shared types ----------

export interface VersionInfo {
  name: string
  version: string
  commit: string
  buildDate: string
}

export interface UISettings {
  serviceName: string
  tagline: string
  primaryColor: string
  fontScale: number
  defaultTheme: string
  locale: string
  loginNotice: string
}

export interface PublicConfig {
  ui: UISettings
  version: VersionInfo
  auth: {
    keycloakEnabled: boolean
    silentSso: boolean
    startUrl: string
    silentUrl: string
    localLogin: boolean
  }
}

export interface User {
  id: number
  username: string
  email: string
  displayName: string
  keycloakSub?: string
  isServiceAdmin: boolean
  roles: string[]
  active: boolean
  source: string
  createdAt: string
  lastLoginAt?: string
  hasPassword: boolean
}

export interface Mapping {
  id: number
  keycloakSub: string
  keycloakUsername: string
  bitbucketUserId: number
  bitbucketUsername: string
  bitbucketEmail: string
  bitbucketDisplay: string
  mappingType: string
  active: boolean
  lastError?: string
  mappedAt: string
  verifiedAt?: string
}

export interface MappingError {
  id: number
  keycloakSub: string
  keycloakUsername: string
  reason: string
  occurrences: number
  firstSeenAt: string
  occurredAt: string
}

export interface Prefs {
  preferUserPat: boolean
  theme: string
  fontScale: number
  locale: string
}

export interface Me {
  user: User
  bitbucket: Mapping | null
  scopes: string[]
  authMode: string
  isServiceAdmin: boolean
  prefs: Prefs
  ui: UISettings
  version: VersionInfo
  allowUserPatMode: boolean
  defaultAuthMode: string
}

export interface ApiKey {
  id: string
  userId: number
  username?: string
  name: string
  prefix: string
  role: string
  scopes: string[]
  rotatedFrom?: string
  rotationDueAt?: string
  expiresAt?: string
  lastUsedAt?: string
  createdAt: string
  revokedAt?: string
  revokedReason?: string
  status: 'active' | 'revoked' | 'expired' | 'rotation_due'
}

export interface IssuedKey {
  key: ApiKey
  secret: string
}

export interface KeyRole {
  name: string
  description: string
  scopes: string[]
  builtin: boolean
  updatedAt?: string
}

export interface ScopeInfo {
  name: string
  label: string
  description: string
  risk: string
}

export interface ToolRecord {
  name: string
  title: string
  description: string
  group: string
  risk: 'READ' | 'WRITE' | 'EXECUTE' | 'ADMIN'
  requiredPermission: string
  scope: string
  tier: number
  highLevel: boolean
  enabled: boolean
  requiresApproval: boolean
  minRole: string
  inputSchema?: Record<string, unknown>
  updatedAt?: string
}

export interface PolicyRule {
  id: number
  kind: 'project' | 'repository' | 'branch'
  pattern: string
  effect: 'allow' | 'deny'
  riskCap?: string
  priority: number
  note: string
  createdAt?: string
}

export interface ApprovalRequest {
  id: string
  keycloakSub: string
  username: string
  toolName: string
  argumentsHash: string
  arguments?: Record<string, unknown>
  resource: string
  prVersion?: number
  status: string
  decidedBy?: string
  decisionNote?: string
  createdAt: string
  expiresAt: string
  approvedAt?: string
  consumedAt?: string
}

export interface AuditEntry {
  id: number
  occurredAt: string
  category: string
  action: string
  keycloakUsername?: string
  bitbucketUsername?: string
  serviceAccount?: string
  mcpClient?: string
  authMode?: string
  toolName?: string
  projectKey?: string
  repository?: string
  pullRequest?: number
  approvalId?: string
  success: boolean
  errorCode?: string
  message?: string
  latencyMs: number
  ip?: string
  detail?: Record<string, unknown>
}

export interface Paged<T> {
  values: T[]
  total: number
}

export interface HealthComponent {
  ok: boolean
  detail: string
  skipped?: boolean
}

export interface Dashboard {
  version: VersionInfo
  counts: Record<string, number>
  toolCalls24h: number
  failures24h: number
  topTools?: { tool: string; calls: number }[]
  recentAudit?: AuditEntry[]
  health: Record<string, HealthComponent>
}

export interface SettingsEnvelope<T> {
  value: T
  secrets?: Record<string, boolean>
  limits?: Record<string, number>
}

export interface KeycloakSettings {
  enabled: boolean
  issuer: string
  clientId: string
  redirectUrl: string
  postLogoutUrl: string
  scopes: string[]
  usernameClaim: string
  roleClaimPath: string
  adminRole: string
  silentSso: boolean
  silentSsoMaxAgeSec: number
  autoProvision: boolean
  insecureSkipTls: boolean
  requireRole: string
}

export interface BitbucketSettings {
  baseUrl: string
  restPrefix: string
  serviceUsername: string
  timeoutSec: number
  insecureSkipTls: boolean
  defaultAuthMode: string
  allowUserPatMode: boolean
  pageSize: number
  attributionNote: boolean
}

export interface PermissionSettings {
  mode: string
  pluginBaseUrl: string
  cacheTtlSec: number
  failClosed: boolean
  timeoutSec: number
}

export interface AISettings {
  enabled: boolean
  provider: string
  baseUrl: string
  model: string
  maxTokens: number
  temperature: number
  topP: number
  streaming: boolean
  systemPrompt: string
  timeoutSec: number
  contextLimit: number
}

export interface SecuritySettings {
  ipAllowlist: string[]
  rateLimitPerMin: number
  rateLimitBurst: number
  sessionTtlMinutes: number
  approvalTtlMinutes: number
  auditRetainDays: number
  trustProxyHeaders: boolean
}

export interface KeyPolicySettings {
  defaultRole: string
  rotationDays: number
  keyTtlDays: number
  maxKeysPerUser: number
  allowSelfCreate: boolean
  graceHours: number
}

export interface MCPSettings {
  serverName: string
  resourceUrl: string
  requireApprovalForWrite: boolean
  maxResponseKb: number
  exposeHighLevelTools: boolean
  denyToolWhenPolicyUnknown: boolean
}

export interface PermissionDecision {
  username: string
  project?: string
  repository?: string
  effective: string
  read: boolean
  write: boolean
  admin: boolean
  source: string
  note?: string
}

export interface MCPSession {
  id: string
  username: string
  client: string
  authMode: string
  ip: string
  createdAt: string
  lastSeenAt: string
  closedAt?: string | null
}

export interface SystemInfo {
  version: VersionInfo
  health: Record<string, HealthComponent>
  database: { version: string; name: string; size: string }
  migrations?: { version: string; appliedAt: string }[]
  pool: Record<string, number>
}
