// Shared Korean-first formatting helpers.

const dateTime = new Intl.DateTimeFormat('ko-KR', {
  dateStyle: 'medium',
  timeStyle: 'short',
})

export function formatDateTime(value?: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '—'
  return dateTime.format(d)
}

export function formatRelative(value?: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '—'
  const diffMs = Date.now() - d.getTime()
  const abs = Math.abs(diffMs)
  const units: [number, string][] = [
    [1000 * 60 * 60 * 24 * 365, '년'],
    [1000 * 60 * 60 * 24 * 30, '개월'],
    [1000 * 60 * 60 * 24, '일'],
    [1000 * 60 * 60, '시간'],
    [1000 * 60, '분'],
  ]
  for (const [ms, label] of units) {
    if (abs >= ms) {
      const n = Math.floor(abs / ms)
      return diffMs >= 0 ? `${n}${label} 전` : `${n}${label} 후`
    }
  }
  return '방금'
}

export function formatNumber(value?: number | null): string {
  if (value === undefined || value === null) return '—'
  return value.toLocaleString('ko-KR')
}

export const riskLabels: Record<string, string> = {
  READ: '조회',
  WRITE: '작성',
  EXECUTE: '실행',
  ADMIN: '관리',
}

export const riskColors: Record<string, string> = {
  READ: 'teal',
  WRITE: 'yellow',
  EXECUTE: 'red',
  ADMIN: 'grape',
}

export const roleLabels: Record<string, string> = {
  'bitbucket-mcp-user': '조회 (user)',
  'bitbucket-mcp-writer': '작성 (writer)',
  'bitbucket-mcp-executor': '실행 (executor)',
  'bitbucket-mcp-admin': '관리 (admin)',
}

export const keyStatusLabels: Record<string, string> = {
  active: '정상',
  revoked: '폐기',
  expired: '만료',
  rotation_due: '회전 필요',
}

export const keyStatusColors: Record<string, string> = {
  active: 'teal',
  revoked: 'gray',
  expired: 'orange',
  rotation_due: 'yellow',
}

export const approvalStatusLabels: Record<string, string> = {
  pending: '대기',
  approved: '승인',
  rejected: '거절',
  expired: '만료',
  consumed: '사용 완료',
}

export const approvalStatusColors: Record<string, string> = {
  pending: 'yellow',
  approved: 'teal',
  rejected: 'red',
  expired: 'gray',
  consumed: 'blue',
}

export const auditCategoryLabels: Record<string, string> = {
  auth: '인증',
  tool: '도구 호출',
  write: '쓰기 작업',
  approval: '승인',
  admin: '관리',
  key: '키',
  error: '오류',
  ai: 'AI',
}

export const errorCodeLabels: Record<string, string> = {
  PERMISSION_DENIED: '권한 거부',
  PERMISSION_UNKNOWN: '권한 확인 불가',
  POLICY_DENIED: '정책 차단',
  BRANCH_RESTRICTED: '브랜치 제한',
  APPROVAL_REQUIRED: '승인 필요',
  APPROVAL_STALE: '승인 무효',
  APPROVAL_DENIED: '승인 거부',
  IDENTITY_UNMAPPED: '매핑 없음',
  TOOL_DISABLED: '도구 비활성',
  ROLE_DENIED: '역할 부족',
  SCOPE_DENIED: '스코프 부족',
  UNKNOWN_TOOL: '알 수 없는 도구',
  BAD_ARGUMENTS: '인자 오류',
  BITBUCKET_ERROR: 'Bitbucket 오류',
  INTERNAL_ERROR: '내부 오류',
  BAD_CREDENTIALS: '인증 실패',
  RATE_LIMITED: '요청 제한',
  IP_DENIED: '주소 차단',
}

/** resultLabel renders an audit outcome in Korean, falling back to the code. */
export function resultLabel(success: boolean, errorCode?: string): string {
  if (success) return '성공'
  if (!errorCode) return '실패'
  return errorCodeLabels[errorCode] ?? errorCode
}

export const healthLabels: Record<string, string> = {
  database: '데이터베이스',
  keycloak: 'Keycloak',
  bitbucket: 'Bitbucket REST',
  servicePat: '서비스 계정 PAT',
  permissionPlugin: '권한 해석기',
  ai: 'AI',
}
