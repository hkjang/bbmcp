// Drive every bbmcp screen in a real browser, fail on any console or page
// error, and save screenshots used by the documentation site.
//
//   node hack/screenshots.mjs [--base http://localhost:18411] [--out docs/screenshots]

import { chromium } from '../web/node_modules/playwright/index.mjs'
import { mkdir } from 'node:fs/promises'

const args = process.argv.slice(2)
const argOf = (name, fallback) => {
  const i = args.indexOf(`--${name}`)
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback
}

const BASE = argOf('base', 'http://localhost:18411')
const OUT = argOf('out', 'docs/screenshots')
const EXECUTABLE = process.env.CHROME_PATH || '/usr/bin/google-chrome'

const ADMIN = { username: process.env.BBMCP_ADMIN || 'admin', password: process.env.BBMCP_ADMIN_PASSWORD || 'bbmcpAdmin!2026' }
const USER = { username: 'hkjang', password: 'bbmcpUser!2026' }

// Benign console noise that does not indicate a broken screen.
const IGNORED = [
  /Download the React DevTools/i,
  /React Router Future Flag/i,
  /\[vite\]/i,
  /favicon/i,
  // The auth bootstrap probes /api/me before sign-in; a 401 there is the
  // expected answer, not a broken screen.
  /status of 401/i,
]

const problems = []

async function capture(page, name, { full = true } = {}) {
  // Let data land and animations settle before the shot.
  await page.waitForLoadState('networkidle').catch(() => {})
  await page.waitForTimeout(450)
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: full })
  console.log(`  저장: ${name}.png`)
}

function watch(page, label) {
  page.on('console', (msg) => {
    if (msg.type() !== 'error' && msg.type() !== 'warning') return
    const text = msg.text()
    if (IGNORED.some((re) => re.test(text))) return
    if (msg.type() === 'error') problems.push(`[${label}] console: ${text}`)
  })
  page.on('pageerror', (err) => problems.push(`[${label}] pageerror: ${err.message}`))
  page.on('requestfailed', (req) => {
    const failure = req.failure()?.errorText ?? ''
    if (/ERR_ABORTED/.test(failure)) return
    problems.push(`[${label}] request failed: ${req.url()} (${failure})`)
  })
  page.on('response', (res) => {
    if (res.status() >= 500) problems.push(`[${label}] HTTP ${res.status()} ${res.url()}`)
  })
}

async function signIn(page, who) {
  await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('아이디').fill(who.username)
  await page.locator('input[type="password"]').first().fill(who.password)
  await page.getByRole('button', { name: '로그인' }).click()
  await page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 20000 })
  await page.waitForLoadState('networkidle').catch(() => {})
}

/** Screens are verified by navigating to the route and asserting its heading. */
const adminScreens = [
  ['admin-dashboard', '/admin', '관리 대시보드'],
  ['admin-auth', '/admin/auth', '인증 (Keycloak)'],
  ['admin-bitbucket', '/admin/bitbucket', 'Bitbucket 연결'],
  ['admin-permission', '/admin/permission', '권한 해석기'],
  ['admin-identity', '/admin/identity', '식별 매핑'],
  ['admin-tools', '/admin/tools', 'MCP 도구'],
  ['admin-policy', '/admin/policy', '접근 정책'],
  ['admin-approvals', '/admin/approvals', '승인 관리'],
  ['admin-sessions', '/admin/sessions', 'MCP 세션'],
  ['admin-keys', '/admin/keys', '키 · 권한 체계'],
  ['admin-users', '/admin/users', '사용자'],
  ['admin-ai', '/admin/ai', 'AI 설정'],
  ['admin-security', '/admin/security', '보안'],
  ['admin-ui', '/admin/ui', '화면 설정'],
  ['admin-audit', '/admin/audit', '감사 로그'],
  ['admin-system', '/admin/system', '시스템'],
]

const userScreens = [
  ['user-overview', '/', '안녕하세요'],
  ['user-keys', '/me/keys', '내 API 키'],
  ['user-bitbucket', '/me/bitbucket', 'Bitbucket 토큰'],
  ['user-approvals', '/me/approvals', '내 승인 요청'],
  ['user-tools', '/me/tools', '사용 가능한 도구'],
  ['user-permissions', '/me/permissions', '내 유효 권한 조회'],
  ['user-ai', '/me/ai', 'AI 리뷰 보조'],
  ['user-audit', '/me/audit', '내 활동 기록'],
  ['user-settings', '/me/settings', '개인 설정'],
]

async function visit(page, [name, path, heading]) {
  await page.goto(`${BASE}${path}`, { waitUntil: 'domcontentloaded' })
  await page.getByRole('heading', { name: heading, exact: false }).first().waitFor({ timeout: 20000 })
  await capture(page, name)
}

async function main() {
  await mkdir(OUT, { recursive: true })
  const browser = await chromium.launch({
    executablePath: EXECUTABLE,
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  })

  // Login screen (shows the version badges).
  const anon = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' })
  const anonPage = await anon.newPage()
  watch(anonPage, 'login')
  await anonPage.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' })
  await anonPage.getByRole('button', { name: '로그인' }).waitFor()
  await capture(anonPage, 'login')
  await anon.close()

  // Admin console.
  const adminCtx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' })
  const adminPage = await adminCtx.newPage()
  watch(adminPage, 'admin')
  await signIn(adminPage, ADMIN)
  console.log('관리자 로그인 완료')
  for (const screen of adminScreens) await visit(adminPage, screen)

  // Profile menu, which carries the version information.
  await adminPage.goto(`${BASE}/admin`, { waitUntil: 'domcontentloaded' })
  await adminPage.getByRole('button', { name: '프로필 메뉴' }).click()
  await adminPage.locator('.mantine-Menu-dropdown').getByText('서비스 버전').waitFor()
  await capture(adminPage, 'profile-version', { full: false })
  await adminPage.keyboard.press('Escape')

  // Dark theme, to prove both schemes render.
  await adminPage.getByRole('button', { name: '테마 전환' }).click()
  await adminPage.waitForTimeout(400)
  await capture(adminPage, 'admin-dashboard-dark')
  await adminPage.getByRole('button', { name: '테마 전환' }).click()
  await adminCtx.close()

  // Personal pages as a non-admin user.
  const userCtx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR' })
  const userPage = await userCtx.newPage()
  watch(userPage, 'user')
  await signIn(userPage, USER)
  console.log('사용자 로그인 완료')
  for (const screen of userScreens) await visit(userPage, screen)

  // Exercise a select and the permission lookup, since those are the
  // interactions most likely to break.
  await userPage.goto(`${BASE}/me/permissions`, { waitUntil: 'domcontentloaded' })
  await userPage.getByLabel('프로젝트 키').fill('AI')
  await userPage.getByLabel('저장소 슬러그 (선택)').fill('text2sql')
  await userPage.getByRole('button', { name: '조회' }).click()
  await userPage.getByText('판정 결과').waitFor({ timeout: 20000 })
  await capture(userPage, 'user-permissions-result')

  await userPage.goto(`${BASE}/me/keys`, { waitUntil: 'domcontentloaded' })
  await userPage.getByRole('button', { name: '키 발급' }).click()
  await userPage.getByLabel('키 이름').fill('MCP 클라이언트')
  await userPage.getByPlaceholder('역할을 선택하십시오').click()
  await userPage.getByRole('option', { name: /reader/ }).click()
  await userPage.waitForTimeout(250)
  await capture(userPage, 'user-keys-create', { full: false })
  await userPage.getByRole('button', { name: '발급', exact: true }).click()
  await userPage.getByText('이 값은 지금 한 번만 표시됩니다').waitFor({ timeout: 20000 })
  await capture(userPage, 'user-keys-issued', { full: false })
  await userPage.getByRole('button', { name: '확인', exact: true }).click()
  await userCtx.close()

  // Mobile layout.
  const mobileCtx = await browser.newContext({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 2,
    isMobile: true,
    hasTouch: true,
    locale: 'ko-KR',
  })
  const mobilePage = await mobileCtx.newPage()
  watch(mobilePage, 'mobile')
  await mobilePage.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' })
  await mobilePage.getByRole('button', { name: '로그인' }).waitFor()
  await capture(mobilePage, 'mobile-login')
  await signIn(mobilePage, USER)
  await capture(mobilePage, 'mobile-overview')
  await mobilePage.getByRole('button', { name: '메뉴 열기' }).click()
  await mobilePage.waitForTimeout(400)
  await capture(mobilePage, 'mobile-nav', { full: false })
  await mobileCtx.close()

  await browser.close()

  if (problems.length > 0) {
    console.error(`\n화면 오류 ${problems.length}건:`)
    for (const p of problems) console.error(`  - ${p}`)
    process.exit(1)
  }
  console.log('\n모든 화면이 오류 없이 렌더링되었습니다.')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
