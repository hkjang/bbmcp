// Rasterise the bbmcp logo into the PNG sizes browsers and app stores expect.
// Run after changing web/public/favicon.svg.
//
//   node hack/icons.mjs

import { chromium } from '../web/node_modules/playwright/index.mjs'
import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises'

const SVG = 'web/public/favicon.svg'
const TARGETS = [
  { file: 'web/public/icon-32.png', size: 32 },
  { file: 'web/public/icon-180.png', size: 180 },
  { file: 'web/public/icon-192.png', size: 192 },
  { file: 'web/public/icon-512.png', size: 512 },
  { file: 'docs/assets/logo-512.png', size: 512 },
  { file: 'docs/assets/logo-192.png', size: 192 },
]

const svg = await readFile(SVG, 'utf8')
const browser = await chromium.launch({
  executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome',
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
})

await mkdir('docs/assets', { recursive: true })

for (const target of TARGETS) {
  const page = await browser.newPage({
    viewport: { width: target.size, height: target.size },
    deviceScaleFactor: 1,
  })
  await page.setContent(
    `<!doctype html><html><head><style>
       html,body{margin:0;padding:0;background:transparent}
       svg{display:block;width:${target.size}px;height:${target.size}px}
     </style></head><body>${svg.replace(/<\?xml[^>]*\?>/, '')}</body></html>`,
    { waitUntil: 'load' },
  )
  await page.screenshot({ path: target.file, omitBackground: true })
  await page.close()
  console.log(`생성: ${target.file} (${target.size}px)`)
}

await browser.close()

// A wide social preview card for link unfurls and search results.
const social = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0b1b33"/><stop offset="60%" stop-color="#0f2a52"/><stop offset="100%" stop-color="#143a73"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <g transform="translate(96,150) scale(2.6)">${svg.replace(/<\?xml[^>]*\?>/, '').replace(/<svg[^>]*>/, '').replace('</svg>', '')}</g>
  <text x="300" y="268" font-family="Pretendard, 'Noto Sans KR', sans-serif" font-size="78" font-weight="800" fill="#ffffff">bbmcp</text>
  <text x="300" y="330" font-family="Pretendard, 'Noto Sans KR', sans-serif" font-size="36" fill="#9dc0ff">Bitbucket MCP 게이트웨이</text>
  <text x="300" y="398" font-family="Pretendard, 'Noto Sans KR', sans-serif" font-size="28" fill="#cfe0ff">Keycloak SSO · 사용자 권한 검증 · 승인 · 감사</text>
  <text x="96" y="560" font-family="Pretendard, 'Noto Sans KR', sans-serif" font-size="25" fill="#7aa3e8">오프라인망 단일 도커 이미지 배포 · Go + React</text>
</svg>`
await writeFile('docs/assets/social-card.svg', social)

const browser2 = await chromium.launch({
  executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome',
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
})
const page = await browser2.newPage({ viewport: { width: 1200, height: 630 } })
await page.setContent(
  `<!doctype html><html><head><style>html,body{margin:0;padding:0}svg{display:block}</style></head><body>${social}</body></html>`,
  { waitUntil: 'load' },
)
await page.screenshot({ path: 'docs/assets/social-card.png' })
await browser2.close()
console.log('생성: docs/assets/social-card.png (1200x630)')

await copyFile('web/public/favicon.svg', 'docs/assets/favicon.svg')
console.log('복사: docs/assets/favicon.svg')
