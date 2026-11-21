// 2.5a e2e (MOCK: real uvicorn backend from playwright.builder.config.ts, which runs in a per-run temp home
// with no .env and no provider keys). A real local stdio MCP fixture server (good_tools.py) is enabled,
// discovered, reviewed and approved through the UI; the approved tool then appears in the agent picker.
// The server's child process is stopped by AgentOS on shutdown (Job Object / process group).

import { test, expect } from '@playwright/test'
import path from 'node:path'
import { loginViaUi } from './login'
import { E2E_TOKEN } from '../playwright.builder.config'

const AUTH = { Authorization: `Bearer ${E2E_TOKEN}` }
const python = process.env.AGENTOS_E2E_PYTHON ||
  (process.platform === 'win32' ? path.resolve(process.cwd(), '..', 'venv', 'Scripts', 'python.exe') : 'python')
const FIXTURE = path.resolve(process.cwd(), '..', 'agentos', 'tests', 'fixtures', 'mcp', 'good_tools.py')

test.beforeEach(async ({ page }) => {
  await loginViaUi(page) // 3.4: log in through the login page
})

test('MCP server: enable shows the command, discover, review and approve, then the agent picker offers it', async ({ page, request }) => {
  const created = await request.post('/api/v2/mcp-servers', {
    data: { name: 'good', transport: 'stdio', command: python, args: [FIXTURE], env: { NOTES_MODE: 'demo' }, secret_env: {} },
    headers: AUTH,
  })
  expect(created.status(), await created.text()).toBe(200)

  await page.goto('/mcp-servers')
  const card = page.getByTestId('mcp-server-good')
  await expect(card.getByTestId('mcp-status')).toHaveText('Disabled')
  await expect(card.getByTestId('mcp-env-names')).toHaveText('env: NOTES_MODE')
  await expect(card).not.toContainText('demo')

  await card.getByTestId('mcp-enable').click()
  await expect(card.getByTestId('mcp-command-line')).toContainText('good_tools.py')
  await expect(card.getByTestId('mcp-preview-env')).not.toContainText('AGENTOS_')
  await card.getByTestId('mcp-enable-confirm').click()
  await expect(card.getByTestId('mcp-status')).toHaveText('Enabled')

  await card.getByTestId('mcp-discover').click()
  const row = card.getByTestId('mcp-tool-read_note')
  await expect(row.getByTestId('mcp-tool-status')).toHaveText('unreviewed', { timeout: 30000 })

  // an unreviewed tool cannot be attached to an agent
  const refused = await request.post('/api/v2/agents', {
    data: { name: 'mcp_agent_refused', role: 'r', goal: 'g', backstory: 'b', tools: ['mcp.good.read_note'] }, headers: AUTH,
  })
  expect(refused.status()).toBe(400)

  await row.getByTestId('mcp-review').click()
  const review = page.getByTestId('review-read_note')
  await expect(review.getByTestId('untrusted-text').first()).toHaveText('Read the latest note.')
  await review.getByTestId('review-description').fill('Read the team notes.')
  await review.getByTestId('review-approve').click()
  await expect(card.getByTestId('mcp-tool-read_note').getByTestId('mcp-tool-status')).toHaveText('approved')

  await page.goto('/agents')
  await page.click('#create-agent-btn')
  await expect(page.getByTestId('tool-option-mcp.good.read_note')).toBeVisible()
  await expect(page.getByTestId('tool-option-mcp.good.save_draft')).toHaveCount(0) // not approved: not offered
  await page.fill('#agent-name', 'mcp_notes_agent')
  await page.fill('#agent-role', 'Notes reader')
  await page.fill('#agent-goal', 'Read notes')
  await page.fill('#agent-backstory', 'Reads notes through MCP')
  await page.getByTestId('tool-option-mcp.good.read_note').click()
  await page.click('#agent-save-btn')
  await expect(page.locator('text=mcp_notes_agent')).toBeVisible()

  // stop the server process now (the e2e server stops the rest on shutdown)
  const off = await request.post('/api/v2/mcp-servers/good/enable', { data: { enabled: false }, headers: AUTH })
  expect(off.status()).toBe(200)
})
