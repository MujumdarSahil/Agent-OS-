// 3.1 e2e (MOCK: real uvicorn backend from playwright.builder.config.ts, per-run temp home, no keys).
// - Agents: the tool picker lists only tools the server resolves (no file_read/file_write); an agent with the
//   calculator tool is saved.
// - Govern > Audit log: entries for a save, a published flow and a refused publish; filter by outcome; detail
//   drawer shows details as plain text; chain badge "Verified"; Overview footer "Audit chain verified".

import { test, expect } from '@playwright/test'
import { loginViaUi } from './login'
import { E2E_TOKEN } from '../playwright.builder.config'

const AUTH = { Authorization: `Bearer ${E2E_TOKEN}` }

test.beforeEach(async ({ page }) => {
  await loginViaUi(page) // 3.4: log in through the login page
})

test('agent tool picker shows only server tools; an agent with calculator is saved', async ({ page, request }) => {
  const server = (await (await request.get('/api/v2/agents/tool-options', { headers: AUTH })).json()) as { name: string }[]
  const serverNames = server.map(t => t.name)
  expect(serverNames).toContain('calculator')
  await page.goto('/agents')
  await page.click('#create-agent-btn')
  const offered = await page.locator('[data-testid^="tool-option-"]').evaluateAll(
    els => els.map(e => (e.getAttribute('data-testid') || '').replace('tool-option-', '')))
  expect(offered.length).toBeGreaterThan(0)
  for (const name of offered) expect(serverNames).toContain(name)  // nothing the server would refuse
  expect(offered).not.toContain('file_read')
  expect(offered).not.toContain('file_write')
  await page.fill('#agent-name', 'calc_agent_e2e')
  await page.fill('#agent-role', 'Calculator')
  await page.fill('#agent-goal', 'Add numbers')
  await page.fill('#agent-backstory', 'Uses the safe calculator tool')
  await page.getByTestId('tool-option-calculator').click()
  await page.click('#agent-save-btn')
  await expect(page.locator('text=calc_agent_e2e')).toBeVisible()
  const saved = await (await request.get('/api/v2/agents/calc_agent_e2e', { headers: AUTH })).json()
  expect(saved.tools ?? saved.tool_refs).toContain('calculator')
})

test('audit log page: entries, filter, plain-text drawer, verified badge, Overview footer', async ({ page, request }) => {
  const ok = {
    id: 'audit_ok_e2e', name: 'audit ok', entrypoint: 'trig', loops: {},
    nodes: { trig: { id: 'trig', type: 'manual_trigger', config: {}, pinned_args: {} },
             send: { id: 'send', type: 'send_email', config: {}, pinned_args: { to: 'support@corp.local', subject: 'S' } } },
    edges: [{ source: 'trig', target: 'send', arg_mapping: { body: 'payload' } }],
  }
  const unsafe = {
    id: 'audit_refused_e2e', name: 'audit refused', entrypoint: 'trig', loops: {},
    nodes: { trig: { id: 'trig', type: 'webhook_trigger', config: {}, pinned_args: {} },
             send: { id: 'send', type: 'send_email', config: {}, pinned_args: {} } },
    edges: [{ source: 'trig', target: 'send', arg_mapping: { to: 'payload', body: 'payload' } }],
  }
  expect((await request.post('/api/v2/flows', { data: ok, headers: AUTH })).status()).toBe(201)
  expect((await request.post('/api/v2/flows/audit_ok_e2e/publish', { headers: AUTH })).status()).toBe(200)
  expect((await request.post('/api/v2/flows', { data: unsafe, headers: AUTH })).status()).toBe(201)
  expect((await request.post('/api/v2/flows/audit_refused_e2e/publish', { headers: AUTH })).status()).toBe(400)

  await page.goto('/audit')
  await expect(page.getByTestId('audit-chain-badge')).toHaveAttribute('data-status', 'ok')
  await expect(page.getByTestId('audit-chain-badge')).toContainText('Verified ·')
  await expect(page.locator('[data-testid="audit-row"][data-action="flow.publish"][data-outcome="ok"]').first()).toBeVisible()
  await page.getByTestId('audit-filter-outcome').selectOption('refused')
  const refused = page.locator('[data-testid="audit-row"][data-action="flow.publish"]')
  await expect(refused.first()).toBeVisible()
  await expect(page.locator('[data-testid="audit-row"][data-outcome="ok"]')).toHaveCount(0)
  await refused.first().click()
  const details = page.getByTestId('audit-details')
  await expect(details).toContainText('"violated_rules"')
  await expect(details).toContainText('send.to')
  expect(await details.evaluate(el => el.children.length)).toBe(0)  // plain text, no HTML elements
  await page.getByTestId('audit-drawer-close').click()

  const download = page.waitForEvent('download')
  await page.getByTestId('audit-export').click()
  expect((await download).suggestedFilename()).toBe('agentos-audit.jsonl')

  await page.goto('/')
  await expect(page.getByTestId('overview-audit-status')).toHaveText('Audit chain verified')
})
