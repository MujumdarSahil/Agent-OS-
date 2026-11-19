// 3.2 e2e (MOCK: real uvicorn backend from playwright.builder.config.ts, per-run temp home, no keys).
// MOCK mode makes no real model calls, so there is no spend here: the cost maths, ledger, run limits and budget
// enforcement are covered by agentos/tests/test_usage_3_2.py. This spec covers the UI wiring:
// - Settings: edit budgets and run limits -> saved through PUT /api/v2/budgets and recorded in the audit log;
// - Overview: the Spend card appears once a budget is set, with its budget bar;
// - Watch > Metrics: the page, its cards and the budget bars.

import { test, expect } from '@playwright/test'
import { E2E_TOKEN } from '../playwright.builder.config'

const AUTH = { Authorization: `Bearer ${E2E_TOKEN}` }

test.beforeEach(async ({ page }) => {
  await page.addInitScript(token => sessionStorage.setItem('agentos_api_token', token), E2E_TOKEN)
})

test('budgets editor saves (audited); Spend card and Metrics show the budget', async ({ page, request }) => {
  await page.goto('/settings')
  const editor = page.getByTestId('budgets-editor')
  await expect(editor).toBeVisible()
  await editor.getByTestId('budget-global-daily').fill('5')
  await editor.getByTestId('budget-global-monthly').fill('50')
  await editor.getByTestId('limit-max-calls').fill('20')
  await editor.getByTestId('budget-provider-new').fill('groq_gpt_oss_20b')
  await editor.getByRole('button', { name: 'Add' }).nth(1).click()
  await editor.getByTestId('budgets-save').click()
  await expect(editor.getByTestId('budgets-message')).toHaveText('Saved (recorded in the audit log).')

  const b = await (await request.get('/api/v2/budgets', { headers: AUTH })).json()
  expect(b.settings.budgets.global_daily).toBe(5)
  expect(b.settings.run_limits.max_model_calls).toBe(20)
  expect(b.settings.budgets.provider_monthly.groq_gpt_oss_20b).toBe(10)
  const audit = await (await request.get('/api/v2/audit', { headers: AUTH, params: { action: 'usage.settings.update' } })).json()
  expect(audit.entries.length).toBeGreaterThan(0)
  expect(audit.entries[0].details.new.global_daily).toBe(5)

  await page.goto('/')
  const card = page.getByTestId('spend-card')
  await expect(card).toBeVisible()
  await expect(card.getByTestId('spend-today')).toContainText('of $5.00')
  await expect(card.locator('[data-testid="budget-bar"][data-name="global_daily"]')).toHaveAttribute('data-pct', '0')

  await page.goto('/metrics')
  await expect(page.getByTestId('metrics-page')).toBeVisible()
  await expect(page.getByTestId('metrics-total-calls')).toContainText('0')
  await expect(page.locator('[data-testid="metrics-budgets"] [data-testid="budget-bar"]')).toHaveCount(3)
  await page.getByTestId('metrics-group').selectOption('flow')
  await expect(page.getByTestId('metrics-by-group')).toContainText('Spend by flow')
})
