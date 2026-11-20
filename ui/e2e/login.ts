// 3.4: builder e2e specs log in through the login page. The e2e admin is created once through the first-run
// setup endpoint with the throwaway e2e local token (fixed, non-secret, only for the temp e2e backend).

import { expect, request, type Page } from '@playwright/test'
import { E2E_TOKEN } from '../playwright.builder.config'

export const E2E_ADMIN = { username: 'e2e-admin', password: 'e2e-orchard-lantern-42' }
const BASE = `http://localhost:${Number(process.env.AGENTOS_E2E_UI_PORT || 5174)}`
let ensured = false

async function ensureAdmin(): Promise<void> {
  if (ensured) return
  const ctx = await request.newContext({ baseURL: BASE }) // own cookie jar: the page still logs in via the UI
  const r = await ctx.post('/api/v2/auth/setup', {
    data: { username: E2E_ADMIN.username, password: E2E_ADMIN.password },
    headers: { Authorization: `Bearer ${E2E_TOKEN}` },
  })
  expect([200, 409]).toContain(r.status()) // 409: an earlier spec already created it
  await ctx.dispose()
  ensured = true
}

export async function loginViaUi(page: Page): Promise<void> {
  await ensureAdmin()
  await page.goto('/')
  await expect(page.getByTestId('login-page')).toBeVisible()
  await page.fill('#auth-username', E2E_ADMIN.username)
  await page.fill('#auth-password', E2E_ADMIN.password)
  await page.click('#login-submit')
  await expect(page.getByTestId('sidebar-nav')).toBeVisible()
}
