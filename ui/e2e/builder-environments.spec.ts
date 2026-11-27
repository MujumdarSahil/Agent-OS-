// 4.3 versions and environments (MOCK, real backend): publish with a change note (auto-deploy to staging only for a
// new flow), the Versions tab (badges, Compare with the security-relevant changes first, Promote and Roll back with a
// confirmation showing the diff), the Run dialog environment choice with the STAGING banner and simulated sends, the
// Flows list "prod vN / staging vM" and the Triggers page environment column.

import { test, expect } from '@playwright/test'
import { loginViaUi } from './login'
import { E2E_TOKEN } from '../playwright.builder.config'

const AUTH = { Authorization: `Bearer ${E2E_TOKEN}` }

function flow(id: string, to: string) {
  return {
    id, name: id, entrypoint: 'trig',
    nodes: {
      trig: { id: 'trig', type: 'manual_trigger', config: {}, position: { x: 0, y: 0 } },
      send: { id: 'send', type: 'send_email', config: {}, pinned_args: { to, subject: 'Hello' }, position: { x: 260, y: 0 } },
    },
    edges: [{ source: 'trig', target: 'send', arg_mapping: { body: 'payload' } }],
    loops: {},
  }
}

test.beforeEach(async ({ page }) => {
  await loginViaUi(page)
})

test('Versions tab: publish note, compare, promote and roll back with the diff, staging run is simulated', async ({ page, request }) => {
  test.setTimeout(180000)
  const id = `env_e2e_${Date.now()}`
  expect((await request.post('/api/v2/flows', { data: flow(id, 'team@corp.local'), headers: AUTH })).status()).toBe(201)
  const v1 = await request.post(`/api/v2/flows/${id}/publish`, { headers: AUTH, data: { note: 'first version' } })
  expect(v1.status(), await v1.text()).toBe(200)
  expect((await v1.json()).deployments.staging.deployed).toBe(true)
  expect((await request.post(`/api/v2/flows/${id}/environments/production/promote`, { headers: AUTH, data: { version: 1 } })).status()).toBe(200)
  // v2 changes the pinned recipient (saved through the API, published through the UI with a note)
  expect((await request.put(`/api/v2/flows/${id}`, { data: flow(id, 'ops@corp.local'), headers: AUTH })).status()).toBe(200)

  await page.goto(`/flows/${id}`)
  await page.getByTestId('publish-flow').click()
  await expect(page.getByTestId('publish-confirm')).toBeDisabled() // the note is required
  await page.getByTestId('publish-note').fill('send to the ops mailbox')
  await expect(page.getByTestId('publish-note-count')).toHaveText('23/500')
  await page.getByTestId('publish-confirm').click()
  await expect(page.getByTestId('editor-message')).toContainText('Published version 2. Deployed to staging.')

  await page.getByTestId('versions-open').click()
  await expect(page.getByTestId('env-badge-staging')).toHaveText('staging: v2')
  await expect(page.getByTestId('env-badge-production')).toHaveText('production: v1')
  await expect(page.getByTestId('version-row-2')).toContainText('send to the ops mailbox')
  await expect(page.getByTestId('version-2-security')).toHaveText('passes')

  // compare: the recipient change is listed first, above the structural diff
  await page.getByTestId('select-version-1').check()
  await page.getByTestId('select-version-2').check()
  await page.getByTestId('compare-versions').click()
  await expect(page.getByTestId('sec-recipient_changed')).toContainText('team@corp.local -> ops@corp.local')

  // promote v2 to production: the confirmation shows the diff
  await page.getByTestId('promote-production-2').click()
  await expect(page.getByTestId('deploy-confirm-dialog').getByTestId('sec-recipient_changed')).toBeVisible()
  await page.getByTestId('deploy-note').fill('ops asked for it')
  await page.getByTestId('deploy-confirm').click()
  await expect(page.getByTestId('env-badge-production')).toHaveText('production: v2')

  // one-click rollback to v1 (confirmation with the diff back)
  await page.getByTestId('rollback-production-1').click()
  await expect(page.getByTestId('deploy-confirm-dialog')).toContainText('Roll back production to v1')
  await expect(page.getByTestId('deploy-confirm-dialog').getByTestId('sec-recipient_changed')).toContainText('ops@corp.local -> team@corp.local')
  await page.getByTestId('deploy-confirm').click()
  await expect(page.getByTestId('env-badge-production')).toHaveText('production: v1')
  await expect(page.getByTestId('versions-message')).toContainText('production: v2 → v1')

  // run staging: sends are simulated and the panel says so
  await page.getByTestId('run-open').click()
  await page.getByTestId('run-target').selectOption('staging')
  await expect(page.getByTestId('run-target-simulated')).toBeVisible()
  await page.getByTestId('run-input').fill('{"payload": "hello"}')
  await page.getByTestId('run-flow').click()
  await expect(page.getByTestId('run-env-banner')).toHaveText('STAGING', { timeout: 30000 })
  await expect(page.getByTestId('simulated-sends')).toContainText('staging: simulated', { timeout: 30000 })

  // Flows list and Triggers page
  await page.goto('/flows')
  await expect(page.getByTestId(`env-summary-${id}`)).toHaveText('prod v1 / staging v2')
  const hook = await request.post('/api/v2/webhooks', { headers: AUTH, data: { name: `hook_${id}`, flow_id: id, environment: 'staging' } })
  expect(hook.status()).toBe(201)
  const hookId = (await hook.json()).webhook_id
  await page.goto('/triggers')
  await expect(page.getByTestId(`env-${hookId}`)).toHaveValue('staging')
})
