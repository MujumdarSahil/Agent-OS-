// 4.2 "Tests" tab (MOCK: scripted test model, fake senders, fixture HTTP responses; nothing is sent).
// Seeds the use case 07 support desk flow and two cases through the API, then drives the UI: Run all, results with
// the regression summary and diffs, Open run, Save as test case from the run panel, Add security tests, the publish
// gate in block mode, and the flow list badge.

import { test, expect, type APIRequestContext } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { loginViaUi } from './login'
import { E2E_TOKEN } from '../playwright.builder.config'

const UC07 = path.resolve(process.cwd(), '..', 'examples', 'usecases', '07-support-desk-copilot')
const AUTH = { Authorization: `Bearer ${E2E_TOKEN}` }
const FX = [{ kind: 'http', method: 'GET', url: 'https://jsonplaceholder.typicode.com/users/1', body: { id: 1 } }]

test.beforeEach(async ({ page }) => {
  await loginViaUi(page)
})

async function seed(request: APIRequestContext, id: string) {
  const flow = { ...JSON.parse(fs.readFileSync(path.join(UC07, 'flows', 'support_desk.flow.json'), 'utf8')), id, name: id }
  const tickets = JSON.parse(fs.readFileSync(path.join(UC07, 'inputs', 'tickets.json'), 'utf8'))
  expect((await request.post('/api/v2/flows', { data: flow, headers: AUTH })).status()).toBe(201)
  const cases = [
    { name: 'normal goes to the queue', tags: ['smoke'], input: tickets.normal, fixtures: FX,
      mock_responses: { triage: 'NORMAL. Billing address question.' },
      expectations: [{ kind: 'status', equals: 'succeeded' },
        { kind: 'sink', target: 'send_email', node: 'queue_note', op: 'called_with', arg: 'to', value: 'support-queue@corp.local' }] },
    { name: 'urgent waits for approval', tags: ['smoke'], input: tickets.urgent, fixtures: FX,
      mock_responses: { triage: 'URGENT. Checkout is down.' },
      expectations: [{ kind: 'status', equals: 'waiting_for_approval' }, { kind: 'approval_reached', node: 'oncall_approval' }] },
  ]
  const ids: string[] = []
  for (const c of cases) {
    const r = await request.post(`/api/v2/flows/${id}/tests`, { data: c, headers: AUTH })
    expect(r.status(), await r.text()).toBe(201)
    ids.push((await r.json()).id)
  }
  return { ids, cases }
}

test('Tests tab: run all, regression, diffs, save from run, security tests, publish gate', async ({ page, request }) => {
  test.setTimeout(240000)
  const id = `tests_${Date.now()}`
  const { ids, cases } = await seed(request, id)

  await page.goto(`/flows/${id}`)
  await page.getByTestId('tests-open').click()
  await expect(page.getByTestId('tests-row')).toHaveCount(2)

  // Run all (draft, MOCK)
  await page.getByTestId('tests-run-all').click()
  await expect(page.getByTestId('tests-counts')).toHaveAttribute('data-pass', '2', { timeout: 90000 })
  await expect(page.getByTestId('regression-summary')).toContainText('First run')

  // A change that breaks a case: the regression summary and the diff show it
  const broken = { ...cases[0], expectations: [{ kind: 'status', equals: 'failed' }] }
  expect((await request.put(`/api/v2/flows/${id}/tests/${ids[0]}`, { data: broken, headers: AUTH })).status()).toBe(200)
  await page.getByTestId('tests-run-all').click()
  await expect(page.getByTestId('reg-newly-failing')).toContainText('normal goes to the queue', { timeout: 90000 })
  await expect(page.getByTestId('tests-diff').first()).toContainText('expected failed, got succeeded')

  // Open the test run in the run panel, then "Save as test case" opens a suggested case in the editor
  await page.getByTestId('tests-result').first().getByTestId('tests-open-run').click()
  await expect(page.getByTestId('save-as-test')).toBeVisible()
  await page.getByTestId('save-as-test').click()
  await expect(page.getByTestId('tests-editor')).toBeVisible()
  await expect(page.getByTestId('tests-name')).toHaveValue(/^From run test_/)
  await expect(page.getByTestId('tests-expectation').first()).toHaveAttribute('data-kind', 'status')
  await page.getByTestId('tests-save').click()
  await expect(page.getByTestId('tests-info')).toHaveText('Test case saved.')
  await expect(page.getByTestId('tests-row')).toHaveCount(3)

  // Publish gate in block mode: the failing case refuses publish
  await page.getByTestId('tests-tab-gate').click()
  await page.getByTestId('tests-gate-mode').selectOption('block')
  await page.getByTestId('tests-gate-save').click()
  await expect(page.getByTestId('tests-info')).toHaveText('Publish gate saved.')
  await page.getByTestId('publish-flow').click()
  await expect(page.getByText(/Publish refused: tests failed/)).toBeVisible({ timeout: 120000 })
  await expect(page.getByTestId('flow-status')).toHaveText('draft')

  // Add security tests (generated from the 4.1 attack families that fit this flow)
  await page.getByTestId('tests-tab-cases').click()
  await page.getByTestId('tests-add-security').click()
  await expect(page.getByTestId('tests-info')).toContainText('security tests')
  expect(await page.getByTestId('tests-row').count()).toBeGreaterThan(10)

  // The flow list shows the last pass rate
  await page.goto('/flows')
  await expect(page.getByTestId(`tests-badge-${id}`)).toContainText('% pass')
})
