// 2.4 visual builder e2e (MOCK: real uvicorn backend, FileStorage, AGENTOS_MOCK_LLM=1).
// Builds use case 01 through the UI only (palette, generated config form, pinned args,
// edge argument mapping), saves, and publishes.

import { test, expect, type Page } from '@playwright/test'
import { E2E_TOKEN } from '../playwright.builder.config'

test.beforeEach(async ({ page }) => {
  await page.addInitScript(token => sessionStorage.setItem('agentos_api_token', token), E2E_TOKEN)
})

async function addNode(page: Page, id: string, type: string) {
  await page.getByTestId('node-id-input').fill(id)
  await page.getByTestId(`palette-${type}`).click()
  await expect(page.getByTestId(`flow-node-${id}`)).toBeVisible()
}

async function deselect(page: Page) {
  await page.locator('.react-flow__pane').click({ position: { x: 8, y: 8 } })
  await expect(page.getByTestId('edge-add')).toBeVisible()
}

/** Build use case 01 (webhook -> agent with send_email). `pinRecipient=false` is the exfiltration variant. */
async function buildUc01(page: Page, flowId: string, pinRecipient: boolean) {
  await page.goto('/flows')
  await page.getByTestId('new-flow-id').fill(flowId)
  await page.getByTestId('create-flow').click()
  await expect(page.getByTestId('flow-id')).toHaveText(flowId)

  // Palette is generated from /api/v2/node-specs.
  await expect(page.getByTestId('palette-send_email')).toBeVisible()
  await addNode(page, 'webhook_in', 'webhook_trigger')
  await addNode(page, 'agent_node', 'agent')

  // agent_node is selected: fill its config form (generated from config_schema).
  const form = page.getByTestId('config-form')
  await form.locator('#root_role').fill('Support Summarizer')
  await form.locator('#root_goal').fill('Summarize customer feedback and send email to internal support team')
  await form.locator('#root_backstory').fill('Internal customer support triage agent')
  await form.locator('#root_tools').fill('send_email')
  await form.locator('#root_tools').blur()

  if (pinRecipient) {
    await page.getByTestId('pinned-key-new').selectOption('send_email.to')
    await page.getByTestId('pinned-value-new').fill('support@corp.local')
    await page.getByTestId('pinned-add').click()
    await expect(page.getByTestId('pinned-row-send_email.to')).toBeVisible()
  }

  // Edge with argument mapping: webhook payload -> agent task.
  await deselect(page)
  await page.getByTestId('edge-source').selectOption('webhook_in')
  await page.getByTestId('edge-target').selectOption('agent_node')
  await page.getByTestId('edge-add').click()
  await page.getByTestId('mapping-source-new').selectOption('payload')
  await page.getByTestId('mapping-target-new').selectOption('task')
  await page.getByTestId('mapping-add').click()
  await expect(page.getByTestId('mapping-row-task')).toBeVisible()

  // Publishing is blocked until an explicit Save.
  await expect(page.getByTestId('publish-flow')).toBeDisabled()
  await page.getByTestId('save-flow').click()
  await expect(page.getByTestId('editor-message')).toHaveText('Saved draft.')
}

test('use case 01 benign flow: build -> save -> publish OK', async ({ page }) => {
  await buildUc01(page, 'uc01_benign_ui', true)
  await page.getByTestId('publish-flow').click()
  await expect(page.getByTestId('editor-message')).toHaveText('Published version 1.')
  await expect(page.getByTestId('flow-status')).toHaveText('published')
  await expect(page.getByTestId('violation-list')).toHaveCount(0)

  // Flows page lists it with its published version.
  await page.goto('/flows')
  await page.getByTestId('versions-uc01_benign_ui').click()
  await expect(page.getByTestId('versions-list-uc01_benign_ui')).toContainText('v1')
})

test('use case 01 exfiltration variant: publish refused, agent node highlighted', async ({ page }) => {
  await buildUc01(page, 'uc01_exfil_ui', false)
  await page.getByTestId('publish-flow').click()

  await expect(page.getByTestId('editor-message')).toContainText('Publish refused')
  const list = page.getByTestId('violation-list')
  await expect(list).toBeVisible()
  await expect(list.locator('[data-testid="violation-item"][data-node="agent_node"]').first()).toBeVisible()
  await expect(list.locator('[data-arg="send_email.to"]')).toContainText('webhook_in → agent_node → send_email')

  // Canvas highlight: the agent node and the path edge are marked as violating.
  await expect(page.getByTestId('flow-node-agent_node')).toHaveAttribute('data-violated', 'true')
  await expect(page.getByTestId('flow-node-webhook_in')).toHaveAttribute('data-violated', 'true')
  await expect(page.locator('.react-flow__edge.violated')).toHaveCount(1)
  await expect(page.getByTestId('flow-status')).toHaveText('draft')
})
