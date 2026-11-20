// 2.4/2.4b visual builder e2e (MOCK: real uvicorn backend, FileStorage, AGENTOS_MOCK_LLM=1).
// Builds use case 01 through the UI only: drag nodes from the palette onto the canvas, rename the
// auto ids, fill the generated config form, pin args, connect by dragging between handles (the
// argument mapping is auto-suggested), save, publish.

import { test, expect, type Page } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { loginViaUi } from './login'

const UC05 = path.resolve(process.cwd(), '..', 'examples', 'usecases', '05-visual-builder', 'flows')

test.beforeEach(async ({ page }) => {
  await loginViaUi(page) // 3.4: log in through the login page
})

export async function dropNode(page: Page, type: string, x: number, y: number) {
  await page.getByTestId(`palette-${type}`).dragTo(page.getByTestId('flow-canvas'), { targetPosition: { x, y } })
}

export async function renameTo(page: Page, autoId: string, newId: string) {
  await expect(page.getByTestId(`flow-node-${autoId}`)).toBeVisible()
  await page.getByTestId('node-rename-input').fill(newId)
  await page.getByTestId('node-rename-apply').click()
  await expect(page.getByTestId(`flow-node-${newId}`)).toBeVisible()
}

export async function connectByDrag(page: Page, from: string, to: string) {
  const src = page.locator(`[data-testid="flow-node-${from}"] .react-flow__handle-right`).first()
  const dst = page.locator(`[data-testid="flow-node-${to}"] .react-flow__handle-left`)
  const a = (await src.boundingBox())!
  const b = (await dst.boundingBox())!
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2)
  await page.mouse.down()
  await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 12 })
  await page.mouse.up()
}

/** Click an edge (its wide invisible interaction path) to open the mapping editor. */
export async function clickEdge(page: Page, from: string, to: string) {
  await page.locator(`[data-testid="rf__edge-${from}->${to}"] .react-flow__edge-interaction`).click({ force: true })
}

/** Build use case 01 (webhook -> agent with send_email). `pinRecipient=false` is the exfiltration variant. */
async function buildUc01(page: Page, flowId: string, pinRecipient: boolean) {
  await page.goto('/flows')
  await page.getByTestId('new-flow-id').fill(flowId)
  await page.getByTestId('create-flow').click()
  await expect(page.getByTestId('flow-id')).toHaveText(flowId)

  // Palette is generated from /api/v2/node-specs; nodes are dragged onto the canvas.
  await expect(page.getByTestId('palette-send_email')).toBeVisible()
  await dropNode(page, 'webhook_trigger', 70, 120)
  await renameTo(page, 'webhook_trigger_1', 'webhook_in')
  await dropNode(page, 'agent', 330, 300)
  await renameTo(page, 'agent_1', 'agent_node')

  // agent_node's drawer is open: fill its config form (generated from config_schema).
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

  // Connect by dragging webhook_in's output handle onto agent_node: mapping payload -> task is suggested.
  await connectByDrag(page, 'webhook_in', 'agent_node')
  await expect(page.locator('.react-flow__edge-text', { hasText: 'payload→task' })).toBeVisible()
  await clickEdge(page, 'webhook_in', 'agent_node')
  await expect(page.getByTestId('mapping-row-task')).toBeVisible()

  // Publishing is blocked until an explicit Save.
  await expect(page.getByTestId('publish-flow')).toBeDisabled()
  await page.getByTestId('save-flow').click()
  await expect(page.getByTestId('editor-message')).toHaveText('Saved draft.')
}

async function exported(page: Page) {
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByTestId('export-flow').click()])
  return JSON.parse(fs.readFileSync(await download.path(), 'utf8'))
}

test('use case 01 benign flow: build -> save -> publish OK', async ({ page }) => {
  await buildUc01(page, 'uc01_benign_ui', true)
  await page.getByTestId('publish-flow').click()
  await expect(page.getByTestId('editor-message')).toHaveText('Published version 1.')
  // 3.4 Part 0c: a published flow says which version, not "draft"
  await expect(page.getByTestId('flow-status')).toHaveText('published v1')
  await expect(page.getByTestId('violation-list')).toHaveCount(0)
  // 3.4 Part 0c: at 1440 px the Run button stays on the toolbar's first row
  await page.setViewportSize({ width: 1440, height: 900 })
  const bar = await page.getByTestId('editor-toolbar').boundingBox()
  const run = await page.getByTestId('run-open').boundingBox()
  expect(bar && run && run.y - bar.y).toBeLessThan(12)

  // Export matches the committed use case 05 benign flow (ids aside).
  const committed = JSON.parse(fs.readFileSync(path.join(UC05, 'benign.flow.json'), 'utf8'))
  expect({ ...(await exported(page)), id: '', name: '' }).toEqual({ ...committed, id: '', name: '' })

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
  await expect(page.getByTestId('flow-status')).toHaveText('draft') // never published

  const committed = JSON.parse(fs.readFileSync(path.join(UC05, 'attack.flow.json'), 'utf8'))
  expect({ ...(await exported(page)), id: '', name: '' }).toEqual({ ...committed, id: '', name: '' })
})
