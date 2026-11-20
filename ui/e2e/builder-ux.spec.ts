// 2.4b builder UX e2e (MOCK: real uvicorn backend, FileStorage). Drop on canvas, auto ids,
// rename validation, "+" picker with auto-mapping, condition branches, keyboard connect,
// undo/redo, Delete key, auto-layout, unsaved-changes warning.

import { test, expect, type Page } from '@playwright/test'
import { loginViaUi } from './login'

test.beforeEach(async ({ page }) => {
  await loginViaUi(page) // 3.4: log in through the login page
})

const node = (page: Page, id: string) => page.getByTestId(`flow-node-${id}`)
const edgeLabel = (page: Page, text: string) => page.locator('.react-flow__edge-text', { hasText: text })

async function newFlow(page: Page, id: string) {
  await page.goto(`/flows/${id}?new=1`)
  await expect(page.getByTestId('palette-llm')).toBeVisible()
}

test('drop on canvas places the node under the cursor', async ({ page }) => {
  await newFlow(page, 'ux_drop')
  const canvas = page.getByTestId('flow-canvas')
  await page.getByTestId('palette-llm').dragTo(canvas, { targetPosition: { x: 180, y: 220 } })
  const c = (await canvas.boundingBox())!
  const n = (await node(page, 'llm_1').boundingBox())!
  expect(Math.abs(n.x + n.width / 2 - (c.x + 180))).toBeLessThan(40)
  expect(Math.abs(n.y + n.height / 2 - (c.y + 220))).toBeLessThan(40)
})

test('automatic ids, palette click, rename validation', async ({ page }) => {
  await newFlow(page, 'ux_ids')
  await page.getByTestId('palette-llm').click()
  await page.getByTestId('palette-llm').click()
  await expect(node(page, 'llm_1')).toBeVisible()
  await expect(node(page, 'llm_2')).toBeVisible()
  await page.getByTestId('node-rename-input').fill('llm_1') // drawer shows llm_2
  await page.getByTestId('node-rename-apply').click()
  await expect(page.getByTestId('rename-error')).toContainText('already exists')
  await page.getByTestId('node-rename-input').fill('bad id!')
  await page.getByTestId('node-rename-apply').click()
  await expect(page.getByTestId('rename-error')).toContainText('letters, digits')
  await page.getByTestId('node-rename-input').fill('summarize')
  await page.getByTestId('node-rename-apply').click()
  await expect(node(page, 'summarize')).toBeVisible()
  await expect(node(page, 'llm_2')).toHaveCount(0)
})

test('"+" picker adds and connects the next node with an auto-suggested mapping', async ({ page }) => {
  await newFlow(page, 'ux_plus')
  await page.getByTestId('palette-webhook_trigger').click()
  await page.getByTestId('add-next-webhook_trigger_1').click()
  await expect(page.getByTestId('next-node-picker')).toBeVisible()
  await page.getByTestId('next-node-search').fill('agen')
  await expect(page.getByTestId('next-node-option-send_email')).toHaveCount(0)
  await page.getByTestId('next-node-option-agent').click()
  await expect(node(page, 'agent_1')).toBeVisible()
  await expect(edgeLabel(page, 'payload→task')).toBeVisible()
  await expect(page.getByTestId('node-summary-agent_1')).toBeVisible()
  await expect(node(page, 'agent_1')).toHaveAttribute('data-category', 'ai')
})

test('condition true/false outputs create branch edges', async ({ page }) => {
  await newFlow(page, 'ux_cond')
  await page.getByTestId('palette-condition').click()
  for (const branch of ['true', 'false']) {
    await page.getByTestId(`add-next-condition_1-${branch}`).click()
    await page.getByTestId('next-node-option-llm').click()
    await expect(edgeLabel(page, `[${branch}]`)).toBeVisible()
  }
})

test('undo/redo (keyboard and buttons) and the Delete key', async ({ page }) => {
  await newFlow(page, 'ux_undo')
  await page.getByTestId('palette-llm').click()
  await expect(node(page, 'llm_1')).toBeVisible()
  await page.locator('.react-flow__pane').click({ position: { x: 10, y: 10 } })
  await page.keyboard.press('Control+z')
  await expect(node(page, 'llm_1')).toHaveCount(0)
  await page.keyboard.press('Control+y')
  await expect(node(page, 'llm_1')).toBeVisible()
  await page.getByTestId('undo').click()
  await expect(node(page, 'llm_1')).toHaveCount(0)
  await page.getByTestId('redo').click()
  await expect(node(page, 'llm_1')).toBeVisible()

  await node(page, 'llm_1').click()
  await page.keyboard.press('Delete')
  await expect(node(page, 'llm_1')).toHaveCount(0)
  await page.keyboard.press('Control+z')
  await expect(node(page, 'llm_1')).toBeVisible()
})

test('keyboard connect from the drawer and auto-layout orders nodes left to right', async ({ page }) => {
  await newFlow(page, 'ux_layout')
  const canvas = page.getByTestId('flow-canvas')
  // Dropped right-to-left on purpose.
  await page.getByTestId('palette-send_email').dragTo(canvas, { targetPosition: { x: 60, y: 300 } })
  await page.getByTestId('palette-llm').dragTo(canvas, { targetPosition: { x: 200, y: 120 } })
  await page.getByTestId('palette-manual_trigger').dragTo(canvas, { targetPosition: { x: 340, y: 300 } })
  for (const [from, to] of [['manual_trigger_1', 'llm_1'], ['llm_1', 'send_email_1']]) {
    await node(page, from).dblclick()
    await page.getByTestId('connect-target').selectOption(to)
    await page.getByTestId('connect-add').click()
  }
  await expect(page.locator('.react-flow__edge')).toHaveCount(2)
  await expect(edgeLabel(page, 'completion→body')).toBeVisible()
  await page.getByTestId('auto-layout').click()
  await page.waitForTimeout(300)
  const x = async (id: string) => (await node(page, id).boundingBox())!.x
  expect(await x('manual_trigger_1')).toBeLessThan(await x('llm_1'))
  expect(await x('llm_1')).toBeLessThan(await x('send_email_1'))
})

test('unsaved-changes warning when leaving the editor', async ({ page }) => {
  await newFlow(page, 'ux_unsaved')
  await page.getByTestId('palette-llm').click()
  await expect(page.getByTestId('unsaved')).toBeVisible()
  let message = ''
  page.once('dialog', d => {
    message = d.message()
    void d.dismiss()
  })
  await page.getByRole('link', { name: '← Flows' }).click()
  expect(message).toContain('unsaved changes')
  await expect(page.getByTestId('flow-id')).toHaveText('ux_unsaved') // stayed on the editor
})
