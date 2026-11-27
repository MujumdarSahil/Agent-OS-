// 4.1 "Attack my flow" (MOCK: adversarial scripted model, fake sinks; nothing sent, nothing saved).
import { test, expect } from '@playwright/test'
import { loginViaUi } from './login'

test.beforeEach(async ({ page }) => {
  await loginViaUi(page)
})

test('Attack my flow: a safe flow scores 100% and nothing is saved', async ({ page }) => {
  test.setTimeout(120000)
  await page.goto('/flows/describe')
  await page.getByTestId('example-support').click()
  await page.getByTestId('describe-build').click()
  await expect(page.getByTestId('builder-check')).toHaveAttribute('data-status', 'passed')
  const id = `attack_${Date.now()}`
  await page.getByTestId('draft-id').fill(id)
  await page.getByTestId('describe-create').click()
  await expect(page).toHaveURL(new RegExp(`/flows/${id}$`))

  await page.getByTestId('attack-my-flow').click()
  await page.getByTestId('attack-run').click()
  await expect(page.getByTestId('attack-score')).toHaveAttribute('data-score', '100', { timeout: 90000 })
  await expect(page.getByTestId('attack-furthest')).toBeVisible()
  await expect(page.getByTestId('attack-table').locator('tr[data-outcome="stopped_at_approval"]').first()).toBeVisible()
  await expect(page.getByTestId('unsaved')).toHaveCount(0)
  await expect(page.getByTestId('flow-status')).toHaveText('draft')
})
