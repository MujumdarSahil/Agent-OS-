// 3.6a Review queue E2E test:
// Tests the full UI review queue flow in Playwright:
// - Review queue list with filters
// - Review modal opening with UNTRUSTED security labels
// - Keyboard shortcuts: 'g' for good, 'b' for bad, 'n' for save-and-next
// - Reviewing two items in succession using keyboard shortcuts
// - Corrected output and bad reasons selection

import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { loginViaUi } from './login'

test.beforeEach(async ({ page }) => {
  // Seed two pending review items into the test project
  const projectDir = process.env.AGENTOS_E2E_PROJECT
  if (projectDir) {
    const stateDir = path.join(projectDir, '.agentos', 'state')
    fs.mkdirSync(stateDir, { recursive: true })
    const items = {
      version: 1,
      docs: {
        'rev-e2e-1': {
          id: 'rev-e2e-1',
          item_id: 'rev-e2e-1',
          run_id: 'run-e2e-1',
          flow_id: 'e2e_flow',
          flow_version: 1,
          node_id: 'step_good',
          status: 'pending',
          created_at: 1700000000,
          inputs: { prompt: 'translate hello' },
          input_labels: { prompt: { integrity: 'untrusted', confidentiality: 'public' } },
          outputs: { translation: 'bonjour' },
          output_labels: { translation: { integrity: 'trusted', confidentiality: 'public' } },
          labels: ['UNTRUSTED'],
        },
        'rev-e2e-2': {
          id: 'rev-e2e-2',
          item_id: 'rev-e2e-2',
          run_id: 'run-e2e-2',
          flow_id: 'e2e_flow',
          flow_version: 1,
          node_id: 'step_bad',
          status: 'pending',
          created_at: 1700000001,
          inputs: { expression: '2 + 2' },
          input_labels: { expression: { integrity: 'untrusted', confidentiality: 'public' } },
          outputs: { result: '5' },
          output_labels: { result: { integrity: 'trusted', confidentiality: 'public' } },
          labels: ['UNTRUSTED'],
        },
      },
    }
    fs.writeFileSync(path.join(stateDir, 'review_items.json'), JSON.stringify(items, null, 2), 'utf8')
  }

  await loginViaUi(page)
})

test('review two items in queue using keyboard shortcuts (G, B, N)', async ({ page }) => {
  // Navigate to review queue
  await page.goto('/review')
  await expect(page.getByTestId('review-queue-page')).toBeVisible()

  // Verify both seeded items are in table
  await expect(page.getByTestId('review-row')).toHaveCount(2)

  // Open the first item for review
  await page.getByTestId('review-item-btn-rev-e2e-1').click()
  await expect(page.getByTestId('review-modal')).toBeVisible()
  await expect(page.getByTestId('review-node-id')).toHaveText('step_good')

  // Verify security label (UNTRUSTED badge) is rendered
  await expect(page.getByTestId('label-badge').first()).toBeVisible()
  await expect(page.getByTestId('label-badge').first()).toContainText('UNTRUSTED')

  // Press 'g' key to mark as Good
  await page.keyboard.press('g')
  await expect(page.getByTestId('verdict-good-btn')).toHaveClass(/btn-primary/)

  // Press 'n' key to Save and Next
  await page.keyboard.press('n')

  // The modal should now automatically advance to the second pending item (step_bad)
  await expect(page.getByTestId('review-modal')).toBeVisible()
  await expect(page.getByTestId('review-node-id')).toHaveText('step_bad')

  // Press 'b' key to mark as Bad
  await page.keyboard.press('b')
  await expect(page.getByTestId('verdict-bad-btn')).toHaveClass(/btn-primary/)

  // Verify bad reasons container appeared
  await expect(page.getByTestId('bad-reasons-container')).toBeVisible()

  // Select 'Wrong / incorrect' reason
  await page.getByTestId('reason-wrong').click()
  await expect(page.getByTestId('reason-wrong')).toBeChecked()

  // Fill in corrected output
  await page.getByTestId('corrected-output-input').fill('4')

  // Click Save and Next to submit second item
  await page.getByTestId('review-save-next-btn').click()

  // Modal should close since no pending items remain
  await expect(page.getByTestId('review-modal')).not.toBeVisible()

  // Verify both items now have status 'reviewed' and their respective verdicts
  await expect(page.locator('[data-testid="review-row"][data-item-id="rev-e2e-1"]')).toHaveAttribute(
    'data-status',
    'reviewed',
  )
  await expect(page.locator('[data-testid="review-row"][data-item-id="rev-e2e-1"]')).toHaveAttribute(
    'data-verdict',
    'good',
  )

  await expect(page.locator('[data-testid="review-row"][data-item-id="rev-e2e-2"]')).toHaveAttribute(
    'data-status',
    'reviewed',
  )
  await expect(page.locator('[data-testid="review-row"][data-item-id="rev-e2e-2"]')).toHaveAttribute(
    'data-verdict',
    'bad',
  )
})
