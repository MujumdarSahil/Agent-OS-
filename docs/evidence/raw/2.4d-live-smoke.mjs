// 2.4d LIVE smoke test driver (owner-requested). Drives the real UI headless with Playwright.
// Usage (from the repo root, AgentOS running on :8000):
//   node docs/evidence/raw/2.4d-live-smoke.mjs check1
//   node docs/evidence/raw/2.4d-live-smoke.mjs check2 <webhook-run-id>
//   node docs/evidence/raw/2.4d-live-smoke.mjs check3 <webhook-run-id>
// The API token comes from AGENTOS_SMOKE_TOKEN and is never printed. Output: statuses, providers,
// models, durations and label names only (no keys, no prompts).

import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const { chromium } = createRequire(path.join(ROOT, 'ui', 'package.json'))('@playwright/test')
const BASE = 'http://localhost:8000'
const FLOW = 'uc07_support_desk'
const SHOTS = path.join(ROOT, 'docs', 'evidence', 'raw')
const TOKEN = process.env.AGENTOS_SMOKE_TOKEN
if (!TOKEN) throw new Error('AGENTOS_SMOKE_TOKEN is not set')
const AUTH = { Authorization: `Bearer ${TOKEN}` }
const out = (k, v) => console.log(`${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)

async function settle(page, ms = 120000) {
  const t0 = Date.now()
  const status = page.getByTestId('run-status')
  while (Date.now() - t0 < ms) {
    const s = (await status.textContent().catch(() => '')) || ''
    if (['waiting', 'succeeded', 'failed'].includes(s.trim())) return { status: s.trim(), waitedMs: Date.now() - t0 }
    await page.waitForTimeout(500)
  }
  return { status: 'timeout', waitedMs: Date.now() - t0 }
}

async function steps(page) {
  await page.getByTestId('tab-steps').click()
  return page.getByTestId('step-row').evaluateAll(rows => rows.map(r => ({
    node: r.getAttribute('data-node'),
    status: r.getAttribute('data-status'),
    duration: r.querySelector('[data-testid="step-duration"]')?.textContent?.trim(),
    llm: r.querySelector('[data-testid="step-llm"]')?.textContent?.trim() || undefined,
  })))
}

async function eventTypes(page) {
  await page.getByTestId('tab-logs').click()
  return page.getByTestId('event-row').evaluateAll(rows => rows.map(r => r.getAttribute('data-type')))
}

async function approvalCard(page) {
  const card = page.getByTestId('approval-card')
  if (!(await card.count())) return null
  return card.locator('tr[data-testid^="approval-arg-"]').evaluateAll(rows => rows.map(r => ({
    arg: r.getAttribute('data-testid').replace('approval-arg-', ''),
    integrity: r.getAttribute('data-integrity'),
    label: r.querySelector('[data-testid="label-badge"]')?.textContent?.trim(),
  })))
}

/** Scan a run's sink events through the API: no sink may ever target the attacker. */
async function sinkTargets(request, runId) {
  const evs = await (await request.get(`${BASE}/api/v2/flows/${FLOW}/runs/${runId}/events`, { headers: AUTH })).json()
  const sinks = evs.filter(e => e.type === 'sink_intent' || e.type === 'sink_committed')
  return { sinks: sinks.map(e => `${e.type}:${e.data?.node_id ?? e.data?.sink_node ?? '?'}`), attacker: JSON.stringify(sinks).includes('mallory') }
}

// Single-port mode has no SPA fallback for deep links (bug found in this smoke test: GET /flows/x -> 404),
// so load "/" and navigate inside the app.
async function go(page, route) {
  if (!page.url().startsWith(BASE)) await page.goto(`${BASE}/`)
  await page.evaluate(r => { history.pushState({}, '', r); dispatchEvent(new PopStateEvent('popstate')) }, route)
}

async function openRun(page, runId) {
  await go(page, `/flows/${FLOW}`)
  await page.getByTestId('toggle-run-panel').click()
  const row = page.locator(`[data-testid="history-row"][data-run-id="${runId}"]`)
  await row.waitFor({ timeout: 30000 })
  out('history_trigger', await row.getAttribute('data-trigger'))
  await row.click()
}

const phase = process.argv[2]
const runArg = process.argv[3]
const browser = await chromium.launch()
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } })
await ctx.addInitScript(t => sessionStorage.setItem('agentos_api_token', t), TOKEN)
const page = await ctx.newPage()
const request = ctx.request
try {
  if (phase === 'check1') {
    await go(page, `/flows/${FLOW}`)
    await page.getByTestId('run-open').click()
    out('prefilled_urgent', (await page.getByTestId('run-input').inputValue()).includes('Production checkout is down'))
    await page.getByTestId('run-flow').click()
    await page.getByTestId('results-panel').waitFor()
    out('run_id', await page.getByTestId('run-id').textContent())
    out('settled', await settle(page))
    out('duration', await page.getByTestId('run-duration').textContent())
    const s = await steps(page)
    out('steps', s)
    out('decision', s.some(x => x.node === 'oncall_approval') ? 'URGENT (approval path)' : s.some(x => x.node === 'queue_note') ? 'NORMAL (queue path)' : 'unknown')
    await page.screenshot({ path: path.join(SHOTS, '2.4d-live-1-urgent.png') })
    const types = await eventTypes(page)
    out('steps_vs_logs', { step_rows: s.length, log_rows: types.length, steps_have_durations: s.every(x => x.duration && x.duration !== '-') })
    // Run must be disabled on a flow that was never published.
    const draft = { id: 'uc07_live_unpublished', name: 'uc07_live_unpublished', entrypoint: 'trig',
      nodes: { trig: { id: 'trig', type: 'manual_trigger', config: {}, pinned_args: {} } }, edges: [], loops: {} }
    const c = await request.post(`${BASE}/api/v2/flows`, { data: draft, headers: AUTH })
    out('unpublished_create_http', c.status())
    await go(page, '/flows/uc07_live_unpublished')
    await page.getByTestId('flow-canvas').waitFor()
    await page.waitForTimeout(1000)
    out('unpublished_run_disabled', await page.getByTestId('run-open').isDisabled())
    out('unpublished_tooltip', await page.getByTestId('run-open').locator('..').getAttribute('title'))
  } else if (phase === 'check2') {
    await openRun(page, runArg)
    out('settled', await settle(page))
    out('steps', await steps(page))
    await page.getByTestId('tab-output').click()
    const card = await approvalCard(page)
    out('approval_card', card)
    out('security_tab_auto_open', await page.getByTestId('tab-panel-security').isVisible())
    out('blocked_calls', await page.getByTestId('blocked-call').count())
    await page.screenshot({ path: path.join(SHOTS, '2.4d-live-2-injection.png') })
    out('sinks_before_decision', await sinkTargets(request, runArg))
    if (card) {
      await page.getByTestId('reject').click()
      out('after_reject', await settle(page, 30000))
      out('send_count', await page.getByTestId('send-count').textContent())
    }
    out('sinks_final', await sinkTargets(request, runArg))
  } else if (phase === 'check3') {
    await openRun(page, runArg)
    out('settled', await settle(page))
    out('steps', await steps(page))
    await page.getByTestId('tab-output').click()
    const card = await approvalCard(page)
    out('approval_card', card)
    if (card) {
      await page.getByTestId('approve').click()
      const t0 = Date.now()
      while (Date.now() - t0 < 30000 && (await page.getByTestId('run-status').textContent()) === 'waiting') await page.waitForTimeout(500)
      out('after_approve', (await page.getByTestId('run-status').textContent())?.trim())
    }
    const types = await eventTypes(page)
    out('sink_intent', types.filter(t => t === 'sink_intent').length)
    out('sink_committed', types.filter(t => t === 'sink_committed').length)
    out('send_count', await page.getByTestId('send-count').textContent())
    out('sinks', await sinkTargets(request, runArg))
    await page.screenshot({ path: path.join(SHOTS, '2.4d-live-3-approval.png') })
  } else {
    throw new Error(`unknown phase ${phase}`)
  }
} finally {
  await browser.close()
}
