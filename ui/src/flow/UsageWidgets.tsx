// src/flow/UsageWidgets.tsx — 3.2: budget bars, the Overview Spend card and the budgets / run limits editor.
// Every budget change goes through PUT /api/v2/budgets, which is audited (3.1) before it applies.

import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { getBudgets, putBudgets, usd, type BudgetStatus, type UsageSettings } from '../api/usage'
import { apiErrorMessage } from '../api/flows'

export function BudgetBars({ budgets }: { budgets: BudgetStatus[] }) {
  if (!budgets.length) return <div className="text-muted" data-testid="budget-bars-empty">No budgets set.</div>
  return (
    <div data-testid="budget-bars">
      {budgets.map(b => {
        const pct = Math.min(100, b.pct_used)
        const color = b.pct_used >= 100 ? 'var(--accent-red)' : b.pct_used >= 80 ? 'var(--accent-amber)' : 'var(--accent-teal, #2dd4bf)'
        return (
          <div key={b.name} data-testid="budget-bar" data-name={b.name} data-pct={b.pct_used} style={{ marginBottom: 8, fontSize: 12 }}>
            <div className="flex justify-between">
              <span className="font-mono">{b.name}</span>
              <span>{usd(b.spent_usd)} of {usd(b.limit_usd)} · {b.pct_used}%</span>
            </div>
            <div style={{ height: 6, background: 'var(--bg-hover)', borderRadius: 3 }}>
              <div style={{ width: `${pct}%`, height: 6, background: color, borderRadius: 3 }} />
            </div>
          </div>
        )
      })}
    </div>
  )
}

/** Overview: today / this month vs the global budgets; shown once there is spend or a budget. */
export function SpendCard() {
  const q = useQuery({ queryKey: ['budgets'], queryFn: getBudgets })
  const d = q.data
  // a missing or malformed response never breaks the Overview: the card just stays hidden
  if (!d || !d.settings?.budgets || !Array.isArray(d.budgets)) return null
  const b = d.settings.budgets
  const spend = d.spend ?? { today_usd: 0, month_usd: 0 }
  const hasBudget = b.global_daily !== null || b.global_monthly !== null || d.budgets.length > 0
  if (!hasBudget && spend.today_usd === 0 && spend.month_usd === 0) return null
  return (
    <div className="card ov-span-12" data-testid="spend-card">
      <div className="ov-card-title flex justify-between">
        <span>Spend (estimate)</span>
        <Link to="/metrics" style={{ fontSize: 12 }}>Metrics</Link>
      </div>
      <div className="flex gap-6" style={{ fontSize: 13, marginBottom: 8 }}>
        <div data-testid="spend-today">Today <strong>{usd(spend.today_usd)}</strong>{b.global_daily !== null && <> of {usd(b.global_daily)}</>}</div>
        <div data-testid="spend-month">This month <strong>{usd(spend.month_usd)}</strong>{b.global_monthly !== null && <> of {usd(b.global_monthly)}</>}</div>
      </div>
      <BudgetBars budgets={d.budgets} />
      <div className="text-muted" style={{ fontSize: 11 }}>Prices are estimates from the price table; the provider's bill is the truth.</div>
    </div>
  )
}

const num = (v: string): number | null => (v.trim() === '' ? null : Number(v))

/** Settings: budgets (USD) and run limits. Saved through PUT /api/v2/budgets (audited). */
export function BudgetsEditor() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['budgets'], queryFn: getBudgets })
  const [s, setS] = useState<UsageSettings | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [newFlow, setNewFlow] = useState('')
  const [newProvider, setNewProvider] = useState('')
  useEffect(() => { if (q.data && !s) setS(q.data.settings) }, [q.data, s])
  if (!s) return <div className="card text-muted">Loading budgets…</div>

  const save = async () => {
    setMsg(null)
    try {
      await putBudgets(s)
      setMsg('Saved (recorded in the audit log).')
      await qc.invalidateQueries({ queryKey: ['budgets'] })
    } catch (e) {
      setMsg(`Not saved: ${apiErrorMessage(e)}`)
    }
  }
  const b = s.budgets
  const rl = s.run_limits
  const setB = (patch: Partial<UsageSettings['budgets']>) => setS({ ...s, budgets: { ...b, ...patch } })
  const setRL = (patch: Partial<UsageSettings['run_limits']>) => setS({ ...s, run_limits: { ...rl, ...patch } })

  return (
    <div className="card" data-testid="budgets-editor">
      <h3 style={{ fontWeight: 700, fontSize: 15, marginBottom: 8 }}>Budgets and run limits</h3>
      <p className="text-muted text-xs mb-3">
        Before every model call, the budgets that apply are checked; a call over budget is not made and the run fails.
        $0 (free-tier, local) models are always allowed. Run limits stop runaway runs, also on free models.
      </p>
      <div className="form-row">
        <div className="form-group">
          <label className="form-label" htmlFor="b-gd">Global daily (USD)</label>
          <input id="b-gd" className="form-input" type="number" min={0} step="0.01" data-testid="budget-global-daily"
            value={b.global_daily ?? ''} onChange={e => setB({ global_daily: num(e.target.value) })} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="b-gm">Global monthly (USD)</label>
          <input id="b-gm" className="form-input" type="number" min={0} step="0.01" data-testid="budget-global-monthly"
            value={b.global_monthly ?? ''} onChange={e => setB({ global_monthly: num(e.target.value) })} />
        </div>
      </div>
      <div className="form-row">
        <div className="form-group">
          <label className="form-label" htmlFor="rl-calls">Max model calls per run</label>
          <input id="rl-calls" className="form-input" type="number" min={1} data-testid="limit-max-calls"
            value={rl.max_model_calls} onChange={e => setRL({ max_model_calls: Math.max(1, Math.trunc(Number(e.target.value) || 1)) })} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="rl-tokens">Max total tokens per run</label>
          <input id="rl-tokens" className="form-input" type="number" min={1} data-testid="limit-max-tokens"
            value={rl.max_total_tokens} onChange={e => setRL({ max_total_tokens: Math.max(1, Math.trunc(Number(e.target.value) || 1)) })} />
        </div>
      </div>
      <div className="form-label">Per flow daily (USD)</div>
      {Object.entries(b.flow_daily).map(([f, v]) => (
        <div key={f} className="flex gap-2 items-center mb-1" data-testid="budget-flow-row" data-flow={f}>
          <code style={{ width: 200 }}>{f}</code>
          <input className="form-input" type="number" min={0} step="0.01" aria-label={`Daily budget for ${f}`} value={v}
            onChange={e => setB({ flow_daily: { ...b.flow_daily, [f]: Number(e.target.value) } })} />
          <button className="btn btn-ghost btn-sm" aria-label={`Remove ${f}`}
            onClick={() => { const n = { ...b.flow_daily }; delete n[f]; setB({ flow_daily: n }) }}>×</button>
        </div>
      ))}
      <div className="flex gap-2 mb-2">
        <input className="form-input" placeholder="flow id" data-testid="budget-flow-new" value={newFlow} onChange={e => setNewFlow(e.target.value)} />
        <button className="btn btn-secondary btn-sm" disabled={!newFlow.trim()}
          onClick={() => { setB({ flow_daily: { ...b.flow_daily, [newFlow.trim()]: 1 } }); setNewFlow('') }}>Add</button>
      </div>
      <div className="form-label">Per provider monthly (USD)</div>
      {Object.entries(b.provider_monthly).map(([p, v]) => (
        <div key={p} className="flex gap-2 items-center mb-1" data-testid="budget-provider-row" data-provider={p}>
          <code style={{ width: 200 }}>{p}</code>
          <input className="form-input" type="number" min={0} step="0.01" aria-label={`Monthly budget for ${p}`} value={v}
            onChange={e => setB({ provider_monthly: { ...b.provider_monthly, [p]: Number(e.target.value) } })} />
          <button className="btn btn-ghost btn-sm" aria-label={`Remove ${p}`}
            onClick={() => { const n = { ...b.provider_monthly }; delete n[p]; setB({ provider_monthly: n }) }}>×</button>
        </div>
      ))}
      <div className="flex gap-2 mb-3">
        <input className="form-input" placeholder="provider name" data-testid="budget-provider-new" value={newProvider} onChange={e => setNewProvider(e.target.value)} />
        <button className="btn btn-secondary btn-sm" disabled={!newProvider.trim()}
          onClick={() => { setB({ provider_monthly: { ...b.provider_monthly, [newProvider.trim()]: 10 } }); setNewProvider('') }}>Add</button>
      </div>
      <button className="btn btn-primary btn-sm" data-testid="budgets-save" onClick={save}>Save budgets and limits</button>
      {msg && <div className="mt-2" data-testid="budgets-message" style={{ fontSize: 12 }}>{msg}</div>}
    </div>
  )
}
