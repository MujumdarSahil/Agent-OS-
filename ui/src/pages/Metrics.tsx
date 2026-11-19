// src/pages/Metrics.tsx — 3.2: Watch > Metrics. Spend and tokens over time (by provider / model / flow), top flows
// by cost, p50 / p95 latency per provider, error and fallback rate, budget bars. Data: GET /api/v2/usage (the
// usage ledger) and GET /api/v2/budgets. Costs are estimates from the price table.

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getBudgets, getUsage, usd, type UsageRow } from '../api/usage'
import { BudgetBars } from '../flow/UsageWidgets'

const WINDOWS: Record<string, number> = { '7d': 7, '30d': 30, '90d': 90 }
const dayMinus = (n: number) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10)

function Bars({ rows, value, label, testid }: { rows: { key: string; v: number }[]; value: (v: number) => string; label: string; testid: string }) {
  const max = Math.max(0, ...rows.map(r => r.v))
  if (!rows.length) return <div className="text-muted" data-testid={`${testid}-empty`}>No usage in this window.</div>
  return (
    <div data-testid={testid} aria-label={label}>
      {rows.map(r => (
        <div key={r.key} data-testid={`${testid}-row`} data-key={r.key} className="flex items-center gap-2" style={{ fontSize: 12, marginBottom: 4 }}>
          <span className="font-mono truncate" style={{ width: 200 }}>{r.key}</span>
          <div style={{ flex: 1, height: 8, background: 'var(--bg-hover)', borderRadius: 4 }}>
            <div style={{ width: max ? `${(100 * r.v) / max}%` : '0%', height: 8, background: 'var(--accent-blue)', borderRadius: 4 }} />
          </div>
          <span style={{ width: 110, textAlign: 'right' }}>{value(r.v)}</span>
        </div>
      ))}
    </div>
  )
}

const keyOf = (r: UsageRow, by: string[]) => by.map(k => String((r as unknown as Record<string, unknown>)[k] ?? '-')).join(' · ')

export default function Metrics() {
  const [win, setWin] = useState<keyof typeof WINDOWS>('30d')
  const [by, setBy] = useState<'provider' | 'model' | 'flow'>('provider')
  const since = dayMinus(WINDOWS[win] - 1)
  const series = useQuery({ queryKey: ['usage', 'day', since], queryFn: () => getUsage('day', since) })
  const grouped = useQuery({ queryKey: ['usage', by, since], queryFn: () => getUsage(by, since) })
  const flows = useQuery({ queryKey: ['usage', 'flow', since], queryFn: () => getUsage('flow', since) })
  const budgets = useQuery({ queryKey: ['budgets'], queryFn: getBudgets })
  const providers = useQuery({ queryKey: ['usage', 'provider', since], queryFn: () => getUsage('provider', since) })
  const groupKey = by === 'flow' ? 'flow_id' : by
  const t = series.data?.totals

  return (
    <div data-testid="metrics-page">
      <div className="page-header flex items-center gap-3">
        <div>
          <h2>Metrics</h2>
          <p>Model calls, tokens and estimated cost from the usage ledger. Provider bills are the truth.</p>
        </div>
        <div className="ml-auto flex gap-2">
          <select className="form-select" aria-label="Window" data-testid="metrics-window" value={win} onChange={e => setWin(e.target.value as keyof typeof WINDOWS)}>
            {Object.keys(WINDOWS).map(w => <option key={w} value={w}>{w}</option>)}
          </select>
          <select className="form-select" aria-label="Group by" data-testid="metrics-group" value={by} onChange={e => setBy(e.target.value as 'provider' | 'model' | 'flow')}>
            <option value="provider">by provider</option>
            <option value="model">by model</option>
            <option value="flow">by flow</option>
          </select>
        </div>
      </div>

      <div className="ov-grid">
        <div className="card ov-span-3" data-testid="metrics-total-cost"><div className="ov-card-title">Spend</div><div style={{ fontSize: 22 }}>{usd(t?.cost_usd ?? 0)}</div>
          {t && t.cost_unknown_calls > 0 && <div className="text-muted" style={{ fontSize: 11 }}>{t.cost_unknown_calls} call(s) with unknown price</div>}</div>
        <div className="card ov-span-3" data-testid="metrics-total-calls"><div className="ov-card-title">Model calls</div><div style={{ fontSize: 22 }}>{t?.calls ?? 0}</div></div>
        <div className="card ov-span-3" data-testid="metrics-total-tokens"><div className="ov-card-title">Tokens</div><div style={{ fontSize: 22 }}>{((t?.prompt_tokens ?? 0) + (t?.completion_tokens ?? 0)).toLocaleString('en-US')}</div></div>
        <div className="card ov-span-3" data-testid="metrics-error-rate"><div className="ov-card-title">Errors · fallbacks</div>
          <div style={{ fontSize: 22 }}>{t && t.calls ? `${Math.round((100 * t.errors) / t.calls)}% · ${Math.round((100 * t.fallbacks) / t.calls)}%` : '-'}</div></div>

        <div className="card ov-span-6" data-testid="metrics-spend-by-day">
          <div className="ov-card-title">Spend per day</div>
          <Bars testid="spend-by-day" label="Spend per day" value={usd}
            rows={(series.data?.rows ?? []).map(r => ({ key: String(r.day), v: r.cost_usd }))} />
        </div>
        <div className="card ov-span-6" data-testid="metrics-tokens-by-day">
          <div className="ov-card-title">Tokens per day</div>
          <Bars testid="tokens-by-day" label="Tokens per day" value={v => v.toLocaleString('en-US')}
            rows={(series.data?.rows ?? []).map(r => ({ key: String(r.day), v: r.prompt_tokens + r.completion_tokens }))} />
        </div>
        <div className="card ov-span-6" data-testid="metrics-by-group">
          <div className="ov-card-title">Spend {by === 'flow' ? 'by flow' : `by ${by}`}</div>
          <Bars testid="spend-by-group" label="Spend by group" value={usd}
            rows={(grouped.data?.rows ?? []).map(r => ({ key: keyOf(r, [groupKey]), v: r.cost_usd }))} />
        </div>
        <div className="card ov-span-6" data-testid="metrics-top-flows">
          <div className="ov-card-title">Top flows by cost</div>
          <Bars testid="top-flows" label="Top flows by cost" value={usd}
            rows={[...(flows.data?.rows ?? [])].sort((a, b) => b.cost_usd - a.cost_usd).slice(0, 10).map(r => ({ key: String(r.flow_id), v: r.cost_usd }))} />
        </div>
        <div className="card ov-span-6" data-testid="metrics-latency">
          <div className="ov-card-title">Latency per provider</div>
          <table style={{ width: '100%', fontSize: 12 }}>
            <thead><tr><th style={{ textAlign: 'left' }}>Provider</th><th>p50</th><th>p95</th><th>samples</th></tr></thead>
            <tbody>
              {(grouped.data?.latency ?? []).map(l => (
                <tr key={l.provider} data-testid="latency-row" data-provider={l.provider}>
                  <td className="font-mono">{l.provider}</td><td>{l.p50_ms ?? '-'} ms</td><td>{l.p95_ms ?? '-'} ms</td><td>{l.samples}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card ov-span-6" data-testid="metrics-provider-health">
          <div className="ov-card-title">Errors and fallbacks per provider</div>
          <table style={{ width: '100%', fontSize: 12 }}>
            <thead><tr><th style={{ textAlign: 'left' }}>Provider</th><th>calls</th><th>error rate</th><th>fallbacks</th></tr></thead>
            <tbody>
              {(providers.data?.rows ?? []).map(r => (
                <tr key={String(r.provider)} data-testid="provider-health-row" data-provider={r.provider}>
                  <td className="font-mono">{r.provider}</td><td>{r.calls}</td>
                  <td>{r.calls ? `${Math.round((100 * r.errors) / r.calls)}%` : '-'}</td><td>{r.fallbacks}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card ov-span-12" data-testid="metrics-budgets">
          <div className="ov-card-title">Budgets</div>
          <BudgetBars budgets={budgets.data?.budgets ?? []} />
        </div>
      </div>
    </div>
  )
}
