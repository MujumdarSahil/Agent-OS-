// src/pages/Overview.tsx — 2.4e: Watch > Overview, the home page.
// Shows only data the backend really has (GET /api/v2/overview plus the per-run events endpoint).
// 3.2: the Spend card (today / this month vs budget) appears once there is spend or a budget. No alerts
// yet (3.3). Fetched on open and on the window
// toggle; no polling. Untrusted values only appear inside the approval card, as plain text.

import { AuditChainStatus } from './AuditLog'
import { SpendCard } from '../flow/UsageWidgets'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { CheckCircle2, Circle, Hand, ShieldAlert, Snowflake } from 'lucide-react'
import { getOverview, type OverviewData, type OverviewWindow } from '../api/flows'
import { formatMs } from '../flow/runModel'
import { runHref } from '../flow/allRuns'
import { DecisionNotice, RunApproval, RunBlocked, useDecisionNotice } from '../flow/RunWidgets'

const STATUS_COLOR: Record<string, string> = {
  succeeded: 'var(--accent-teal)', failed: 'var(--accent-red)', waiting: 'var(--accent-amber)',
  running: 'var(--accent-brand)', queued: 'var(--text-muted)', pending: 'var(--text-muted)',
}

const HEALTH: Record<string, { text: (s: number | null) => string; color: string }> = {
  healthy: { text: () => 'healthy', color: 'var(--accent-teal)' },
  cooling: { text: s => `cooling ${Math.ceil(s ?? 0)}s`, color: 'var(--accent-amber)' },
  disabled: { text: () => 'disabled', color: 'var(--text-muted)' },
  no_key: { text: () => 'no key', color: 'var(--text-muted)' },
}

function when(ts: string | null): string {
  return ts ? new Date(ts).toLocaleString() : '-'
}

function NeedsYou({ d }: { d: OverviewData }) {
  const n = d.needs_you
  if (!n.waiting_approvals && !n.attacks_blocked_today && !n.providers_cooling) return null
  return (
    <div className="ov-needs" data-testid="needs-you">
      <strong style={{ fontSize: 13 }}>Needs you now</strong>
      {n.waiting_approvals > 0 && (
        <a href="#waiting" className="ov-pill ov-pill-amber" data-testid="needs-approvals">
          <Hand size={13}/> {n.waiting_approvals} waiting for approval
        </a>
      )}
      {n.attacks_blocked_today > 0 && (
        <Link to="/security" className="ov-pill ov-pill-red" data-testid="needs-attacks">
          <ShieldAlert size={13}/> {n.attacks_blocked_today} attack{n.attacks_blocked_today === 1 ? '' : 's'} blocked today
        </Link>
      )}
      {n.providers_cooling > 0 && (
        <a href="#models" className="ov-pill ov-pill-amber" data-testid="needs-cooling">
          <Snowflake size={13}/> {n.providers_cooling} provider{n.providers_cooling === 1 ? '' : 's'} cooling down
        </a>
      )}
    </div>
  )
}

function Kpi({ testid, label, value, sub, color }: { testid: string; label: string; value: React.ReactNode; sub?: React.ReactNode; color?: string }) {
  return (
    <div className="card ov-span-3" data-testid={testid}>
      <div className="ov-card-title">{label}</div>
      <div className="ov-kpi-value" data-testid={`${testid}-value`} style={{ color }}>{value}</div>
      {sub && <div className="ov-kpi-sub">{sub}</div>}
    </div>
  )
}

const STEPS: { key: keyof OverviewData['getting_started']; text: string; to: string }[] = [
  { key: 'key_added', text: 'Add a model key', to: '/providers' },
  { key: 'flow_published', text: 'Publish a flow', to: '/flows' },
  { key: 'first_run', text: 'Run a flow', to: '/flows' },
  { key: 'first_approval', text: 'Approve or reject a waiting run', to: '/approvals' },
  { key: 'webhook_created', text: 'Create a webhook trigger', to: '/triggers' },
]

export default function Overview() {
  const [win, setWin] = useState<OverviewWindow>('24h')
  const [decisionNotice, showDecision] = useDecisionNotice()
  const q = useQuery({ queryKey: ['overview', win], queryFn: () => getOverview(win) })
  const d = q.data

  return (
    <div data-testid="overview-page">
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div>
          <h2>Overview</h2>
          <p>What is running, what needs you, and what was blocked. Live from this AgentOS{d?.mock_llm ? ' (MOCK model mode)' : ''}.</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <div className="ov-toggle" role="group" aria-label="Time window" data-testid="window-toggle">
            {(['24h', '7d'] as OverviewWindow[]).map(w => (
              <button key={w} aria-pressed={win === w} data-testid={`window-${w}`} onClick={() => setWin(w)}>
                {w === '24h' ? '24 h' : '7 d'}
              </button>
            ))}
          </div>
          <button className="btn btn-ghost btn-sm" data-testid="overview-refresh" onClick={() => q.refetch()}>Refresh</button>
        </div>
      </div>

      {q.isLoading && <div className="text-muted">Loading…</div>}
      {q.isError && <div style={{ color: 'var(--accent-red)' }} data-testid="overview-error">Could not load the overview.</div>}

      {d && (
        <>
          <DecisionNotice notice={decisionNotice} />
          <NeedsYou d={d} />
          {d.truncated && (
            <div className="text-muted" style={{ fontSize: 12, marginBottom: 8 }} data-testid="overview-truncated">
              Counts cover the newest 500 runs only.
            </div>
          )}

          <div className="ov-grid">
            <Kpi
              testid="kpi-runs" label={`Runs · ${win === '24h' ? '24 h' : '7 d'}`} value={d.kpis.runs.total}
              sub={<><span style={{ color: 'var(--accent-teal)' }}>{d.kpis.runs.succeeded} succeeded</span> · <span style={{ color: 'var(--accent-red)' }}>{d.kpis.runs.failed} failed</span></>}
            />
            <Kpi testid="kpi-attacks" label="Attacks blocked" value={d.kpis.attacks_blocked} color={d.kpis.attacks_blocked ? 'var(--accent-red)' : undefined}
              sub="blocked tool calls and sink-rule violations" />
            <Kpi testid="kpi-waiting" label="Waiting for approval" value={d.kpis.waiting_for_approval} color={d.kpis.waiting_for_approval ? 'var(--accent-amber)' : undefined}
              sub="runs paused at an approval" />
            <Kpi
              testid="kpi-model-calls" label="Model calls" value={d.kpis.model_calls.total}
              sub={<>median {d.kpis.model_calls.median_latency_ms === null ? '-' : formatMs(d.kpis.model_calls.median_latency_ms)} · {d.kpis.model_calls.fallbacks} fallback{d.kpis.model_calls.fallbacks === 1 ? '' : 's'}</>}
            />

            <SpendCard />
            <div className="card ov-span-8" data-testid="recent-runs">
              <div className="ov-card-title">Live and recent runs <Link to="/runs" className="ml-auto" style={{ fontSize: 11, textTransform: 'none' }}>All runs</Link></div>
              {d.recent_runs.length === 0 ? (
                <div className="text-muted" style={{ fontSize: 12 }}>No runs in this window.</div>
              ) : (
                <table className="ov-table">
                  <thead><tr><th>Flow</th><th>Trigger</th><th>Status</th><th>Model that answered</th><th>Started</th><th>Duration</th></tr></thead>
                  <tbody>
                    {d.recent_runs.map(r => (
                      <tr key={r.run_id} data-testid="recent-run" data-run-id={r.run_id} data-status={r.status}>
                        <td><Link to={runHref(r.flow_id, r.run_id)}>{r.flow_id}</Link>{r.flow_version ? <span className="text-muted"> v{r.flow_version}</span> : null}</td>
                        <td><span className="badge badge-default">{r.trigger}</span></td>
                        <td style={{ color: STATUS_COLOR[r.status] }}>{r.status}</td>
                        <td data-testid="recent-run-model">
                          {r.answered_by ? (
                            <>
                              {r.answered_by.provider}
                              {r.answered_by.mock && <span className="badge badge-default" style={{ marginLeft: 4 }}>mock</span>}
                              {r.answered_by.fallback && <span className="ov-pill ov-pill-amber" style={{ marginLeft: 4, padding: '1px 6px' }} data-testid="fallback-mark">fallback</span>}
                            </>
                          ) : <span className="text-muted">no model call</span>}
                        </td>
                        <td>{when(r.started_at)}</td>
                        <td>{r.status === 'waiting' ? <span style={{ color: 'var(--accent-amber)' }}>waiting</span> : formatMs(r.duration_ms)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            <div className="card ov-span-4" id="models" data-testid="fallback-chain">
              <div className="ov-card-title">Model fallback chain</div>
              <ol style={{ margin: 0, paddingLeft: 18, fontSize: 12.5 }}>
                {d.providers.map(p => (
                  <li key={p.name} data-testid="provider-row" data-provider={p.name} data-state={p.state} style={{ padding: '3px 0', opacity: p.state === 'disabled' ? 0.6 : 1 }}>
                    <span>{p.display_name}</span>{' '}
                    <span data-testid="provider-health" style={{ color: HEALTH[p.state].color, fontWeight: 600 }}>{HEALTH[p.state].text(p.cooling_s)}</span>
                    {p.cooling_reason && <span className="text-muted"> ({p.cooling_reason})</span>}
                  </li>
                ))}
              </ol>
              <div className="text-muted" style={{ fontSize: 11, marginTop: 6 }}>
                Order from Models &amp; keys. Health comes from this server's circuit breaker (resets on restart). Key values are never shown.
              </div>
            </div>

            <div className="card ov-span-7" id="waiting" data-testid="waiting-card">
              <div className="ov-card-title">Waiting for you <Link to="/approvals" className="ml-auto" style={{ fontSize: 11, textTransform: 'none' }}>All approvals</Link></div>
              {d.waiting.length === 0 ? (
                <div className="text-muted" style={{ fontSize: 12 }} data-testid="waiting-empty">Nothing is waiting for an approval.</div>
              ) : (
                d.waiting.slice(0, 3).map(w => (
                  <RunApproval key={w.run_id} flowId={w.flow_id} runId={w.run_id} refresh={[['overview']]} onDecided={showDecision} />
                ))
              )}
            </div>

            <div className="card ov-span-5" data-testid="attacks-card">
              <div className="ov-card-title">Attacks blocked <Link to="/security" className="ml-auto" style={{ fontSize: 11, textTransform: 'none' }}>Security log</Link></div>
              {d.blocked.length === 0 ? (
                <div className="text-muted" style={{ fontSize: 12 }} data-testid="attacks-empty">No blocked calls in this window.</div>
              ) : (
                Object.entries(
                  d.blocked.slice(0, 5).reduce<Record<string, { flowId: string; seqs: number[] }>>((acc, b) => {
                    acc[b.run_id] = acc[b.run_id] ?? { flowId: b.flow_id, seqs: [] }
                    acc[b.run_id].seqs.push(b.seq)
                    return acc
                  }, {}),
                ).map(([runId, v]) => <RunBlocked key={runId} flowId={v.flowId} runId={runId} seqs={v.seqs} />)
              )}
            </div>

            <div className="card ov-span-6" data-testid="flows-card">
              <div className="ov-card-title">Your flows <Link to="/flows" className="ml-auto" style={{ fontSize: 11, textTransform: 'none' }}>All flows</Link></div>
              {d.flows.length === 0 ? (
                <div className="text-muted" style={{ fontSize: 12 }}>No flows yet. <Link to="/flows">Create one</Link>.</div>
              ) : (
                <table className="ov-table">
                  <tbody>
                    {d.flows.map(f => (
                      <tr key={f.flow_id} data-testid="flow-row">
                        <td><Link to={`/flows/${encodeURIComponent(f.flow_id)}`}>{f.name}</Link></td>
                        <td>{f.latest_version ? <span className="ov-pill ov-pill-teal" style={{ padding: '1px 6px' }}>v{f.latest_version} published</span> : <span className="text-muted">draft</span>}</td>
                        <td className="text-muted">{when(f.updated_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            <div className="card ov-span-6" data-testid="getting-started">
              <div className="ov-card-title">Getting started</div>
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, fontSize: 13 }}>
                {STEPS.map(s => {
                  const done = d.getting_started[s.key]
                  return (
                    <li key={s.key} data-testid={`gs-${s.key}`} data-done={done ? 'true' : 'false'} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0' }}>
                      {done ? <CheckCircle2 size={15} color="var(--accent-teal)"/> : <Circle size={15} color="var(--text-muted)"/>}
                      {done ? <span className="text-muted" style={{ textDecoration: 'line-through' }}>{s.text}</span> : <Link to={s.to}>{s.text}</Link>}
                    </li>
                  )
                })}
              </ul>
            </div>
          </div>
        </>
      )}
      <div className="mt-3" data-testid="overview-footer" style={{ textAlign: 'right' }}>
        <Link to="/audit" style={{ textDecoration: 'none' }}><AuditChainStatus /></Link>
      </div>
    </div>
  )
}
