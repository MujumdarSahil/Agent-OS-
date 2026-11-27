// src/pages/Triggers.tsx — 2.4e: Build > Triggers. Webhooks and schedules (read-only list).
// Webhook secret paths and signing keys are never requested or shown here; they are returned
// only once, on create or rotate (send_webhook.py --setup, or the API).

import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { listSchedules, listWebhooks } from '../api/flows'

const when = (ts?: string | null) => (ts ? new Date(ts).toLocaleString() : '-')

export default function Triggers() {
  const hooks = useQuery({ queryKey: ['webhooks'], queryFn: listWebhooks })
  const sched = useQuery({ queryKey: ['schedules'], queryFn: listSchedules })
  return (
    <div data-testid="triggers-page">
      <div className="page-header">
        <h2>Triggers</h2>
        <p>What starts your flows besides the Run button. Runs they start appear in Runs with trigger <code>webhook</code> or <code>cron</code>.</p>
      </div>
      <div className="card mb-3" data-testid="webhooks-card">
        <div className="ov-card-title">Webhooks</div>
        {hooks.isLoading ? <div className="text-muted">Loading…</div> : (hooks.data ?? []).length === 0 ? (
          <div className="text-muted" data-testid="webhooks-empty">No webhooks. Create one with the API or <code>send_webhook.py --setup</code>.</div>
        ) : (
          <table className="ov-table">
            <thead><tr><th>Name</th><th>Flow</th><th>Enabled</th><th>Rate limit</th><th>Created</th></tr></thead>
            <tbody>
              {hooks.data!.map(w => (
                <tr key={w.webhook_id} data-testid="webhook-row">
                  <td>{w.name}</td>
                  <td><Link to={`/flows/${encodeURIComponent(w.flow_id)}`}>{w.flow_id}</Link></td>
                  <td>{w.enabled ? 'yes' : 'no'}</td>
                  <td>{w.rate_limit_per_minute}/min</td>
                  <td>{when(w.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="text-muted" style={{ fontSize: 11, marginTop: 6 }}>Secret paths and signing keys are shown only once, when created or rotated.</div>
      </div>
      <div className="card" data-testid="schedules-card">
        <div className="ov-card-title">Schedules</div>
        {sched.isLoading ? <div className="text-muted">Loading…</div> : (sched.data ?? []).length === 0 ? (
          <div className="text-muted" data-testid="schedules-empty">No schedules.</div>
        ) : (
          <table className="ov-table">
            <thead><tr><th>Name</th><th>Flow</th><th>Cron</th><th>Enabled</th><th>Last run</th><th>Next run</th></tr></thead>
            <tbody>
              {sched.data!.map(s => (
                <tr key={s.schedule_id} data-testid="schedule-row">
                  <td>{s.name}</td>
                  <td><Link to={`/flows/${encodeURIComponent(s.flow_id)}`}>{s.flow_id}</Link></td>
                  <td><code>{s.cron_expression}</code> {s.timezone}</td>
                  <td>{s.enabled ? 'yes' : 'no'}</td>
                  <td>{when(s.last_run_at)}</td>
                  <td>{when(s.next_run_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
