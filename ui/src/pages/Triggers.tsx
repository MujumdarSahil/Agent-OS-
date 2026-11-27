// src/pages/Triggers.tsx — 2.4e: Build > Triggers. Webhooks and schedules. 4.3: each runs the version of its
// environment (staging / production) at the moment a run starts; admins can change the binding (audited).
// Webhook secret paths and signing keys are never requested or shown here; they are returned
// only once, on create or rotate (send_webhook.py --setup, or the API).

import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { listSchedules, listWebhooks } from '../api/flows'
import type { EnvironmentName } from '../api/flows'
import { deployError, setTriggerEnvironment } from '../api/environments'
import { useAuth } from '../components/AuthContext'

const when = (ts?: string | null) => (ts ? new Date(ts).toLocaleString() : '-')

function EnvCell({ kind, id, env, canAdmin, onChanged, onError }: {
  kind: 'webhooks' | 'schedules'; id: string; env?: EnvironmentName; canAdmin: boolean
  onChanged: () => void; onError: (m: string) => void
}) {
  const value = env ?? 'production'
  if (!canAdmin) return <span data-testid={`env-${id}`}>{value}</span>
  return (
    <select data-testid={`env-${id}`} value={value} title="Admins only; the change is audited"
            onChange={e => setTriggerEnvironment(kind, id, e.target.value as EnvironmentName).then(onChanged, err => onError(deployError(err)))}>
      <option value="production">production</option>
      <option value="staging">staging</option>
    </select>
  )
}

export default function Triggers() {
  const hooks = useQuery({ queryKey: ['webhooks'], queryFn: listWebhooks })
  const sched = useQuery({ queryKey: ['schedules'], queryFn: listSchedules })
  const canAdmin = useAuth().can('admin')
  const [error, setError] = useState<string | null>(null)
  return (
    <div data-testid="triggers-page">
      <div className="page-header">
        <h2>Triggers</h2>
        <p>What starts your flows besides the Run button. Runs they start appear in Runs with trigger <code>webhook</code> or <code>cron</code>.
          Each runs the version its environment points to when the run starts.</p>
      </div>
      {error && <div data-testid="triggers-error" style={{ color: 'var(--accent-red)' }}>{error}</div>}
      <div className="card mb-3" data-testid="webhooks-card">
        <div className="ov-card-title">Webhooks</div>
        {hooks.isLoading ? <div className="text-muted">Loading…</div> : (hooks.data ?? []).length === 0 ? (
          <div className="text-muted" data-testid="webhooks-empty">No webhooks. Create one with the API or <code>send_webhook.py --setup</code>.</div>
        ) : (
          <table className="ov-table">
            <thead><tr><th>Name</th><th>Flow</th><th>Environment</th><th>Enabled</th><th>Rate limit</th><th>Created</th></tr></thead>
            <tbody>
              {hooks.data!.map(w => (
                <tr key={w.webhook_id} data-testid="webhook-row">
                  <td>{w.name}</td>
                  <td><Link to={`/flows/${encodeURIComponent(w.flow_id)}`}>{w.flow_id}</Link></td>
                  <td><EnvCell kind="webhooks" id={w.webhook_id} env={w.environment} canAdmin={canAdmin}
                               onChanged={() => void hooks.refetch()} onError={setError} /></td>
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
            <thead><tr><th>Name</th><th>Flow</th><th>Environment</th><th>Cron</th><th>Enabled</th><th>Last run</th><th>Next run</th></tr></thead>
            <tbody>
              {sched.data!.map(s => (
                <tr key={s.schedule_id} data-testid="schedule-row">
                  <td>{s.name}</td>
                  <td><Link to={`/flows/${encodeURIComponent(s.flow_id)}`}>{s.flow_id}</Link></td>
                  <td><EnvCell kind="schedules" id={s.schedule_id} env={s.environment} canAdmin={canAdmin}
                               onChanged={() => void sched.refetch()} onError={setError} /></td>
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
