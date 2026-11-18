// src/pages/Runs.tsx — 2.4e: Work > Runs. All runs across flows with filters (flow, status, trigger).
// Built on the existing per-flow run lists; a row opens the run in the flow editor's results view.

import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { runHref, useAllRuns } from '../flow/allRuns'
import { triggerOf } from '../flow/runModel'

const STATUS_COLOR: Record<string, string> = {
  succeeded: 'var(--accent-teal)', failed: 'var(--accent-red)', waiting: 'var(--accent-amber)', running: 'var(--accent-brand)',
}

export default function Runs() {
  const q = useAllRuns()
  const [flow, setFlow] = useState('')
  const [status, setStatus] = useState('')
  const [trigger, setTrigger] = useState('')

  const runs = q.data ?? []
  const options = useMemo(() => ({
    flows: [...new Set(runs.map(r => r.flow_id))].sort(),
    statuses: [...new Set(runs.map(r => r.status))].sort(),
    triggers: [...new Set(runs.map(r => triggerOf(r)))].sort(),
  }), [runs])
  const rows = runs.filter(r => (!flow || r.flow_id === flow) && (!status || r.status === status) && (!trigger || triggerOf(r) === trigger))

  const select = (testid: string, value: string, set: (v: string) => void, opts: string[], label: string) => (
    <label style={{ fontSize: 12 }}>
      {label}{' '}
      <select className="form-select" data-testid={testid} value={value} onChange={e => set(e.target.value)} style={{ width: 'auto', display: 'inline-block' }}>
        <option value="">all</option>
        {opts.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  )

  return (
    <div data-testid="runs-page">
      <div className="page-header">
        <h2>Runs</h2>
        <p>Every run of every flow: manual, webhook and schedule. Click a run to open it with its steps, inputs and outputs.</p>
      </div>
      <div className="card">
        <div className="flex items-center gap-3 mb-2" style={{ flexWrap: 'wrap' }}>
          {select('filter-flow', flow, setFlow, options.flows, 'Flow')}
          {select('filter-status', status, setStatus, options.statuses, 'Status')}
          {select('filter-trigger', trigger, setTrigger, options.triggers, 'Trigger')}
          <span className="text-muted ml-auto" style={{ fontSize: 12 }} data-testid="runs-count">{rows.length} of {runs.length}</span>
          <button className="btn btn-ghost btn-sm" onClick={() => q.refetch()}>Refresh</button>
        </div>
        {q.isLoading ? <div className="text-muted">Loading…</div> : rows.length === 0 ? (
          <div className="text-muted" data-testid="runs-empty">No runs match.</div>
        ) : (
          <table className="ov-table">
            <thead><tr><th>Flow</th><th>Run</th><th>Trigger</th><th>Status</th><th>Started</th><th>Updated</th></tr></thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.run_id} data-testid="runs-row" data-run-id={r.run_id} data-status={r.status} data-trigger={triggerOf(r)} data-flow={r.flow_id}>
                  <td>{r.flow_name}{r.flow_version ? <span className="text-muted"> v{r.flow_version}</span> : null}</td>
                  <td><Link to={runHref(r.flow_id, r.run_id)} data-testid="runs-open"><code>{r.run_id}</code></Link></td>
                  <td><span className="badge badge-default">{triggerOf(r)}</span></td>
                  <td style={{ color: STATUS_COLOR[r.status] }}>{r.status}</td>
                  <td>{r.created_at ? new Date(r.created_at).toLocaleString() : '-'}</td>
                  <td className="text-muted">{r.updated_at ? new Date(r.updated_at).toLocaleString() : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
