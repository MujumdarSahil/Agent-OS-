// src/pages/SecurityLog.tsx — 2.4e: Govern > Security log. Runtime blocks (blocked tool calls and
// sink-rule violations) of the last 7 days, each with its reason and provenance chain (the Security
// tab rendering). Refused publishes are not stored yet; they will be recorded by the 3.1 audit log.

import { useQuery } from '@tanstack/react-query'
import { getOverview } from '../api/flows'
import { RunBlocked } from '../flow/RunWidgets'

export default function SecurityLog() {
  const q = useQuery({ queryKey: ['overview', '7d'], queryFn: () => getOverview('7d') })
  const byRun = Object.entries(
    (q.data?.blocked ?? []).reduce<Record<string, { flowId: string; seqs: number[] }>>((acc, b) => {
      acc[b.run_id] = acc[b.run_id] ?? { flowId: b.flow_id, seqs: [] }
      acc[b.run_id].seqs.push(b.seq)
      return acc
    }, {}),
  )
  return (
    <div data-testid="security-log-page">
      <div className="page-header" style={{ display: 'flex', alignItems: 'center' }}>
        <div>
          <h2>Security log</h2>
          <p>Calls AgentOS blocked at run time in the last 7 days, with where the untrusted data came from.</p>
        </div>
        <button className="btn btn-ghost btn-sm ml-auto" onClick={() => q.refetch()}>Refresh</button>
      </div>
      <div className="text-muted" style={{ fontSize: 12, marginBottom: 10 }} data-testid="security-log-note">
        Refused publishes are shown in the flow editor when they happen; they are not stored yet (the 3.1 audit log will record them).
      </div>
      {q.isLoading ? <div className="text-muted">Loading…</div> : byRun.length === 0 ? (
        <div className="card text-muted" data-testid="security-log-empty">No blocked calls in the last 7 days.</div>
      ) : (
        byRun.map(([runId, v]) => (
          <div className="card mb-3" key={runId}>
            <RunBlocked flowId={v.flowId} runId={runId} seqs={v.seqs} />
          </div>
        ))
      )}
    </div>
  )
}
