// src/pages/Approvals.tsx — 2.4e: Work > Approvals. Every waiting approval across flows, each with
// the full sink call and labels (the 2.4d-fix card) and inline approve / reject.
// 2.5a-fix: the decision confirmation is shown at page level, so it stays after the list refresh
// removes the decided run (even when no approvals are left).

import { useAllRuns } from '../flow/allRuns'
import { DecisionNotice, RunApproval, useDecisionNotice } from '../flow/RunWidgets'

export default function Approvals() {
  const q = useAllRuns()
  const [decisionNotice, showDecision] = useDecisionNotice()
  const waiting = (q.data ?? []).filter(r => r.status === 'waiting')
  return (
    <div data-testid="approvals-page">
      <div className="page-header" style={{ display: 'flex', alignItems: 'center' }}>
        <div>
          <h2>Approvals</h2>
          <p>Runs paused before a side effect. Each card shows the exact call that approving releases.</p>
        </div>
        <button className="btn btn-ghost btn-sm ml-auto" onClick={() => q.refetch()}>Refresh</button>
      </div>
      <DecisionNotice notice={decisionNotice} />
      {q.isLoading ? <div className="text-muted">Loading…</div> : waiting.length === 0 ? (
        <div className="card text-muted" data-testid="approvals-empty">Nothing is waiting for an approval.</div>
      ) : (
        <div className="card" style={{ padding: 4 }}>
          {waiting.map(r => (
            <RunApproval key={r.run_id} flowId={r.flow_id} runId={r.run_id} refresh={[['all-runs'], ['overview']]}
              onDecided={showDecision} />
          ))}
        </div>
      )}
    </div>
  )
}
