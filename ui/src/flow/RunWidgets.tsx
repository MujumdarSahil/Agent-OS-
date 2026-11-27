// src/flow/RunWidgets.tsx — 2.4e: the run panel's approval card and blocked-call list, for pages
// outside the editor (Overview, Approvals, Security log). Each loads one run's events over HTTP
// and derives the card / provenance with the same runModel functions as the results panel, so
// the rendering (labels, plain-text untrusted values) is identical.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiErrorMessage, decideApproval, getRunEvents } from '../api/flows'
import { ApprovalCard, BlockedList } from './RunPanel'
import { blockedCalls, pendingApproval, type RunEvent } from './runModel'
import { runHref } from './allRuns'

export function useRunEventsOnce(flowId: string, runId: string) {
  return useQuery({
    queryKey: ['run-events', flowId, runId],
    queryFn: async () => (await getRunEvents(flowId, runId)) as RunEvent[],
  })
}

/** How long the page-level decision confirmation stays visible (at least 5 s). */
export const DECISION_NOTICE_MS = 6000

/** Page-level decision confirmation. It lives on the page, not on the card, so it survives the card list
 *  refresh that removes the decided run (the approver must still see what happened). */
export function useDecisionNotice(): [string | null, (message: string) => void] {
  const [notice, setNotice] = useState<string | null>(null)
  const timer = useRef<number | null>(null)
  useEffect(() => () => { if (timer.current) window.clearTimeout(timer.current) }, [])
  const show = useCallback((message: string) => {
    setNotice(message)
    if (timer.current) window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setNotice(null), DECISION_NOTICE_MS)
  }, [])
  return [notice, show]
}

export function DecisionNotice({ notice }: { notice: string | null }) {
  if (!notice) return null
  return (
    <div role="status" aria-live="polite" data-testid="approval-decided" className="card"
      style={{ padding: '8px 12px', marginBottom: 12, borderColor: 'var(--accent-teal)', fontSize: 13 }}>
      {notice}
    </div>
  )
}

/** Approval card for a waiting run. After a decision the given query keys are refreshed (the card then
 *  disappears with the run); the confirmation is reported to the page through ``onDecided``. */
export function RunApproval({ flowId, runId, refresh = [], onDecided }: {
  flowId: string; runId: string; refresh?: string[][]; onDecided?: (message: string) => void
}) {
  const qc = useQueryClient()
  const q = useRunEventsOnce(flowId, runId)
  const approval = useMemo(() => (q.data ? pendingApproval(q.data) : undefined), [q.data])
  const [deciding, setDeciding] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (q.isLoading) return <div className="text-muted" style={{ fontSize: 12 }}>Loading approval…</div>
  if (!approval) return null

  const onDecide = async (approve: boolean, confirmLookalike = false) => {
    setDeciding(true)
    setError(null)
    try {
      await decideApproval(flowId, runId, approval.nodeId, approve, confirmLookalike)
      onDecided?.(approve ? `Approved: ${runId} continues.` : `Rejected: nothing was sent for ${runId}.`)
      setDeciding(false)
      for (const key of [['run-events', flowId, runId], ...refresh]) await qc.invalidateQueries({ queryKey: key })
    } catch (e) {
      setError(`Decision failed: ${apiErrorMessage(e)}`)
      setDeciding(false)
    }
  }

  return (
    <div data-testid="run-approval" data-run-id={runId}>
      <ApprovalCard
        approval={approval}
        deciding={deciding}
        onDecide={onDecide}
        title={
          <>
            Approval required: <code>{approval.nodeId}</code> in <Link to={runHref(flowId, runId)}>{flowId}</Link>
          </>
        }
      />
      {error && <div style={{ color: 'var(--accent-red)', fontSize: 12, margin: '0 8px' }}>{error}</div>}
    </div>
  )
}

/** Blocked calls of one run with provenance chains; optionally only the given event seqs. */
export function RunBlocked({ flowId, runId, seqs }: { flowId: string; runId: string; seqs?: number[] }) {
  const q = useRunEventsOnce(flowId, runId)
  const blocked = useMemo(() => {
    const all = q.data ? blockedCalls(q.data) : []
    return seqs ? all.filter(b => seqs.includes(b.seq)) : all
  }, [q.data, seqs])
  if (q.isLoading) return <div className="text-muted" style={{ fontSize: 12 }}>Loading provenance…</div>
  return (
    <div data-testid="run-blocked" data-run-id={runId} style={{ fontSize: 12 }}>
      <div className="text-muted" style={{ marginBottom: 4 }}>
        Run <Link to={runHref(flowId, runId)}><code>{runId}</code></Link> · flow <code>{flowId}</code>
      </div>
      <BlockedList blocked={blocked} empty="Blocked event found, but its provenance could not be rebuilt." />
    </div>
  )
}
