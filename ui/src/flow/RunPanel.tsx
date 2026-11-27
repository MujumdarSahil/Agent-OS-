// src/flow/RunPanel.tsx — 2.4d run & inspect: the Run dialog and the bottom results panel.
// Live events over the WebSocket (token subprotocol, after_seq replay on reconnect); tabs for
// Output | Steps | Logs | Security; inline approval (THREAT_MODEL T-14); node input/output with
// labels; run history for the flow (manual, webhook, schedule).
// Safety (T-12): run values are untrusted and are rendered only as plain text via
// <UntrustedText>; nothing here renders markdown/HTML or loads remote content.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { needs, useAuth } from '../components/AuthContext'
import { useQuery } from '@tanstack/react-query'
import { apiErrorMessage, decideApproval, listRuns, runEventsUrl, startRun } from '../api/flows'
import {
  blockedCalls, eventSummary, finalOutput, formatMs, lastDecision, mergeEvents, missingSeqs, nodeIO, nodeStatuses,
  pendingApproval,
  runStatusFromEvents, runTiming, stepTimeline, triggerOf,
  type BlockedCall, type DestinationWarning, type LabelInfo, type PendingApproval, type RunEvent,
} from './runModel'
import type { NodeRunStatus } from './flowGraph'
import { declassificationText, declassifiedBy, visibleSources } from './ExtractionConfig'
import { SandboxCalls } from './SandboxWidgets'
import { sendToReview } from '../api/review'

type ConnState = 'idle' | 'connecting' | 'open' | 'closed' | 'finished'
type Tab = 'output' | 'steps' | 'logs' | 'security'

/** Renders any value as inert text. Never markdown, never HTML, never a link or image. */
export function UntrustedText({ value, untrusted = true }: { value: unknown; untrusted?: boolean }) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2) ?? String(value)
  return (
    <pre
      data-testid="untrusted-text"
      data-untrusted={untrusted ? 'true' : 'false'}
      style={{
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        margin: 0,
        padding: '4px 6px',
        fontSize: 12,
        borderRadius: 4,
        maxHeight: 220,
        overflow: 'auto',
        background: untrusted ? 'rgba(245,158,11,0.10)' : 'var(--bg-input)',
        border: untrusted ? '1px dashed var(--accent-amber)' : '1px solid var(--border)',
      }}
    >
      {text}
    </pre>
  )
}

/** 3.2: the run's model calls, tokens and estimated cost (from its llm_call events). */
function RunCostTotal({ steps }: { steps: { llm: { tokens: number; costUsd?: number | null }[] }[] }) {
  const calls = steps.flatMap(s => s.llm)
  if (!calls.length) return null
  const known = calls.filter(c => typeof c.costUsd === 'number')
  const unknown = calls.filter(c => c.costUsd === null).length
  const total = known.reduce((a, c) => a + (c.costUsd as number), 0)
  const tokens = calls.reduce((a, c) => a + c.tokens, 0)
  return (
    <div data-testid="run-cost-total" style={{ fontSize: 12, marginBottom: 6 }}>
      Run total: {calls.length} model call{calls.length === 1 ? '' : 's'} · {tokens} tokens · <strong data-testid="run-cost-usd">${total.toFixed(4)}</strong>
      {unknown > 0 && <span className="text-muted"> (+{unknown} with unknown price)</span>}
      <span className="text-muted"> · estimate</span>
    </div>
  )
}

/** Integrity/confidentiality badge. A pinned value reads "pinned in flow" (its source is the flow author). */
export function LabelBadge({ label, pinned = false }: { label?: LabelInfo; pinned?: boolean }) {
  if (!label) return <span className="badge badge-default" data-testid="label-badge" data-integrity="unknown">label unknown</span>
  const untrusted = label.integrity !== 'trusted'
  // 2.5b: validator and extraction markers read "declassified by <kind> (<node>)", not as sources
  const declassified = untrusted ? [] : declassifiedBy(label)
  const sources = visibleSources(label)
  return (
    <span
      className="badge"
      data-testid="label-badge"
      data-integrity={label.integrity}
      data-declassified={declassified.length ? [...new Set(declassified.map(d => d.kind))].join(' ') : undefined}
      style={{ background: untrusted ? 'rgba(239,68,68,0.15)' : 'rgba(45,212,191,0.15)', color: untrusted ? 'var(--accent-red)' : 'var(--accent-teal, #2dd4bf)' }}
      title={`confidentiality: ${label.confidentiality}; sources: ${pinned ? 'pinned in flow' : sources.join(', ') || '-'}`}
    >
      {untrusted ? 'UNTRUSTED' : 'trusted'}
      {declassified.length ? ` · ${declassificationText(label)}` : ''} · {label.confidentiality}
      {!pinned && sources.length ? ` · from ${sources.join(', ')}` : ''}
    </span>
  )
}

/** 2.4d-fix approval card: the exact sink call with every argument and its label (reused on Overview/Approvals). */
export function ApprovalCard({
  approval, deciding, onDecide, title,
}: {
  approval: PendingApproval
  deciding: boolean
  onDecide: (approve: boolean, confirmLookalike?: boolean) => void
  title?: React.ReactNode
}) {
  const canApprove = useAuth().can('approve') // 3.4: display only; the server refuses other roles
  const warnings = approval.destinationWarnings ?? []
  const [confirming, setConfirming] = useState(false)
  return (
    <div className="card" style={{ margin: 8, padding: 10, borderColor: 'var(--accent-amber)' }} data-testid="approval-card">
      <div className="font-semibold">{title ?? <>Approval required: {approval.nodeId}</>}</div>
      <div className="text-muted" style={{ fontSize: 12 }}>Author prompt:</div>
      <UntrustedText value={approval.prompt} untrusted={false} />
      <div className="mt-2" style={{ fontSize: 12 }}>
        Approving releases this <strong>exact</strong> call to sink <code>{approval.sinkNode ?? '?'}</code>
        {approval.sinkArgs ? <> (every argument it will receive)</> : null}.
        Values marked UNTRUSTED came from outside sources and are shown as plain text; pinned values are fixed in the flow.
      </div>
      <table style={{ width: '100%', fontSize: 12, marginTop: 6 }} data-testid="approval-call">
        <tbody>
          {(approval.sinkArgs ?? approval.args.map(a => ({ ...a, pinned: false, pending: false, source: undefined }))).map(a => (
            <tr
              key={a.name}
              data-testid={`approval-arg-${a.name}`}
              data-integrity={a.label?.integrity ?? 'unknown'}
              data-pinned={a.pinned ? 'true' : 'false'}
            >
              <td className="font-mono" style={{ verticalAlign: 'top', paddingRight: 6 }}>{a.name}</td>
              <td>
                <LabelBadge label={a.label} pinned={a.pinned} />
                {a.pinned && <span className="badge badge-default" data-testid="approval-pinned" style={{ marginLeft: 4 }}>pinned in flow</span>}
                {a.pending ? (
                  <div className="text-muted" data-testid="approval-pending">not known yet (comes from {a.source ?? '?'}, which has not run)</div>
                ) : (
                  <UntrustedText value={a.value} untrusted={a.label?.integrity !== 'trusted'} />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {warnings.length > 0 && <LookalikeWarnings warnings={warnings} />}
      <div className="flex gap-2 mt-2" title={canApprove ? undefined : needs('approve')}>
        {warnings.length > 0 && confirming ? (
          <button className="btn btn-danger btn-sm" data-testid="approve-confirm-lookalike" disabled={deciding || !canApprove}
                  onClick={() => onDecide(true, true)}>
            Yes, send to this exact address ({warnings.map(w => w.ascii_form).join(', ')})
          </button>
        ) : (
          <button className="btn btn-primary btn-sm" data-testid="approve" disabled={deciding || !canApprove}
                  onClick={() => (warnings.length > 0 ? setConfirming(true) : onDecide(true))}>Approve these values</button>
        )}
        <button className="btn btn-danger btn-sm" data-testid="reject" disabled={deciding || !canApprove} onClick={() => onDecide(false)}>Reject</button>
      </div>
    </div>
  )
}

/** 4.1b: red warning for destinations with non-ASCII or look-alike characters, with the punycode/escaped form. */
export function LookalikeWarnings({ warnings }: { warnings: DestinationWarning[] }) {
  return (
    <div data-testid="lookalike-warnings" className="mt-2" style={{ border: '1px solid var(--accent-red)', borderRadius: 6, padding: 8, background: 'rgba(239,68,68,0.10)' }}>
      {warnings.map((w, i) => (
        <div key={`${w.arg}-${i}`} data-testid="lookalike-warning" data-confusable={w.confusable ? 'true' : 'false'} style={{ fontSize: 12 }}>
          <span className="badge" style={{ background: 'var(--accent-red)', color: '#fff' }}>look-alike characters</span>{' '}
          <code>{w.arg}</code>: <span className="font-mono">{w.value}</span> is really{' '}
          <strong className="font-mono" data-testid="lookalike-ascii">{w.ascii_form}</strong>
          <div className="text-muted">{w.confusable ? 'Looks like another address. ' : 'Non-English characters. '}{w.reasons.join('; ')}</div>
        </div>
      ))}
      <div style={{ fontSize: 12, marginTop: 4 }}>Approving needs a second click that confirms this exact address.</div>
    </div>
  )
}

/** Blocked or refused calls with reason and provenance chain (Security tab, Overview, Security log). */
export function BlockedList({ blocked, empty }: { blocked: BlockedCall[]; empty?: string }) {
  if (!blocked.length) return <div className="text-muted" data-testid="security-empty">{empty ?? 'No blocked calls in this run.'}</div>
  return (
    <div data-testid="blocked-calls">
      {blocked.map(b => (
        <div key={`${b.nodeId}-${b.seq}`} className="mb-2" data-testid="blocked-call" data-node={b.nodeId}>
          <div><code>{b.nodeId}</code> · {b.kind} (#{b.seq})</div>
          <div data-testid="blocked-reason" style={{ color: 'var(--accent-red)' }}>Reason: {b.reason}</div>
          <ol style={{ fontSize: 11, margin: '4px 0 0 16px' }} data-testid="provenance-chain">
            {b.chain.map((s, i) => (
              <li key={i} data-testid="provenance-step" style={{ color: s.untrusted ? 'var(--accent-red)' : undefined }}>
                {s.text}{s.seq ? ` #${s.seq}` : ''}
              </li>
            ))}
          </ol>
        </div>
      ))}
    </div>
  )
}

/** Key/value table: each value with its label; anything not trusted is shown as untrusted text. */
/** `selfNode`: a trusted value whose only source is this node was pinned in the flow (reads "pinned in flow"). */
function LabelledValues({ values, labels, testid, selfNode }: { values?: Record<string, unknown>; labels: Record<string, LabelInfo>; testid: string; selfNode?: string }) {
  const keys = Object.keys(values ?? {})
  const pinnedHere = (lbl?: LabelInfo) =>
    !!selfNode && lbl?.integrity === 'trusted' && (lbl.sources ?? []).length === 1 && lbl.sources[0] === selfNode
  if (!keys.length) return <div className="text-muted" style={{ fontSize: 12 }} data-testid={`${testid}-empty`}>none</div>
  return (
    <table style={{ width: '100%', fontSize: 12 }} data-testid={testid}>
      <tbody>
        {keys.map(k => {
          const lbl = labels[k] ?? labels['*']
          return (
            <tr key={k} data-testid={`${testid}-row`} data-key={k} data-integrity={lbl?.integrity ?? 'unknown'}>
              <td className="font-mono" style={{ verticalAlign: 'top', paddingRight: 6, whiteSpace: 'nowrap' }}>{k}</td>
              <td>
                <LabelBadge label={lbl} pinned={pinnedHere(lbl)} />
                {pinnedHere(lbl) && <span className="badge badge-default" data-testid="value-pinned" style={{ marginLeft: 4 }}>pinned in flow</span>}
                <UntrustedText value={values![k]} untrusted={lbl?.integrity !== 'trusted'} />
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/** WebSocket event stream with gap-free resume: reconnects with after_seq = last seen seq. */
function useRunEvents(flowId: string, runId: string | null) {
  const [events, setEvents] = useState<RunEvent[]>([])
  const [conn, setConn] = useState<ConnState>('idle')
  const [finished, setFinished] = useState<{ status: string; error?: string | null } | null>(null)
  const [connects, setConnects] = useState(0)
  const lastSeq = useRef(0)
  const ws = useRef<WebSocket | null>(null)
  const done = useRef(false)
  const retry = useRef<number | null>(null)

  const open = useCallback(() => {
    if (!runId || done.current) return
    setConn('connecting')
    // 3.4: the HttpOnly session cookie authenticates the upgrade (no token in the page)
    const sock = new WebSocket(runEventsUrl(flowId, runId, lastSeq.current), ['agentos.v1'])
    ws.current = sock
    sock.onopen = () => {
      setConn('open')
      setConnects(c => c + 1)
    }
    sock.onmessage = msg => {
      let parsed: unknown
      try {
        parsed = JSON.parse(String(msg.data))
      } catch {
        return
      }
      const m = parsed as Partial<RunEvent> & { event?: string; status?: string; error?: string | null }
      if (m.event === 'run_finished') {
        done.current = true
        setFinished({ status: String(m.status), error: m.error })
        setConn('finished')
        return
      }
      if (typeof m.seq === 'number' && typeof m.type === 'string') {
        const ev = { run_id: String(m.run_id), seq: m.seq, type: m.type, data: (m.data ?? {}) as Record<string, unknown>, ts: m.ts }
        lastSeq.current = Math.max(lastSeq.current, ev.seq)
        setEvents(prev => mergeEvents(prev, [ev]))
      }
    }
    sock.onclose = () => {
      if (ws.current !== sock) return
      ws.current = null
      if (done.current) return
      setConn('closed')
      // One scheduled reconnect after an unexpected drop (no polling loop).
      retry.current = window.setTimeout(open, 500)
    }
  }, [flowId, runId])

  useEffect(() => {
    lastSeq.current = 0
    done.current = false
    setEvents([])
    setFinished(null)
    setConnects(0)
    open()
    return () => {
      done.current = true
      if (retry.current) window.clearTimeout(retry.current)
      ws.current?.close()
      ws.current = null
    }
  }, [open])

  /** Drop the socket; the onclose handler reconnects with after_seq. */
  const reconnect = useCallback(() => ws.current?.close(), [])

  return { events, conn, finished, connects, reconnect }
}

// ---------------------------------------------------------------------------- Run dialog

export function RunDialog({
  flowId,
  sample,
  onClose,
  onStarted,
}: {
  flowId: string
  sample?: unknown
  onClose: () => void
  onStarted: (runId: string) => void
}) {
  const [inputText, setInputText] = useState(() => JSON.stringify(sample ?? {}, null, 2))
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setError(null)
    let inputs: Record<string, unknown>
    try {
      const parsed = JSON.parse(inputText)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Inputs must be a JSON object.')
      inputs = parsed
    } catch (e) {
      setError(`Invalid JSON input: ${(e as Error).message}`)
      return
    }
    setBusy(true)
    try {
      const r = await startRun(flowId, inputs)
      onStarted(r.run_id)
    } catch (e) {
      setError(`Run failed to start: ${apiErrorMessage(e)}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      role="dialog"
      aria-label="Run flow"
      data-testid="run-dialog"
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onKeyDown={e => e.key === 'Escape' && onClose()}
    >
      <div className="card" style={{ width: 560, maxWidth: '92vw', padding: 16 }}>
        <div className="font-semibold mb-1">Run the latest published version</div>
        <label className="form-label" htmlFor="run-input">Input (JSON)</label>
        <div className="text-muted" style={{ fontSize: 11, color: 'var(--accent-amber)' }} data-testid="untrusted-input-note">
          Inputs are treated as untrusted.
        </div>
        <textarea
          id="run-input"
          className="form-textarea font-mono"
          data-testid="run-input"
          rows={10}
          autoFocus
          value={inputText}
          onChange={e => setInputText(e.target.value)}
        />
        {error && <div style={{ color: 'var(--accent-red)', fontSize: 12 }} data-testid="run-error">{error}</div>}
        <div className="flex gap-2 mt-2" style={{ justifyContent: 'flex-end' }}>
          <button className="btn btn-ghost btn-sm" data-testid="run-cancel" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary btn-sm" data-testid="run-flow" onClick={run} disabled={busy}>Run</button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------- results panel

const STATUS_COLOR: Record<string, string> = {
  succeeded: 'var(--accent-green)', failed: 'var(--accent-red)', blocked: 'var(--accent-red)',
  waiting: 'var(--accent-amber)', running: 'var(--accent-blue, #60a5fa)', queued: 'var(--text-muted)',
}

export default function ResultsPanel({
  flowId,
  runId,
  onSelectRun,
  inspectNode,
  inspectSeq = 0,
  onInspectNode,
  onStatuses,
  onClose,
  dock = 'bottom',
  onSaveAsTest,
}: {
  dock?: 'bottom' | 'right'
  /** 4.2: "Save as test case" (builders); absent for viewers */
  onSaveAsTest?: (runId: string) => void
  /** bumped on every selection, so re-selecting the same node scrolls and flashes again */
  inspectSeq?: number
  flowId: string
  runId: string | null
  onSelectRun: (runId: string) => void
  inspectNode: string | null
  onInspectNode: (nodeId: string | null) => void
  onStatuses: (s: Record<string, NodeRunStatus>) => void
  onClose: () => void
}) {
  const [tab, setTab] = useState<Tab>('output')
  const [height, setHeight] = useState(320)
  const [width, setWidth] = useState(470) // 2.4e: right-docked panel (top-to-bottom flows)
  const right = dock === 'right'
  const [collapsed, setCollapsed] = useState(false)
  const [deciding, setDeciding] = useState(false)
  const [sendingReview, setSendingReview] = useState(false)
  const [reviewSent, setReviewSent] = useState(false)
  const [copiedTrace, setCopiedTrace] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [, setTick] = useState(0)
  const { events, conn, finished, connects, reconnect } = useRunEvents(flowId, runId)

  const history = useQuery({ queryKey: ['runs', flowId], queryFn: () => listRuns(flowId) })
  const refetchHistory = history.refetch
  // Refresh the history whenever the selected run changes status (queued -> running -> waiting -> ...).
  const liveStatus = finished?.status ?? runStatusFromEvents(events)
  useEffect(() => void refetchHistory(), [runId, liveStatus, refetchHistory])

  const statuses = useMemo(() => nodeStatuses(events), [events])
  useEffect(() => onStatuses(statuses), [statuses, onStatuses])
  const approval = useMemo(() => pendingApproval(events), [events])
  const decision = useMemo(() => lastDecision(events), [events]) // 3.4: who decided
  const blocked = useMemo(() => blockedCalls(events), [events])
  const steps = useMemo(() => stepTimeline(events), [events])
  const gaps = useMemo(() => missingSeqs(events), [events])
  const output = useMemo(() => finalOutput(events), [events])
  const io = useMemo(() => (inspectNode ? nodeIO(events, inspectNode) : undefined), [events, inspectNode])
  // 3.4 Part 0c: every node selection (canvas or Steps row) brings the inspector into view and flashes it
  const inspectorRef = useRef<HTMLDivElement | null>(null)
  useEffect(() => {
    const el = inspectorRef.current
    if (!inspectNode || !el) return
    el.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' })
    el.classList.remove('inspector-highlight')
    void el.offsetWidth // restart the animation on a repeated selection
    el.classList.add('inspector-highlight')
  }, [inspectNode, inspectSeq])
  const runStatus = finished?.status ?? runStatusFromEvents(events) ?? (runId ? 'queued' : '')
  const sends = events.filter(e => e.type === 'sink_committed').length
  // 3.3: a send with no configured channel is SIMULATED; say so (AgentOS-written reason from the sink result)
  const simulated = events
    .filter(e => e.type === 'sink_committed' && (e.data?.result as { status?: string } | undefined)?.status === 'simulated')
    .map(e => String((e.data?.result as { reason?: string }).reason ?? 'simulated'))

  // The running clock ticks once a second only while the run is live (no polling of the server).
  const live = !!runId && !finished && runStatus !== 'waiting'
  useEffect(() => {
    if (!live) return
    const t = window.setInterval(() => setTick(x => x + 1), 1000)
    return () => window.clearInterval(t)
  }, [live])

  // A security block is the most important thing to see: open the Security tab when one appears.
  const blockedCount = blocked.length
  useEffect(() => {
    if (blockedCount > 0) setTab('security')
  }, [blockedCount])

  const decide = async (approve: boolean, confirmLookalike = false) => {
    if (!runId || !approval) return
    setDeciding(true)
    setError(null)
    try {
      await decideApproval(flowId, runId, approval.nodeId, approve, confirmLookalike)
    } catch (e) {
      setError(`Decision failed: ${apiErrorMessage(e)}`)
    } finally {
      setDeciding(false)
    }
  }

  const handleSendToReview = async (targetNode?: string) => {
    if (!runId) return
    setSendingReview(true)
    setError(null)
    try {
      await sendToReview({ run_id: runId, node_id: targetNode || inspectNode || undefined })
      setReviewSent(true)
      setTimeout(() => setReviewSent(false), 3000)
    } catch (e) {
      setError(`Send to review failed: ${apiErrorMessage(e)}`)
    } finally {
      setSendingReview(false)
    }
  }

  const startResize = (e: React.MouseEvent) => {
    e.preventDefault()
    const y0 = e.clientY
    const x0 = e.clientX
    const h0 = height
    const w0 = width
    const move = (ev: MouseEvent) =>
      right
        ? setWidth(Math.min(Math.max(320, w0 + (x0 - ev.clientX)), window.innerWidth - 520))
        : setHeight(Math.min(Math.max(160, h0 + (y0 - ev.clientY)), window.innerHeight - 200))
    const up = () => {
      window.removeEventListener('mousemove', move)
      window.removeEventListener('mouseup', up)
    }
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
  }

  const runs = [...(history.data ?? [])].sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')))
  const isTestRun = runs.find(r => r.run_id === runId)?.trigger === 'test'

  return (
    <div
      className="card"
      data-testid="results-panel"
      data-dock={dock}
      style={right
        ? { padding: 0, display: 'flex', flexDirection: 'column', width: collapsed ? 'auto' : width, height: '100%', flexShrink: 0, position: 'relative' }
        : { padding: 0, display: 'flex', flexDirection: 'column', height: collapsed ? 'auto' : height, flexShrink: 0 }}
    >
      <div
        data-testid="results-resize"
        onMouseDown={startResize}
        title="Drag to resize"
        style={right
          ? { position: 'absolute', left: -4, top: 0, bottom: 0, width: 8, cursor: 'ew-resize', display: collapsed ? 'none' : undefined, zIndex: 2 }
          : { height: 6, cursor: 'ns-resize', borderBottom: '1px solid var(--border)', display: collapsed ? 'none' : undefined }}
      />
      <div className="flex items-center gap-3" style={{ padding: '6px 10px', fontSize: 12, borderBottom: collapsed ? undefined : '1px solid var(--border)', flexWrap: right ? 'wrap' : undefined, rowGap: 4 }}>
        <strong>Results</strong>
        {runId ? (
          <>
            <span>Run <code data-testid="run-id">{runId}</code></span>
            <span>Status: <strong data-testid="run-status" style={{ color: STATUS_COLOR[runStatus] }}>{runStatus}</strong></span>
            {(() => {
              const t = runTiming(events)
              if (t.waitingSince) {
                return (
                  <span>
                    Active: <span data-testid="run-duration">{formatMs(t.activeMs)}</span> ·{' '}
                    <span data-testid="run-waiting-since" style={{ color: STATUS_COLOR.waiting }}>
                      waiting since {new Date(t.waitingSince).toLocaleTimeString()}
                    </span>
                  </span>
                )
              }
              return (
                <span>
                  {t.waitingMs > 0 ? 'Active' : 'Duration'}: <span data-testid="run-duration">{formatMs(t.activeMs)}</span>
                  {t.waitingMs > 0 && <> · <span data-testid="run-waited">waited {formatMs(t.waitingMs)}</span></>}
                </span>
              )
            })()}
            {finished?.error ? <span data-testid="run-error-reason" style={{ color: 'var(--accent-red)' }}>{finished.error}</span> : null}
            <span className="text-muted">
              stream <span data-testid="ws-state">{conn}</span> · connections <span data-testid="ws-connects">{connects}</span> ·
              sends <span data-testid="send-count">{sends}</span> · missing events <span data-testid="missing-seqs">{gaps.length}</span>
            </span>
            {simulated.length > 0 && (
              <span data-testid="simulated-sends" style={{ color: 'var(--accent-amber)' }} title="Configure a channel in Connect > Notification channels">
                {simulated.length} send{simulated.length === 1 ? '' : 's'} {[...new Set(simulated)].join('; ')}
              </span>
            )}
            <button className="btn btn-ghost btn-sm" data-testid="ws-reconnect" onClick={reconnect} disabled={conn !== 'open'}>Reconnect</button>
            <button className="btn btn-ghost btn-sm" data-testid="send-to-review-btn" onClick={() => void handleSendToReview()} disabled={sendingReview || reviewSent}>
              {reviewSent ? 'Sent to review' : sendingReview ? 'Sending…' : 'Send to review'}
            </button>
            {onSaveAsTest && runId && (
              <button className="btn btn-ghost btn-sm" data-testid="save-as-test" onClick={() => onSaveAsTest(runId)}
                      title="Make a test case from this run: input, recorded responses and suggested expectations">
                Save as test case
              </button>
            )}
            {(() => {
              const selectedRun = runs.find(r => r.run_id === runId)
              if (!selectedRun?.trace_id) return null
              return (
                <span className="flex items-center gap-1" data-testid="trace-id-container">
                  Trace <code data-testid="trace-id">{selectedRun.trace_id}</code>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    data-testid="copy-trace-id"
                    onClick={() => {
                      void navigator.clipboard?.writeText(selectedRun.trace_id!)
                      setCopiedTrace(true)
                      setTimeout(() => setCopiedTrace(false), 2000)
                    }}
                    title="Copy trace ID"
                  >
                    {copiedTrace ? 'Copied!' : 'Copy'}
                  </button>
                </span>
              )
            })()}
          </>
        ) : (
          <span className="text-muted" data-testid="results-empty">No run selected. Use Run, or pick a run from the history.</span>
        )}
        <div className="ml-auto flex gap-2">
          <button className="btn btn-ghost btn-sm" data-testid="results-collapse" onClick={() => setCollapsed(c => !c)}>
            {collapsed ? 'Expand' : 'Collapse'}
          </button>
          <button className="btn btn-ghost btn-sm" data-testid="results-close" onClick={onClose}>Close</button>
        </div>
      </div>

      {!collapsed && (
        <div className="flex" style={{ flex: 1, minHeight: 0, flexDirection: right ? 'column' : 'row' }}>
          {/* run history */}
          <div
            style={right
              ? { maxHeight: 110, borderBottom: '1px solid var(--border)', overflowY: 'auto', fontSize: 12, flexShrink: 0 }
              : { width: 230, borderRight: '1px solid var(--border)', overflowY: 'auto', fontSize: 12 }}
            data-testid="run-history"
          >
            <div className="form-label" style={{ padding: '6px 8px 0' }}>History</div>
            {runs.length === 0 && <div className="text-muted" style={{ padding: 8 }}>No runs yet.</div>}
            {runs.map(r => (
              <button
                key={r.run_id}
                data-testid="history-row"
                data-run-id={r.run_id}
                data-trigger={triggerOf(r)}
                data-status={r.status}
                onClick={() => onSelectRun(r.run_id)}
                style={{
                  display: 'block', width: '100%', textAlign: 'left', padding: '5px 8px', border: 0, cursor: 'pointer',
                  background: r.run_id === runId ? 'var(--bg-input)' : 'transparent', color: 'inherit',
                }}
              >
                <span className="badge badge-default" style={{ marginRight: 4 }}>{triggerOf(r)}</span>
                {(() => {
                  // The selected run shows its live status (the list can lag behind the stream).
                  const s = r.run_id === runId && runStatus ? runStatus : r.status
                  return <span data-testid="history-status" style={{ color: STATUS_COLOR[s] }}>{s}</span>
                })()}
                <div className="text-muted" style={{ fontSize: 11 }}>{r.created_at ? new Date(r.created_at).toLocaleString() : r.run_id}</div>
              </button>
            ))}
          </div>

          {/* main area: approval + tabs */}
          <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: 'flex', flexDirection: 'column', overflowY: right ? 'auto' : undefined }}>
            {error && <div style={{ color: 'var(--accent-red)', padding: '4px 10px' }} data-testid="run-error">{error}</div>}
            {/* 4.2: a test run's approval is decided only by its test case (the API refuses with 409) */}
            {approval && isTestRun && (
              <div className="card text-muted" style={{ margin: 8, padding: 8, fontSize: 12 }} data-testid="test-run-note">
                This is a test run: only its test case decides approvals; nothing here can resume it.
              </div>
            )}
            {approval && !isTestRun && <ApprovalCard approval={approval} deciding={deciding} onDecide={decide} />}
            {!approval && decision && (
              <div className="card" style={{ margin: 8, padding: 8, fontSize: 12 }} data-testid="approval-decided">
                Approval <code>{decision.nodeId}</code>: <strong>{decision.approved ? 'approved' : 'rejected'}</strong> by{' '}
                <strong data-testid="approval-decided-by">{decision.by}</strong>
              </div>
            )}

            <div className="flex gap-1" role="tablist" style={{ padding: '6px 8px 0' }}>
              {(['output', 'steps', 'logs', 'security'] as Tab[]).map(t => (
                <button
                  key={t}
                  role="tab"
                  aria-selected={tab === t}
                  data-testid={`tab-${t}`}
                  className={`btn btn-sm ${tab === t ? 'btn-secondary' : 'btn-ghost'}`}
                  onClick={() => setTab(t)}
                >
                  {t === 'output' ? 'Output' : t === 'steps' ? `Steps (${steps.length})` : t === 'logs' ? `Logs (${events.length})` : `Security${blocked.length ? ` (${blocked.length})` : ''}`}
                </button>
              ))}
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: 8, fontSize: 12 }} data-testid={`tab-panel-${tab}`}>
              {tab === 'output' && (
                output ? (
                  <div data-testid="final-output">
                    <div className="text-muted mb-1">Final output (last step: <code>{output.nodeId}</code>)</div>
                    <LabelledValues values={output.outputs as Record<string, unknown>} labels={output.labels} testid="final-output-values" />
                  </div>
                ) : (
                  <div className="text-muted">{runId ? 'No step has finished yet.' : 'Nothing to show.'}</div>
                )
              )}
              {tab === 'steps' && (
                <>
                <RunCostTotal steps={steps} />
                <table style={{ width: '100%' }} data-testid="step-timeline">
                  <tbody>
                    {steps.map(s => (
                      <tr
                        key={s.nodeId}
                        data-testid="step-row"
                        data-node={s.nodeId}
                        data-status={s.status}
                        onClick={() => onInspectNode(s.nodeId)}
                        style={{ cursor: 'pointer', background: s.nodeId === inspectNode ? 'var(--bg-input)' : undefined }}
                      >
                        <td className="font-mono" style={{ padding: '3px 6px' }}>{s.nodeId}</td>
                        <td style={{ color: STATUS_COLOR[s.status] }}>{s.status}</td>
                        <td data-testid="step-duration">{formatMs(s.durationMs)}</td>
                        <td data-testid="step-llm">
                          {s.llm.map((l, i) => (
                            <div key={i} data-testid="step-llm-call">{l.provider} · {l.model} · {l.tokens} tokens{l.costUsd !== undefined && <> · <span data-testid="step-cost">{l.costUsd === null ? 'price unknown' : `$${l.costUsd.toFixed(4)}`}</span></>} · {l.hops}</div>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {/* 3.5: sandbox calls (code, exit code, limit hit, stdout/stderr and files: UNTRUSTED) */}
                <SandboxCalls events={events} />
                </>
              )}
              {tab === 'logs' && (
                <ol style={{ margin: 0, paddingLeft: 18, fontSize: 11 }} data-testid="event-list">
                  {events.map(e => (
                    <li key={e.seq} data-testid="event-row" data-seq={e.seq} data-type={e.type} value={e.seq}>
                      <code>{e.type}</code> {eventSummary(e)}
                    </li>
                  ))}
                </ol>
              )}
              {tab === 'security' && <BlockedList blocked={blocked} />}
            </div>
          </div>

          {/* node inspector */}
          {inspectNode && (
            <div
              style={right
                ? { maxHeight: '45%', borderTop: '1px solid var(--border)', overflowY: 'auto', padding: 8, fontSize: 12, flexShrink: 0 }
                : { width: 340, borderLeft: '1px solid var(--border)', overflowY: 'auto', padding: 8, fontSize: 12 }}
              data-testid="node-inspector"
              data-node={inspectNode}
              ref={inspectorRef}
            >
              <div className="flex items-center mb-1">
                <strong className="font-mono">{inspectNode}</strong>
                <button
                  className="btn btn-ghost btn-sm ml-auto"
                  data-testid="node-send-to-review-btn"
                  onClick={() => void handleSendToReview(inspectNode)}
                  disabled={sendingReview || reviewSent}
                >
                  Send to review
                </button>
                <button className="btn btn-ghost btn-sm" data-testid="node-inspector-close" onClick={() => onInspectNode(null)}>×</button>
              </div>
              {!io ? (
                <div className="text-muted" data-testid="node-io-none">This step has not run in this run.</div>
              ) : (
                <>
                  <div className="form-label">Input</div>
                  <LabelledValues values={io.inputs} labels={io.inputLabels} testid="node-io-input" selfNode={inspectNode} />
                  <div className="form-label mt-2">Output</div>
                  {io.error ? (
                    <div style={{ color: 'var(--accent-red)' }} data-testid="node-io-error">{io.error}</div>
                  ) : (
                    <LabelledValues values={io.outputs} labels={io.outputLabels} testid="node-io-output" />
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
