// src/flow/RunPanel.tsx — run a published flow, stream live events over the WebSocket
// (token subprotocol, after_seq replay on reconnect), show blocked calls with provenance,
// and the approval card (THREAT_MODEL T-14).
// Safety (T-12): run values are untrusted and are rendered only as plain text via
// <UntrustedText>; nothing here renders markdown/HTML or loads remote content.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getAuthToken } from '../api/client'
import { apiErrorMessage, decideApproval, runEventsUrl, startRun } from '../api/flows'
import {
  blockedCalls, eventSummary, mergeEvents, missingSeqs, nodeStatuses, pendingApproval, runStatusFromEvents,
  type LabelInfo, type RunEvent,
} from './runModel'
import type { NodeRunStatus } from './flowGraph'

type ConnState = 'idle' | 'connecting' | 'open' | 'closed' | 'finished'

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
        background: untrusted ? 'rgba(245,158,11,0.10)' : 'var(--bg-input)',
        border: untrusted ? '1px dashed var(--accent-amber)' : '1px solid var(--border)',
      }}
    >
      {text}
    </pre>
  )
}

function LabelBadge({ label }: { label?: LabelInfo }) {
  if (!label) return <span className="badge badge-default" data-testid="label-badge" data-integrity="unknown">label unknown</span>
  const untrusted = label.integrity !== 'trusted'
  return (
    <span
      className="badge"
      data-testid="label-badge"
      data-integrity={label.integrity}
      style={{ background: untrusted ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)', color: untrusted ? 'var(--accent-red)' : 'var(--accent-green)' }}
      title={`confidentiality: ${label.confidentiality}; sources: ${label.sources.join(', ') || '-'}`}
    >
      {untrusted ? 'UNTRUSTED' : 'trusted'} · {label.confidentiality}
      {label.sources.length ? ` · from ${label.sources.join(', ')}` : ''}
    </span>
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
    const sock = new WebSocket(runEventsUrl(flowId, runId, lastSeq.current), [`agentos.token.${getAuthToken() || ''}`, 'agentos.v1'])
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

  return { events, conn, finished, connects, reconnect, lastSeq: lastSeq.current }
}

export default function RunPanel({
  flowId,
  canRun,
  onStatuses,
}: {
  flowId: string
  canRun: boolean
  onStatuses: (s: Record<string, NodeRunStatus>) => void
}) {
  const [inputText, setInputText] = useState('{\n  "text": "Customer reports the export button does nothing."\n}')
  const [runId, setRunId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [deciding, setDeciding] = useState(false)
  const { events, conn, finished, connects, reconnect } = useRunEvents(flowId, runId)

  const statuses = useMemo(() => nodeStatuses(events), [events])
  useEffect(() => onStatuses(statuses), [statuses, onStatuses])
  const approval = useMemo(() => pendingApproval(events), [events])
  const blocked = useMemo(() => blockedCalls(events), [events])
  const gaps = useMemo(() => missingSeqs(events), [events])
  const runStatus = finished?.status ?? runStatusFromEvents(events) ?? (runId ? 'queued' : '')
  const sends = events.filter(e => e.type === 'sink_committed').length

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
    try {
      const r = await startRun(flowId, inputs)
      setRunId(r.run_id)
    } catch (e) {
      setError(`Run failed to start: ${apiErrorMessage(e)}`)
    }
  }

  const decide = async (approve: boolean) => {
    if (!runId || !approval) return
    setDeciding(true)
    setError(null)
    try {
      await decideApproval(flowId, runId, approval.nodeId, approve)
    } catch (e) {
      setError(`Decision failed: ${apiErrorMessage(e)}`)
    } finally {
      setDeciding(false)
    }
  }

  return (
    <div className="flex flex-col gap-3" data-testid="run-panel">
      <div>
        <label className="form-label" htmlFor="run-input">Run input (JSON)</label>
        <div className="text-muted" style={{ fontSize: 11, color: 'var(--accent-amber)' }} data-testid="untrusted-input-note">
          Inputs are treated as untrusted.
        </div>
        <textarea
          id="run-input"
          className="form-textarea font-mono"
          data-testid="run-input"
          rows={5}
          value={inputText}
          onChange={e => setInputText(e.target.value)}
        />
        <button className="btn btn-primary btn-sm mt-2" data-testid="run-flow" onClick={run} disabled={!canRun}>
          Run latest published version
        </button>
        {!canRun && <div className="text-muted" style={{ fontSize: 11 }}>Publish the flow first.</div>}
      </div>

      {error && <div style={{ color: 'var(--accent-red)' }} data-testid="run-error">{error}</div>}

      {runId && (
        <div className="flex flex-col gap-1" style={{ fontSize: 12 }}>
          <div>Run <code data-testid="run-id">{runId}</code></div>
          <div>
            Status: <strong data-testid="run-status">{runStatus}</strong>
            {finished?.error ? <> · <span data-testid="run-error-reason">{finished.error}</span></> : null}
          </div>
          <div>
            Stream: <span data-testid="ws-state">{conn}</span> · connections <span data-testid="ws-connects">{connects}</span> ·
            sends <span data-testid="send-count">{sends}</span> · missing events <span data-testid="missing-seqs">{gaps.length}</span>
            <button className="btn btn-ghost btn-sm ml-2" data-testid="ws-reconnect" onClick={reconnect} disabled={conn !== 'open'}>
              Reconnect stream
            </button>
          </div>
        </div>
      )}

      {approval && (
        <div className="card" style={{ padding: 10, borderColor: 'var(--accent-amber)' }} data-testid="approval-card">
          <div className="font-semibold">Approval required: {approval.nodeId}</div>
          <div className="text-muted" style={{ fontSize: 12 }}>Author prompt:</div>
          <UntrustedText value={approval.prompt} untrusted={false} />
          <div className="mt-2" style={{ fontSize: 12 }}>
            You are approving these <strong>exact</strong> values for sink <code>{approval.sinkNode ?? '?'}</code>.
            Values marked UNTRUSTED came from outside sources and are shown as plain text.
          </div>
          <table style={{ width: '100%', fontSize: 12, marginTop: 6 }}>
            <tbody>
              {approval.args.map(a => (
                <tr key={a.name} data-testid={`approval-arg-${a.name}`} data-integrity={a.label?.integrity ?? 'unknown'}>
                  <td className="font-mono" style={{ verticalAlign: 'top', paddingRight: 6 }}>{a.name}</td>
                  <td>
                    <LabelBadge label={a.label} />
                    <UntrustedText value={a.value} untrusted={a.label?.integrity !== 'trusted'} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex gap-2 mt-2">
            <button className="btn btn-primary btn-sm" data-testid="approve" disabled={deciding} onClick={() => decide(true)}>Approve these values</button>
            <button className="btn btn-danger btn-sm" data-testid="reject" disabled={deciding} onClick={() => decide(false)}>Reject</button>
          </div>
        </div>
      )}

      {blocked.length > 0 && (
        <div className="card" style={{ padding: 10, borderColor: 'var(--accent-red)' }} data-testid="blocked-calls">
          <div className="font-semibold" style={{ color: 'var(--accent-red)' }}>Blocked</div>
          {blocked.map(b => (
            <div key={b.seq} className="mt-1" data-testid="blocked-call" data-node={b.nodeId}>
              <div style={{ fontSize: 12 }}><code>{b.nodeId}</code> · {b.kind} (#{b.seq})</div>
              <div style={{ fontSize: 12 }} data-testid="blocked-reason">Reason: {b.reason}</div>
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
      )}

      {runId && (
        <div data-testid="event-list" style={{ fontSize: 11 }}>
          <div className="form-label">Events</div>
          <ol style={{ margin: 0, paddingLeft: 18 }}>
            {events.map(e => (
              <li key={e.seq} data-testid="event-row" data-seq={e.seq} data-type={e.type} value={e.seq}>
                <code>{e.type}</code> {eventSummary(e)}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}
