// src/pages/AuditLog.tsx — 3.1: Govern > Audit log. The tamper-evident record of security-relevant actions
// (flow save/publish, approvals, webhooks, schedules, vault names, providers, MCP, config, auth failures).
// Details are metadata only and are shown as plain text (never rendered as HTML).

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { exportAudit, listAudit, verifyAudit, type AuditEntry, type AuditFilters, type AuditVerify } from '../api/audit'

const OUTCOME_COLOR: Record<string, string> = {
  ok: 'var(--accent-teal, #2dd4bf)', refused: 'var(--accent-red)', failed: 'var(--accent-amber)',
}

export function ChainBadge({ v, testid = 'audit-chain-badge' }: { v?: AuditVerify; testid?: string }) {
  if (!v) return <span className="badge badge-default" data-testid={testid} data-status="loading">Checking chain…</span>
  if (v.status === 'broken') {
    return (
      <span className="badge" data-testid={testid} data-status="broken" title={v.reason ?? ''}
        style={{ background: 'rgba(239,68,68,0.15)', color: 'var(--accent-red)' }}>
        Broken at #{v.first_broken_seq}
      </span>
    )
  }
  const n = v.entries_checked.toLocaleString('en-US')
  return (
    <span className="badge" data-testid={testid} data-status={v.status}
      style={{ background: 'rgba(45,212,191,0.15)', color: 'var(--accent-teal, #2dd4bf)' }}>
      {v.status === 'empty' ? 'Verified · no entries yet' : `Verified · ${n} ${v.entries_checked === 1 ? 'entry' : 'entries'}`}
    </span>
  )
}

/** Small status for the Overview footer. */
export function AuditChainStatus() {
  const q = useQuery({ queryKey: ['audit-verify'], queryFn: verifyAudit })
  if (q.isError) return <span className="text-muted" data-testid="overview-audit-status" data-status="error">Audit chain: could not verify</span>
  if (!q.data) return null
  const broken = q.data.status === 'broken'
  return (
    <span data-testid="overview-audit-status" data-status={q.data.status}
      style={{ color: broken ? 'var(--accent-red)' : 'var(--text-muted)', fontSize: 12 }}>
      {broken ? `Audit chain broken at #${q.data.first_broken_seq}` : 'Audit chain verified'}
    </span>
  )
}

function download(text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/x-ndjson' }))
  const a = document.createElement('a')
  a.href = url
  a.download = 'agentos-audit.jsonl'
  a.click()
  URL.revokeObjectURL(url)
}

export default function AuditLog() {
  const [filters, setFilters] = useState<AuditFilters>({ limit: 50 })
  const [cursor, setCursor] = useState<number[]>([])  // stack of before_seq values for paging back
  const [selected, setSelected] = useState<AuditEntry | null>(null)
  const page = useQuery({
    queryKey: ['audit', filters, cursor[cursor.length - 1]],
    queryFn: () => listAudit({ ...filters, before_seq: cursor[cursor.length - 1] }),
  })
  const verify = useQuery({ queryKey: ['audit-verify'], queryFn: verifyAudit })
  const set = (k: keyof AuditFilters, v: string) => { setCursor([]); setFilters(f => ({ ...f, [k]: v || undefined })) }

  return (
    <div data-testid="audit-page">
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div>
          <h2>Audit log</h2>
          <p>Every security-relevant action, in a hash chain keyed from the master key. Details are metadata only.</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <ChainBadge v={verify.data} />
          <button className="btn btn-ghost btn-sm" data-testid="audit-refresh" onClick={() => { page.refetch(); verify.refetch() }}>Refresh</button>
          <button className="btn btn-secondary btn-sm" data-testid="audit-export" onClick={async () => download(await exportAudit())}>Export JSONL</button>
        </div>
      </div>

      <div className="card mb-3 flex gap-2" style={{ flexWrap: 'wrap', padding: 10 }} data-testid="audit-filters">
        <input className="form-input" style={{ width: 180 }} placeholder="action (prefix, e.g. flow.)" aria-label="Action"
          data-testid="audit-filter-action" onChange={e => set('action', e.target.value.trim())} />
        <input className="form-input" style={{ width: 140 }} placeholder="actor" aria-label="Actor"
          data-testid="audit-filter-actor" onChange={e => set('actor', e.target.value.trim())} />
        <input className="form-input" style={{ width: 140 }} placeholder="target type" aria-label="Target type"
          data-testid="audit-filter-target-type" onChange={e => set('target_type', e.target.value.trim())} />
        <input className="form-input" style={{ width: 160 }} placeholder="target id" aria-label="Target id"
          data-testid="audit-filter-target-id" onChange={e => set('target_id', e.target.value.trim())} />
        <select className="form-select" style={{ width: 130 }} aria-label="Outcome" data-testid="audit-filter-outcome"
          onChange={e => set('outcome', e.target.value)}>
          <option value="">any outcome</option>
          <option value="ok">ok</option>
          <option value="refused">refused</option>
          <option value="failed">failed</option>
        </select>
        <input className="form-input" style={{ width: 200 }} type="datetime-local" aria-label="Since"
          data-testid="audit-filter-since" onChange={e => set('since', e.target.value ? new Date(e.target.value).toISOString() : '')} />
        <input className="form-input" style={{ width: 200 }} type="datetime-local" aria-label="Until"
          data-testid="audit-filter-until" onChange={e => set('until', e.target.value ? new Date(e.target.value).toISOString() : '')} />
      </div>

      <div className="card" style={{ padding: 0 }}>
        {page.isLoading ? <div className="text-muted" style={{ padding: 12 }}>Loading…</div> : (
          <table className="table" style={{ width: '100%', fontSize: 13 }} data-testid="audit-table">
            <thead>
              <tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th></tr>
            </thead>
            <tbody>
              {(page.data?.entries ?? []).map(e => (
                <tr key={e.seq} data-testid="audit-row" data-seq={e.seq} data-action={e.action} data-outcome={e.outcome}
                  style={{ cursor: 'pointer' }} onClick={() => setSelected(e)}>
                  <td className="text-muted">{e.seq}</td>
                  <td className="text-muted">{new Date(e.ts).toLocaleString()}</td>
                  <td>{e.actor} <span className="text-muted">({e.source})</span></td>
                  <td className="font-mono">{e.action}</td>
                  <td><span className="text-muted">{e.target.type}</span> <code>{e.target.id}</code></td>
                  <td style={{ color: OUTCOME_COLOR[e.outcome] }}>{e.outcome}</td>
                </tr>
              ))}
              {page.data && page.data.entries.length === 0 && (
                <tr><td colSpan={6} className="text-muted" data-testid="audit-empty" style={{ padding: 12 }}>No entries match.</td></tr>
              )}
            </tbody>
          </table>
        )}
        <div className="flex gap-2" style={{ padding: 8 }}>
          <button className="btn btn-ghost btn-sm" data-testid="audit-newer" disabled={cursor.length === 0}
            onClick={() => setCursor(c => c.slice(0, -1))}>Newer</button>
          <button className="btn btn-ghost btn-sm" data-testid="audit-older" disabled={!page.data?.next_before_seq}
            onClick={() => page.data?.next_before_seq && setCursor(c => [...c, page.data!.next_before_seq!])}>Older</button>
        </div>
      </div>

      {selected && (
        <div className="modal-overlay" onClick={ev => ev.target === ev.currentTarget && setSelected(null)}>
          <div className="modal" style={{ maxWidth: 640 }} data-testid="audit-drawer">
            <div className="modal-header">
              <h3>#{selected.seq} · <span className="font-mono">{selected.action}</span></h3>
              <button className="btn btn-ghost btn-sm" aria-label="Close" data-testid="audit-drawer-close" onClick={() => setSelected(null)}>×</button>
            </div>
            <div style={{ fontSize: 13 }}>
              <div>{new Date(selected.ts).toLocaleString()} · {selected.actor} ({selected.source}) · <span style={{ color: OUTCOME_COLOR[selected.outcome] }}>{selected.outcome}</span></div>
              <div className="mt-1">Target: {selected.target.type} <code>{selected.target.id}</code></div>
              <div className="form-label mt-2">Details</div>
              {/* plain text: rendered as a string, never as HTML */}
              <pre data-testid="audit-details" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12, background: 'var(--bg-hover)', padding: 8, borderRadius: 6 }}>
                {JSON.stringify(selected.details, null, 2)}
              </pre>
              <div className="text-muted mt-2" style={{ fontSize: 11, wordBreak: 'break-all' }}>
                hash {selected.hash}<br />prev {selected.prev_hash}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
