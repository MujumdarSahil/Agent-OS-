// src/pages/Flows.tsx — flow list: create, open, archive, published versions (2.4).

import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiErrorMessage, archiveFlow, flowStatusLabel, listFlows, listVersions } from '../api/flows'
import { getReviewMetrics } from '../api/review'
import FlowSettingsModal from '../flow/FlowSettingsModal'

export default function Flows() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const flowsQ = useQuery({ queryKey: ['flows'], queryFn: listFlows })
  const [newId, setNewId] = useState('')
  const [newName, setNewName] = useState('')
  const [openVersions, setOpenVersions] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showNew, setShowNew] = useState(false)

  const archiveMut = useMutation({
    mutationFn: archiveFlow,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['flows'] }),
    onError: err => setError(apiErrorMessage(err)),
  })

  const create = () => {
    const id = newId.trim()
    if (!/^[A-Za-z0-9_-]+$/.test(id)) {
      setError('Flow id must use letters, digits, "_" or "-".')
      return
    }
    if (flowsQ.data?.some(f => f.id === id)) {
      setError(`Flow "${id}" already exists.`)
      return
    }
    // The flow is created on first Save in the editor (the server requires a valid entrypoint).
    navigate(`/flows/${encodeURIComponent(id)}?new=1&name=${encodeURIComponent(newName.trim() || id)}`)
  }

  // Several records may exist per id (draft + versions); show one row per id.
  const rows = Object.values(
    (flowsQ.data ?? []).reduce<Record<string, NonNullable<typeof flowsQ.data>[number]>>((acc, f) => {
      const prev = acc[f.id]
      if (!prev || (f.version ?? 0) >= (prev.version ?? 0)) acc[f.id] = f
      return acc
    }, {}),
  )

  return (
    <div>
      <div className="page-header">
        <h1>Flows</h1>
        <p className="text-muted">Visual flow builder. Publishing runs the static security check.</p>
      </div>

      <div className="mb-4">
        <button className="btn btn-primary" data-testid="new-flow-open" aria-expanded={showNew} onClick={() => setShowNew(v => !v)}>
          + New flow
        </button>
        {showNew && (
          <div className="flex gap-3 flex-wrap" style={{ marginTop: 10 }} data-testid="new-flow-cards">
            <div className="card" style={{ padding: 12, flex: '1 1 360px' }} data-testid="card-build-visually">
              <h3 style={{ marginTop: 0 }}>Build visually</h3>
              <p className="text-muted" style={{ fontSize: 12 }}>Start from an empty canvas and add nodes yourself.</p>
              <div className="flex gap-2 items-end flex-wrap">
                <div className="form-group">
                  <label className="form-label" htmlFor="new-flow-id">Flow id</label>
                  <input id="new-flow-id" className="form-input" data-testid="new-flow-id" value={newId} onChange={e => setNewId(e.target.value)} />
                </div>
                <div className="form-group">
                  <label className="form-label" htmlFor="new-flow-name">Name</label>
                  <input id="new-flow-name" className="form-input" data-testid="new-flow-name" value={newName} onChange={e => setNewName(e.target.value)} />
                </div>
                <button className="btn btn-primary" data-testid="create-flow" onClick={create} disabled={!newId.trim()}>Open editor</button>
              </div>
              {error && <div style={{ color: 'var(--accent-red)', marginTop: 8 }} data-testid="flows-error">{error}</div>}
            </div>
            <div className="card" style={{ padding: 12, flex: '1 1 360px' }} data-testid="card-describe-it">
              <h3 style={{ marginTop: 0 }}>Describe it</h3>
              <p className="text-muted" style={{ fontSize: 12 }}>
                Say in plain English what the flow should do. AgentOS drafts it, runs the security check, fixes or asks
                where it must not guess, and explains the result. You review it before anything is saved.
              </p>
              <Link to="/flows/describe" className="btn btn-primary" data-testid="open-describe-it">Describe it</Link>
            </div>
          </div>
        )}
      </div>

      {flowsQ.isLoading ? (
        <div className="empty-state">Loading…</div>
      ) : flowsQ.error ? (
        <div className="empty-state">Could not load flows: {apiErrorMessage(flowsQ.error)}</div>
      ) : rows.length === 0 ? (
        <div className="empty-state">No flows yet.</div>
      ) : (
        <div className="table-container">
          <table data-testid="flows-table">
            <thead>
              <tr><th>Id</th><th>Name</th><th>Status</th><th>Version</th><th /></tr>
            </thead>
            <tbody>
              {rows.map(f => (
                <FlowRow
                  key={f.id}
                  id={f.id}
                  name={f.name}
                  status={flowStatusLabel(f)}
                  version={f.published_version ?? f.version}
                  showVersions={openVersions === f.id}
                  onToggleVersions={() => setOpenVersions(v => (v === f.id ? null : f.id))}
                  onArchive={() => archiveMut.mutate(f.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function FlowRow(props: {
  id: string
  name: string
  status: string
  version: number | null
  showVersions: boolean
  onToggleVersions: () => void
  onArchive: () => void
}) {
  const [showSettings, setShowSettings] = useState(false)
  const versionsQ = useQuery({ queryKey: ['flow-versions', props.id], queryFn: () => listVersions(props.id), enabled: props.showVersions })
  const metricsQ = useQuery({ queryKey: ['flow-review-metrics', props.id, props.version], queryFn: () => getReviewMetrics(props.id, props.version ?? undefined) })
  const metrics = metricsQ.data

  return (
    <>
      <tr data-testid={`flow-row-${props.id}`}>
        <td className="font-mono"><Link to={`/flows/${encodeURIComponent(props.id)}`}>{props.id}</Link></td>
        <td>
          {props.name}
          {metrics && metrics.total_reviewed > 0 && (
            <span
              className="badge"
              data-testid={`quality-badge-${props.id}`}
              style={{
                marginLeft: 8,
                background: metrics.pct_good >= 80 ? 'rgba(45,212,191,0.15)' : 'rgba(239,68,68,0.15)',
                color: metrics.pct_good >= 80 ? 'var(--accent-teal)' : 'var(--accent-red)',
              }}
              title={`Reviewed: ${metrics.total_reviewed} (${metrics.good_count} good, ${metrics.bad_count} bad)`}
            >
              {Math.round(metrics.pct_good)}% good ({metrics.total_reviewed})
            </span>
          )}
        </td>
        <td><span className="badge badge-default">{props.status}</span></td>
        <td>{props.version ?? '-'}</td>
        <td className="flex gap-2">
          <button className="btn btn-ghost btn-sm" data-testid={`settings-${props.id}`} onClick={() => setShowSettings(true)}>Settings</button>
          <button className="btn btn-ghost btn-sm" data-testid={`versions-${props.id}`} onClick={props.onToggleVersions}>Versions</button>
          <button className="btn btn-danger btn-sm" data-testid={`archive-${props.id}`} disabled={props.status === 'archived'} onClick={props.onArchive}>Archive</button>
        </td>
      </tr>
      {showSettings && (
        <FlowSettingsModal
          flowId={props.id}
          onClose={() => setShowSettings(false)}
        />
      )}
      {props.showVersions && (
        <tr>
          <td colSpan={5} data-testid={`versions-list-${props.id}`}>
            {versionsQ.isLoading ? 'Loading…' : (versionsQ.data ?? []).length === 0 ? 'No published versions.' : (
              <ul style={{ margin: 0 }}>
                {versionsQ.data!.map(v => (
                  <li key={v.version ?? 0} className="font-mono">
                    v{v.version} · {v.status} · sha256 {v.content_sha256?.slice(0, 12) ?? '-'}
                  </li>
                ))}
              </ul>
            )}
          </td>
        </tr>
      )}
    </>
  )
}
