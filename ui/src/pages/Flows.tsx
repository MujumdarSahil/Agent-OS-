// src/pages/Flows.tsx — flow list: create, open, archive, published versions (2.4).

import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiErrorMessage, archiveFlow, listFlows, listVersions } from '../api/flows'

export default function Flows() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const flowsQ = useQuery({ queryKey: ['flows'], queryFn: listFlows })
  const [newId, setNewId] = useState('')
  const [newName, setNewName] = useState('')
  const [openVersions, setOpenVersions] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

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

      <div className="card mb-4" style={{ padding: 12 }}>
        <div className="flex gap-2 items-end flex-wrap">
          <div className="form-group">
            <label className="form-label" htmlFor="new-flow-id">Flow id</label>
            <input id="new-flow-id" className="form-input" data-testid="new-flow-id" value={newId} onChange={e => setNewId(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="new-flow-name">Name</label>
            <input id="new-flow-name" className="form-input" data-testid="new-flow-name" value={newName} onChange={e => setNewName(e.target.value)} />
          </div>
          <button className="btn btn-primary" data-testid="create-flow" onClick={create} disabled={!newId.trim()}>New flow</button>
        </div>
        {error && <div style={{ color: 'var(--accent-red)', marginTop: 8 }} data-testid="flows-error">{error}</div>}
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
                  status={f.status}
                  version={f.version}
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
  const versionsQ = useQuery({ queryKey: ['flow-versions', props.id], queryFn: () => listVersions(props.id), enabled: props.showVersions })
  return (
    <>
      <tr data-testid={`flow-row-${props.id}`}>
        <td className="font-mono"><Link to={`/flows/${encodeURIComponent(props.id)}`}>{props.id}</Link></td>
        <td>{props.name}</td>
        <td><span className="badge badge-default">{props.status}</span></td>
        <td>{props.version ?? '-'}</td>
        <td className="flex gap-2">
          <button className="btn btn-ghost btn-sm" data-testid={`versions-${props.id}`} onClick={props.onToggleVersions}>Versions</button>
          <button className="btn btn-danger btn-sm" data-testid={`archive-${props.id}`} disabled={props.status === 'archived'} onClick={props.onArchive}>Archive</button>
        </td>
      </tr>
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
