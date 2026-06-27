import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getRunStatus } from '../api/client'
import { ArrowLeft, CheckCircle, XCircle, Clock, Loader } from 'lucide-react'

function StatusBadge({ status }: { status: string }) {
  const cls = status === 'completed' ? 'badge-completed'
    : status === 'failed' ? 'badge-failed'
    : status === 'running' ? 'badge-running' : 'badge-queued'
  return <span className={`badge ${cls}`}>{status}</span>
}

export default function RunDetail() {
  const { runId } = useParams<{ runId: string }>()

  const { data: run, isLoading, error } = useQuery({
    queryKey: ['run', runId],
    queryFn: () => getRunStatus(runId!),
    refetchInterval: (query) => {
      const s = query.state.data?.status
      return s === 'completed' || s === 'failed' ? false : 2000
    },
    enabled: !!runId,
  })

  if (isLoading) return <div className="empty-state"><div className="spinner"/></div>
  if (error || !run) return <div className="empty-state"><XCircle size={40}/><h3>Run not found</h3><p>The run ID may be incorrect.</p></div>

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <Link to="/missions" className="btn btn-ghost btn-sm"><ArrowLeft size={15}/> Missions</Link>
      </div>

      <div className="page-header">
        <div className="flex items-center gap-3">
          <h2>Run: <span className="font-mono" style={{ fontSize: 18 }}>{run.mission_name}</span></h2>
          <StatusBadge status={run.status} />
          {run.status === 'running' && <div className="spinner"/>}
        </div>
        <p className="font-mono" style={{ fontSize: 12 }}>{runId}</p>
      </div>

      <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: 24 }}>
        <div className="stat-card">
          <div className="stat-label">Status</div>
          <div className="stat-value" style={{ fontSize: 20 }}>{run.status}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Task Index</div>
          <div className="stat-value" style={{ fontSize: 20 }}>{run.task_index}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">LLM Provider</div>
          <div className="stat-value" style={{ fontSize: 14, marginTop: 8 }}>{run.provider ?? 'N/A'}</div>
        </div>
      </div>

      {run.error && (
        <div className="card mb-4" style={{ borderColor: 'var(--accent-red)', background: 'rgba(239,68,68,0.07)' }}>
          <div className="flex items-center gap-2" style={{ marginBottom: 8, color: 'var(--accent-red)' }}>
            <XCircle size={16}/><strong>Error</strong>
          </div>
          <div className="code-block">{run.error}</div>
        </div>
      )}

      <div className="card">
        <h3 style={{ fontWeight: 700, marginBottom: 16, fontSize: 15 }}>Task Outputs</h3>
        {run.outputs.length === 0 ? (
          <div className="empty-state" style={{ padding: 32 }}>
            {run.status === 'running' ? <><Loader size={24}/><p style={{ marginTop: 12 }}>Running...</p></> :
              <><Clock size={24}/><p style={{ marginTop: 12 }}>No outputs yet</p></>}
          </div>
        ) : (
          <div className="run-timeline">
            {run.outputs.map((out, i) => (
              <div key={i} className="run-task">
                <div className={`run-task-dot task-done`}>
                  <CheckCircle size={12} color="#0a0b0f"/>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Task {i + 1}</div>
                  <div className="code-block" style={{ fontSize: 12 }}>{out}</div>
                </div>
              </div>
            ))}
            {run.status === 'running' && (
              <div className="run-task">
                <div className="run-task-dot task-running"/>
                <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>Executing task {run.task_index + 1}...</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
