import { useQuery } from '@tanstack/react-query'
import { getHealth, getCheckpoints } from '../api/client'
import { Bot, Wrench, Users, Target, Activity } from 'lucide-react'

function StatusBadge({ status }: { status: string }) {
  const cls = status === 'completed' ? 'badge-completed'
    : status === 'failed' ? 'badge-failed'
    : status === 'running' ? 'badge-running' : 'badge-queued'
  return <span className={`badge ${cls}`}>{status}</span>
}

export default function Dashboard() {
  const { data: health } = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 10000 })
  const { data: checkpoints } = useQuery({ queryKey: ['checkpoints'], queryFn: () => getCheckpoints() })

  const recentRuns = checkpoints?.slice(0, 8) ?? []

  return (
    <div>
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Overview of your AgentOS project</p>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(79,110,247,0.15)' }}>
            <Bot size={18} color="#4f6ef7" />
          </div>
          <div className="stat-value">{health?.agents ?? '—'}</div>
          <div className="stat-label">Agents</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(20,184,166,0.15)' }}>
            <Wrench size={18} color="#14b8a6" />
          </div>
          <div className="stat-value">{health?.tools ?? '—'}</div>
          <div className="stat-label">Tools</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(139,92,246,0.15)' }}>
            <Users size={18} color="#8b5cf6" />
          </div>
          <div className="stat-value">{health?.crews ?? '—'}</div>
          <div className="stat-label">Crews</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(245,158,11,0.15)' }}>
            <Target size={18} color="#f59e0b" />
          </div>
          <div className="stat-value">{health?.missions ?? '—'}</div>
          <div className="stat-label">Missions</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(34,197,94,0.15)' }}>
            <Activity size={18} color="#22c55e" />
          </div>
          <div className="stat-value">{recentRuns.filter(r => r.status === 'completed').length}</div>
          <div className="stat-label">Completed Runs</div>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 style={{ fontWeight: 700, fontSize: 15 }}>Recent Checkpoint History</h3>
        </div>
        {recentRuns.length === 0 ? (
          <div className="empty-state">
            <Activity size={32} />
            <h3>No runs yet</h3>
            <p>Trigger a mission from the Missions page to see history here.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Mission</th>
                  <th>Task #</th>
                  <th>Status</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {recentRuns.map((r, i) => (
                  <tr key={i}>
                    <td className="font-mono" style={{ fontSize: 12 }}>{r.mission_id}</td>
                    <td>{r.task_index}</td>
                    <td><StatusBadge status={r.status} /></td>
                    <td className="text-muted" style={{ fontSize: 12 }}>{r.timestamp.slice(0, 19).replace('T', ' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
