import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  getHealth,
  getCheckpoints,
  getProviders,
  getFallbackChain,
  testProvider,
} from '../api/client'
import type { Checkpoint } from '../api/client'
import {
  Activity,
  ChevronRight,
  Plus,
  Play,
  CheckCircle,
  XCircle,
  ArrowUpRight,
} from 'lucide-react'
import ProviderConfigModal from '../components/ProviderConfigModal'

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === 'completed' || status === 'completed_runs'
      ? 'badge-completed'
      : status === 'failed'
      ? 'badge-failed'
      : status === 'running' || status === 'in_progress'
      ? 'badge-running'
      : 'badge-queued'
  return <span className={`badge ${cls}`}>{status.replace('_', ' ')}</span>
}

const PROVIDER_METADATA: Record<string, { initials: string; bg: string; text: string }> = {
  openai_gpt4o: { initials: 'OA', bg: 'rgba(16,185,129,0.15)', text: '#10b981' },
  openai_gpt4o_mini: { initials: 'OA', bg: 'rgba(16,185,129,0.15)', text: '#10b981' },
  anthropic_claude_sonnet: { initials: 'AN', bg: 'rgba(217,119,6,0.15)', text: '#d97706' },
  openrouter_claude_sonnet: { initials: 'OR', bg: 'rgba(139,92,246,0.15)', text: '#8b5cf6' },
  openrouter_gpt4o: { initials: 'OR', bg: 'rgba(139,92,246,0.15)', text: '#8b5cf6' },
  openrouter_llama3_1_free: { initials: 'OR', bg: 'rgba(139,92,246,0.15)', text: '#8b5cf6' },
  gemini_flash: { initials: 'G', bg: 'rgba(59,130,246,0.15)', text: '#3b82f6' },
  deepseek_v4_flash: { initials: 'DS', bg: 'rgba(14,165,233,0.15)', text: '#0ea5e9' },
  groq_llama3_3: { initials: 'GR', bg: 'rgba(249,115,22,0.15)', text: '#f97316' },
  groq_llama3_1_instant: { initials: 'GR', bg: 'rgba(249,115,22,0.15)', text: '#f97316' },
  groq_gemma2: { initials: 'GR', bg: 'rgba(249,115,22,0.15)', text: '#f97316' },
  together_llama3_3_70b: { initials: 'TO', bg: 'rgba(99,102,241,0.15)', text: '#6366f1' },
  together_qwen2_5_72b: { initials: 'TO', bg: 'rgba(99,102,241,0.15)', text: '#6366f1' },
  fireworks_llama3_1_70b: { initials: 'FW', bg: 'rgba(236,72,153,0.15)', text: '#ec4899' },
  fireworks_qwen2_5_72b: { initials: 'FW', bg: 'rgba(236,72,153,0.15)', text: '#ec4899' },
  openai_compatible: { initials: 'OC', bg: 'rgba(107,114,128,0.15)', text: '#9ca3af' },
  ollama_qwen: { initials: 'OL', bg: 'rgba(243,244,246,0.1)', text: '#f3f4f6' },
  ollama_llama: { initials: 'OL', bg: 'rgba(243,244,246,0.1)', text: '#f3f4f6' },
}

interface GroupedRun {
  missionId: string
  status: string
  started: string
  duration: string
  modelUsed: string
  tasks: string
}

export default function Dashboard() {
  const { data: health } = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 30000 })
  const { data: checkpoints, refetch: refetchCheckpoints } = useQuery({ queryKey: ['checkpoints'], queryFn: () => getCheckpoints() })
  const { data: providers, refetch: refetchProviders } = useQuery({ queryKey: ['providers'], queryFn: getProviders, refetchInterval: 30000 })
  const { refetch: refetchChain } = useQuery({ queryKey: ['fallback-chain'], queryFn: getFallbackChain, refetchInterval: 30000 })

  const [testingName, setTestingName] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, { latency: number; success: boolean }>>({})
  const [selectedProvider, setSelectedProvider] = useState<string | undefined>(undefined)
  const [isModalOpen, setIsModalOpen] = useState(false)

  const handleTest = async (e: React.MouseEvent, name: string) => {
    e.stopPropagation()
    setTestingName(name)
    try {
      const res = await testProvider(name)
      setTestResults((prev) => ({
        ...prev,
        [name]: { latency: res.latency_ms, success: res.success },
      }))
      refetchProviders()
      refetchChain()
    } catch (err) {
      console.error(err)
      setTestResults((prev) => ({
        ...prev,
        [name]: { latency: 0, success: false },
      }))
    } finally {
      setTestingName(null)
    }
  }

  const handleOpenConfig = (name: string) => {
    setSelectedProvider(name)
    setIsModalOpen(true)
  }

  const handleAddProvider = () => {
    setSelectedProvider(undefined)
    setIsModalOpen(true)
  }

  const handleSaved = () => {
    refetchProviders()
    refetchChain()
    refetchCheckpoints()
  }

  // Find the highest priority active provider in the chain
  const sortedProviders = providers ? [...providers].sort((a, b) => a.priority - b.priority) : []
  const firstActiveProvider = sortedProviders.find((p) => p.status === 'active')?.name || ''

  // Group task checkpoints by mission run
  const groupedRuns: GroupedRun[] = []
  if (checkpoints) {
    const map = new Map<string, Checkpoint[]>()
    checkpoints.forEach((cp) => {
      const list = map.get(cp.mission_id) || []
      list.push(cp)
      map.set(cp.mission_id, list)
    })

    map.forEach((list, missionId) => {
      list.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
      const oldest = list[0]
      const newest = list[list.length - 1]

      const startTime = new Date(oldest.timestamp).getTime()
      const endTime = new Date(newest.timestamp).getTime()
      const diffSeconds = Math.max(0, Math.round((endTime - startTime) / 1000))
      const durationStr = diffSeconds === 0 ? '< 1s' : `${diffSeconds}s`

      groupedRuns.push({
        missionId,
        status: newest.status,
        started: oldest.timestamp,
        duration: durationStr,
        modelUsed: newest.provider || 'unknown',
        tasks: `Task ${newest.task_index + 1}`,
      })
    })

    groupedRuns.sort((a, b) => new Date(b.started).getTime() - new Date(a.started).getTime())
  }

  const recentRuns = groupedRuns.slice(0, 5)

  return (
    <div>
      {/* TOP BAR */}
      <div className="page-header flex justify-between items-center mb-6">
        <div>
          <h2 style={{ fontSize: 24, fontWeight: 800 }}>AgentOS</h2>
          <p className="text-secondary" style={{ fontSize: 13 }}>Multi-Agent Framework</p>
        </div>

        <div
          className="font-mono text-xs px-3 py-1.5 rounded-full border flex items-center gap-2"
          style={{
            background: 'var(--bg-hover)',
            borderColor: 'var(--border-color)',
            color: 'var(--text-primary)',
          }}
        >
          <span
            className="w-2 h-2 rounded-full"
            style={{
              backgroundColor: health?.last_used_model && health.last_used_model !== 'No model used yet' ? '#22c55e' : '#6b7280',
              boxShadow: health?.last_used_model && health.last_used_model !== 'No model used yet' ? '0 0 8px #22c55e' : 'none',
            }}
          ></span>
          <span className="text-muted">Model:</span>
          <span className="font-semibold">{health?.last_used_model || 'No model used yet'}</span>
        </div>
      </div>

      {/* FALLBACK CHAIN PANEL */}
      <div className="mb-6">
        <h3 className="mb-3" style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-secondary)' }}>
          LLM Fallback Chain
        </h3>
        <div className="flex flex-wrap items-stretch gap-3 p-4 bg-dark-secondary rounded border border-dark-primary">
          {sortedProviders.map((p, idx) => {
            const meta = PROVIDER_METADATA[p.name] || { initials: 'LL', bg: 'rgba(255,255,255,0.05)', text: '#fff' }
            const isFirstActive = p.name === firstActiveProvider
            const hasResult = testResults[p.name] !== undefined

            let badgeText = 'Not configured'
            let badgeColor = 'var(--text-secondary)'
            let badgeBg = 'var(--bg-hover)'

            if (p.status === 'probe_failed') {
              badgeText = 'Failed'
              badgeColor = '#ef4444'
              badgeBg = 'rgba(239,68,68,0.1)'
            } else if (p.api_key_configured || p.is_local) {
              if (isFirstActive) {
                badgeText = 'Active'
                badgeColor = '#22c55e'
                badgeBg = 'rgba(34,197,94,0.1)'
              } else {
                badgeText = 'Standby'
                badgeColor = '#f59e0b'
                badgeBg = 'rgba(245,158,11,0.1)'
              }
            }

            const isTesting = testingName === p.name

            return (
              <div key={p.name} className="flex items-center gap-3">
                <div
                  onClick={() => handleOpenConfig(p.name)}
                  className={`card flex flex-col justify-between p-3.5 cursor-pointer transition-all duration-200 ${
                    isTesting ? 'animate-pulse' : ''
                  }`}
                  style={{
                    width: 190,
                    minHeight: 125,
                    border: isFirstActive ? '1px solid #8b5cf6' : '1px solid var(--border-color)',
                    boxShadow: isFirstActive ? '0 0 12px rgba(139,92,246,0.1)' : 'none',
                    backgroundColor: 'var(--bg-card)',
                  }}
                >
                  <div className="flex items-start justify-between">
                    <div
                      className="w-7 h-7 rounded-full flex items-center justify-center font-bold text-xs font-mono"
                      style={{ background: meta.bg, color: meta.text }}
                    >
                      {meta.initials}
                    </div>
                    <div className="flex flex-col items-end">
                      <span className="text-[10px] text-muted font-semibold">PRIORITY {idx + 1}</span>
                      <span
                        className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold mt-1"
                        style={{ color: badgeColor, backgroundColor: badgeBg }}
                      >
                        {badgeText}
                      </span>
                    </div>
                  </div>

                  <div className="my-2">
                    <div className="font-mono text-xs font-semibold truncate" title={p.litellm_model}>
                      {p.litellm_model.split('/')[1] || p.litellm_model}
                    </div>
                    <div className="text-[10px] text-muted font-mono truncate">{p.name}</div>
                  </div>

                  <div className="flex items-center justify-between mt-auto">
                    <div className="text-[10px] font-mono">
                      {isTesting && <span className="text-purple animate-pulse">testing...</span>}
                      {!isTesting && hasResult && (
                        <span
                          style={{ color: testResults[p.name].success ? '#22c55e' : '#ef4444' }}
                          className="flex items-center gap-0.5"
                        >
                          {testResults[p.name].success ? (
                            <>
                              <CheckCircle size={10} /> {testResults[p.name].latency}ms
                            </>
                          ) : (
                            <>
                              <XCircle size={10} /> failed
                            </>
                          )}
                        </span>
                      )}
                    </div>
                    {(p.api_key_configured || p.is_local) && (
                      <button
                        onClick={(e) => handleTest(e, p.name)}
                        disabled={isTesting || testingName !== null}
                        className="btn btn-secondary text-[10px] py-0.5 px-2 font-mono flex items-center gap-1"
                      >
                        <Play size={8} /> Test
                      </button>
                    )}
                  </div>
                </div>

                {idx < sortedProviders.length - 1 && (
                  <ChevronRight size={18} className="text-muted flex-shrink-0" />
                )}
              </div>
            )
          })}

          {/* ADD PROVIDER CARD */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleAddProvider}
              className="card flex flex-col items-center justify-center border-dashed border-2 hover:border-purple transition-all duration-200"
              style={{
                width: 190,
                minHeight: 125,
                borderColor: 'var(--border-color)',
                backgroundColor: 'rgba(255,255,255,0.01)',
              }}
            >
              <div className="w-8 h-8 rounded-full bg-dark-secondary flex items-center justify-center text-muted mb-2">
                <Plus size={16} />
              </div>
              <span className="text-xs font-semibold text-muted">Add Provider</span>
            </button>
          </div>
        </div>
      </div>

      {/* STATS ROW */}
      <div className="stat-grid mb-6">
        <div className="stat-card">
          <div className="stat-value">{health?.agents ?? '—'}</div>
          <div className="stat-label">Agents</div>
          <p className="text-[10px] text-muted mt-1">Configured agents</p>
        </div>
        <div className="stat-card">
          <div className="stat-value">{health?.tools ?? '—'}</div>
          <div className="stat-label">Tools</div>
          <p className="text-[10px] text-muted mt-1">Available plugins</p>
        </div>
        <div className="stat-card">
          <div className="stat-value">{health?.crews ?? '—'}</div>
          <div className="stat-label">Crews</div>
          <p className="text-[10px] text-muted mt-1">Hierarchical processes</p>
        </div>
        <div className="stat-card">
          <div className="stat-value">{health?.missions ?? '—'}</div>
          <div className="stat-label">Missions</div>
          <p className="text-[10px] text-muted mt-1">Run templates</p>
        </div>
        <div className="stat-card">
          <div className="stat-value">{groupedRuns.filter((r) => r.status === 'completed').length}</div>
          <div className="stat-label">Completed Runs</div>
          <p className="text-[10px] text-muted mt-1">
            {groupedRuns.length > 0 ? `${groupedRuns.length} total runs recorded` : 'No history yet'}
          </p>
        </div>
        <div className="stat-card">
          <div className="stat-value text-purple" style={{ color: '#8b5cf6' }}>
            {health?.fallback_events ?? 0}
          </div>
          <div className="stat-label">Fallback Events</div>
          <p className="text-[10px] text-muted mt-1">Auto-routed errors (24h)</p>
        </div>
      </div>

      {/* RECENT RUNS TABLE */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 style={{ fontWeight: 700, fontSize: 15 }}>Recent Mission Executions</h3>
        </div>
        {recentRuns.length === 0 ? (
          <div className="empty-state">
            <Activity size={32} className="text-muted mb-2" />
            <h3 className="text-sm font-semibold">No runs yet</h3>
            <p className="text-xs text-muted mb-4">
              Trigger a mission from the Missions catalog to see history here.
            </p>
            <Link to="/missions" className="btn btn-primary py-1.5 px-4 text-xs flex items-center gap-1">
              Trigger Mission <ArrowUpRight size={14} />
            </Link>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Mission</th>
                  <th>Started</th>
                  <th>Duration</th>
                  <th>Status</th>
                  <th>Model Used</th>
                  <th>Tasks Progress</th>
                </tr>
              </thead>
              <tbody>
                {recentRuns.map((r, i) => (
                  <tr key={i}>
                    <td className="font-mono font-semibold" style={{ fontSize: 12 }}>
                      {r.missionId}
                    </td>
                    <td className="text-muted" style={{ fontSize: 12 }}>
                      {r.started.slice(0, 19).replace('T', ' ')}
                    </td>
                    <td style={{ fontSize: 12 }}>{r.duration}</td>
                    <td>
                      <StatusBadge status={r.status} />
                    </td>
                    <td className="font-mono text-muted" style={{ fontSize: 11 }}>
                      {r.modelUsed}
                    </td>
                    <td style={{ fontSize: 12 }}>{r.tasks}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ProviderConfigModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        providerName={selectedProvider}
        onSaved={handleSaved}
      />
    </div>
  )
}
