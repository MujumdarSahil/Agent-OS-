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
  FolderOpen,
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
  const {
    data: health,
    isLoading: healthLoading,
    isError: healthIsError,
    error: healthError,
  } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 30000,
  })
  const { data: checkpoints, refetch: refetchCheckpoints } = useQuery({ queryKey: ['checkpoints'], queryFn: () => getCheckpoints() })
  const { data: providers, refetch: refetchProviders } = useQuery({ queryKey: ['providers'], queryFn: getProviders, refetchInterval: 30000 })
  const { refetch: refetchChain } = useQuery({ queryKey: ['fallback-chain'], queryFn: getFallbackChain, refetchInterval: 30000 })

  const [testingName, setTestingName] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, { latency: number; success: boolean }>>({})
  const [selectedProvider, setSelectedProvider] = useState<string | undefined>(undefined)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [isAvailableExpanded, setIsAvailableExpanded] = useState(false)

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
  const configuredProviders = sortedProviders.filter((p) => p.api_key_configured || p.is_local)
  const firstActiveProvider = configuredProviders.find((p) => p.status === 'active')?.name || ''

  // Categories for available/unconfigured providers (Fix B)
  const cloudAvailable = sortedProviders.filter((p) => !p.is_local && p.name !== 'openai_compatible' && !p.api_key_configured)
  const localAvailable = sortedProviders.filter((p) => (p.is_local || p.name === 'openai_compatible') && (!p.api_key_configured || p.status === 'probe_failed'))
  const availableCount = cloudAvailable.length + localAvailable.length

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

      const provObj = providers?.find((p) => p.name === newest.provider)
      const displayModel = provObj ? provObj.display_name : (newest.provider || 'unknown')

      groupedRuns.push({
        missionId,
        status: newest.status,
        started: oldest.timestamp,
        duration: durationStr,
        modelUsed: displayModel,
        tasks: `Task ${newest.task_index + 1}`,
      })
    })

    groupedRuns.sort((a, b) => new Date(b.started).getTime() - new Date(a.started).getTime())
  }

  const recentRuns = groupedRuns.slice(0, 5)

  const renderStatValue = (val: number | undefined) => {
    if (healthLoading) {
      return <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Loading...</span>
    }
    const axiosError = healthError as any
    const isProjectError = healthIsError && (axiosError?.response?.status === 404 || axiosError?.response?.status === 422)
    const isNoProject = (health && !health.has_project) || isProjectError

    if (isNoProject) {
      return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)' }}>
          <FolderOpen size={16} style={{ flexShrink: 0, color: 'var(--text-muted)' }} />
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
            <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600 }}>No project open</span>
            <span style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 2, whiteSpace: 'normal', lineHeight: '1.2', fontWeight: 'normal' }}>
              Run agentos new-project myproject then restart with python main.py --project myproject
            </span>
          </div>
        </div>
      )
    }

    if (healthIsError) {
      return (
        <span style={{ fontSize: 11, color: '#ef4444' }} title={String(healthError)}>
          API Error
        </span>
      )
    }
    return val !== undefined ? val : '—'
  }

  return (
    <div>
      {/* TOP BAR */}
      <div className="page-header flex justify-between items-center mb-6">
        <div>
          <h2 style={{ fontSize: 24, fontWeight: 800 }}>AgentOS</h2>
          <p className="text-secondary" style={{ fontSize: 13 }}>Multi-Agent Framework</p>
        </div>

        <div
          className="font-mono flex items-center gap-2"
          style={{
            fontSize: 12,
            padding: '6px 12px',
            borderRadius: 20,
            border: '1px solid var(--border)',
            background: 'var(--bg-hover)',
            color: 'var(--text-primary)',
          }}
        >
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
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
        <div className="flex flex-col mb-3">
          <h3 style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-secondary)' }}>
            LLM Fallback Chain
          </h3>
          <p className="text-muted text-xs mt-1">
            Providers are tried in order. If one fails, the next continues automatically.
          </p>
        </div>

        {configuredProviders.length === 0 ? (
          <div
            className="flex flex-col items-center justify-center p-6 text-center"
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1px dashed var(--border)',
              borderRadius: 'var(--radius-lg)',
              padding: '40px 24px',
            }}
          >
            <Activity size={36} className="text-muted mb-2" style={{ opacity: 0.5 }} />
            <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>No providers configured yet</h3>
            <p className="text-secondary mb-4" style={{ fontSize: 13, maxWidth: 360, margin: '0 auto 16px' }}>
              Add your API keys to build an active LLM fallback chain.
            </p>
            <button
              onClick={handleAddProvider}
              className="btn btn-primary py-1.5 px-4 text-xs flex items-center gap-1"
            >
              <Plus size={14} /> Add Provider
            </button>
          </div>
        ) : (
          <div
            className="flex flex-row items-center gap-3"
            style={{
              padding: 16,
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-lg)',
              overflowX: 'auto',
              whiteSpace: 'nowrap',
            }}
          >
            {configuredProviders.map((p, idx) => {
              const meta = PROVIDER_METADATA[p.name] || { initials: 'LL', bg: 'rgba(255,255,255,0.05)', text: '#fff' }
              const isFirstActive = p.name === firstActiveProvider
              const hasResult = testResults[p.name] !== undefined

              let badgeText = 'Standby'
              let badgeColor = '#f59e0b'
              let badgeBg = 'rgba(245,158,11,0.1)'

              if (p.status === 'probe_failed') {
                badgeText = 'Failed'
                badgeColor = '#ef4444'
                badgeBg = 'rgba(239,68,68,0.1)'
              } else if (isFirstActive) {
                badgeText = 'Active'
                badgeColor = '#22c55e'
                badgeBg = 'rgba(34,197,94,0.1)'
              }

              const isTesting = testingName === p.name
              const getOrdinal = (n: number) => {
                const j = n % 10;
                const k = n % 100;
                if (j === 1 && k !== 11) return n + "st";
                if (j === 2 && k !== 12) return n + "nd";
                if (j === 3 && k !== 13) return n + "rd";
                return n + "th";
              }

              return (
                <div key={p.name} className="flex items-center gap-3" style={{ display: 'inline-flex', verticalAlign: 'middle' }}>
                  <div
                    onClick={() => handleOpenConfig(p.name)}
                    className={`card flex flex-col justify-between transition-all duration-200 ${
                      isTesting ? 'animate-pulse' : ''
                    }`}
                    style={{
                      width: 190,
                      minHeight: 125,
                      padding: 14,
                      borderRadius: 'var(--radius-lg)',
                      cursor: 'pointer',
                      border: isFirstActive ? '1px solid #8b5cf6' : '1px solid var(--border)',
                      boxShadow: isFirstActive ? '0 0 12px rgba(139,92,246,0.1)' : 'none',
                      backgroundColor: 'var(--bg-card)',
                      whiteSpace: 'normal',
                      display: 'flex',
                    }}
                  >
                    <div className="flex items-start justify-between">
                      <div
                        className="flex items-center justify-center font-bold font-mono"
                        style={{
                          width: 28,
                          height: 28,
                          borderRadius: '50%',
                          fontSize: 12,
                          background: meta.bg,
                          color: meta.text,
                        }}
                      >
                        {meta.initials}
                      </div>
                      <div className="flex flex-col items-end">
                        <span className="font-semibold text-muted" style={{ fontSize: 10 }}>{getOrdinal(idx + 1)}</span>
                        <span
                          className="font-mono font-semibold"
                          style={{
                            fontSize: 10,
                            padding: '2px 6px',
                            borderRadius: 'var(--radius-sm)',
                            marginTop: 4,
                            color: badgeColor,
                            backgroundColor: badgeBg,
                          }}
                        >
                          {badgeText}
                        </span>
                      </div>
                    </div>

                    <div style={{ margin: '8px 0' }}>
                      <div className="font-semibold truncate" style={{ fontSize: 12 }} title={p.display_name}>
                        {p.display_name}
                      </div>
                      <div className="text-muted font-mono truncate" style={{ fontSize: 10 }}>
                        {p.litellm_model.split('/')[1] || p.litellm_model}
                      </div>
                    </div>

                    <div className="flex items-center justify-between mt-auto">
                      <div className="font-mono" style={{ fontSize: 10 }}>
                        {isTesting && <span className="text-purple animate-pulse">testing...</span>}
                        {!isTesting && hasResult && (
                          <span
                            style={{ color: testResults[p.name].success ? '#22c55e' : '#ef4444' }}
                            className="flex items-center gap-1"
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
                      <button
                        onClick={(e) => handleTest(e, p.name)}
                        disabled={isTesting || testingName !== null}
                        className="btn btn-secondary flex items-center gap-1"
                        style={{ fontSize: 10, padding: '2px 8px' }}
                      >
                        <Play size={8} /> Test
                      </button>
                    </div>
                  </div>

                  <ChevronRight size={18} className="text-muted flex-shrink-0" />
                </div>
              )
            })}

            {/* ADD PROVIDER CARD */}
            <button
              onClick={handleAddProvider}
              className="card flex flex-col items-center justify-center transition-all duration-200"
              style={{
                width: 190,
                minHeight: 125,
                borderRadius: 'var(--radius-lg)',
                border: '2px dashed var(--border)',
                backgroundColor: 'rgba(255,255,255,0.01)',
                cursor: 'pointer',
                display: 'inline-flex',
                verticalAlign: 'top',
              }}
            >
              <div
                className="flex items-center justify-center text-muted"
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: '50%',
                  backgroundColor: 'var(--bg-hover)',
                  marginBottom: 8,
                }}
              >
                <Plus size={16} />
              </div>
              <span className="font-semibold text-muted" style={{ fontSize: 12 }}>Add Provider</span>
            </button>
          </div>
        )}
      </div>

      {/* AVAILABLE PROVIDERS (Fix B) */}
      {availableCount > 0 && (
        <div className="mb-6">
          <button
            onClick={() => setIsAvailableExpanded(!isAvailableExpanded)}
            className="btn btn-secondary w-full flex items-center justify-between p-3"
            style={{
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-surface)',
              borderColor: 'var(--border)',
              fontSize: 13,
            }}
          >
            <span>
              Available providers ({availableCount}) &nbsp;&nbsp; {isAvailableExpanded ? ' [Hide ▲]' : ' [Show ▼]'}
            </span>
            <ChevronRight
              size={16}
              style={{
                transform: isAvailableExpanded ? 'rotate(90deg)' : 'rotate(0deg)',
                transition: 'transform 0.2s',
              }}
            />
          </button>

          {isAvailableExpanded && (
            <div
              className="mt-3 p-4 rounded-lg"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-lg)',
              }}
            >
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                  gap: 24,
                }}
              >
                {/* Column 1: Cloud Providers */}
                <div>
                  <h4 style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Cloud Providers
                  </h4>
                  <div className="flex flex-col gap-2">
                    {cloudAvailable.length === 0 ? (
                      <div className="text-xs text-muted p-2">None unconfigured</div>
                    ) : (
                      cloudAvailable.map((p) => {
                        const meta = PROVIDER_METADATA[p.name] || { initials: 'LL', bg: 'rgba(255,255,255,0.05)', text: '#fff' }
                        return (
                          <div
                            key={p.name}
                            className="card flex items-center justify-between p-3"
                            style={{
                              borderRadius: 'var(--radius-md)',
                              backgroundColor: 'var(--bg-card)',
                              border: '1px solid var(--border)',
                              display: 'flex',
                              flexDirection: 'row',
                            }}
                          >
                            <div className="flex items-center gap-3 overflow-hidden" style={{ minWidth: 0, flex: 1 }}>
                              <div
                                        className="flex items-center justify-center font-bold font-mono"
                                        style={{
                                          width: 28,
                                          height: 28,
                                          borderRadius: '50%',
                                          fontSize: 11,
                                          background: meta.bg,
                                          color: meta.text,
                                          flexShrink: 0,
                                        }}
                              >
                                {meta.initials}
                              </div>
                              <div style={{ minWidth: 0, flex: 1 }}>
                                <div className="font-semibold truncate" style={{ fontSize: 12 }}>
                                  {p.display_name}
                                </div>
                                <div className="text-muted font-mono truncate" style={{ fontSize: 10 }}>
                                  {p.litellm_model.split('/')[1] || p.litellm_model}
                                </div>
                              </div>
                            </div>
                            <button
                              onClick={() => handleOpenConfig(p.name)}
                              className="btn btn-secondary flex-shrink-0"
                              style={{ height: 26, fontSize: 10, padding: '2px 8px', marginLeft: 8 }}
                            >
                              + Configure
                            </button>
                          </div>
                        )
                      })
                    )}
                  </div>
                </div>

                {/* Column 2: Local & Compatible */}
                <div>
                  <h4 style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Local & Compatible
                  </h4>
                  <div className="flex flex-col gap-2">
                    {localAvailable.length === 0 ? (
                      <div className="text-xs text-muted p-2">None unconfigured</div>
                    ) : (
                      localAvailable.map((p) => {
                        const meta = PROVIDER_METADATA[p.name] || { initials: 'LL', bg: 'rgba(255,255,255,0.05)', text: '#fff' }
                        return (
                          <div
                            key={p.name}
                            className="card flex items-center justify-between p-3"
                            style={{
                              borderRadius: 'var(--radius-md)',
                              backgroundColor: 'var(--bg-card)',
                              border: '1px solid var(--border)',
                              display: 'flex',
                              flexDirection: 'row',
                            }}
                          >
                            <div className="flex items-center gap-3 overflow-hidden" style={{ minWidth: 0, flex: 1 }}>
                              <div
                                        className="flex items-center justify-center font-bold font-mono"
                                        style={{
                                          width: 28,
                                          height: 28,
                                          borderRadius: '50%',
                                          fontSize: 11,
                                          background: meta.bg,
                                          color: meta.text,
                                          flexShrink: 0,
                                        }}
                              >
                                {meta.initials}
                              </div>
                              <div style={{ minWidth: 0, flex: 1 }}>
                                <div className="font-semibold truncate" style={{ fontSize: 12 }}>
                                  {p.display_name}
                                </div>
                                <div className="text-muted font-mono truncate" style={{ fontSize: 10 }}>
                                  {p.litellm_model.split('/')[1] || p.litellm_model}
                                </div>
                              </div>
                            </div>
                            <button
                              onClick={() => handleOpenConfig(p.name)}
                              className="btn btn-secondary flex-shrink-0"
                              style={{ height: 26, fontSize: 10, padding: '2px 8px', marginLeft: 8 }}
                            >
                              + Configure
                            </button>
                          </div>
                        )
                      })
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* STATS ROW */}
      <div className="stat-grid mb-6">
        <div className="stat-card">
          <div className="stat-value">{renderStatValue(health?.agents)}</div>
          <div className="stat-label">Agents</div>
          <p className="text-[10px] text-muted mt-1">Configured agents</p>
        </div>
        <div className="stat-card">
          <div className="stat-value">{renderStatValue(health?.tools)}</div>
          <div className="stat-label">Tools</div>
          <p className="text-[10px] text-muted mt-1">Available plugins</p>
        </div>
        <div className="stat-card">
          <div className="stat-value">{renderStatValue(health?.crews)}</div>
          <div className="stat-label">Crews</div>
          <p className="text-[10px] text-muted mt-1">Hierarchical processes</p>
        </div>
        <div className="stat-card">
          <div className="stat-value">{renderStatValue(health?.missions)}</div>
          <div className="stat-label">Missions</div>
          <p className="text-[10px] text-muted mt-1">Run templates</p>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            {renderStatValue(groupedRuns.filter((r) => r.status === 'completed').length)}
          </div>
          <div className="stat-label">Completed Runs</div>
          <p className="text-[10px] text-muted mt-1">
            {groupedRuns.length > 0 ? `${groupedRuns.length} total runs recorded` : 'No history yet'}
          </p>
        </div>
        <div className="stat-card">
          <div className="stat-value text-purple" style={{ color: '#8b5cf6' }}>
            {renderStatValue(health?.fallback_events)}
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
