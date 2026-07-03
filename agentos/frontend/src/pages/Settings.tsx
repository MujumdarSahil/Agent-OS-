import { useState, useEffect } from 'react'
import {
  getProviders,
  getFallbackChain,
  testProvider,
} from '../api/client'
import type { ProviderStatus, FallbackChainItem } from '../api/client'
import {
  Settings as SettingsIcon,
  Play,
  CheckCircle2,
  XCircle,
  Loader2,
  ArrowRight,
  ShieldCheck,
  Cpu,
  Edit2,
} from 'lucide-react'
import ProviderConfigModal from '../components/ProviderConfigModal'

interface DiagnosticRow {
  providerName: string
  model: string
  running: boolean
  completed: boolean
  success?: boolean
  latencyMs?: number
  response?: string | null
  error?: string | null
}

export default function Settings() {
  const [providers, setProviders] = useState<ProviderStatus[]>([])
  const [fallbackChain, setFallbackChain] = useState<FallbackChainItem[]>([])
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [selectedProvider, setSelectedProvider] = useState<string | undefined>(undefined)

  // Diagnostics state
  const [diagnostics, setDiagnostics] = useState<DiagnosticRow[]>([])
  const [diagnosticRunning, setDiagnosticRunning] = useState(false)

  const loadData = async () => {
    try {
      const provs = await getProviders()
      setProviders(provs)

      const chain = await getFallbackChain()
      setFallbackChain(chain)
    } catch (e) {
      console.error('Failed to load settings data', e)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleConfigure = (name: string) => {
    setSelectedProvider(name)
    setIsModalOpen(true)
  }

  const handleAdd = () => {
    setSelectedProvider(undefined)
    setIsModalOpen(true)
  }

  const runDiagnostics = async () => {
    // Only test providers that are configured or local
    const configured = providers.filter((p) => p.api_key_configured || p.is_local)
    if (configured.length === 0) {
      alert('No providers are configured. Configure at least one provider first.')
      return
    }

    setDiagnosticRunning(true)
    const initialRows: DiagnosticRow[] = configured.map((p) => ({
      providerName: p.name,
      model: p.litellm_model,
      running: false,
      completed: false,
    }))
    setDiagnostics(initialRows)

    for (let i = 0; i < configured.length; i++) {
      const p = configured[i]
      setDiagnostics((prev) =>
        prev.map((row) => (row.providerName === p.name ? { ...row, running: true } : row))
      )

      try {
        const res = await testProvider(p.name)
        setDiagnostics((prev) =>
          prev.map((row) =>
            row.providerName === p.name
              ? {
                  ...row,
                  running: false,
                  completed: true,
                  success: res.success,
                  latencyMs: res.latency_ms,
                  response: res.response,
                  error: res.error,
                }
              : row
          )
        )
      } catch (err: any) {
        setDiagnostics((prev) =>
          prev.map((row) =>
            row.providerName === p.name
              ? {
                  ...row,
                  running: false,
                  completed: true,
                  success: false,
                  error: err.message || 'Connection error',
                }
              : row
          )
        )
      }
    }
    setDiagnosticRunning(false)
    loadData() // Refresh status badges after diagnostic tests
  }

  return (
    <div>
      <div className="page-header flex justify-between items-center mb-6">
        <div>
          <h2>Settings</h2>
          <p className="text-secondary">Manage AgentOS global settings and LLM providers</p>
        </div>
        <button className="btn btn-primary" onClick={handleAdd}>
          + Add Provider
        </button>
      </div>

      <div className="grid gap-6">
        {/* Section 1: LLM Providers Registry */}
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Cpu size={18} color="#8b5cf6" />
            <h3 style={{ fontWeight: 700, fontSize: 15 }}>LLM Provider Registry</h3>
          </div>
          <p className="text-muted text-xs mb-4">
            Below is the list of all supported LLM providers. Providers with configured keys/URLs are automatically included in the fallback chain.
          </p>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>LiteLLM Model Name</th>
                  <th>Tags</th>
                  <th>Status</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {providers.map((p) => {
                  let badgeCls = 'badge-queued'
                  let badgeText = 'Not Configured'
                  if (p.status === 'active') {
                    badgeCls = 'badge-completed'
                    badgeText = 'Active'
                  } else if (p.status === 'probe_failed') {
                    badgeCls = 'badge-failed'
                    badgeText = 'Failed'
                  }

                  return (
                    <tr key={p.name}>
                      <td className="font-semibold text-sm">
                        {p.name.replace(/_/g, ' ').toUpperCase()}
                      </td>
                      <td className="font-mono text-xs">{p.litellm_model}</td>
                      <td>
                        <div className="flex gap-1">
                          {p.tags.map((t) => (
                            <span
                              key={t}
                              className="text-[10px] bg-dark-secondary px-1.5 py-0.5 rounded font-mono text-muted"
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <span className={`badge ${badgeCls}`}>{badgeText}</span>
                      </td>
                      <td className="text-right">
                        <button
                          onClick={() => handleConfigure(p.name)}
                          className="btn btn-secondary py-1 px-2.5 inline-flex items-center gap-1.5 text-xs"
                        >
                          <Edit2 size={12} /> Configure
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 2: Fallback Chain Preview */}
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <ShieldCheck size={18} color="#10b981" />
            <h3 style={{ fontWeight: 700, fontSize: 15 }}>Fallback Chain Preview</h3>
          </div>
          <p className="text-muted text-xs mb-4">
            This shows the exact ordered priority of models that will execute when a mission runs. The first active, non-failing model is tried first, then fallbacks are triggered sequentially.
          </p>

          {fallbackChain.length === 0 ? (
            <div className="text-sm text-center py-6 text-muted bg-dark-secondary rounded">
              No active providers in the fallback chain. Add a provider key to activate the chain.
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-3 p-4 bg-dark-secondary rounded border border-dark-primary">
              {fallbackChain.map((item, idx) => (
                <div key={item.name} className="flex items-center gap-3">
                  <div
                    className="p-3 bg-dark-primary border rounded flex flex-col font-mono text-xs"
                    style={{
                      borderColor: item.status === 'active' ? 'rgba(139,92,246,0.3)' : 'rgba(239,68,68,0.3)',
                      boxShadow: item.status === 'active' ? '0 0 10px rgba(139,92,246,0.05)' : 'none',
                    }}
                  >
                    <div className="flex justify-between items-center gap-6 mb-1">
                      <span className="text-secondary font-bold">
                        #{item.order} {item.name.replace(/_/g, ' ').toUpperCase()}
                      </span>
                      <span
                        className={`text-[10px] px-1 rounded ${
                          item.status === 'active'
                            ? 'bg-success-subtle text-success'
                            : 'bg-failed-subtle text-failed'
                        }`}
                        style={{
                          color: item.status === 'active' ? '#22c55e' : '#ef4444',
                        }}
                      >
                        {item.status === 'active' ? 'ACTIVE' : 'FAILED'}
                      </span>
                    </div>
                    <span className="text-muted text-[11px]">{item.litellm_model}</span>
                  </div>
                  {idx < fallbackChain.length - 1 && (
                    <ArrowRight size={16} className="text-muted" />
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Section 3: Diagnostic Suite */}
        <div className="card">
          <div className="flex justify-between items-center mb-4">
            <div className="flex items-center gap-2">
              <SettingsIcon size={18} color="#f59e0b" />
              <h3 style={{ fontWeight: 700, fontSize: 15 }}>Run Full Diagnostic</h3>
            </div>
            <button
              onClick={runDiagnostics}
              className="btn btn-primary flex items-center gap-1.5"
              disabled={diagnosticRunning}
            >
              {diagnosticRunning ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Play size={14} />
              )}
              {diagnosticRunning ? 'Running Tests...' : 'Run Diagnostics'}
            </button>
          </div>
          <p className="text-muted text-xs mb-4">
            Sequentially executes a connectivity test on all configured cloud and local providers to verify API key validity, base URLs, and response latencies before you trigger a mission.
          </p>

          {diagnostics.length > 0 && (
            <div className="table-container mt-4 border border-dark-primary rounded">
              <table>
                <thead>
                  <tr>
                    <th>Provider</th>
                    <th>Model</th>
                    <th>Status</th>
                    <th>Latency</th>
                    <th>Response / Error Details</th>
                  </tr>
                </thead>
                <tbody>
                  {diagnostics.map((d) => (
                    <tr key={d.providerName}>
                      <td className="font-mono font-semibold text-xs">
                        {d.providerName.replace(/_/g, ' ').toUpperCase()}
                      </td>
                      <td className="font-mono text-xs text-muted">{d.model}</td>
                      <td>
                        {d.running && (
                          <span className="flex items-center gap-1.5 text-xs text-secondary">
                            <Loader2 size={12} className="animate-spin text-purple" /> Testing
                          </span>
                        )}
                        {d.completed && d.success && (
                          <span className="flex items-center gap-1 text-xs text-success" style={{ color: '#22c55e' }}>
                            <CheckCircle2 size={12} /> Success
                          </span>
                        )}
                        {d.completed && !d.success && (
                          <span className="flex items-center gap-1 text-xs text-failed" style={{ color: '#ef4444' }}>
                            <XCircle size={12} /> Failed
                          </span>
                        )}
                        {!d.running && !d.completed && (
                          <span className="text-xs text-muted">Queued</span>
                        )}
                      </td>
                      <td className="font-mono text-xs">
                        {d.latencyMs !== undefined ? `${d.latencyMs}ms` : '—'}
                      </td>
                      <td className="text-xs">
                        {d.success && d.response && (
                          <span className="text-secondary font-mono">Response: "{d.response}"</span>
                        )}
                        {!d.success && d.error && (
                          <span className="text-failed font-mono" style={{ color: '#ef4444' }}>{d.error}</span>
                        )}
                        {!d.completed && <span className="text-muted">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <ProviderConfigModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        providerName={selectedProvider}
        onSaved={loadData}
      />
    </div>
  )
}
