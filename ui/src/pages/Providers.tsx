import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getV2Providers,
  testV2ProviderConnection,
  getV2VaultKeys,
  saveV2VaultKey,
  deleteV2VaultKey,
  getV2FallbackPolicy,
  updateV2FallbackPolicy,
  type V2FallbackPolicyItem,
} from '../api/client'
import {
  Cpu,
  Key,
  CheckCircle2,
  XCircle,
  Loader2,
  ArrowUp,
  ArrowDown,
  Trash2,
  Plus,
  X,
  Lock,
  Zap,
} from 'lucide-react'

export default function Providers() {
  const qc = useQueryClient()

  // State for active test runs
  const [testingProvider, setTestingProvider] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, { ok: boolean; error_class?: string | null; message?: string | null }>>({})

  // State for Vault Modal
  const [showVaultModal, setShowVaultModal] = useState(false)
  const [vaultKeyName, setVaultKeyName] = useState('')
  const [vaultKeySecret, setVaultKeySecret] = useState('')
  const [vaultKeyProvider, setVaultKeyProvider] = useState('')

  // State for Fallback Policy Editor
  const [fallbackPolicy, setFallbackPolicy] = useState<V2FallbackPolicyItem[]>([])
  const [policySavedMsg, setPolicySavedMsg] = useState(false)

  // 1. Providers Catalog Query
  const { data: providers = [], isLoading: loadingProviders } = useQuery({
    queryKey: ['v2-providers'],
    queryFn: getV2Providers,
  })

  // 2. Vault Keys Query
  const { data: vaultKeys = [], isLoading: loadingVault } = useQuery({
    queryKey: ['v2-vault-keys'],
    queryFn: getV2VaultKeys,
  })

  // 3. Fallback Policy Query
  const { isLoading: loadingPolicy } = useQuery({
    queryKey: ['v2-fallback-policy'],
    queryFn: async () => {
      const data = await getV2FallbackPolicy()
      setFallbackPolicy(data)
      return data
    },
  })

  // Mutations
  const saveVault = useMutation({
    mutationFn: saveV2VaultKey,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['v2-vault-keys'] })
      qc.invalidateQueries({ queryKey: ['v2-providers'] })
      setShowVaultModal(false)
      setVaultKeyName('')
      setVaultKeySecret('')
      setVaultKeyProvider('')
    },
    onError: (err: any) => {
      alert(`Failed to save vault secret: ${err.response?.data?.detail || err.message}`)
    },
  })

  const deleteVault = useMutation({
    mutationFn: deleteV2VaultKey,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['v2-vault-keys'] })
      qc.invalidateQueries({ queryKey: ['v2-providers'] })
    },
    onError: (err: any) => {
      alert(`Failed to delete vault secret: ${err.response?.data?.detail || err.message}`)
    },
  })

  const savePolicy = useMutation({
    mutationFn: updateV2FallbackPolicy,
    onSuccess: data => {
      qc.invalidateQueries({ queryKey: ['v2-fallback-policy'] })
      setFallbackPolicy(data)
      setPolicySavedMsg(true)
      setTimeout(() => setPolicySavedMsg(false), 3000)
    },
    onError: (err: any) => {
      alert(`Failed to save fallback policy: ${err.response?.data?.detail || err.message}`)
    },
  })

  // Test connection handler
  const handleTestConnection = async (providerName: string) => {
    setTestingProvider(providerName)
    try {
      const res = await testV2ProviderConnection(providerName)
      setTestResults(prev => ({ ...prev, [providerName]: res }))
    } catch (err: any) {
      setTestResults(prev => ({
        ...prev,
        [providerName]: {
          ok: false,
          error_class: 'ClientRequestError',
          message: err.response?.data?.detail || err.message,
        },
      }))
    } finally {
      setTestingProvider(null)
    }
  }

  // Fallback policy reordering
  const movePolicyItem = (index: number, direction: 'up' | 'down') => {
    const nextList = [...fallbackPolicy]
    const targetIndex = direction === 'up' ? index - 1 : index + 1
    if (targetIndex < 0 || targetIndex >= nextList.length) return

    const temp = nextList[index]
    nextList[index] = nextList[targetIndex]
    nextList[targetIndex] = temp

    // Re-index order 1-based
    const updated = nextList.map((item, idx) => ({ ...item, order: idx + 1 }))
    setFallbackPolicy(updated)
  }

  const togglePolicyItemEnabled = (index: number) => {
    setFallbackPolicy(prev =>
      prev.map((item, idx) => (idx === index ? { ...item, enabled: !item.enabled } : item))
    )
  }

  const updatePolicyItemTimeout = (index: number, timeoutStr: string) => {
    const val = timeoutStr ? parseFloat(timeoutStr) : null
    setFallbackPolicy(prev =>
      prev.map((item, idx) => (idx === index ? { ...item, timeout_s: val } : item))
    )
  }

  return (
    <div>
      <div className="page-header">
        <h2>Providers & Vault (v2)</h2>
        <p>Manage LLM providers, credentials vault (AES-256-GCM envelope), and fallback policies</p>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* SECTION 1: Credentials Vault */}
      {/* ------------------------------------------------------------------ */}
      <div className="card mb-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Lock size={18} color="var(--accent-teal)" />
            <h3 style={{ margin: 0, fontSize: 16 }}>Credentials Vault</h3>
          </div>
          <button id="add-vault-key-btn" className="btn btn-primary btn-sm" onClick={() => setShowVaultModal(true)}>
            <Plus size={14}/> Store Secret
          </button>
        </div>

        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
          API keys are encrypted using an AES-256-GCM envelope and stored securely. Secret plaintext is <strong>never returned or logged</strong>.
        </p>

        {loadingVault ? (
          <div className="spinner" />
        ) : vaultKeys.length === 0 ? (
          <div className="empty-state" style={{ padding: 20 }}>
            <Key size={32}/>
            <p style={{ margin: 0 }}>No secrets stored in vault yet.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Secret Name</th>
                  <th>Associated Provider</th>
                  <th>Masked Value (Hint)</th>
                  <th>Key ID</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {vaultKeys.map(k => (
                  <tr key={k.name}>
                    <td><strong>{k.name}</strong></td>
                    <td>{k.provider ? <span className="badge badge-default">{k.provider}</span> : '—'}</td>
                    <td className="font-mono text-muted">{k.hint}</td>
                    <td className="font-mono text-muted" style={{ fontSize: 11 }}>{k.key_id}</td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--accent-red)' }}
                        onClick={() => {
                          if (confirm(`Delete vault secret "${k.name}"?`)) {
                            deleteVault.mutate(k.name)
                          }
                        }}
                      >
                        <Trash2 size={14}/>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* SECTION 2: Provider Catalog & Connectivity Tests */}
      {/* ------------------------------------------------------------------ */}
      <div className="card mb-4">
        <div className="flex items-center gap-2 mb-3">
          <Cpu size={18} color="var(--accent-purple)" />
          <h3 style={{ margin: 0, fontSize: 16 }}>Provider Catalog</h3>
        </div>

        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
          Catalog inspection performs zero network calls. Reachability is tested safely on demand.
        </p>

        {loadingProviders ? (
          <div className="spinner" />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>LiteLLM Model</th>
                  <th>Configured</th>
                  <th>Tags</th>
                  <th>Connectivity</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {providers.map(p => {
                  const result = testResults[p.name]
                  const isTesting = testingProvider === p.name
                  return (
                    <tr key={p.name}>
                      <td>
                        <strong>{p.display_name}</strong>
                        <div className="font-mono text-muted" style={{ fontSize: 11 }}>{p.name}</div>
                      </td>
                      <td className="font-mono" style={{ fontSize: 12 }}>{p.litellm_model}</td>
                      <td>
                        <span className={`badge ${p.api_key_configured ? 'badge-completed' : 'badge-default'}`}>
                          {p.api_key_configured ? 'Configured' : 'Missing Key'}
                        </span>
                      </td>
                      <td>
                        {p.tags.map(t => (
                          <span key={t} className="badge badge-default" style={{ marginRight: 4, fontSize: 11 }}>
                            {t}
                          </span>
                        ))}
                      </td>
                      <td>
                        {isTesting ? (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--accent-teal)' }}>
                            <Loader2 size={13} className="spin" /> Probing...
                          </span>
                        ) : result ? (
                          result.ok ? (
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: '#10b981', fontSize: 12 }}>
                              <CheckCircle2 size={14} /> Reachable
                            </span>
                          ) : (
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--accent-red)', fontSize: 12 }} title={result.message || ''}>
                              <XCircle size={14} /> {result.error_class || 'Failed'}
                            </span>
                          )
                        ) : (
                          <span className="text-muted" style={{ fontSize: 12 }}>Untested</span>
                        )}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          disabled={isTesting}
                          onClick={() => handleTestConnection(p.name)}
                        >
                          Test Connection
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* SECTION 3: Fallback Policy Editor */}
      {/* ------------------------------------------------------------------ */}
      <div className="card mb-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Zap size={18} color="var(--accent-gold, #f59e0b)" />
            <h3 style={{ margin: 0, fontSize: 16 }}>Fallback Policy & Order</h3>
          </div>
          <button
            id="save-fallback-policy-btn"
            className="btn btn-primary btn-sm"
            disabled={savePolicy.isPending || fallbackPolicy.length === 0}
            onClick={() => savePolicy.mutate(fallbackPolicy)}
          >
            {savePolicy.isPending ? 'Saving...' : 'Save Policy'}
          </button>
        </div>

        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
          Determines the order in which AgentOS cascades requests upon provider failures or rate limits.
        </p>

        {policySavedMsg && (
          <div style={{ padding: '8px 12px', background: 'rgba(16,185,129,0.15)', color: '#10b981', borderRadius: 6, marginBottom: 12, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
            <CheckCircle2 size={16}/> Fallback policy saved and router cache updated synchronously!
          </div>
        )}

        {loadingPolicy ? (
          <div className="spinner" />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 60 }}>Order</th>
                  <th>Provider</th>
                  <th>Status</th>
                  <th>Timeout (s)</th>
                  <th style={{ width: 140 }}>Reorder</th>
                </tr>
              </thead>
              <tbody>
                {fallbackPolicy.map((item, index) => (
                  <tr key={item.name} style={{ opacity: item.enabled ? 1 : 0.5 }}>
                    <td><strong>#{item.order}</strong></td>
                    <td>
                      <strong>{item.display_name || item.name}</strong>
                      <div className="font-mono text-muted" style={{ fontSize: 11 }}>{item.litellm_model}</div>
                    </td>
                    <td>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={item.enabled}
                          onChange={() => togglePolicyItemEnabled(index)}
                        />
                        <span style={{ fontSize: 12 }}>{item.enabled ? 'Enabled' : 'Disabled'}</span>
                      </label>
                    </td>
                    <td>
                      <input
                        type="number"
                        className="form-input"
                        style={{ width: 90, padding: '4px 8px', fontSize: 12 }}
                        value={item.timeout_s ?? ''}
                        placeholder="default"
                        onChange={e => updatePolicyItemTimeout(index, e.target.value)}
                      />
                    </td>
                    <td>
                      <div className="flex gap-1">
                        <button
                          className="btn btn-ghost btn-sm"
                          disabled={index === 0}
                          onClick={() => movePolicyItem(index, 'up')}
                          title="Move Up"
                        >
                          <ArrowUp size={14}/>
                        </button>
                        <button
                          className="btn btn-ghost btn-sm"
                          disabled={index === fallbackPolicy.length - 1}
                          onClick={() => movePolicyItem(index, 'down')}
                          title="Move Down"
                        >
                          <ArrowDown size={14}/>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Vault Modal */}
      {showVaultModal && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setShowVaultModal(false)}>
          <div className="modal" style={{ maxWidth: '500px' }}>
            <div className="modal-header">
              <h3>Store Secret in Vault</h3>
              <button className="btn btn-ghost btn-sm" onClick={() => setShowVaultModal(false)}><X size={16}/></button>
            </div>

            <div className="form-group">
              <label className="form-label">Secret Name *</label>
              <input
                id="vault-key-name"
                className="form-input"
                value={vaultKeyName}
                onChange={e => setVaultKeyName(e.target.value)}
                placeholder="e.g. openai_gpt4o or OPENAI_API_KEY"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Secret Value (Plaintext) *</label>
              <input
                id="vault-key-secret"
                type="password"
                className="form-input font-mono"
                value={vaultKeySecret}
                onChange={e => setVaultKeySecret(e.target.value)}
                placeholder="sk-..."
              />
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Secret is immediately envelope-encrypted with AES-256-GCM. Plaintext is never stored.
              </p>
            </div>

            <div className="form-group">
              <label className="form-label">Associated Provider (Optional)</label>
              <input
                className="form-input"
                value={vaultKeyProvider}
                onChange={e => setVaultKeyProvider(e.target.value)}
                placeholder="openai_gpt4o"
              />
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowVaultModal(false)}>Cancel</button>
              <button
                id="save-vault-secret-btn"
                className="btn btn-primary"
                disabled={!vaultKeyName.trim() || !vaultKeySecret.trim()}
                onClick={() =>
                  saveVault.mutate({
                    name: vaultKeyName.trim(),
                    secret: vaultKeySecret.trim(),
                    provider: vaultKeyProvider.trim() || undefined,
                  })
                }
              >
                Encrypt & Store
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
