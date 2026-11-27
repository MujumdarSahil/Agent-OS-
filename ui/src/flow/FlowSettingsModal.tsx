// src/flow/FlowSettingsModal.tsx — 3.6a: Flow settings with Review sampling rules
import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { X, Check, AlertTriangle, Settings as SettingsIcon } from 'lucide-react'
import { useAuth } from '../components/AuthContext'
import {
  getSamplingConfig,
  updateSamplingConfig,
  REVIEW_SAMPLING_RULES,
  type ReviewSamplingConfig,
  type ReviewSamplingMode,
  type ReviewSamplingRule,
} from '../api/review'

export interface FlowSettingsModalProps {
  flowId: string
  availableNodes?: { id: string; label?: string }[]
  onClose: () => void
}

export default function FlowSettingsModal({
  flowId,
  availableNodes = [],
  onClose,
}: FlowSettingsModalProps) {
  const qc = useQueryClient()
  const { can, me } = useAuth()
  const canBuild = can('build') || me?.role === 'builder' || me?.role === 'admin'

  const [mode, setMode] = useState<ReviewSamplingMode>('off')
  const [percentage, setPercentage] = useState<number>(10)
  const [rules, setRules] = useState<ReviewSamplingRule[]>([])
  const [useSpecificNodes, setUseSpecificNodes] = useState<boolean>(false)
  const [selectedNodes, setSelectedNodes] = useState<string[]>([])
  const [statusMsg, setStatusMsg] = useState<{ type: 'ok' | 'error'; text: string } | null>(null)

  const configQ = useQuery({
    queryKey: ['review-sampling', flowId],
    queryFn: () => getSamplingConfig(flowId),
  })

  useEffect(() => {
    if (configQ.data) {
      setMode(configQ.data.mode || 'off')
      setPercentage(configQ.data.percentage ?? 10)
      setRules(configQ.data.rules || [])
      const nodes = configQ.data.node_ids || []
      setSelectedNodes(nodes)
      setUseSpecificNodes(nodes.length > 0)
    }
  }, [configQ.data])

  const saveMut = useMutation({
    mutationFn: (cfg: Partial<ReviewSamplingConfig>) => updateSamplingConfig(flowId, cfg),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['review-sampling', flowId] })
      setStatusMsg({ type: 'ok', text: 'Review settings saved successfully.' })
      setTimeout(() => setStatusMsg(null), 3000)
    },
    onError: (err: any) => {
      setStatusMsg({
        type: 'error',
        text: err?.response?.data?.detail || err.message || 'Failed to save settings',
      })
    },
  })

  const handleSave = () => {
    setStatusMsg(null)
    saveMut.mutate({
      mode,
      percentage: Number(percentage) || 10,
      rules,
      node_ids: useSpecificNodes ? selectedNodes : [],
    })
  }

  const toggleRule = (r: ReviewSamplingRule) => {
    setRules(prev => (prev.includes(r) ? prev.filter(x => x !== r) : [...prev, r]))
  }

  const toggleNode = (nodeId: string) => {
    setSelectedNodes(prev =>
      prev.includes(nodeId) ? prev.filter(x => x !== nodeId) : [...prev, nodeId],
    )
  }

  return (
    <div
      className="modal-backdrop"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: 20,
      }}
      data-testid="flow-settings-modal"
    >
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: 600,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          padding: 0,
          overflow: 'hidden',
          boxShadow: '0 8px 30px rgba(0,0,0,0.4)',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '12px 18px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--bg-secondary)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <SettingsIcon size={16} />
            <h3 style={{ margin: 0, fontSize: 16 }}>Flow Settings: <code>{flowId}</code></h3>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onClose} data-testid="flow-settings-close-btn">
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          {/* Review Sampling Section */}
          <div data-testid="flow-settings-review">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <h4 style={{ margin: 0, fontSize: 14 }}>Review Queue Sampling</h4>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
              Configure which runs and nodes automatically enter the human review queue upon completion.
            </p>

            {configQ.isLoading ? (
              <div className="text-muted" style={{ fontSize: 12 }}>Loading settings…</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {/* Mode selector */}
                <div className="form-group">
                  <label className="form-label" style={{ marginBottom: 6 }}>
                    Sampling Mode
                  </label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="sampling-mode"
                        value="off"
                        checked={mode === 'off'}
                        disabled={!canBuild}
                        onChange={() => setMode('off')}
                        data-testid="sampling-mode-off"
                      />
                      <span><strong>Off</strong> (default) — no runs sampled automatically</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="sampling-mode"
                        value="all"
                        checked={mode === 'all'}
                        disabled={!canBuild}
                        onChange={() => setMode('all')}
                        data-testid="sampling-mode-all"
                      />
                      <span><strong>All</strong> — enqueue every completed run</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="sampling-mode"
                        value="percentage"
                        checked={mode === 'percentage'}
                        disabled={!canBuild}
                        onChange={() => setMode('percentage')}
                        data-testid="sampling-mode-percentage"
                      />
                      <span><strong>Sample percentage</strong> — random sample of runs</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="sampling-mode"
                        value="rules"
                        checked={mode === 'rules'}
                        disabled={!canBuild}
                        onChange={() => setMode('rules')}
                        data-testid="sampling-mode-rules"
                      />
                      <span><strong>Rules-based</strong> — only runs matching specific triggers</span>
                    </label>
                  </div>
                </div>

                {/* Percentage configuration */}
                {mode === 'percentage' && (
                  <div
                    className="card"
                    style={{ padding: 12, background: 'var(--bg-input)' }}
                    data-testid="sampling-percentage-config"
                  >
                    <label className="form-label" htmlFor="sampling-pct" style={{ marginBottom: 4 }}>
                      Sample Rate (%)
                    </label>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <input
                        id="sampling-pct"
                        type="number"
                        min={1}
                        max={100}
                        className="form-input"
                        data-testid="sampling-percentage-input"
                        value={percentage}
                        disabled={!canBuild}
                        onChange={e => setPercentage(Math.max(1, Math.min(100, Number(e.target.value))))}
                        style={{ width: 90 }}
                      />
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        % of completed runs (1 - 100%)
                      </span>
                    </div>
                  </div>
                )}

                {/* Rules configuration */}
                {mode === 'rules' && (
                  <div
                    className="card"
                    style={{ padding: 12, background: 'var(--bg-input)' }}
                    data-testid="sampling-rules-config"
                  >
                    <div className="form-label" style={{ marginBottom: 8 }}>
                      Enqueue run when any of these occur:
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {REVIEW_SAMPLING_RULES.map(r => (
                        <label
                          key={r.key}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            fontSize: 12,
                            cursor: canBuild ? 'pointer' : 'default',
                          }}
                        >
                          <input
                            type="checkbox"
                            data-testid={`sampling-rule-${r.key}`}
                            checked={rules.includes(r.key)}
                            disabled={!canBuild}
                            onChange={() => toggleRule(r.key)}
                          />
                          <span>{r.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {/* Target Nodes */}
                <div className="form-group" style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}>
                  <label className="form-label" style={{ marginBottom: 6 }}>
                    Target Nodes to Review
                  </label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 8 }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="target-nodes"
                        checked={!useSpecificNodes}
                        disabled={!canBuild}
                        onChange={() => setUseSpecificNodes(false)}
                        data-testid="target-nodes-default"
                      />
                      <span><strong>Final output</strong> (default) — last executed step</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="target-nodes"
                        checked={useSpecificNodes}
                        disabled={!canBuild}
                        onChange={() => setUseSpecificNodes(true)}
                        data-testid="target-nodes-specific"
                      />
                      <span><strong>Specific nodes</strong> — chosen agent/llm/extraction steps</span>
                    </label>
                  </div>

                  {useSpecificNodes && (
                    <div
                      className="card"
                      style={{ padding: 10, background: 'var(--bg-input)', maxHeight: 150, overflowY: 'auto' }}
                      data-testid="specific-nodes-list"
                    >
                      {availableNodes.length === 0 ? (
                        <div className="text-muted" style={{ fontSize: 12 }}>
                          No nodes found. Enter node IDs manually in flow configuration or add nodes to the canvas.
                        </div>
                      ) : (
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                          {availableNodes.map(n => (
                            <label
                              key={n.id}
                              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}
                            >
                              <input
                                type="checkbox"
                                data-testid={`target-node-${n.id}`}
                                checked={selectedNodes.includes(n.id)}
                                disabled={!canBuild}
                                onChange={() => toggleNode(n.id)}
                              />
                              <code>{n.id}</code>
                            </label>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {statusMsg && (
            <div
              style={{
                marginTop: 14,
                padding: '8px 12px',
                borderRadius: 4,
                fontSize: 12,
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                backgroundColor: statusMsg.type === 'ok' ? 'rgba(45,212,191,0.1)' : 'rgba(239,68,68,0.1)',
                color: statusMsg.type === 'ok' ? 'var(--accent-teal)' : 'var(--accent-red)',
              }}
              data-testid="flow-settings-msg"
            >
              {statusMsg.type === 'ok' ? <Check size={14} /> : <AlertTriangle size={14} />}
              {statusMsg.text}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '12px 20px',
            borderTop: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: 10,
            background: 'var(--bg-secondary)',
          }}
        >
          <button className="btn btn-ghost btn-sm" onClick={onClose} disabled={saveMut.isPending}>
            Close
          </button>
          {canBuild && (
            <button
              className="btn btn-primary btn-sm"
              data-testid="flow-settings-save-btn"
              disabled={saveMut.isPending}
              onClick={handleSave}
            >
              {saveMut.isPending ? 'Saving…' : 'Save settings'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
