import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getV2Agents, createV2Agent, deleteV2Agent, getV2Tools, type V2AgentConfig } from '../api/client'
import { Plus, Trash2, Bot, X, ShieldAlert, Check } from 'lucide-react'

// Known safe built-in tools that match NodeSpec declarations
const BUILTIN_TOOLS = [
  { name: 'fetch_url', desc: 'Safely fetch web documents' },
  { name: 'send_email', desc: 'Outbound email notification' },
  { name: 'calculator', desc: 'Deterministic math evaluation' },
  { name: 'file_read', desc: 'Read files within workspace' },
  { name: 'file_write', desc: 'Write files within workspace' },
]

const EMPTY: V2AgentConfig = {
  name: '',
  role: '',
  goal: '',
  backstory: '',
  tools: [],
  verbose: false,
  llm: 'agentos-default',
  allow_delegation: false,
  allow_code_execution: false,
}

function AgentModal({
  knownTools,
  onClose,
  onSave,
}: {
  knownTools: string[]
  onClose: () => void
  onSave: (a: V2AgentConfig) => void
}) {
  const [form, setForm] = useState<V2AgentConfig>(EMPTY)
  const [error, setError] = useState<string | null>(null)

  const set = (k: keyof V2AgentConfig, v: unknown) => setForm(prev => ({ ...prev, [k]: v }))

  const toggleTool = (toolName: string) => {
    setForm(prev => {
      const cur = prev.tools || []
      const next = cur.includes(toolName) ? cur.filter(t => t !== toolName) : [...cur, toolName]
      return { ...prev, tools: next }
    })
  }

  const handleSave = () => {
    // Validate required fields
    if (!form.name.trim() || !form.role.trim() || !form.goal.trim()) {
      setError('Name, role, and goal are required.')
      return
    }

    // Safety check: ensure no prohibited keys
    const raw = form as unknown as Record<string, unknown>
    if ('mcps' in raw || 'apps' in raw || 'knowledge_sources' in raw || 'memory' in raw) {
      setError('Prohibited legacy fields (mcps, apps, memory, knowledge_sources) detected. Fail-closed.')
      return
    }

    onSave(form)
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={{ maxWidth: '640px' }}>
        <div className="modal-header">
          <h3>Create Agent (v2)</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16}/></button>
        </div>

        {error && (
          <div style={{ padding: '8px 12px', background: 'rgba(239,68,68,0.1)', color: 'var(--accent-red)', borderRadius: 6, marginBottom: 12, fontSize: 13, display: 'flex', gap: 6, alignItems: 'center' }}>
            <ShieldAlert size={15}/> {error}
          </div>
        )}

        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Name *</label>
            <input
              id="agent-name"
              className="form-input"
              value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="Researcher"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Role *</label>
            <input
              id="agent-role"
              className="form-input"
              value={form.role}
              onChange={e => set('role', e.target.value)}
              placeholder="Senior Research Analyst"
            />
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">Goal *</label>
          <input
            id="agent-goal"
            className="form-input"
            value={form.goal}
            onChange={e => set('goal', e.target.value)}
            placeholder="Gather and synthesize information accurately"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Backstory</label>
          <textarea
            id="agent-backstory"
            className="form-textarea"
            value={form.backstory}
            onChange={e => set('backstory', e.target.value)}
            placeholder="An experienced research specialist with attention to nuance and verification..."
          />
        </div>

        <div className="form-group">
          <label className="form-label">Tools (NodeSpec-Declared Only)</label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '6px' }}>
            {knownTools.map(t => {
              const selected = (form.tools || []).includes(t)
              return (
                <button
                  key={t}
                  type="button"
                  className={`btn btn-sm ${selected ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                  onClick={() => toggleTool(t)}
                >
                  {selected && <Check size={13}/>}
                  {t}
                </button>
              )
            })}
          </div>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '6px' }}>
            Only tools with declared NodeSpecs can be attached (fail-closed security rule).
          </p>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label className="form-label">LLM Selector</label>
            <input
              className="form-input"
              value={form.llm || ''}
              onChange={e => set('llm', e.target.value)}
              placeholder="agentos-default"
            />
          </div>
          <div className="form-group" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: 13, marginTop: 18 }}>
              <input
                type="checkbox"
                checked={form.allow_delegation || false}
                onChange={e => set('allow_delegation', e.target.checked)}
              />
              Allow Delegation
            </label>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            id="agent-save-btn"
            className="btn btn-primary"
            disabled={!form.name || !form.role || !form.goal}
            onClick={handleSave}
          >
            Save Agent
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Agents() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)

  const { data: agents = [], isLoading } = useQuery({
    queryKey: ['v2-agents'],
    queryFn: getV2Agents,
  })

  const { data: toolsData = [] } = useQuery({
    queryKey: ['v2-tools'],
    queryFn: getV2Tools,
  })

  const create = useMutation({
    mutationFn: createV2Agent,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['v2-agents'] })
      setShowModal(false)
    },
    onError: (err: any) => {
      alert(`Failed to create agent: ${err.response?.data?.detail || err.message}`)
    },
  })

  const remove = useMutation({
    mutationFn: deleteV2Agent,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['v2-agents'] }),
    onError: (err: any) => {
      alert(`Failed to delete agent: ${err.response?.data?.detail || err.message}`)
    },
  })

  // Combine built-in declared tools and custom stored tools
  const knownToolsList = Array.from(
    new Set([
      ...BUILTIN_TOOLS.map(t => t.name),
      ...toolsData.map(t => t.name),
    ])
  )

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Agents (v2)</h2>
          <p>Autonomous agents backed by hardened NodeSpec schema and storage ports</p>
        </div>
        <button id="create-agent-btn" className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={15}/> New Agent
        </button>
      </div>

      {isLoading ? (
        <div className="empty-state"><div className="spinner"/></div>
      ) : agents.length === 0 ? (
        <div className="empty-state">
          <Bot size={40}/>
          <h3>No agents configured</h3>
          <p>Create your first autonomous agent using validated NodeSpec tools.</p>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Role</th>
                <th>Goal</th>
                <th>Tools</th>
                <th>Delegation</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {agents.map(a => {
                const tools = a.tools || a.tool_refs || []
                return (
                  <tr key={a.name}>
                    <td><strong>{a.name}</strong></td>
                    <td className="text-muted">{a.role}</td>
                    <td style={{ maxWidth: 260, fontSize: 13 }} className="truncate">{a.goal}</td>
                    <td>
                      {tools.length === 0 ? (
                        <span className="text-muted" style={{ fontSize: 12 }}>None</span>
                      ) : (
                        tools.map(t => (
                          <span key={t} className="badge badge-default" style={{ marginRight: 4 }}>
                            {t}
                          </span>
                        ))
                      )}
                    </td>
                    <td>
                      <span className={`badge ${a.allow_delegation ? 'badge-running' : 'badge-default'}`}>
                        {a.allow_delegation ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--accent-red)' }}
                        onClick={() => {
                          if (confirm(`Delete agent "${a.name}"?`)) {
                            remove.mutate(a.name)
                          }
                        }}
                      >
                        <Trash2 size={14}/>
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {showModal && (
        <AgentModal
          knownTools={knownToolsList}
          onClose={() => setShowModal(false)}
          onSave={agent => create.mutate(agent)}
        />
      )}
    </div>
  )
}
