import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getAgents, createAgent, deleteAgent, type Agent } from '../api/client'
import { Plus, Trash2, Bot, X } from 'lucide-react'

const EMPTY: Agent = { name: '', role: '', goal: '', backstory: '', llm_tags: ['fast'], tool_refs: [], memory_ref: null }

function AgentModal({ onClose, onSave }: { onClose: () => void; onSave: (a: Agent) => void }) {
  const [form, setForm] = useState<Agent>(EMPTY)
  const set = (k: keyof Agent, v: unknown) => setForm(prev => ({ ...prev, [k]: v }))

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">
          <h3>Create Agent</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16}/></button>
        </div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Name *</label>
            <input id="agent-name" className="form-input" value={form.name} onChange={e => set('name', e.target.value)} placeholder="ResearchAgent" />
          </div>
          <div className="form-group">
            <label className="form-label">Role *</label>
            <input className="form-input" value={form.role} onChange={e => set('role', e.target.value)} placeholder="Senior Researcher" />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Goal *</label>
          <input className="form-input" value={form.goal} onChange={e => set('goal', e.target.value)} placeholder="Research and summarize topics accurately" />
        </div>
        <div className="form-group">
          <label className="form-label">Backstory</label>
          <textarea className="form-textarea" value={form.backstory} onChange={e => set('backstory', e.target.value)} placeholder="An experienced researcher with..." />
        </div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">LLM Tags (comma-separated)</label>
            <input className="form-input" value={form.llm_tags.join(',')} onChange={e => set('llm_tags', e.target.value.split(',').map(s => s.trim()).filter(Boolean))} placeholder="fast,openai" />
          </div>
          <div className="form-group">
            <label className="form-label">Tool Refs (comma-separated)</label>
            <input className="form-input" value={form.tool_refs.join(',')} onChange={e => set('tool_refs', e.target.value.split(',').map(s => s.trim()).filter(Boolean))} placeholder="web_search,code_runner" />
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            id="agent-save-btn"
            className="btn btn-primary"
            disabled={!form.name || !form.role || !form.goal}
            onClick={() => onSave(form)}
          >
            Create Agent
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Agents() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const { data: agents = [], isLoading } = useQuery({ queryKey: ['agents'], queryFn: getAgents })
  const create = useMutation({ mutationFn: createAgent, onSuccess: () => { qc.invalidateQueries({ queryKey: ['agents'] }); setShowModal(false) } })
  const remove = useMutation({ mutationFn: deleteAgent, onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }) })

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Agents</h2>
          <p>Manage autonomous agents in your project</p>
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
          <h3>No agents yet</h3>
          <p>Create your first agent or use the Builder to generate one.</p>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr><th>Name</th><th>Role</th><th>Goal</th><th>Tags</th><th>Tools</th><th></th></tr>
            </thead>
            <tbody>
              {agents.map(a => (
                <tr key={a.name}>
                  <td><strong>{a.name}</strong></td>
                  <td className="text-muted">{a.role}</td>
                  <td style={{ maxWidth: 260 }} className="truncate">{a.goal}</td>
                  <td>{a.llm_tags.map(t => <span key={t} className="badge badge-default" style={{ marginRight: 4 }}>{t}</span>)}</td>
                  <td>{a.tool_refs.length > 0 ? a.tool_refs.join(', ') : <span className="text-muted">none</span>}</td>
                  <td>
                    <button
                      className="btn btn-ghost btn-sm btn-danger"
                      onClick={() => { if (confirm(`Delete agent '${a.name}'?`)) remove.mutate(a.name) }}
                    ><Trash2 size={14}/></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && (
        <AgentModal
          onClose={() => setShowModal(false)}
          onSave={a => create.mutate(a)}
        />
      )}
    </div>
  )
}
