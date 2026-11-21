import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getV2Squads, createV2Squad, deleteV2Squad, getV2Agents, type V2Squad } from '../api/client'
import { Plus, Users, Trash2, X, UserCheck } from 'lucide-react'

const ROLES = ['coordinator', 'worker', 'reviewer', 'lead', 'observer']

function SquadModal({
  availableAgents,
  onClose,
  onSave,
}: {
  availableAgents: string[]
  onClose: () => void
  onSave: (s: V2Squad) => void
}) {
  const [name, setName] = useState('')
  const [process, setProcess] = useState('sequential')
  const [selectedAgents, setSelectedAgents] = useState<string[]>([])
  const [memberRoles, setMemberRoles] = useState<Record<string, string>>({})
  const [error, setError] = useState<string | null>(null)

  const toggleAgent = (agentName: string) => {
    if (selectedAgents.includes(agentName)) {
      setSelectedAgents(prev => prev.filter(a => a !== agentName))
      setMemberRoles(prev => {
        const next = { ...prev }
        delete next[agentName]
        return next
      })
    } else {
      setSelectedAgents(prev => [...prev, agentName])
      setMemberRoles(prev => ({ ...prev, [agentName]: 'worker' }))
    }
  }

  const setRole = (agentName: string, role: string) => {
    setMemberRoles(prev => ({ ...prev, [agentName]: role }))
  }

  const handleSave = () => {
    if (!name.trim()) {
      setError('Squad name is required')
      return
    }
    if (selectedAgents.length === 0) {
      setError('At least one agent must be added to the squad')
      return
    }

    onSave({
      name: name.trim(),
      process,
      agents: selectedAgents,
      roles: memberRoles,
    })
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={{ maxWidth: '600px' }}>
        <div className="modal-header">
          <h3>Create Squad (v2)</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16}/></button>
        </div>

        {error && (
          <div style={{ padding: '8px 12px', background: 'rgba(239,68,68,0.1)', color: 'var(--accent-red)', borderRadius: 6, marginBottom: 12, fontSize: 13 }}>
            {error}
          </div>
        )}

        <div className="form-group">
          <label className="form-label">Squad Name *</label>
          <input
            id="squad-name"
            className="form-input"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="research_and_review_squad"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Execution Process</label>
          <select className="form-select" value={process} onChange={e => setProcess(e.target.value)}>
            <option value="sequential">Sequential</option>
            <option value="hierarchical">Hierarchical</option>
          </select>
        </div>

        <div className="form-group">
          <label className="form-label">Select Members & Assign Roles</label>
          {availableAgents.length === 0 ? (
            <p className="text-muted" style={{ fontSize: 13 }}>No agents available. Create agents first.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 6 }}>
              {availableAgents.map(agentName => {
                const isSelected = selectedAgents.includes(agentName)
                return (
                  <div
                    key={agentName}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      background: isSelected ? 'var(--bg-hover)' : 'transparent',
                      border: '1px solid var(--border-color)',
                      borderRadius: 8,
                    }}
                  >
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleAgent(agentName)}
                      />
                      <span style={{ fontWeight: 600, fontSize: 13 }}>{agentName}</span>
                    </label>

                    {isSelected && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Role:</span>
                        <select
                          className="form-select"
                          style={{ padding: '4px 8px', fontSize: 12, height: 28, width: 130 }}
                          value={memberRoles[agentName] || 'worker'}
                          onChange={e => setRole(agentName, e.target.value)}
                        >
                          {ROLES.map(r => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            id="squad-save-btn"
            className="btn btn-primary"
            disabled={!name.trim() || selectedAgents.length === 0}
            onClick={handleSave}
          >
            Create Squad
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Squads() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)

  const { data: squads = [], isLoading } = useQuery({
    queryKey: ['v2-squads'],
    queryFn: getV2Squads,
  })

  const { data: agents = [] } = useQuery({
    queryKey: ['v2-agents'],
    queryFn: getV2Agents,
  })

  const create = useMutation({
    mutationFn: createV2Squad,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['v2-squads'] })
      setShowModal(false)
    },
    onError: (err: any) => {
      alert(`Failed to create squad: ${err.response?.data?.detail || err.message}`)
    },
  })

  const remove = useMutation({
    mutationFn: deleteV2Squad,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['v2-squads'] }),
    onError: (err: any) => {
      alert(`Failed to delete squad: ${err.response?.data?.detail || err.message}`)
    },
  })

  const agentNames = agents.map(a => a.name)

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Squads (v2)</h2>
          <p>Multi-agent squads with explicit role assignments (coordinator, worker, reviewer)</p>
        </div>
        <button id="create-squad-btn" className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={15}/> New Squad
        </button>
      </div>

      {isLoading ? (
        <div className="empty-state"><div className="spinner"/></div>
      ) : squads.length === 0 ? (
        <div className="empty-state">
          <Users size={40}/>
          <h3>No squads configured</h3>
          <p>Combine multiple agents into a collaborative squad with defined roles.</p>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Process</th>
                <th>Members & Assigned Roles</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {squads.map(sq => (
                <tr key={sq.name}>
                  <td><strong>{sq.name}</strong></td>
                  <td>
                    <span className={`badge ${sq.process === 'hierarchical' ? 'badge-running' : 'badge-default'}`}>
                      {sq.process}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {sq.agents.map(a => {
                        const role = sq.roles?.[a] || 'member'
                        return (
                          <span
                            key={a}
                            className="badge badge-default"
                            style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
                          >
                            <UserCheck size={11} color="var(--accent-purple)"/>
                            <strong>{a}</strong>
                            <span style={{ opacity: 0.7, fontSize: 11 }}>({role})</span>
                          </span>
                        )
                      })}
                    </div>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-ghost btn-sm"
                      style={{ color: 'var(--accent-red)' }}
                      onClick={() => {
                        if (confirm(`Delete squad "${sq.name}"?`)) {
                          remove.mutate(sq.name)
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

      {showModal && (
        <SquadModal
          availableAgents={agentNames}
          onClose={() => setShowModal(false)}
          onSave={squad => create.mutate(squad)}
        />
      )}
    </div>
  )
}
