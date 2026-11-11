import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getCrews, getAgents, createCrew, type Crew } from '../api/client'
import { Plus, Users, X } from 'lucide-react'

function CrewModal({ agentNames, onClose, onSave }: { agentNames: string[]; onClose: () => void; onSave: (c: Crew) => void }) {
  const [name, setName] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [process, setProcess] = useState('sequential')

  const toggle = (a: string) => setSelected(prev => prev.includes(a) ? prev.filter(x => x !== a) : [...prev, a])

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">
          <h3>Create Crew</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16}/></button>
        </div>
        <div className="form-group">
          <label className="form-label">Crew Name *</label>
          <input id="crew-name" className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder="research_crew" />
        </div>
        <div className="form-group">
          <label className="form-label">Process</label>
          <select className="form-select" value={process} onChange={e => setProcess(e.target.value)}>
            <option value="sequential">Sequential</option>
            <option value="hierarchical">Hierarchical</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Agents (select members)</label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 6 }}>
            {agentNames.map(a => (
              <button
                key={a}
                className={`btn btn-sm ${selected.includes(a) ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => toggle(a)}
                type="button"
              >
                {a}
              </button>
            ))}
            {agentNames.length === 0 && <span className="text-muted" style={{ fontSize: 13 }}>No agents in project. Create agents first.</span>}
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            id="crew-save-btn"
            className="btn btn-primary"
            disabled={!name || selected.length === 0}
            onClick={() => onSave({ name, agents: selected, process })}
          >
            Create Crew
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Crews() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const { data: crews = [], isLoading } = useQuery({ queryKey: ['crews'], queryFn: getCrews })
  const { data: agents = [] } = useQuery({ queryKey: ['agents'], queryFn: getAgents })
  const create = useMutation({ mutationFn: createCrew, onSuccess: () => { qc.invalidateQueries({ queryKey: ['crews'] }); setShowModal(false) } })

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Crews</h2>
          <p>Groups of agents working together toward a shared goal</p>
        </div>
        <button id="create-crew-btn" className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={15}/> New Crew
        </button>
      </div>

      {isLoading ? <div className="empty-state"><div className="spinner"/></div> :
        crews.length === 0 ? (
          <div className="empty-state"><Users size={40}/><h3>No crews yet</h3><p>Create a crew to assign agents to missions.</p></div>
        ) : (
          <div className="table-container">
            <table>
              <thead><tr><th>Name</th><th>Agents</th><th>Process</th></tr></thead>
              <tbody>
                {crews.map(c => (
                  <tr key={c.name}>
                    <td><strong>{c.name}</strong></td>
                    <td>{c.agents.map(a => <span key={a} className="badge badge-default" style={{ marginRight: 4 }}>{a}</span>)}</td>
                    <td><span className={`badge ${c.process === 'hierarchical' ? 'badge-running' : 'badge-default'}`}>{c.process}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      }

      {showModal && (
        <CrewModal
          agentNames={agents.map(a => a.name)}
          onClose={() => setShowModal(false)}
          onSave={c => create.mutate(c)}
        />
      )}
    </div>
  )
}
