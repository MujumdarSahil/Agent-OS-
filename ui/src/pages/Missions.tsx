import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getMissions, getCrews, createMission, runMission, type Mission } from '../api/client'
import { useNavigate } from 'react-router-dom'
import { Plus, Play, Target, X, RotateCcw } from 'lucide-react'

function MissionModal({ crewNames, onClose, onSave }: { crewNames: string[]; onClose: () => void; onSave: (m: Mission) => void }) {
  const [form, setForm] = useState<Mission>({ name: '', goal: '', description: '', crew: crewNames[0] || '', tasks: [] })
  const [taskDesc, setTaskDesc] = useState('')

  const addTask = () => { if (taskDesc.trim()) { setForm(p => ({ ...p, tasks: [...p.tasks, { description: taskDesc.trim(), assigned_agent: null }] })); setTaskDesc('') } }
  const removeTask = (i: number) => setForm(p => ({ ...p, tasks: p.tasks.filter((_, idx) => idx !== i) }))

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={{ maxWidth: 640 }}>
        <div className="modal-header">
          <h3>Create Mission</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16}/></button>
        </div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Name *</label>
            <input className="form-input" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="research_mission" />
          </div>
          <div className="form-group">
            <label className="form-label">Crew *</label>
            <select className="form-select" value={form.crew} onChange={e => setForm(p => ({ ...p, crew: e.target.value }))}>
              {crewNames.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Goal *</label>
          <input className="form-input" value={form.goal} onChange={e => setForm(p => ({ ...p, goal: e.target.value }))} placeholder="Research the latest AI developments" />
        </div>
        <div className="form-group">
          <label className="form-label">Description</label>
          <textarea className="form-textarea" value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
        </div>

        <div className="form-group">
          <label className="form-label">Tasks</label>
          {form.tasks.map((t, i) => (
            <div key={i} className="flex items-center gap-2" style={{ marginBottom: 6 }}>
              <div className="form-input" style={{ flex: 1, color: 'var(--text-secondary)', fontSize: 13 }}>
                {i + 1}. {t.description}
              </div>
              <button className="btn btn-ghost btn-sm" onClick={() => removeTask(i)}><X size={13}/></button>
            </div>
          ))}
          <div className="flex gap-2 mt-4">
            <input className="form-input" value={taskDesc} onChange={e => setTaskDesc(e.target.value)} onKeyDown={e => e.key === 'Enter' && addTask()} placeholder="Task description..." />
            <button className="btn btn-secondary" onClick={addTask}>Add</button>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={!form.name || !form.goal || !form.crew} onClick={() => onSave(form)}>
            Create Mission
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Missions() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [resume, setResume] = useState<Record<string, boolean>>({})

  const { data: missions = [], isLoading } = useQuery({ queryKey: ['missions'], queryFn: getMissions })
  const { data: crews = [] } = useQuery({ queryKey: ['crews'], queryFn: getCrews })
  const create = useMutation({ mutationFn: createMission, onSuccess: () => { qc.invalidateQueries({ queryKey: ['missions'] }); setShowModal(false) } })
  const run = useMutation({
    mutationFn: ({ name, r }: { name: string; r: boolean }) => runMission(name, r),
    onSuccess: (data) => navigate(`/runs/${data.run_id}`)
  })

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Missions</h2>
          <p>Define goals and task sequences for your crews to execute</p>
        </div>
        <button id="create-mission-btn" className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={15}/> New Mission
        </button>
      </div>

      {isLoading ? <div className="empty-state"><div className="spinner"/></div> :
        missions.length === 0 ? (
          <div className="empty-state"><Target size={40}/><h3>No missions yet</h3><p>Create a mission to orchestrate your crews.</p></div>
        ) : (
          <div className="table-container">
            <table>
              <thead><tr><th>Name</th><th>Goal</th><th>Crew</th><th>Tasks</th><th>Resume</th><th>Action</th></tr></thead>
              <tbody>
                {missions.map(m => (
                  <tr key={m.name}>
                    <td><strong>{m.name}</strong></td>
                    <td style={{ maxWidth: 220 }} className="truncate">{m.goal}</td>
                    <td><span className="badge badge-default">{m.crew}</span></td>
                    <td>{m.tasks.length}</td>
                    <td>
                      <input type="checkbox" checked={!!resume[m.name]} onChange={e => setResume(p => ({ ...p, [m.name]: e.target.checked }))} />
                    </td>
                    <td>
                      <button
                        id={`run-${m.name}`}
                        className="btn btn-sm btn-primary"
                        onClick={() => run.mutate({ name: m.name, r: !!resume[m.name] })}
                        disabled={run.isPending}
                      >
                        {resume[m.name] ? <RotateCcw size={12}/> : <Play size={12}/>}
                        {resume[m.name] ? 'Resume' : 'Run'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      }

      {showModal && (
        <MissionModal
          crewNames={crews.map(c => c.name)}
          onClose={() => setShowModal(false)}
          onSave={m => create.mutate(m)}
        />
      )}
    </div>
  )
}
