import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getPolicies, createPolicy, deletePolicy } from '../api/client'
import { Plus, Shield, Trash2, X } from 'lucide-react'

function PolicyModal({ onClose, onSave }: { onClose: () => void; onSave: (p: { name: string; policy_type: string; denied_keywords: string[]; allowed_keywords: string[]; priority: number }) => void }) {
  const [form, setForm] = useState({ name: '', policy_type: 'action', denied_keywords: '', allowed_keywords: '', priority: 0 })

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">
          <h3>Add Policy</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16}/></button>
        </div>
        <div className="form-group">
          <label className="form-label">Policy Name *</label>
          <input id="policy-name" className="form-input" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="Block Exploit Actions" />
        </div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Type</label>
            <select className="form-select" value={form.policy_type} onChange={e => setForm(p => ({ ...p, policy_type: e.target.value }))}>
              <option value="action">Action</option>
              <option value="privacy">Privacy</option>
              <option value="resource">Resource</option>
              <option value="safety">Safety</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Priority</label>
            <input type="number" className="form-input" value={form.priority} onChange={e => setForm(p => ({ ...p, priority: Number(e.target.value) }))} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Denied Keywords (comma-separated)</label>
          <input className="form-input" value={form.denied_keywords} onChange={e => setForm(p => ({ ...p, denied_keywords: e.target.value }))} placeholder="exploit,malware,brute_force" />
        </div>
        <div className="form-group">
          <label className="form-label">Allowed Keywords (comma-separated, or leave empty for deny-only)</label>
          <input className="form-input" value={form.allowed_keywords} onChange={e => setForm(p => ({ ...p, allowed_keywords: e.target.value }))} placeholder="" />
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            id="policy-save-btn"
            className="btn btn-primary"
            disabled={!form.name}
            onClick={() => onSave({
              name: form.name,
              policy_type: form.policy_type,
              denied_keywords: form.denied_keywords.split(',').map(s => s.trim()).filter(Boolean),
              allowed_keywords: form.allowed_keywords.split(',').map(s => s.trim()).filter(Boolean),
              priority: form.priority,
            })}
          >
            Add Policy
          </button>
        </div>
      </div>
    </div>
  )
}

const TYPE_COLORS: Record<string, string> = {
  action: 'badge-running',
  privacy: 'badge-queued',
  resource: 'badge-default',
  safety: 'badge-failed',
}

export default function Governance() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const { data: policies = [], isLoading } = useQuery({ queryKey: ['policies'], queryFn: getPolicies })
  const create = useMutation({ mutationFn: createPolicy, onSuccess: () => { qc.invalidateQueries({ queryKey: ['policies'] }); setShowModal(false) } })
  const remove = useMutation({ mutationFn: deletePolicy, onSuccess: () => qc.invalidateQueries({ queryKey: ['policies'] }) })

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Governance</h2>
          <p>Policies that control what agents can and cannot do</p>
        </div>
        <button id="create-policy-btn" className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={15}/> Add Policy
        </button>
      </div>

      {isLoading ? <div className="empty-state"><div className="spinner"/></div> :
        policies.length === 0 ? (
          <div className="empty-state"><Shield size={40}/><h3>No policies</h3><p>Add policies to enforce security and safety constraints.</p></div>
        ) : (
          <div className="table-container">
            <table>
              <thead><tr><th>Name</th><th>Type</th><th>Priority</th><th>ID</th><th></th></tr></thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id}>
                    <td><strong>{p.name}</strong></td>
                    <td><span className={`badge ${TYPE_COLORS[p.policy_type] || 'badge-default'}`}>{p.policy_type}</span></td>
                    <td>{p.priority}</td>
                    <td className="font-mono text-muted" style={{ fontSize: 11 }}>{p.id.slice(0, 12)}...</td>
                    <td>
                      <button className="btn btn-ghost btn-sm btn-danger" onClick={() => remove.mutate(p.id)}>
                        <Trash2 size={13}/>
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
        <PolicyModal
          onClose={() => setShowModal(false)}
          onSave={p => create.mutate(p)}
        />
      )}
    </div>
  )
}
