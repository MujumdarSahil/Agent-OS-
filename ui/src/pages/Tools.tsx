import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getTools, createTool } from '../api/client'
import { Plus, Wrench, FileCode } from 'lucide-react'

export default function Tools() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [showForm, setShowForm] = useState(false)

  const { data: tools = [], isLoading } = useQuery({ queryKey: ['tools'], queryFn: getTools })
  const create = useMutation({
    mutationFn: () => createTool(name, desc),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['tools'] }); setName(''); setDesc(''); setShowForm(false) }
  })

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Tools</h2>
          <p>Python BaseTool stubs used by your agents</p>
        </div>
        <button id="create-tool-btn" className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          <Plus size={15}/> Scaffold Tool
        </button>
      </div>

      {showForm && (
        <div className="card mb-4">
          <h3 style={{ fontWeight: 700, marginBottom: 16, fontSize: 14 }}>New Tool Stub</h3>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label">Tool Name (snake_case) *</label>
              <input id="tool-name-input" className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder="web_search" />
            </div>
            <div className="form-group">
              <label className="form-label">Description</label>
              <input className="form-input" value={desc} onChange={e => setDesc(e.target.value)} placeholder="Searches the web for information" />
            </div>
          </div>
          <div className="flex gap-2">
            <button className="btn btn-primary" disabled={!name} onClick={() => create.mutate()}>Create Stub</button>
            <button className="btn btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? <div className="empty-state"><div className="spinner"/></div> :
        tools.length === 0 ? (
          <div className="empty-state">
            <Wrench size={40}/>
            <h3>No tools yet</h3>
            <p>Scaffold a stub or use the Builder to generate tool code.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead><tr><th>Name</th><th>File</th></tr></thead>
              <tbody>
                {tools.map(t => (
                  <tr key={t.name}>
                    <td><div className="flex items-center gap-2"><FileCode size={14} color="var(--accent-teal)"/><strong>{t.name}</strong></div></td>
                    <td className="font-mono text-muted" style={{ fontSize: 12 }}>{t.file}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      }
    </div>
  )
}
