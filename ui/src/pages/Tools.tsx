import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getV2Tools, createV2Tool, deleteV2Tool, type V2Tool } from '../api/client'
import { Plus, Wrench, FileCode, Trash2, ShieldCheck, Lock } from 'lucide-react'

const DEFAULT_TOOL_CODE = `from agentos.tools import BaseTool

class CustomTool(BaseTool):
    name: str = "custom_tool"
    description: str = "A custom tool definition"

    def _run(self, query: str) -> str:
        # Tool logic executes only inside the secure sandbox
        return f"Processed query: {query}"
`

export default function Tools() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [code, setCode] = useState(DEFAULT_TOOL_CODE)
  const [showForm, setShowForm] = useState(false)
  const [selectedTool, setSelectedTool] = useState<V2Tool | null>(null)

  const { data: tools = [], isLoading } = useQuery({
    queryKey: ['v2-tools'],
    queryFn: getV2Tools,
  })

  const create = useMutation({
    mutationFn: () => createV2Tool({ name, description: desc, code, language: 'python' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['v2-tools'] })
      setName('')
      setDesc('')
      setCode(DEFAULT_TOOL_CODE)
      setShowForm(false)
    },
    onError: (err: any) => {
      alert(`Failed to create tool: ${err.response?.data?.detail || err.message}`)
    },
  })

  const remove = useMutation({
    mutationFn: deleteV2Tool,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['v2-tools'] })
      if (selectedTool?.name === name) setSelectedTool(null)
    },
    onError: (err: any) => {
      alert(`Failed to delete tool: ${err.response?.data?.detail || err.message}`)
    },
  })

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Tools (v2)</h2>
          <p>Tool definitions backed by storage ports (stored code runs only in sandboxes)</p>
        </div>
        <button id="create-tool-btn" className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          <Plus size={15}/> New Tool
        </button>
      </div>

      {showForm && (
        <div className="card mb-4">
          <h3 style={{ fontWeight: 700, marginBottom: 16, fontSize: 14 }}>Create Custom Tool</h3>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label">Tool Name (snake_case) *</label>
              <input
                id="tool-name-input"
                className="form-input"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="analyze_sentiment"
              />
            </div>
            <div className="form-group">
              <label className="form-label">Description</label>
              <input
                id="tool-desc-input"
                className="form-input"
                value={desc}
                onChange={e => setDesc(e.target.value)}
                placeholder="Analyzes sentiment of the supplied text"
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Python Source Code</label>
            <textarea
              id="tool-code-input"
              className="form-textarea font-mono"
              style={{ minHeight: '160px', fontSize: '13px' }}
              value={code}
              onChange={e => setCode(e.target.value)}
            />
            <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Stored code is preserved as text and never imported by the API server (principle 6).
            </p>
          </div>

          <div className="flex gap-2">
            <button
              id="save-tool-btn"
              className="btn btn-primary"
              disabled={!name.trim()}
              onClick={() => create.mutate()}
            >
              Save Tool
            </button>
            <button className="btn btn-secondary" onClick={() => setShowForm(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="empty-state"><div className="spinner"/></div>
      ) : tools.length === 0 ? (
        <div className="empty-state">
          <Wrench size={40}/>
          <h3>No tools found</h3>
          <p>Create a custom tool definition or add project tools in tools/*.py.</p>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Origin</th>
                <th>Description</th>
                <th>Source Code</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {tools.map(t => {
                const isProject = t.origin === 'project'
                return (
                  <tr key={t.name}>
                    <td>
                      <div className="flex items-center gap-2">
                        <FileCode size={14} color={isProject ? 'var(--accent-teal)' : 'var(--accent-purple)'}/>
                        <strong>{t.name}</strong>
                      </div>
                    </td>
                    <td>
                      <span className={`badge ${isProject ? 'badge-default' : 'badge-completed'}`}>
                        {isProject ? (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            <Lock size={10} /> Project (Read-Only)
                          </span>
                        ) : (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            <ShieldCheck size={10} /> Stored (Sandboxed)
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="text-muted" style={{ fontSize: 13 }}>{t.description || '—'}</td>
                    <td>
                      {t.code ? (
                        <button
                          className="btn btn-ghost btn-sm font-mono"
                          style={{ fontSize: 11 }}
                          onClick={() => setSelectedTool(selectedTool?.name === t.name ? null : t)}
                        >
                          {selectedTool?.name === t.name ? 'Hide Code' : 'View Code'}
                        </button>
                      ) : (
                        <span className="text-muted" style={{ fontSize: 12 }}>File-based</span>
                      )}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {!isProject && (
                        <button
                          className="btn btn-ghost btn-sm"
                          style={{ color: 'var(--accent-red)' }}
                          onClick={() => {
                            if (confirm(`Delete tool "${t.name}"?`)) {
                              remove.mutate(t.name)
                            }
                          }}
                        >
                          <Trash2 size={14}/>
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedTool && selectedTool.code && (
        <div className="card mt-4">
          <div className="flex items-center justify-between mb-2">
            <h4 style={{ margin: 0, fontSize: 14 }}>Code: {selectedTool.name}</h4>
            <button className="btn btn-ghost btn-sm" onClick={() => setSelectedTool(null)}>Close</button>
          </div>
          <pre className="code-block" style={{ maxHeight: '300px', overflowY: 'auto' }}>
            {selectedTool.code}
          </pre>
        </div>
      )}
    </div>
  )
}
