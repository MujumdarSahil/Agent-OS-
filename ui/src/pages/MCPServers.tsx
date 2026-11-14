import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getV2MCPServers, createV2MCPServer, deleteV2MCPServer } from '../api/client'
import { Plus, Server, Trash2, X, ShieldAlert, Key } from 'lucide-react'

export default function MCPServers() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [name, setName] = useState('')
  const [transport, setTransport] = useState<'stdio' | 'sse' | 'http'>('stdio')
  const [command, setCommand] = useState('')
  const [argsStr, setArgsStr] = useState('')
  const [url, setUrl] = useState('')
  const [envRefsStr, setEnvRefsStr] = useState('')
  const [error, setError] = useState<string | null>(null)

  const { data: servers = [], isLoading } = useQuery({
    queryKey: ['v2-mcp-servers'],
    queryFn: getV2MCPServers,
  })

  const create = useMutation({
    mutationFn: createV2MCPServer,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['v2-mcp-servers'] })
      setShowModal(false)
      setName('')
      setCommand('')
      setArgsStr('')
      setUrl('')
      setEnvRefsStr('')
    },
    onError: (err: any) => {
      setError(err.response?.data?.detail || err.message)
    },
  })

  const remove = useMutation({
    mutationFn: deleteV2MCPServer,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['v2-mcp-servers'] }),
    onError: (err: any) => {
      alert(`Failed to delete MCP server: ${err.response?.data?.detail || err.message}`)
    },
  })

  const handleSave = () => {
    if (!name.trim()) {
      setError('Server name is required')
      return
    }

    if (transport === 'stdio' && !command.trim()) {
      setError('stdio MCP servers require a command')
      return
    }

    if ((transport === 'sse' || transport === 'http') && !url.trim()) {
      setError(`${transport} MCP servers require a URL`)
      return
    }

    // Parse secret env vault refs (e.g. GITHUB_TOKEN=github_vault_key)
    const secretEnv: Record<string, string> = {}
    if (envRefsStr.trim()) {
      const lines = envRefsStr.split('\n')
      for (const line of lines) {
        const parts = line.split('=')
        if (parts.length === 2 && parts[0].trim() && parts[1].trim()) {
          secretEnv[parts[0].trim()] = parts[1].trim()
        }
      }
    }

    const args = argsStr
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)

    create.mutate({
      name: name.trim(),
      transport,
      command: transport === 'stdio' ? command.trim() : undefined,
      args,
      url: transport !== 'stdio' ? url.trim() : undefined,
      env: {},
      secret_env: secretEnv,
      enabled: false, // stdio servers start disabled until explicitly approved
    })
  }

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>External MCP Servers (v2)</h2>
          <p>Register and configure Model Context Protocol (MCP) servers</p>
        </div>
        <button id="create-mcp-server-btn" className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={15}/> New MCP Server
        </button>
      </div>

      <div
        className="card mb-4"
        style={{
          borderLeft: '4px solid var(--accent-purple)',
          background: 'rgba(139, 92, 246, 0.05)',
          padding: '14px 18px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldAlert size={18} color="var(--accent-purple)" />
          <div>
            <strong style={{ fontSize: 13, display: 'block', marginBottom: 2 }}>
              Phase 1.4 Security Policy Notice
            </strong>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: 0, lineHeight: 1.4 }}>
              MCP server configurations are stored and validated, but <strong>never launched automatically</strong> by the server. Stdio commands and connections remain dormant until approved execution environments are provisioned.
            </p>
          </div>
        </div>
      </div>

      {isLoading ? (
        <div className="empty-state"><div className="spinner"/></div>
      ) : servers.length === 0 ? (
        <div className="empty-state">
          <Server size={40}/>
          <h3>No MCP servers registered</h3>
          <p>Add external MCP servers (stdio, SSE, HTTP) with secure vault secret references.</p>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Transport</th>
                <th>Target (Command / URL)</th>
                <th>Vault Secret Refs</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {servers.map(s => (
                <tr key={s.name}>
                  <td><strong>{s.name}</strong></td>
                  <td><span className="badge badge-default">{s.transport.toUpperCase()}</span></td>
                  <td className="font-mono text-muted" style={{ fontSize: 12 }}>
                    {s.transport === 'stdio' ? (
                      `${s.command} ${(s.args || []).join(' ')}`
                    ) : (
                      s.url || '—'
                    )}
                  </td>
                  <td>
                    {Object.keys(s.secret_env || {}).length === 0 ? (
                      <span className="text-muted" style={{ fontSize: 12 }}>None</span>
                    ) : (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {Object.entries(s.secret_env).map(([k, v]) => (
                          <span key={k} className="badge badge-default" style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            <Key size={10} color="var(--accent-teal)" />
                            {k} → <em>{v}</em>
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className="badge badge-default">
                      Configured (Dormant)
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-ghost btn-sm"
                      style={{ color: 'var(--accent-red)' }}
                      onClick={() => {
                        if (confirm(`Delete MCP server "${s.name}"?`)) {
                          remove.mutate(s.name)
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
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setShowModal(false)}>
          <div className="modal" style={{ maxWidth: '600px' }}>
            <div className="modal-header">
              <h3>Register MCP Server (v2)</h3>
              <button className="btn btn-ghost btn-sm" onClick={() => setShowModal(false)}><X size={16}/></button>
            </div>

            {error && (
              <div style={{ padding: '8px 12px', background: 'rgba(239,68,68,0.1)', color: 'var(--accent-red)', borderRadius: 6, marginBottom: 12, fontSize: 13 }}>
                {error}
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Server Name *</label>
              <input
                id="mcp-name"
                className="form-input"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="github_mcp"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Transport</label>
              <select
                className="form-select"
                value={transport}
                onChange={e => setTransport(e.target.value as any)}
              >
                <option value="stdio">stdio (Local Command)</option>
                <option value="sse">sse (Server-Sent Events)</option>
                <option value="http">http (HTTP Post / JSON-RPC)</option>
              </select>
            </div>

            {transport === 'stdio' ? (
              <>
                <div className="form-group">
                  <label className="form-label">Command *</label>
                  <input
                    id="mcp-command"
                    className="form-input"
                    value={command}
                    onChange={e => setCommand(e.target.value)}
                    placeholder="npx -y @modelcontextprotocol/server-github"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Arguments (comma-separated)</label>
                  <input
                    className="form-input"
                    value={argsStr}
                    onChange={e => setArgsStr(e.target.value)}
                    placeholder="--port, 8080"
                  />
                </div>
              </>
            ) : (
              <div className="form-group">
                <label className="form-label">Endpoint URL *</label>
                <input
                  id="mcp-url"
                  className="form-input"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  placeholder="https://mcp.internal.corp/sse"
                />
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Secret Environment References (KEY=vault_secret_name)</label>
              <textarea
                className="form-textarea font-mono"
                style={{ minHeight: '80px', fontSize: 12 }}
                value={envRefsStr}
                onChange={e => setEnvRefsStr(e.target.value)}
                placeholder="GITHUB_PERSONAL_ACCESS_TOKEN=github_token&#10;API_SECRET=my_vault_key"
              />
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Secret values are never saved in plain text. Reference keys stored in the Vault.
              </p>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
              <button
                id="mcp-save-btn"
                className="btn btn-primary"
                disabled={!name.trim()}
                onClick={handleSave}
              >
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
