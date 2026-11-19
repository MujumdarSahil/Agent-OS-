// src/pages/MCPServers.tsx — 2.5a: Connect > MCP servers.
// Register a server, enable it (the exact command line or URL is shown first), discover its tools, and
// review each tool before any agent can use it. Tool descriptions and schemas come from the server and are
// UNTRUSTED: they are shown only as plain text (<UntrustedText>), never rendered as markdown or HTML.
// env shows variable NAMES only; secret_env shows vault NAMES only; values are never displayed.

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Key, Plus, Server, ShieldAlert, Trash2 } from 'lucide-react'
import {
  approveMCPTool, createV2MCPServer, deleteV2MCPServer, discoverMCPServer, getMCPLaunchPreview,
  getMCPServersView, revokeMCPTool, setMCPEnabled,
  type MCPLaunchPreview, type MCPSideEffect, type MCPToolState, type V2MCPServerView,
} from '../api/client'
import { UntrustedText } from '../flow/RunPanel'

const errText = (e: unknown) => {
  const r = (e as { response?: { data?: { detail?: unknown } }; message?: string })
  const d = r?.response?.data?.detail
  return typeof d === 'string' ? d : d ? JSON.stringify(d) : r?.message || String(e)
}

const STATUS_STYLE: Record<string, { label: string; color: string }> = {
  unreviewed: { label: 'unreviewed', color: 'var(--text-muted)' },
  approved: { label: 'approved', color: 'var(--accent-teal)' },
  changed: { label: 'changed, needs review', color: 'var(--accent-red)' },
  missing: { label: 'no longer offered', color: 'var(--text-muted)' },
}

function ReviewPanel({ server, tool, state, onDone }: {
  server: string; tool: string; state: MCPToolState; onDone: () => void
}) {
  const props = Object.keys(((state.snapshot.input_schema || {}) as { properties?: Record<string, unknown> }).properties || {})
  const [sideEffect, setSideEffect] = useState<MCPSideEffect>(state.approval?.side_effect ?? 'read')
  const [untrustedOk, setUntrustedOk] = useState<string[]>(state.approval?.untrusted_ok_args ?? [])
  const [conf, setConf] = useState(state.approval?.output_confidentiality ?? 'internal')
  const [desc, setDesc] = useState(state.approval?.replacement_description ?? '')
  const [error, setError] = useState<string | null>(null)
  const approve = useMutation({
    mutationFn: () => approveMCPTool(server, tool, {
      expected_sha256: state.snapshot.sha256, side_effect: sideEffect,
      untrusted_ok_args: sideEffect === 'read' ? [] : untrustedOk, output_confidentiality: conf,
      replacement_description: desc.trim() || null,
    }),
    onSuccess: onDone,
    onError: e => setError(errText(e)),
  })
  const revoke = useMutation({ mutationFn: () => revokeMCPTool(server, tool), onSuccess: onDone, onError: e => setError(errText(e)) })

  return (
    <div className="card" style={{ margin: '6px 0 10px', padding: 12 }} data-testid={`review-${tool}`}>
      <div className="text-muted" style={{ fontSize: 12, marginBottom: 6 }}>
        Description and schema below were written by the server: <strong>untrusted</strong>, shown as plain text.
        If you don't write a replacement description, agents using this tool start with an untrusted context.
      </div>
      <div className="form-label">Server description</div>
      <UntrustedText value={state.snapshot.description || '(none)'} />
      <div className="form-label mt-2">Input schema</div>
      <UntrustedText value={state.snapshot.input_schema} />
      {state.warnings.map(w => (
        <div key={w} style={{ color: 'var(--accent-amber)', fontSize: 12, marginTop: 6 }} data-testid="review-warning">{w}</div>
      ))}
      <div className="form-row mt-2">
        <div className="form-group">
          <label className="form-label" htmlFor={`se-${tool}`}>Side-effect class</label>
          <select id={`se-${tool}`} className="form-select" data-testid="review-side-effect" value={sideEffect}
            onChange={e => setSideEffect(e.target.value as MCPSideEffect)}>
            <option value="read">read</option>
            <option value="write">write</option>
            <option value="external_send">external_send</option>
            <option value="destructive">destructive</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`conf-${tool}`}>Output confidentiality</label>
          <select id={`conf-${tool}`} className="form-select" data-testid="review-confidentiality" value={conf}
            onChange={e => setConf(e.target.value)}>
            {['public', 'internal', 'confidential', 'secret'].map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
      </div>
      {sideEffect !== 'read' && (
        <div className="form-group" data-testid="review-sink-rules">
          <div className="form-label">Sink rules (above read, every argument must be trusted: pinned or allowlisted)</div>
          {props.length === 0 && <div className="text-muted" style={{ fontSize: 12 }}>This tool takes no arguments.</div>}
          {props.map(p => (
            <label key={p} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <input type="checkbox" data-testid={`review-untrusted-ok-${p}`} checked={untrustedOk.includes(p)}
                onChange={e => setUntrustedOk(cur => e.target.checked ? [...cur, p] : cur.filter(x => x !== p))} />
              <code>{p}</code> may be untrusted
            </label>
          ))}
        </div>
      )}
      <div className="form-group">
        <label className="form-label" htmlFor={`desc-${tool}`}>Replacement description (recommended: the model sees only this)</label>
        <textarea id={`desc-${tool}`} className="form-textarea" data-testid="review-description" value={desc}
          onChange={e => setDesc(e.target.value)} placeholder="What this tool does, in your words" />
      </div>
      {error && <div style={{ color: 'var(--accent-red)', fontSize: 12 }} data-testid="review-error">{error}</div>}
      <div className="flex gap-2">
        <button className="btn btn-primary btn-sm" data-testid="review-approve" disabled={approve.isPending}
          onClick={() => approve.mutate()}>Approve this version</button>
        {state.approval && (
          <button className="btn btn-ghost btn-sm" data-testid="review-revoke" onClick={() => revoke.mutate()}>Revoke</button>
        )}
      </div>
    </div>
  )
}

function ServerCard({ s, onChanged }: { s: V2MCPServerView; onChanged: () => void }) {
  const [preview, setPreview] = useState<MCPLaunchPreview | null>(null)
  const [reviewing, setReviewing] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const enable = useMutation({
    mutationFn: (on: boolean) => setMCPEnabled(s.name, on),
    onSuccess: () => { setPreview(null); onChanged() },
    onError: e => setError(errText(e)),
  })
  const discover = useMutation({ mutationFn: () => discoverMCPServer(s.name), onSuccess: () => { setError(null); onChanged() }, onError: e => setError(errText(e)) })
  const remove = useMutation({ mutationFn: () => deleteV2MCPServer(s.name), onSuccess: onChanged, onError: e => setError(errText(e)) })
  const tools = Object.entries(s.tools || {})
  const target = s.transport === 'stdio' ? `${s.command ?? ''} ${(s.args || []).join(' ')}`.trim() : s.url || '-'

  return (
    <div className="card mb-3" data-testid={`mcp-server-${s.name}`}>
      <div className="flex items-center gap-2" style={{ flexWrap: 'wrap' }}>
        <strong>{s.name}</strong>
        <span className="badge badge-default">{s.transport.toUpperCase()}</span>
        <span className="badge" data-testid="mcp-status"
          style={{ color: s.enabled ? 'var(--accent-teal)' : 'var(--text-muted)' }}>{s.enabled ? 'Enabled' : 'Disabled'}</span>
        <div className="ml-auto flex gap-2">
          {s.enabled ? (
            <>
              <button className="btn btn-secondary btn-sm" data-testid="mcp-discover" disabled={discover.isPending}
                onClick={() => discover.mutate()}>{discover.isPending ? 'Discovering…' : 'Discover tools'}</button>
              <button className="btn btn-ghost btn-sm" data-testid="mcp-disable" onClick={() => enable.mutate(false)}>Disable</button>
            </>
          ) : (
            <button className="btn btn-secondary btn-sm" data-testid="mcp-enable"
              onClick={async () => { try { setPreview(await getMCPLaunchPreview(s.name)) } catch (e) { setError(errText(e)) } }}>
              Enable…
            </button>
          )}
          <button className="btn btn-ghost btn-sm" style={{ color: 'var(--accent-red)' }} aria-label={`Delete ${s.name}`}
            onClick={() => { if (confirm(`Delete MCP server "${s.name}"?`)) remove.mutate() }}><Trash2 size={14} /></button>
        </div>
      </div>
      <div className="font-mono text-muted" style={{ fontSize: 12, marginTop: 6 }} data-testid="mcp-target">{target}</div>
      <div style={{ fontSize: 12, marginTop: 6, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <span data-testid="mcp-env-names">env: {Object.keys(s.env || {}).join(', ') || 'none'}</span>
        <span data-testid="mcp-secret-env">
          secret_env: {Object.keys(s.secret_env || {}).length === 0 ? 'none' : Object.entries(s.secret_env).map(([k, v]) => (
            <span key={k} className="badge badge-default" style={{ marginRight: 4 }}><Key size={10} /> {k} → vault:{v}</span>
          ))}
        </span>
      </div>

      {preview && (
        <div className="card" style={{ marginTop: 10, padding: 12, borderColor: 'var(--accent-amber)' }} data-testid="mcp-enable-preview">
          <div className="font-semibold" style={{ fontSize: 13 }}>Enabling allows AgentOS to {preview.transport === 'stdio' ? 'run this exact command' : 'connect to this URL'}:</div>
          <pre className="font-mono" style={{ whiteSpace: 'pre-wrap', fontSize: 12, margin: '6px 0' }} data-testid="mcp-command-line">
            {preview.transport === 'stdio' ? preview.command_line : preview.url}
          </pre>
          {preview.transport === 'stdio' && (
            <div className="text-muted" style={{ fontSize: 12 }}>
              Working folder: <code>{preview.cwd}</code>. Environment (names only, built from scratch, nothing inherited):{' '}
              <code data-testid="mcp-preview-env">{(preview.env_names || []).join(', ')}</code>
              {preview.secret_env && Object.keys(preview.secret_env).length > 0 && (
                <> plus vault secrets {Object.entries(preview.secret_env).map(([k, v]) => `${k}←${v}`).join(', ')}</>
              )}
            </div>
          )}
          {preview.note && <div style={{ color: 'var(--accent-red)', fontSize: 12 }}>{preview.note}</div>}
          <div className="flex gap-2 mt-2">
            <button className="btn btn-primary btn-sm" data-testid="mcp-enable-confirm" onClick={() => enable.mutate(true)}>Enable</button>
            <button className="btn btn-ghost btn-sm" onClick={() => setPreview(null)}>Cancel</button>
          </div>
        </div>
      )}

      {error && <div style={{ color: 'var(--accent-red)', fontSize: 12, marginTop: 6 }} data-testid="mcp-error">{error}</div>}

      {(s.last_discovery?.rejected || []).map(r => (
        <div key={r.tool} style={{ color: 'var(--accent-red)', fontSize: 12, marginTop: 6 }} data-testid="mcp-rejected">
          Rejected tool name {r.tool}: {r.reason}
        </div>
      ))}

      {tools.length > 0 && (
        <table style={{ width: '100%', fontSize: 13, marginTop: 10 }} data-testid="mcp-tools">
          <thead><tr><th style={{ textAlign: 'left' }}>Tool</th><th style={{ textAlign: 'left' }}>Status</th><th /></tr></thead>
          <tbody>
            {tools.map(([tool, st]) => (
              <tr key={tool} data-testid={`mcp-tool-${tool}`} data-status={st.status}>
                <td colSpan={reviewing === tool ? 3 : 1}>
                  <code>{st.canonical_name}</code>
                  {st.approval?.side_effect && st.status === 'approved' && <span className="text-muted"> · {st.approval.side_effect}</span>}
                  {reviewing === tool && (
                    <ReviewPanel server={s.name} tool={tool} state={st} onDone={() => { setReviewing(null); onChanged() }} />
                  )}
                </td>
                {reviewing !== tool && (
                  <>
                    <td data-testid="mcp-tool-status" style={{ color: STATUS_STYLE[st.status]?.color }}>{STATUS_STYLE[st.status]?.label ?? st.status}</td>
                    <td style={{ textAlign: 'right' }}>
                      {st.status !== 'missing' && (
                        <button className="btn btn-ghost btn-sm" data-testid="mcp-review" onClick={() => setReviewing(tool)}>Review</button>
                      )}
                    </td>
                  </>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default function MCPServers() {
  const qc = useQueryClient()
  const { data: servers = [], isLoading } = useQuery({ queryKey: ['v2-mcp-servers'], queryFn: getMCPServersView })
  const refresh = () => qc.invalidateQueries({ queryKey: ['v2-mcp-servers'] })
  const [showModal, setShowModal] = useState(false)
  const [name, setName] = useState('')
  const [transport, setTransport] = useState<'stdio' | 'http'>('stdio')
  const [command, setCommand] = useState('')
  const [argsStr, setArgsStr] = useState('')
  const [url, setUrl] = useState('')
  const [envStr, setEnvStr] = useState('')
  const [secretStr, setSecretStr] = useState('')
  const [error, setError] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: createV2MCPServer,
    onSuccess: () => { refresh(); setShowModal(false); setName(''); setCommand(''); setArgsStr(''); setUrl(''); setEnvStr(''); setSecretStr('') },
    onError: e => setError(errText(e)),
  })

  const pairs = (text: string) => {
    const out: Record<string, string> = {}
    for (const line of text.split('\n')) {
      const i = line.indexOf('=')
      if (i > 0 && line.slice(0, i).trim()) out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
    }
    return out
  }

  const handleSave = () => {
    if (!name.trim()) return setError('Server name is required')
    if (transport === 'stdio' && !command.trim()) return setError('stdio MCP servers require a command')
    if (transport === 'http' && !url.trim()) return setError('http MCP servers require a URL')
    create.mutate({
      name: name.trim(), transport,
      command: transport === 'stdio' ? command.trim() : undefined,
      args: argsStr.split(',').map(x => x.trim()).filter(Boolean),
      url: transport === 'http' ? url.trim() : undefined,
      env: pairs(envStr), secret_env: pairs(secretStr),
      enabled: false, // servers start disabled; enabling shows the exact command line first
    })
  }

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', alignItems: 'center' }}>
        <div>
          <h2>External MCP Servers (v2)</h2>
          <p>Connect Model Context Protocol servers and review their tools before agents can use them</p>
        </div>
        <button id="create-mcp-server-btn" className="btn btn-primary ml-auto" onClick={() => setShowModal(true)}>
          <Plus size={15} /> New MCP Server
        </button>
      </div>

      <div className="card mb-4" data-testid="mcp-policy" style={{ borderLeft: '4px solid var(--accent-amber)', padding: '14px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldAlert size={18} color="var(--accent-amber)" />
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
            A server <strong>only starts after an admin enables it</strong> (the exact command line or URL is shown first).
            stdio servers get a minimal environment built from scratch: never your provider keys, the vault master key or
            the API token. Discovered tools are <strong>untrusted until reviewed</strong>; a tool that changes after approval
            is blocked until reviewed again. Tools are only ever available as <code>mcp.&lt;server&gt;.&lt;tool&gt;</code>.
          </p>
        </div>
      </div>

      {isLoading ? (
        <div className="empty-state"><div className="spinner" /></div>
      ) : servers.length === 0 ? (
        <div className="empty-state">
          <Server size={40} />
          <h3>No MCP servers registered</h3>
          <p>Add a stdio or http MCP server. Secrets go through the vault (secret_env).</p>
        </div>
      ) : (
        servers.map(s => <ServerCard key={s.name} s={s} onChanged={refresh} />)
      )}

      {showModal && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setShowModal(false)}>
          <div className="modal" style={{ maxWidth: '600px' }}>
            <div className="modal-header"><h3>Register MCP Server</h3></div>
            <div className="form-group">
              <label className="form-label" htmlFor="mcp-name">Name</label>
              <input id="mcp-name" className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder="notes" />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="mcp-transport">Transport</label>
              <select id="mcp-transport" className="form-select" value={transport} onChange={e => setTransport(e.target.value as 'stdio' | 'http')}>
                <option value="stdio">stdio (local command)</option>
                <option value="http">http (streamable HTTP)</option>
              </select>
            </div>
            {transport === 'stdio' ? (
              <>
                <div className="form-group">
                  <label className="form-label" htmlFor="mcp-command">Command</label>
                  <input id="mcp-command" className="form-input font-mono" value={command} onChange={e => setCommand(e.target.value)} placeholder="python" />
                </div>
                <div className="form-group">
                  <label className="form-label" htmlFor="mcp-args">Arguments (comma separated)</label>
                  <input id="mcp-args" className="form-input font-mono" value={argsStr} onChange={e => setArgsStr(e.target.value)} placeholder="path/to/server.py" />
                </div>
              </>
            ) : (
              <div className="form-group">
                <label className="form-label" htmlFor="mcp-url">URL</label>
                <input id="mcp-url" className="form-input font-mono" value={url} onChange={e => setUrl(e.target.value)} placeholder="http://127.0.0.1:8000/mcp" />
                <p className="text-muted" style={{ fontSize: 11 }}>Local and private addresses need an admin allowlist entry.</p>
              </div>
            )}
            <div className="form-group">
              <label className="form-label" htmlFor="mcp-env">Environment (NAME=value per line; not for secrets)</label>
              <textarea id="mcp-env" className="form-textarea font-mono" value={envStr} onChange={e => setEnvStr(e.target.value)} placeholder="NOTES_FILE=C:\data\notes.json" />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="mcp-secret-env">Secrets from the vault (ENV_NAME=vault_name per line)</label>
              <textarea id="mcp-secret-env" className="form-textarea font-mono" value={secretStr} onChange={e => setSecretStr(e.target.value)} placeholder="SERVICE_TOKEN=my_service_token" />
            </div>
            {error && <div style={{ color: 'var(--accent-red)', fontSize: 12 }}>{error}</div>}
            <div className="flex gap-2">
              <button id="mcp-save-btn" className="btn btn-primary" onClick={handleSave} disabled={create.isPending}>Save (disabled)</button>
              <button className="btn btn-ghost" onClick={() => setShowModal(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
