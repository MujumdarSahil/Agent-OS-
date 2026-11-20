// src/pages/NotificationChannels.tsx — 3.3: Connect > Notification channels (admin; every change audited).
// Email (SMTP, TLS by default; plaintext only for a local test server with "allow insecure local") and Slack
// (incoming webhook on hooks.slack.com). Passwords and webhook URLs are write-only: they go to the vault and are
// never shown again. "Send test" errors are written by AgentOS (no server response text).

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Mail, MessageSquare, Send, Trash2 } from 'lucide-react'
import {
  createChannel, deleteChannel, errorText, listChannels, testChannel, updateChannel, type Channel,
} from '../api/notify'

const csv = (s: string) => s.split(',').map(x => x.trim()).filter(Boolean)

function EmailForm({ onDone }: { onDone: () => void }) {
  const [f, setF] = useState({
    name: '', host: '', port: '587', security: 'starttls', allow_insecure_local: false, username: '', password: '',
    from_address: '', alert_recipients: '', allowed_recipient_domains: '', use_for_flows: false,
  })
  const [err, setErr] = useState<string | null>(null)
  const set = (k: string, v: unknown) => setF(p => ({ ...p, [k]: v }))
  const save = async () => {
    setErr(null)
    try {
      await createChannel({
        type: 'email', name: f.name, host: f.host, port: Number(f.port), security: f.security,
        allow_insecure_local: f.allow_insecure_local, username: f.username || null,
        ...(f.password ? { password: f.password } : {}), from_address: f.from_address,
        alert_recipients: csv(f.alert_recipients), allowed_recipient_domains: csv(f.allowed_recipient_domains),
        use_for_flows: f.use_for_flows,
      })
      onDone()
    } catch (e) { setErr(errorText(e)) }
  }
  return (
    <div className="card" data-testid="email-form" style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 8 }}>
      <input className="form-input" placeholder="name (e.g. ops-mail)" aria-label="Email channel name" value={f.name} onChange={e => set('name', e.target.value)} />
      <input className="form-input" placeholder="SMTP host" aria-label="SMTP host" value={f.host} onChange={e => set('host', e.target.value)} />
      <input className="form-input" placeholder="port" aria-label="SMTP port" value={f.port} onChange={e => set('port', e.target.value)} />
      <select className="form-select" aria-label="Security" value={f.security} onChange={e => set('security', e.target.value)}>
        <option value="starttls">STARTTLS (required)</option>
        <option value="ssl">TLS (SMTPS)</option>
        <option value="none">None (local test server only)</option>
      </select>
      <input className="form-input" placeholder="username (optional)" aria-label="SMTP username" value={f.username} onChange={e => set('username', e.target.value)} />
      <input className="form-input" type="password" autoComplete="new-password" placeholder="password (stored in the vault)" aria-label="SMTP password" value={f.password} onChange={e => set('password', e.target.value)} />
      <input className="form-input" placeholder="From address (fixed)" aria-label="From address" value={f.from_address} onChange={e => set('from_address', e.target.value)} />
      <input className="form-input" placeholder="alert recipients, comma separated" aria-label="Alert recipients" value={f.alert_recipients} onChange={e => set('alert_recipients', e.target.value)} />
      <input className="form-input" placeholder="allowed recipient domains (optional)" aria-label="Allowed recipient domains" value={f.allowed_recipient_domains} onChange={e => set('allowed_recipient_domains', e.target.value)} />
      <div className="flex gap-3 items-center" style={{ fontSize: 12 }}>
        <label><input type="checkbox" checked={f.use_for_flows} onChange={e => set('use_for_flows', e.target.checked)} /> use for flows (send_email)</label>
        <label title="Plaintext SMTP to localhost only, for a local test server"><input type="checkbox" checked={f.allow_insecure_local} onChange={e => set('allow_insecure_local', e.target.checked)} /> allow insecure local</label>
      </div>
      <div className="flex gap-2 items-center" style={{ gridColumn: '1 / -1' }}>
        <button className="btn btn-primary btn-sm" data-testid="email-save" onClick={save}>Add email channel</button>
        {err && <span data-testid="channel-error" style={{ fontSize: 12, color: 'var(--accent-red)' }}>{err}</span>}
      </div>
    </div>
  )
}

function SlackForm({ onDone }: { onDone: () => void }) {
  const [f, setF] = useState({ name: '', webhook_url: '', display_channel: '', internal: false })
  const [err, setErr] = useState<string | null>(null)
  const save = async () => {
    setErr(null)
    try {
      await createChannel({ type: 'slack', ...f })
      onDone()
    } catch (e) { setErr(errorText(e)) }
  }
  return (
    <div className="card" data-testid="slack-form" style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 8 }}>
      <input className="form-input" placeholder="name (e.g. sec-alerts)" aria-label="Slack channel name" value={f.name} onChange={e => setF({ ...f, name: e.target.value })} />
      <input className="form-input" type="password" autoComplete="off" placeholder="https://hooks.slack.com/services/... (stored in the vault)" aria-label="Slack webhook URL" value={f.webhook_url} onChange={e => setF({ ...f, webhook_url: e.target.value })} />
      <input className="form-input" placeholder="#channel (label only)" aria-label="Slack channel label" value={f.display_channel} onChange={e => setF({ ...f, display_channel: e.target.value })} />
      <label style={{ fontSize: 12 }} title="Flows may send untrusted text (escaped) only to an internal channel">
        <input type="checkbox" checked={f.internal} onChange={e => setF({ ...f, internal: e.target.checked })} /> internal (may receive untrusted text)
      </label>
      <div className="flex gap-2 items-center" style={{ gridColumn: '1 / -1' }}>
        <button className="btn btn-primary btn-sm" data-testid="slack-save" onClick={save}>Add Slack channel</button>
        {err && <span data-testid="channel-error" style={{ fontSize: 12, color: 'var(--accent-red)' }}>{err}</span>}
      </div>
    </div>
  )
}

function summary(c: Channel): string {
  if (c.type === 'slack') return `${c.display_channel || 'Slack webhook'}${c.internal ? ' · internal' : ''}`
  const sec = c.security === 'none' ? 'plaintext (local test)' : c.security.toUpperCase()
  return `${c.host}:${c.port} · ${sec} · from ${c.from_address}${c.use_for_flows ? ' · used for flows' : ''}`
}

export default function NotificationChannels() {
  const qc = useQueryClient()
  const channels = useQuery({ queryKey: ['notify-channels'], queryFn: listChannels })
  const [adding, setAdding] = useState<'email' | 'slack' | null>(null)
  const [tests, setTests] = useState<Record<string, { ok: boolean; error?: string }>>({})
  const refresh = () => qc.invalidateQueries({ queryKey: ['notify-channels'] })
  const toggle = useMutation({
    mutationFn: (c: Channel) => updateChannel(c.name, { ...c, enabled: !c.enabled }),
    onSuccess: refresh,
  })
  const remove = useMutation({ mutationFn: (n: string) => deleteChannel(n), onSuccess: refresh })
  const runTest = async (name: string) => {
    try {
      const r = await testChannel(name)
      setTests(t => ({ ...t, [name]: r }))
    } catch (e) {
      setTests(t => ({ ...t, [name]: { ok: false, error: errorText(e) } }))
    }
  }
  return (
    <div data-testid="channels-page">
      <div className="page-header flex items-center gap-3">
        <div>
          <h2>Notification channels</h2>
          <p>Where alerts and flow messages go. Secrets are stored in the vault and never shown again. Every change is audited.</p>
        </div>
        <div className="ml-auto flex gap-2">
          <button className="btn btn-secondary btn-sm" data-testid="add-email" onClick={() => setAdding(adding === 'email' ? null : 'email')}><Mail size={13}/> Email (SMTP)</button>
          <button className="btn btn-secondary btn-sm" data-testid="add-slack" onClick={() => setAdding(adding === 'slack' ? null : 'slack')}><MessageSquare size={13}/> Slack</button>
        </div>
      </div>
      {adding === 'email' && <EmailForm onDone={() => { setAdding(null); refresh() }} />}
      {adding === 'slack' && <SlackForm onDone={() => { setAdding(null); refresh() }} />}
      <div className="card" style={{ marginTop: 12 }}>
        {channels.isLoading ? <div className="spinner" /> : !channels.data?.length ? (
          <div className="text-muted" data-testid="channels-empty">No channels yet. Alerts are recorded but not sent until a rule has a channel; send_email in flows is simulated until an email channel is used for flows.</div>
        ) : (
          <div className="table-container">
            <table data-testid="channels-table">
              <thead><tr><th>Name</th><th>Type</th><th>Settings</th><th>Secret</th><th>Enabled</th><th></th></tr></thead>
              <tbody>
                {channels.data.map(c => (
                  <tr key={c.name} data-testid="channel-row" data-name={c.name}>
                    <td><strong>{c.name}</strong></td>
                    <td><span className="badge badge-default">{c.type}</span></td>
                    <td style={{ fontSize: 12 }}>{summary(c)}</td>
                    <td style={{ fontSize: 12 }}>{(c.type === 'slack' ? c.webhook_set : c.password_set) ? 'set (vault)' : '—'}</td>
                    <td><input type="checkbox" aria-label={`Enable ${c.name}`} checked={c.enabled} onChange={() => toggle.mutate(c)} /></td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button className="btn btn-secondary btn-sm" data-testid={`test-${c.name}`} onClick={() => runTest(c.name)}><Send size={12}/> Send test</button>{' '}
                      <button className="btn btn-secondary btn-sm" aria-label={`Delete ${c.name}`} onClick={() => remove.mutate(c.name)}><Trash2 size={12}/></button>
                      {tests[c.name] && (
                        <div data-testid={`test-result-${c.name}`} style={{ fontSize: 12, color: tests[c.name].ok ? 'var(--accent-teal)' : 'var(--accent-red)' }}>
                          {tests[c.name].ok ? 'Test sent' : tests[c.name].error}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
