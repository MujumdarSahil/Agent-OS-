// 3.4 Settings sections: your account (password), your API tokens, Users (admin), legacy local token (admin).
// Secrets are shown once (a new API token, a rotated legacy token) and never stored by the page.

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Users as UsersIcon, ShieldCheck, UserCog } from 'lucide-react'
import {
  ROLES, ROLE_LABEL, changePassword, createMyToken, createUser, getLegacyToken, listMyTokens, listUsers, resetPassword,
  revokeMyToken, rotateLegacyToken, setLegacyTokenEnabled, updateUser, type Role, type User,
} from '../api/auth'
import { apiErrorMessage } from '../api/flows'
import { useAuth } from '../components/AuthContext'

type Note = { ok: boolean; text: string } | null

function Msg({ m }: { m: Note }) {
  if (!m) return null
  return <div data-testid="access-msg" style={{ fontSize: 12, marginTop: 6, color: m.ok ? 'var(--accent-teal)' : 'var(--accent-red)' }}>{m.text}</div>
}

function OnceSecret({ label, value, onDone }: { label: string; value: string; onDone: () => void }) {
  return (
    <div className="card" data-testid="secret-once" style={{ padding: 10, marginTop: 8, borderColor: 'var(--accent-amber)' }}>
      <div style={{ fontSize: 12, marginBottom: 4 }}>{label} It is shown <strong>once</strong>; AgentOS keeps only a hash.</div>
      <code data-testid="secret-once-value" style={{ wordBreak: 'break-all', fontSize: 12 }}>{value}</code>
      <div className="flex gap-2 mt-2">
        <button className="btn btn-ghost btn-sm" onClick={() => void navigator.clipboard?.writeText(value)}>Copy</button>
        <button className="btn btn-secondary btn-sm" data-testid="secret-once-done" onClick={onDone}>Done, hide it</button>
      </div>
    </div>
  )
}

function MyAccount() {
  const { me } = useAuth()
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [msg, setMsg] = useState<Note>(null)
  if (!me || me.kind !== 'session') return null
  const submit = async () => {
    try {
      const r = (await changePassword(cur, next)) as { other_sessions_revoked: number }
      setMsg({ ok: true, text: `Password changed. Other sessions signed out: ${r.other_sessions_revoked}.` })
    } catch (e) {
      setMsg({ ok: false, text: apiErrorMessage(e) })
    } finally {
      setCur('')
      setNext('')
    }
  }
  return (
    <div className="card" data-testid="my-account">
      <div className="flex items-center gap-2 mb-2"><UserCog size={18} /><h3 style={{ fontWeight: 700, fontSize: 15 }}>Your account</h3></div>
      <p className="text-muted text-xs mb-2">Signed in as <strong>{me.username}</strong> ({ROLE_LABEL[me.role]}).</p>
      <div className="flex gap-2" style={{ flexWrap: 'wrap' }}>
        <input className="form-input" type="password" autoComplete="current-password" placeholder="Current password" value={cur} onChange={e => setCur(e.target.value)} />
        <input className="form-input" type="password" autoComplete="new-password" placeholder="New password (12+)" value={next} onChange={e => setNext(e.target.value)} />
        <button className="btn btn-secondary btn-sm" disabled={!cur || !next} onClick={submit}>Change password</button>
      </div>
      <Msg m={msg} />
    </div>
  )
}

function MyTokens() {
  const { me } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['my-tokens'], queryFn: listMyTokens, enabled: !!me?.user_id })
  const [name, setName] = useState('')
  const [days, setDays] = useState(90)
  const [secret, setSecret] = useState<string | null>(null)
  const [msg, setMsg] = useState<Note>(null)
  if (!me?.user_id) return null
  const create = async () => {
    try {
      const t = await createMyToken(name.trim(), days)
      setSecret(t.token)
      setName('')
      setMsg(null)
      await qc.invalidateQueries({ queryKey: ['my-tokens'] })
    } catch (e) {
      setMsg({ ok: false, text: apiErrorMessage(e) })
    }
  }
  const revoke = async (id: string) => {
    await revokeMyToken(id)
    await qc.invalidateQueries({ queryKey: ['my-tokens'] })
  }
  return (
    <div className="card" data-testid="my-tokens">
      <div className="flex items-center gap-2 mb-2"><KeyRound size={18} /><h3 style={{ fontWeight: 700, fontSize: 15 }}>API tokens</h3></div>
      <p className="text-muted text-xs mb-2">
        For scripts and the CLI: <code>Authorization: Bearer &lt;token&gt;</code>. A token acts with your current role.
      </p>
      {me.kind === 'session' && (
        <div className="flex gap-2" style={{ flexWrap: 'wrap' }}>
          <input className="form-input" data-testid="token-name" placeholder="Token name, e.g. ci" value={name} onChange={e => setName(e.target.value)} />
          <label className="text-xs flex items-center gap-1">Expires in
            <input className="form-input" type="number" min={1} max={365} style={{ width: 80 }} value={days} onChange={e => setDays(Number(e.target.value))} /> days
          </label>
          <button className="btn btn-primary btn-sm" data-testid="token-create" disabled={!name.trim()} onClick={create}>Create token</button>
        </div>
      )}
      {secret && <OnceSecret label="Your new API token." value={secret} onDone={() => setSecret(null)} />}
      <Msg m={msg} />
      <table style={{ width: '100%', fontSize: 12, marginTop: 8 }} data-testid="token-list">
        <thead><tr><th>Name</th><th>Prefix</th><th>Expires</th><th>Last used</th><th>Status</th><th /></tr></thead>
        <tbody>
          {(q.data ?? []).map(t => (
            <tr key={t.token_id} data-testid={`token-row-${t.name}`}>
              <td>{t.name}</td><td className="font-mono">{t.prefix}…</td>
              <td>{new Date(t.expires_at).toLocaleDateString()}</td>
              <td>{t.last_used_at ? new Date(t.last_used_at).toLocaleString() : '-'}</td>
              <td>{t.revoked_at ? 'revoked' : t.active ? 'active' : 'expired'}</td>
              <td>{t.active && <button className="btn btn-danger btn-sm" onClick={() => revoke(t.token_id)}>Revoke</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function UserRow({ u, onChanged }: { u: User; onChanged: (m: Note) => void }) {
  const [pw, setPw] = useState('')
  const act = async (fn: () => Promise<unknown>, ok: string) => {
    try {
      await fn()
      onChanged({ ok: true, text: ok })
    } catch (e) {
      onChanged({ ok: false, text: apiErrorMessage(e) })
    }
  }
  return (
    <tr data-testid={`user-row-${u.username}`}>
      <td>{u.username}</td>
      <td>{u.display_name}</td>
      <td>
        <select className="form-input" aria-label={`Role of ${u.username}`} value={u.role}
                onChange={e => act(() => updateUser(u.id, { role: e.target.value as Role }), `Role of ${u.username} changed`)}>
          {ROLES.map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
        </select>
      </td>
      <td>
        <button className="btn btn-ghost btn-sm" data-testid={`user-toggle-${u.username}`}
                onClick={() => act(() => updateUser(u.id, { disabled: !u.disabled }), `${u.username} ${u.disabled ? 'enabled' : 'disabled'}`)}>
          {u.disabled ? 'Enable' : 'Disable'}
        </button>
      </td>
      <td className="flex gap-1">
        <input className="form-input" type="password" autoComplete="new-password" placeholder="New password" value={pw}
               onChange={e => setPw(e.target.value)} style={{ width: 150 }} />
        <button className="btn btn-secondary btn-sm" disabled={!pw}
                onClick={() => act(async () => { await resetPassword(u.id, pw); setPw('') }, `Password of ${u.username} reset; their sessions ended`)}>
          Reset
        </button>
      </td>
    </tr>
  )
}

function UsersAdmin() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['users'], queryFn: listUsers })
  const [form, setForm] = useState({ username: '', display_name: '', role: 'viewer' as Role, password: '' })
  const [msg, setMsg] = useState<Note>(null)
  const refresh = (m: Note) => {
    setMsg(m)
    void qc.invalidateQueries({ queryKey: ['users'] })
  }
  const create = useMutation({
    mutationFn: () => createUser({ ...form, display_name: form.display_name || undefined }),
    onSuccess: u => {
      setForm({ username: '', display_name: '', role: 'viewer', password: '' })
      refresh({ ok: true, text: `User ${u.username} created` })
    },
    onError: e => setMsg({ ok: false, text: apiErrorMessage(e) }),
  })
  return (
    <div className="card" data-testid="users-admin">
      <div className="flex items-center gap-2 mb-2"><UsersIcon size={18} /><h3 style={{ fontWeight: 700, fontSize: 15 }}>Users</h3></div>
      <p className="text-muted text-xs mb-2">Viewer: read. Approver: + approve runs. Builder: + build, publish and run flows. Admin: everything.</p>
      <div className="flex gap-2" style={{ flexWrap: 'wrap' }}>
        <input className="form-input" data-testid="new-username" placeholder="username" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} />
        <input className="form-input" placeholder="display name" value={form.display_name} onChange={e => setForm({ ...form, display_name: e.target.value })} />
        <select className="form-input" data-testid="new-role" value={form.role} onChange={e => setForm({ ...form, role: e.target.value as Role })}>
          {ROLES.map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
        </select>
        <input className="form-input" data-testid="new-password" type="password" autoComplete="new-password" placeholder="password (12+)"
               value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
        <button className="btn btn-primary btn-sm" data-testid="user-create" disabled={!form.username || !form.password || create.isPending}
                onClick={() => create.mutate()}>Create user</button>
      </div>
      <Msg m={msg} />
      <table style={{ width: '100%', fontSize: 12, marginTop: 8 }} data-testid="user-list">
        <thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th>Password</th></tr></thead>
        <tbody>{(q.data ?? []).map(u => <UserRow key={u.id + u.role + u.disabled} u={u} onChanged={refresh} />)}</tbody>
      </table>
    </div>
  )
}

function LegacyToken() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['legacy-token'], queryFn: getLegacyToken })
  const [secret, setSecret] = useState<string | null>(null)
  const [msg, setMsg] = useState<Note>(null)
  const s = q.data
  const run = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      setMsg(null)
    } catch (e) {
      setMsg({ ok: false, text: apiErrorMessage(e) })
    } finally {
      await qc.invalidateQueries({ queryKey: ['legacy-token'] })
    }
  }
  return (
    <div className="card" data-testid="legacy-token">
      <div className="flex items-center gap-2 mb-2"><ShieldCheck size={18} /><h3 style={{ fontWeight: 700, fontSize: 15 }}>Legacy local token</h3></div>
      <p className="text-muted text-xs mb-2">
        The pre-3.4 local API token. It still works as an admin token for scripts (send_webhook.py, the demo script, CI).
        Its value is never shown here.
      </p>
      {s && (
        <div style={{ fontSize: 12 }}>
          Status: <strong data-testid="legacy-status">{s.enabled ? 'enabled' : 'disabled'}</strong> · source:{' '}
          {s.source === 'env' ? 'AGENTOS_API_TOKEN environment variable' : <code>{s.path}</code>}
          <div className="flex gap-2 mt-2">
            <button className="btn btn-secondary btn-sm" data-testid="legacy-toggle" onClick={() => run(() => setLegacyTokenEnabled(!s.enabled))}>
              {s.enabled ? 'Disable' : 'Enable'}
            </button>
            <button className="btn btn-ghost btn-sm" disabled={!s.can_rotate}
                    title={s.can_rotate ? 'Replace it with a new random token' : 'Set by AGENTOS_API_TOKEN: change the variable instead'}
                    onClick={() => run(async () => setSecret((await rotateLegacyToken()).token))}>Rotate</button>
          </div>
        </div>
      )}
      {secret && <OnceSecret label="The new legacy local token (also written to the token file)." value={secret} onDone={() => setSecret(null)} />}
      <Msg m={msg} />
    </div>
  )
}

export default function AccessSettings() {
  const { can } = useAuth()
  return (
    <>
      <MyAccount />
      <MyTokens />
      {can('admin') && <UsersAdmin />}
      {can('admin') && <LegacyToken />}
    </>
  )
}
