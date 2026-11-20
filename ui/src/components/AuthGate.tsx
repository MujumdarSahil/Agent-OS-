// 3.4: login page, and the one-time setup page when no user exists yet.
// Setup needs the local API token (printed path in the server banner) so nobody else on the network can claim
// admin; the token is sent once and never stored by the page. Login errors are generic (no user enumeration).

import React, { useState } from 'react'
import { ShieldCheck, ArrowRight, AlertCircle, Eye, EyeOff, User as UserIcon, Key } from 'lucide-react'
import { login, setup, type Me } from '../api/auth'

interface AuthGateProps {
  mode: 'login' | 'setup'
  onAuthenticated: (me: Me) => void
}

function errorText(err: unknown): string {
  const e = err as { response?: { status?: number; data?: { detail?: unknown } } }
  const detail = e?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (e?.response?.status === 429) return 'Too many failed logins; wait and try again'
  return 'Could not reach the AgentOS server'
}

const card: React.CSSProperties = {
  width: '100%', maxWidth: 460, padding: 36, boxShadow: '0 20px 40px rgba(0,0,0,0.6)', borderRadius: 16,
  border: '1px solid var(--border-color, #1f2430)', background: 'var(--bg-secondary, #12141c)',
}

export default function AuthGate({ mode, onAuthenticated }: AuthGateProps) {
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [localToken, setLocalToken] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const isSetup = mode === 'setup'

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!username.trim() || !password) return setError('Enter a username and password')
    if (isSetup && password !== confirm) return setError('The passwords do not match')
    if (isSetup && !localToken.trim()) return setError('Enter the local API token')
    setBusy(true)
    try {
      const res = isSetup
        ? await setup(localToken.trim(), username.trim(), displayName.trim(), password)
        : await login(username.trim(), password)
      setLocalToken('')
      onAuthenticated(res.me)
    } catch (err) {
      setError(errorText(err))
    } finally {
      setPassword('')
      setConfirm('')
      setBusy(false)
    }
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center',
                  background: 'var(--bg-primary, #0a0b0f)', color: 'var(--text-primary, #f3f4f6)', padding: 24 }}>
      <div className="card" style={card} data-testid={isSetup ? 'setup-page' : 'login-page'}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <div style={{ width: 56, height: 56, margin: '0 auto 16px', borderRadius: 14, background: 'rgba(139, 92, 246, 0.15)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-purple, #8b5cf6)' }}>
            <ShieldCheck size={32} />
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 700, margin: '0 0 8px 0' }}>
            {isSetup ? 'Set up AgentOS' : <>Sign in to Agent<span style={{ color: 'var(--accent-purple, #8b5cf6)' }}>OS</span></>}
          </h2>
          <p style={{ fontSize: 13, color: 'var(--text-secondary, #9ca3af)', margin: 0, lineHeight: 1.5 }}>
            {isSetup
              ? 'No users yet. Create the first admin account. The local API token proves you run this server.'
              : 'Use your AgentOS account. Scripts keep using API tokens.'}
          </p>
        </div>

        {error && (
          <div role="alert" data-testid="auth-error" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 14px',
               marginBottom: 20, borderRadius: 8, background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)',
               color: '#ef4444', fontSize: 13 }}>
            <AlertCircle size={16} /> <span>{error}</span>
          </div>
        )}

        <form onSubmit={onSubmit} autoComplete="on">
          {isSetup && (
            <div className="form-group" style={{ marginBottom: 16 }}>
              <label className="form-label" htmlFor="setup-token" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Key size={14} /> Local API token
              </label>
              <input id="setup-token" type="password" className="form-input" style={{ width: '100%', fontFamily: 'monospace' }}
                     autoComplete="off" value={localToken} onChange={e => setLocalToken(e.target.value)} />
              <p style={{ fontSize: 11, color: 'var(--text-muted, #6b7280)', marginTop: 6, lineHeight: 1.4 }}>
                The server prints where it is stored when it starts (or run <code>agentos users create-admin</code>).
              </p>
            </div>
          )}
          <div className="form-group" style={{ marginBottom: 16 }}>
            <label className="form-label" htmlFor="auth-username" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <UserIcon size={14} /> Username
            </label>
            <input id="auth-username" className="form-input" style={{ width: '100%' }} autoComplete="username" autoFocus
                   value={username} onChange={e => setUsername(e.target.value)} />
          </div>
          {isSetup && (
            <div className="form-group" style={{ marginBottom: 16 }}>
              <label className="form-label" htmlFor="setup-display">Display name (optional)</label>
              <input id="setup-display" className="form-input" style={{ width: '100%' }} value={displayName}
                     onChange={e => setDisplayName(e.target.value)} />
            </div>
          )}
          <div className="form-group" style={{ marginBottom: isSetup ? 16 : 24 }}>
            <label className="form-label" htmlFor="auth-password">Password{isSetup ? ' (12+ characters)' : ''}</label>
            <div style={{ position: 'relative' }}>
              <input id="auth-password" type={show ? 'text' : 'password'} className="form-input" style={{ width: '100%', paddingRight: 42 }}
                     autoComplete={isSetup ? 'new-password' : 'current-password'} value={password} onChange={e => setPassword(e.target.value)} />
              <button type="button" aria-label={show ? 'Hide password' : 'Show password'} onClick={() => setShow(!show)}
                      style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none',
                               border: 'none', color: 'var(--text-muted, #6b7280)', cursor: 'pointer', padding: 4 }}>
                {show ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>
          {isSetup && (
            <div className="form-group" style={{ marginBottom: 24 }}>
              <label className="form-label" htmlFor="setup-confirm">Confirm password</label>
              <input id="setup-confirm" type={show ? 'text' : 'password'} className="form-input" style={{ width: '100%' }}
                     autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} />
            </div>
          )}
          <button id={isSetup ? 'setup-submit' : 'login-submit'} type="submit" className="btn btn-primary" disabled={busy}
                  style={{ width: '100%', height: 42, justifyContent: 'center', fontSize: 14, fontWeight: 600 }}>
            {isSetup ? 'Create admin and sign in' : 'Sign in'} <ArrowRight size={16} />
          </button>
        </form>
      </div>
    </div>
  )
}
