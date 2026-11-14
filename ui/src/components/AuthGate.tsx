import React, { useState } from 'react'
import { ShieldCheck, Key, ArrowRight, AlertCircle, Eye, EyeOff } from 'lucide-react'
import { setAuthToken } from '../api/client'

interface AuthGateProps {
  onAuthenticated: () => void
}

export default function AuthGate({ onAuthenticated }: AuthGateProps) {
  const [tokenInput, setTokenInput] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = tokenInput.trim()
    if (!trimmed) {
      setError('Please enter a valid API token')
      return
    }
    setAuthToken(trimmed)
    onAuthenticated()
  }

  return (
    <div
      style={{
        display: 'flex',
        minHeight: '100vh',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-primary, #0a0b0f)',
        color: 'var(--text-primary, #f3f4f6)',
        padding: '24px',
      }}
    >
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: '460px',
          padding: '36px',
          boxShadow: '0 20px 40px rgba(0,0,0,0.6)',
          borderRadius: '16px',
          border: '1px solid var(--border-color, #1f2430)',
          background: 'var(--bg-secondary, #12141c)',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div
            style={{
              width: '56px',
              height: '56px',
              margin: '0 auto 16px',
              borderRadius: '14px',
              background: 'rgba(139, 92, 246, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-purple, #8b5cf6)',
            }}
          >
            <ShieldCheck size={32} />
          </div>
          <h2 style={{ fontSize: '22px', fontWeight: 700, margin: '0 0 8px 0' }}>
            Agent<span style={{ color: 'var(--accent-purple, #8b5cf6)' }}>OS</span> Authentication
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary, #9ca3af)', margin: 0, lineHeight: 1.5 }}>
            An API token is required to access your local agent resources and backend services.
          </p>
        </div>

        {error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '10px 14px',
              marginBottom: '20px',
              borderRadius: '8px',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#ef4444',
              fontSize: '13px',
            }}
          >
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group" style={{ marginBottom: '20px' }}>
            <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
              <Key size={14} /> Local API Token
            </label>
            <div style={{ position: 'relative' }}>
              <input
                id="api-token-input"
                type={showPassword ? 'text' : 'password'}
                className="form-input"
                style={{
                  width: '100%',
                  paddingRight: '42px',
                  fontFamily: 'monospace',
                  fontSize: '14px',
                  height: '42px',
                }}
                value={tokenInput}
                onChange={e => {
                  setTokenInput(e.target.value)
                  if (error) setError(null)
                }}
                placeholder="Paste token generated at server startup"
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted, #6b7280)',
                  cursor: 'pointer',
                  padding: '4px',
                }}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-muted, #6b7280)', marginTop: '8px', lineHeight: 1.4 }}>
              Look for the one-time link or token printed in your terminal when running <code>agentos start</code>.
            </p>
          </div>

          <button
            id="auth-unlock-btn"
            type="submit"
            className="btn btn-primary"
            style={{
              width: '100%',
              height: '42px',
              justifyContent: 'center',
              fontSize: '14px',
              fontWeight: 600,
            }}
          >
            Unlock AgentOS <ArrowRight size={16} />
          </button>
        </form>
      </div>
    </div>
  )
}
