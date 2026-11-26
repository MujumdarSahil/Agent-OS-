// src/flow/AiEditPanel.tsx — 4.0 "Edit with AI": a change request produces a PROPOSED new version, shown as a diff
// (added/removed/changed nodes and edges) with its security check. Apply loads it into the editor as unsaved
// changes (undo works; Save and Publish apply as usual); Discard drops it. The server never saves it.

import { useState } from 'react'
import { checkFlow, generateFlow } from '../api/builder'
import type { BuilderFlow, GenerateResult, OneClickFix } from '../api/builder'
import { apiErrorMessage } from '../api/flows'
import { CheckView, DiffView } from './BuilderPreview'

export default function AiEditPanel({ flowId, current, canBuild, onApply, onClose }: {
  flowId: string
  current: () => BuilderFlow
  canBuild: boolean
  onApply: (flow: BuilderFlow) => void
  onClose: () => void
}) {
  const [request, setRequest] = useState('')
  const [result, setResult] = useState<GenerateResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const propose = async () => {
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const r = await generateFlow({ flow_id: flowId, change_request: request, base_flow: current() })
      if (r.status === 'error') setError(r.error ?? 'The model did not produce a valid proposal.')
      else setResult(r)
    } catch (e) {
      setError(apiErrorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const fix = async (f: OneClickFix) => {
    setBusy(true)
    try {
      const r = await checkFlow(f.flow, request)
      setResult(prev => (prev ? { ...prev, flow: r.flow, check: { ...r.check, fixed: prev.check?.fixed ?? [] } } : prev))
    } catch (e) {
      setError(apiErrorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card" style={{ width: 380, overflowY: 'auto', padding: 12 }} data-testid="ai-edit-panel">
      <div className="flex items-center" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>Edit with AI</h3>
        <button className="btn btn-ghost btn-sm" data-testid="ai-edit-close" onClick={onClose}>Close</button>
      </div>
      <p className="text-muted" style={{ fontSize: 12 }}>
        Describe a change. You get a proposed version to review; nothing changes until you apply it, and it is saved
        only when you press Save.
      </p>
      <textarea className="form-input" data-testid="ai-edit-request" rows={3} maxLength={1000} value={request}
                onChange={e => setRequest(e.target.value)} placeholder="also notify Slack ops-alerts" disabled={busy} />
      <button className="btn btn-primary btn-sm" style={{ marginTop: 6 }} data-testid="ai-edit-propose"
              onClick={propose} disabled={busy || !request.trim() || !canBuild}>
        {busy ? 'Working…' : 'Propose change'}
      </button>
      {error && <div style={{ color: 'var(--accent-red)', marginTop: 8 }} data-testid="ai-edit-error">{error}</div>}
      {result?.status === 'questions' && (
        <div data-testid="ai-edit-questions" style={{ marginTop: 8 }}>
          <strong>AgentOS needs to know (rephrase the request to include it):</strong>
          <ul style={{ margin: '4px 0 0 18px' }}>{result.questions?.map((q, i) => <li key={i}>{q}</li>)}</ul>
        </div>
      )}
      {result?.status === 'draft' && result.flow && (
        <div className="flex flex-col gap-2" style={{ marginTop: 8 }}>
          <h4 style={{ margin: 0 }}>Proposed changes</h4>
          {result.diff && <DiffView diff={result.diff} />}
          {result.check && <CheckView check={result.check} onFix={fix} busy={busy} />}
          <div className="flex gap-2">
            <button className="btn btn-primary btn-sm" data-testid="ai-edit-apply" disabled={busy}
                    onClick={() => { onApply(result.flow!); setResult(null); setRequest('') }}>
              Apply
            </button>
            <button className="btn btn-ghost btn-sm" data-testid="ai-edit-discard" disabled={busy}
                    onClick={() => setResult(null)}>
              Discard
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
