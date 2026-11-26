// src/flow/AttackPanel.tsx — 4.1 "Attack my flow": runs the attack families that fit this flow against an isolated
// copy with an adversarial MOCK model and fake sinks (no real model, no cost, nothing sent, nothing saved).

import { useState } from 'react'
import { attackMyFlow } from '../api/builder'
import type { AttackReport, BuilderFlow } from '../api/builder'
import { apiErrorMessage } from '../api/flows'

const OUTCOME_LABEL: Record<string, string> = {
  succeeded: 'succeeded',
  reached_flagged_sink: 'reached a flagged sink',
  stopped_at_approval: 'stopped at approval',
  blocked_at_runtime: 'blocked at run time',
  pinned_only: 'reached only pinned recipients',
  no_effect: 'no effect',
}

export default function AttackPanel({ flowId, current, canBuild, onApply, onClose }: {
  flowId: string
  current: () => BuilderFlow
  canBuild: boolean
  onApply: (flow: BuilderFlow) => void
  onClose: () => void
}) {
  const [report, setReport] = useState<AttackReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setError(null)
    try {
      setReport(await attackMyFlow(flowId, current()))
    } catch (e) {
      setError(apiErrorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const worst = report?.furthest
  return (
    <div className="card" style={{ width: 400, overflowY: 'auto', padding: 12 }} data-testid="attack-panel">
      <div className="flex items-center" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>Attack my flow</h3>
        <button className="btn btn-ghost btn-sm" data-testid="attack-close" onClick={onClose}>Close</button>
      </div>
      <p className="text-muted" style={{ fontSize: 12 }}>
        Tries the injection attacks that fit this flow on a copy, with a test model that always obeys the attacker and
        fake senders. No real model, no cost, nothing is sent and nothing is saved.
      </p>
      <button className="btn btn-primary btn-sm" data-testid="attack-run" onClick={run} disabled={busy || !canBuild}>
        {busy ? 'Attacking…' : report ? 'Run again' : 'Run attacks'}
      </button>
      {error && <div style={{ color: 'var(--accent-red)', marginTop: 8 }} data-testid="attack-error">{error}</div>}
      {report && (
        <div className="flex flex-col gap-2" style={{ marginTop: 10 }}>
          <div data-testid="attack-score" data-score={report.score_pct ?? ''}
               style={{ fontSize: 18, fontWeight: 600, color: report.succeeded ? 'var(--accent-red)' : 'var(--accent-green)' }}>
            Security score: {report.stopped} / {report.tried} attacks stopped
            {report.score_pct !== null ? ` (${report.score_pct}%)` : ''}
          </div>
          {worst && (
            <div className="card" style={{ padding: 8 }} data-testid="attack-furthest">
              <strong>Got furthest:</strong> <span className="font-mono">{worst.id}</span>: {OUTCOME_LABEL[worst.outcome]}.{' '}
              {worst.why}.
              {worst.paths.length > 0 && (
                <div className="font-mono" data-testid="attack-path" style={{ marginTop: 4 }}>
                  Path: {worst.paths[0].join(' → ')}
                </div>
              )}
            </div>
          )}
          {report.succeeded > 0 && (report.fixes.length > 0 || report.refusals.length > 0) && (
            <div className="card" style={{ padding: 8 }} data-testid="attack-fixes">
              <strong>Fixes</strong>
              <div className="flex gap-2 flex-wrap" style={{ marginTop: 4 }}>
                {report.fixes.map(f => (
                  <button key={f.id} className="btn btn-secondary btn-sm" data-testid={`attack-fix-${f.kind}-${f.node_id}`}
                          onClick={() => onApply(f.flow)} title="Applies the change as unsaved edits; run the attacks again to check">
                    {f.label}{f.passes ? ' ✓' : ''}
                  </button>
                ))}
              </div>
              {report.refusals.map((r, i) => <div key={i} style={{ color: 'var(--accent-red)', fontSize: 12 }}>{r}</div>)}
            </div>
          )}
          <table data-testid="attack-table" style={{ fontSize: 12 }}>
            <thead><tr><th>Attack</th><th>Where it stopped</th></tr></thead>
            <tbody>
              {report.attacks.map(a => (
                <tr key={a.id} data-testid={`attack-row-${a.id}`} data-outcome={a.outcome}>
                  <td className="font-mono">{a.id}</td>
                  <td style={{ color: a.stopped ? 'inherit' : 'var(--accent-red)' }} title={a.why}>{OUTCOME_LABEL[a.outcome]}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {report.not_run.map((n, i) => <div key={i} className="text-muted" style={{ fontSize: 11 }}>Not run: {n}</div>)}
        </div>
      )}
    </div>
  )
}
