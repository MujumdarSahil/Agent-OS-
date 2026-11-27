// src/flow/VersionsPanel.tsx — 4.3 "Versions" tab: published versions with their note, publisher, test pass rate and
// security check (against the CURRENT policy), environment badges, Compare two versions (security-relevant changes
// first, then the 4.0 DiffView), Promote, Rollback (confirmation shows the diff) and Archive. The server decides
// permissions: builders act on staging, admins on production.

import { useCallback, useEffect, useState } from 'react'
import type { EnvironmentName } from '../api/flows'
import {
  archiveVersion, deploy, deployError, getEnvironments, getVersionDiff, getVersionsSummary, putProductionSettings,
  putStagingSettings,
} from '../api/environments'
import type { EnvironmentsInfo, VersionDiff, VersionsSummary } from '../api/environments'
import { DiffView } from './BuilderPreview'

const ENVS: EnvironmentName[] = ['staging', 'production']

export function SecurityChanges({ diff }: { diff: VersionDiff }) {
  if (!diff.security.length) {
    return <div className="text-muted" data-testid="security-changes-none" style={{ fontSize: 12 }}>No security-relevant changes.</div>
  }
  return (
    <div data-testid="security-changes" style={{ border: '1px solid var(--accent-red)', borderRadius: 6, padding: 8, marginBottom: 8 }}>
      <div className="font-semibold" style={{ color: 'var(--accent-red)', fontSize: 12 }}>
        Security-relevant changes ({diff.security.length})
      </div>
      <ul style={{ margin: '4px 0 0 16px', fontSize: 12 }}>
        {diff.security.map((s, i) => (
          <li key={i} data-testid={`sec-${s.kind}`}>
            <span className="font-mono">{s.kind.replace(/_/g, ' ')}</span> · <span className="font-mono">{s.node}</span>: {s.detail}
          </li>
        ))}
      </ul>
    </div>
  )
}

function DiffBlock({ diff }: { diff: VersionDiff }) {
  return (
    <div data-testid="version-diff">
      <div className="text-muted" style={{ fontSize: 11, marginBottom: 4 }}>
        {diff.from === 'draft' ? 'draft' : `v${diff.from}`} → {diff.to === 'draft' ? 'draft' : `v${diff.to}`} · security check{' '}
        {diff.analysis.before.passed ? 'passes' : 'fails'} → {diff.analysis.after.passed ? 'passes' : 'fails'} (current policy)
      </div>
      <SecurityChanges diff={diff} />
      <DiffView diff={diff} />
      {diff.nodes_changed_detail.length > 0 && (
        <ul style={{ margin: '4px 0 0 16px', fontSize: 11 }} data-testid="changed-detail">
          {diff.nodes_changed_detail.map(r => (
            <li key={r.id}>
              <span className="font-mono">{r.id}</span>:{' '}
              {Object.entries({ ...(r.config ?? {}), ...(r.pinned_args ?? {}) }).map(([k, [a, b]]) => (
                <span key={k} className="font-mono" style={{ marginRight: 8 }}>{k}: {String(a ?? '∅')} → {String(b ?? '∅')}</span>
              ))}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

interface Pending { env: EnvironmentName; action: 'promote' | 'rollback'; version: number; expected: number | null; diff: VersionDiff | null }

export default function VersionsPanel({ flowId, canBuild, canAdmin, onChanged, onClose }: {
  flowId: string
  canBuild: boolean
  canAdmin: boolean
  onChanged?: () => void
  onClose: () => void
}) {
  const [summary, setSummary] = useState<VersionsSummary | null>(null)
  const [envs, setEnvs] = useState<EnvironmentsInfo | null>(null)
  const [selected, setSelected] = useState<number[]>([])
  const [compare, setCompare] = useState<VersionDiff | null>(null)
  const [pending, setPending] = useState<Pending | null>(null)
  const [note, setNote] = useState('')
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const [s, e] = await Promise.all([getVersionsSummary(flowId), getEnvironments(flowId)])
      setSummary(s)
      setEnvs(e)
    } catch (err) {
      setMessage({ kind: 'error', text: `Could not load versions: ${deployError(err)}` })
    }
  }, [flowId])
  useEffect(() => void load(), [load])

  const canAct = (env: EnvironmentName) => (env === 'production' ? canAdmin : canBuild)
  const needsRole = (env: EnvironmentName) => (env === 'production' ? 'Needs the admin role' : 'Needs the builder role')

  const toggle = (v: number) =>
    setSelected(s => (s.includes(v) ? s.filter(x => x !== v) : [...s.slice(-1), v]))

  const doCompare = async () => {
    if (selected.length !== 2) return
    const [a, b] = [...selected].sort((x, y) => x - y)
    try {
      setCompare(await getVersionDiff(flowId, a, b))
    } catch (err) {
      setMessage({ kind: 'error', text: deployError(err) })
    }
  }

  const ask = async (env: EnvironmentName, action: 'promote' | 'rollback', version: number) => {
    const expected = summary?.environments[env] ?? null
    setNote('')
    setPending({ env, action, version, expected, diff: null })
    if (expected !== null && expected !== version) {
      try {
        const diff = await getVersionDiff(flowId, expected, version)
        setPending(p => (p && p.version === version && p.env === env ? { ...p, diff } : p))
      } catch { /* the confirmation still works without the diff */ }
    }
  }

  const confirm = async () => {
    if (!pending) return
    setBusy(true)
    try {
      const res = await deploy(flowId, pending.env, pending.action, pending.version, pending.expected, note)
      setMessage({ kind: 'ok', text: `${pending.env}: v${res.from ?? '–'} → v${res.to}` + (res.warnings.length ? ` (${res.warnings.join('; ')})` : '') })
      setPending(null)
      await load()
      onChanged?.()
    } catch (err) {
      setMessage({ kind: 'error', text: `${pending.action === 'rollback' ? 'Rollback' : 'Promote'} refused: ${deployError(err)}` })
      setPending(null)
      await load()
    } finally {
      setBusy(false)
    }
  }

  const archive = async (v: number) => {
    try {
      await archiveVersion(flowId, v)
      await load()
    } catch (err) {
      setMessage({ kind: 'error', text: deployError(err) })
    }
  }

  const setting = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      await load()
    } catch (err) {
      setMessage({ kind: 'error', text: deployError(err) })
    }
  }

  const st = envs?.settings
  return (
    <div className="card" style={{ width: 560, overflowY: 'auto', padding: 12 }} data-testid="versions-panel">
      <div className="flex items-center" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>Versions</h3>
        <button className="btn btn-ghost btn-sm" data-testid="versions-close" onClick={onClose}>Close</button>
      </div>
      <div className="flex gap-2" style={{ margin: '8px 0' }}>
        {ENVS.map(env => (
          <span key={env} className="badge" data-testid={`env-badge-${env}`}
                style={{ padding: '2px 8px', borderRadius: 10, border: '1px solid var(--border)', fontSize: 12 }}>
            {env}: {summary?.environments[env] ? `v${summary.environments[env]}` : 'none'}
          </span>
        ))}
      </div>
      {st && (
        <div style={{ fontSize: 12, marginBottom: 8 }} data-testid="env-settings">
          <label title={canBuild ? undefined : 'Needs the builder role'} style={{ marginRight: 12 }}>
            <input type="checkbox" data-testid="auto-deploy-staging" checked={st.auto_deploy_staging} disabled={!canBuild}
                   onChange={e => void setting(() => putStagingSettings(flowId, e.target.checked))} /> auto-deploy to staging on publish
          </label>
          <label title={canAdmin ? undefined : 'Needs the admin role'} style={{ marginRight: 12 }}>
            <input type="checkbox" data-testid="auto-deploy-production" checked={st.auto_deploy_production} disabled={!canAdmin}
                   onChange={e => void setting(() => putProductionSettings(flowId, { auto_deploy_production: e.target.checked }))} /> auto-deploy to production
          </label>
          <label title={canAdmin ? undefined : 'Needs the admin role'} style={{ marginRight: 12 }}>
            <input type="checkbox" data-testid="second-person" checked={st.second_person} disabled={!canAdmin}
                   onChange={e => void setting(() => putProductionSettings(flowId, { second_person: e.target.checked }))} /> second person promotes
          </label>
          <label title={canAdmin ? undefined : 'Needs the admin role'}>
            test gate{' '}
            <select data-testid="promote-test-gate" value={st.promote_test_gate} disabled={!canAdmin}
                    onChange={e => void setting(() => putProductionSettings(flowId, { promote_test_gate: e.target.value as 'off' | 'warn' | 'block' }))}>
              <option value="off">off</option><option value="warn">warn</option><option value="block">block</option>
            </select>
          </label>
        </div>
      )}
      {message && (
        <div data-testid="versions-message" data-kind={message.kind}
             style={{ color: message.kind === 'ok' ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: 12, marginBottom: 6 }}>
          {message.text}
        </div>
      )}
      <div className="flex gap-2" style={{ marginBottom: 6 }}>
        <button className="btn btn-secondary btn-sm" data-testid="compare-versions" disabled={selected.length !== 2}
                onClick={() => void doCompare()}>
          Compare {selected.length === 2 ? `v${Math.min(...selected)} ↔ v${Math.max(...selected)}` : '(pick two)'}
        </button>
      </div>
      {compare && <DiffBlock diff={compare} />}
      <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }} data-testid="versions-table">
        <thead>
          <tr className="text-muted"><th></th><th style={{ textAlign: 'left' }}>Version</th><th style={{ textAlign: 'left' }}>Note</th><th>Tests</th><th>Security</th><th></th></tr>
        </thead>
        <tbody>
          {(summary?.versions ?? []).map(v => (
            <tr key={v.version} data-testid={`version-row-${v.version}`} style={{ borderTop: '1px solid var(--border)', opacity: v.archived ? 0.55 : 1 }}>
              <td><input type="checkbox" data-testid={`select-version-${v.version}`} checked={selected.includes(v.version)} onChange={() => toggle(v.version)} /></td>
              <td>
                <div className="font-semibold">v{v.version}{v.archived ? ' (archived)' : ''}</div>
                {v.environments.map(e => (
                  <span key={e} data-testid={`version-${v.version}-env-${e}`} style={{ fontSize: 10, marginRight: 4, padding: '0 6px', borderRadius: 8, background: e === 'production' ? 'var(--accent-green)' : 'var(--accent-amber)', color: '#111' }}>{e}</span>
                ))}
                <div className="text-muted" style={{ fontSize: 10 }}>{v.published_by ?? '–'} · {v.published_at ? new Date(v.published_at).toLocaleString() : ''} · {v.runs} runs</div>
              </td>
              <td style={{ maxWidth: 160, wordBreak: 'break-word' }}>{v.change_note ?? <span className="text-muted">(no note: before 4.3)</span>}</td>
              <td style={{ textAlign: 'center' }} data-testid={`version-${v.version}-tests`}>{v.test_pass_rate === null ? '–' : `${Math.round(v.test_pass_rate)}%`}</td>
              <td style={{ textAlign: 'center', color: v.security.passed ? 'var(--accent-green)' : 'var(--accent-red)' }}
                  data-testid={`version-${v.version}-security`}
                  title={v.security.policy_changed ? 'The policy changed since this version was published' : undefined}>
                {v.security.passed ? 'passes' : `fails (${v.security.violations})`}
              </td>
              <td style={{ whiteSpace: 'nowrap' }}>
                {!v.archived && ENVS.map(env => {
                  const cur = summary?.environments[env] ?? null
                  if (cur === v.version) return null
                  const action = cur !== null && v.version < cur ? 'rollback' : 'promote'
                  return (
                    <button key={env} className="btn btn-ghost btn-sm" data-testid={`${action}-${env}-${v.version}`}
                            disabled={!canAct(env) || busy} title={canAct(env) ? undefined : needsRole(env)}
                            onClick={() => void ask(env, action, v.version)}>
                      {action === 'rollback' ? 'Roll back' : 'Promote'} {env === 'production' ? 'prod' : 'staging'}
                    </button>
                  )
                })}
                {!v.archived && v.environments.length === 0 && (
                  <button className="btn btn-ghost btn-sm" data-testid={`archive-${v.version}`} disabled={!canBuild}
                          onClick={() => void archive(v.version)}>Archive</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {summary && summary.versions.length === 0 && <div className="text-muted" style={{ fontSize: 12 }}>No published versions yet.</div>}

      {pending && (
        <div role="dialog" aria-label="Confirm deployment" data-testid="deploy-confirm-dialog"
             style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="card" style={{ width: 620, maxWidth: '94vw', maxHeight: '86vh', overflowY: 'auto', padding: 16 }}>
            <div className="font-semibold" style={{ marginBottom: 6 }}>
              {pending.action === 'rollback' ? 'Roll back' : 'Promote'} {pending.env} to v{pending.version}
              {pending.expected !== null ? ` (now v${pending.expected})` : ' (empty now)'}
            </div>
            <p className="text-muted" style={{ fontSize: 12 }}>
              The security check runs again against the current policy{pending.env === 'production' && pending.action === 'promote' ? ', then the test gate and the second-person rule if they are on' : ''}.
              Runs that already started keep their version.
            </p>
            {pending.expected !== null && !pending.diff && <div className="text-muted" style={{ fontSize: 12 }}>Loading the diff…</div>}
            {pending.diff && <DiffBlock diff={pending.diff} />}
            <label className="form-label" htmlFor="deploy-note">Note (optional)</label>
            <input id="deploy-note" className="form-input" data-testid="deploy-note" maxLength={500} value={note} onChange={e => setNote(e.target.value)} />
            <div className="flex gap-2 mt-2" style={{ justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost btn-sm" data-testid="deploy-cancel" onClick={() => setPending(null)}>Cancel</button>
              <button className="btn btn-primary btn-sm" data-testid="deploy-confirm" disabled={busy} onClick={() => void confirm()}>
                {pending.action === 'rollback' ? 'Roll back' : 'Promote'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
