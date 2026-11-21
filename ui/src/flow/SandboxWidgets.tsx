// src/flow/SandboxWidgets.tsx — 3.5 code sandbox: Settings -> Sandbox, and the run panel's sandbox calls.
// Sandbox output (stdout, stderr, files) is UNTRUSTED: always shown as inert plain text, never markdown or HTML.

import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Box } from 'lucide-react'
import { apiErrorMessage } from '../api/flows'
import {
  getSandboxSettings, getSandboxStatus, installWasm, putSandboxSettings, testSandbox,
  type SandboxLimits, type SandboxSettings, type SandboxTestResult,
} from '../api/sandbox'
import { needs, useAuth } from '../components/AuthContext'
import type { LabelInfo, RunEvent } from './runModel'
import { LabelBadge, UntrustedText } from './RunPanel'

const LIMIT_FIELDS: { key: keyof SandboxLimits; label: string; step?: number }[] = [
  { key: 'timeout_s', label: 'Time limit (s)' },
  { key: 'memory_mb', label: 'Memory (MB)' },
  { key: 'cpus', label: 'CPUs', step: 0.5 },
  { key: 'pids', label: 'Processes (Docker)' },
  { key: 'stdout_kb', label: 'stdout cap (KB)' },
  { key: 'stderr_kb', label: 'stderr cap (KB)' },
  { key: 'workspace_mb', label: 'Workspace (MB)' },
  { key: 'file_mb', label: 'Per file (MB)' },
]

function Avail({ ok, testid }: { ok: boolean; testid: string }) {
  return <span className={`badge ${ok ? 'badge-success' : 'badge-default'}`} data-testid={testid}>{ok ? 'available' : 'not available'}</span>
}

/** Settings -> Sandbox: status, versions, limits, image allowlist, test button (admin changes are audited). */
export function SandboxSettingsCard() {
  const { can } = useAuth()
  const admin = can('admin')
  const qc = useQueryClient()
  const status = useQuery({ queryKey: ['sandbox-status'], queryFn: getSandboxStatus })
  const settingsQ = useQuery({ queryKey: ['sandbox-settings'], queryFn: getSandboxSettings, enabled: admin })
  const [s, setS] = useState<SandboxSettings | null>(null)
  const [newImage, setNewImage] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [test, setTest] = useState<SandboxTestResult | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (settingsQ.data && !s) setS(settingsQ.data) }, [settingsQ.data, s])

  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: ['sandbox-status'] })
    await qc.invalidateQueries({ queryKey: ['v2-agent-tool-options'] })
  }
  const save = async () => {
    if (!s) return
    setMsg(null)
    try {
      setS(await putSandboxSettings(s))
      setMsg('Saved (recorded in the audit log).')
      await refresh()
    } catch (e) {
      setMsg(`Not saved: ${apiErrorMessage(e)}`)
    }
  }
  const runTest = async () => {
    setBusy(true)
    setTest(null)
    try {
      setTest(await testSandbox())
    } catch (e) {
      setTest({ ok: false, backend: null, error: apiErrorMessage(e) })
    } finally {
      setBusy(false)
    }
  }
  const install = async () => {
    setBusy(true)
    setMsg(null)
    try {
      await installWasm()
      setMsg('wasm runtime installed and verified (sha256).')
      await refresh()
    } catch (e) {
      setMsg(`Install failed: ${apiErrorMessage(e)}`)
    } finally {
      setBusy(false)
    }
  }

  const st = status.data
  return (
    <div className="card" data-testid="sandbox-settings">
      <div className="flex items-center gap-2 mb-2">
        <Box size={18} color="#0ea5e9" />
        <h3 style={{ fontWeight: 700, fontSize: 15 }}>Sandbox (code tools)</h3>
      </div>
      <p className="text-muted text-xs mb-3">
        python_exec, shell_exec, file_read and file_write run only inside a sandbox: Docker (strongest; needed for shell)
        or wasm (Python only, no Docker needed). No network, no host files, no secrets. With no backend the tools refuse.
      </p>
      {!st ? (
        <div className="text-muted">{status.isError ? `Status unavailable: ${apiErrorMessage(status.error)}` : 'Loading…'}</div>
      ) : (
        <div data-testid="sandbox-status" data-python={st.effective.python ?? 'none'} data-shell={st.effective.shell ?? 'none'}>
          <div className="mb-2" style={{ fontSize: 13 }}>
            <strong data-testid="sandbox-summary">{st.summary}</strong>
          </div>
          <table style={{ fontSize: 12, marginBottom: 8 }}>
            <tbody>
              <tr>
                <td style={{ paddingRight: 8 }}>Docker</td>
                <td><Avail ok={st.docker.available} testid="sandbox-docker" /></td>
                <td className="text-muted" style={{ paddingLeft: 8 }}>
                  {st.docker.server ? `client ${st.docker.client ?? '?'} · server ${st.docker.server}` : ''} {st.docker.detail}
                </td>
              </tr>
              <tr>
                <td style={{ paddingRight: 8 }}>wasm</td>
                <td><Avail ok={st.wasm.available} testid="sandbox-wasm" /></td>
                <td className="text-muted" style={{ paddingLeft: 8 }}>
                  {st.wasm.wasmtime ? `wasmtime ${st.wasm.wasmtime} · ` : ''}build {st.wasm.build} {st.wasm.detail}
                </td>
              </tr>
            </tbody>
          </table>
          <div className="text-muted text-xs mb-2" data-testid="sandbox-tools">
            Tools offered to agents: {st.tools.length ? st.tools.join(', ') : 'none'}
          </div>
        </div>
      )}
      <div className="flex gap-2 mb-3">
        <button className="btn btn-secondary btn-sm" data-testid="sandbox-test" onClick={runTest} disabled={!admin || busy}
          title={admin ? 'Runs print(6 * 7) in the sandbox' : needs('admin')}>Test sandbox</button>
        {st && !st.wasm.available && st.wasm.wasmtime && (
          <button className="btn btn-ghost btn-sm" data-testid="sandbox-install-wasm" onClick={install} disabled={!admin || busy}
            title={admin ? 'Downloads the pinned CPython WASI build and verifies its sha256' : needs('admin')}>Install wasm runtime</button>
        )}
      </div>
      {test && (
        <div className="mb-3" data-testid="sandbox-test-result" data-ok={test.ok ? 'true' : 'false'} style={{ fontSize: 12 }}>
          {test.ok
            ? <span style={{ color: 'var(--accent-green)' }}>OK: {test.backend} printed 42 in {Math.round(test.duration_ms ?? 0)} ms</span>
            : <span style={{ color: 'var(--accent-red)' }}>Failed: {test.error ?? `exit ${test.exit_code}, limit ${test.limit_hit ?? '-'}`}</span>}
        </div>
      )}
      {admin && s && (
        <div data-testid="sandbox-editor">
          <div className="form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="sb-mode">Backend</label>
              <select id="sb-mode" className="form-input" data-testid="sandbox-mode" value={s.backend}
                onChange={e => setS({ ...s, backend: e.target.value as SandboxSettings['backend'] })}>
                <option value="auto">auto (Docker, else wasm for Python)</option>
                <option value="docker">Docker only</option>
                <option value="wasm">wasm only (Python)</option>
                <option value="off">off (code tools disabled)</option>
              </select>
            </div>
          </div>
          <div className="form-row" style={{ flexWrap: 'wrap' }}>
            {LIMIT_FIELDS.map(f => (
              <div className="form-group" key={f.key} style={{ minWidth: 130 }}>
                <label className="form-label" htmlFor={`sb-${f.key}`}>{f.label}</label>
                <input id={`sb-${f.key}`} className="form-input" type="number" min={0} step={f.step ?? 1}
                  data-testid={`sandbox-limit-${f.key}`} value={s.limits[f.key]}
                  onChange={e => setS({ ...s, limits: { ...s.limits, [f.key]: Number(e.target.value) } })} />
              </div>
            ))}
          </div>
          <div className="form-label">Image allowlist (pinned by digest; Docker uses the default image)</div>
          {s.images.map(img => (
            <div key={img.ref} className="flex gap-2 items-center mb-1" data-testid="sandbox-image-row">
              <input type="radio" name="sb-default" aria-label={`Use ${img.ref} as the default image`}
                checked={s.default_image === img.ref} onChange={() => setS({ ...s, default_image: img.ref })} />
              <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{img.ref}</code>
              <button className="btn btn-ghost btn-sm" aria-label={`Remove ${img.ref}`} disabled={s.images.length === 1}
                onClick={() => {
                  const images = s.images.filter(i => i.ref !== img.ref)
                  setS({ ...s, images, default_image: s.default_image === img.ref ? images[0].ref : s.default_image })
                }}>×</button>
            </div>
          ))}
          <div className="flex gap-2 mb-3">
            <input className="form-input" placeholder="name@sha256:<64 hex>" data-testid="sandbox-image-new" value={newImage}
              onChange={e => setNewImage(e.target.value)} />
            <button className="btn btn-secondary btn-sm" disabled={!newImage.trim()}
              onClick={() => { setS({ ...s, images: [...s.images, { ref: newImage.trim(), note: '' }] }); setNewImage('') }}>Add</button>
          </div>
          <button className="btn btn-primary btn-sm" data-testid="sandbox-save" onClick={save}>Save sandbox settings</button>
        </div>
      )}
      {msg && <div className="mt-2" data-testid="sandbox-message" style={{ fontSize: 12 }}>{msg}</div>}
    </div>
  )
}

/** Run panel: every sandbox call of the run with its code, exit code, limit hit, output and files (all UNTRUSTED). */
export function SandboxCalls({ events }: { events: RunEvent[] }) {
  const calls = events.filter(e => e.type === 'sandbox_exec' || e.type === 'sandbox_file')
  if (!calls.length) return null
  // the code is the preceding tool_called argument of the same agent node and tool
  const codeFor = (ev: RunEvent): unknown => {
    const prior = events.filter(e => e.seq < ev.seq && e.type === 'tool_called'
      && e.data.agent_node === ev.data.agent_node && e.data.tool_name === ev.data.tool_name)
    const args = (prior[prior.length - 1]?.data.args ?? {}) as Record<string, unknown>
    return args.code ?? args.command
  }
  return (
    <div data-testid="sandbox-calls" style={{ marginTop: 8 }}>
      <div className="form-label">Sandbox calls ({calls.length})</div>
      {calls.map(ev => {
        const d = ev.data as Record<string, unknown>
        const files = (d.files_out ?? {}) as Record<string, number>
        const code = codeFor(ev)
        return (
          <div key={ev.seq} className="card" style={{ padding: 8, marginBottom: 6 }} data-testid="sandbox-call"
            data-tool={String(d.tool_name)} data-exit={String(d.exit_code ?? '')} data-limit={String(d.limit_hit ?? '')}>
            <div className="flex gap-2 items-center" style={{ flexWrap: 'wrap' }}>
              <code>{String(d.tool_name)}</code>
              {ev.type === 'sandbox_exec' ? (
                <>
                  <span>backend {String(d.backend)}</span>
                  <span>exit <strong data-testid="sandbox-exit">{d.exit_code === null || d.exit_code === undefined ? '-' : String(d.exit_code)}</strong></span>
                  {d.limit_hit ? <span className="badge badge-warning" data-testid="sandbox-limit">limit hit: {String(d.limit_hit)}</span> : null}
                  <span className="text-muted">{Math.round(Number(d.duration_ms ?? 0))} ms</span>
                </>
              ) : (
                <span>{String(d.op)} <code>{String(d.path)}</code> ({String(d.bytes)} B)</span>
              )}
              <LabelBadge label={d.label as LabelInfo | undefined} />
            </div>
            {ev.type === 'sandbox_exec' && (
              <>
                {code !== undefined && <><div className="text-muted mt-1">code (untrusted argument)</div><UntrustedText value={code} /></>}
                <div className="text-muted mt-1">stdout{d.stdout_truncated ? ' (truncated)' : ''}</div>
                <UntrustedText value={String(d.stdout ?? '')} />
                {d.stderr ? <><div className="text-muted mt-1">stderr{d.stderr_truncated ? ' (truncated)' : ''}</div><UntrustedText value={String(d.stderr)} /></> : null}
                {Object.keys(files).length > 0 && (
                  <div className="text-muted mt-1" data-testid="sandbox-files">files out: {Object.entries(files).map(([k, v]) => `${k} (${v} B)`).join(', ')}</div>
                )}
                {Array.isArray(d.refused_files) && d.refused_files.length > 0 && (
                  <div style={{ color: 'var(--accent-amber)' }} className="mt-1">refused on copy-out: {(d.refused_files as string[]).join('; ')}</div>
                )}
                {d.error ? <div style={{ color: 'var(--accent-red)' }} className="mt-1">{String(d.error)}</div> : null}
              </>
            )}
          </div>
        )
      })}
    </div>
  )
}
