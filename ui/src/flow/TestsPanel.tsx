// src/flow/TestsPanel.tsx — 4.2 "Tests" tab of the flow editor: test cases (list, editor with an expectation builder),
// Run all (version + model), results with diffs and the regression summary, model comparison, publish gate.
// Test runs never cause real side effects (fake email/Slack, fixture HTTP/fetch_url/MCP responses).

import { useCallback, useEffect, useState } from 'react'
import { apiErrorMessage } from '../api/flows'
import {
  blankCase, compareModels, deleteTestCase, expectationLabel, generateSecurityTests, importFromReview,
  listSuiteRuns, listTestCases, putGate, runSuite, saveTestCase,
} from '../api/flowTests'
import type { ComparisonRow, Expectation, ExpectationKind, GateSettings, SuiteRun, TestCase } from '../api/flowTests'

type Tab = 'cases' | 'results' | 'compare' | 'gate'
const KINDS: ExpectationKind[] = ['status', 'output', 'extraction', 'sink', 'security', 'approval_reached', 'limits',
  'judge']
const DEFAULTS: Record<ExpectationKind, Expectation> = {
  status: { kind: 'status', equals: 'succeeded' },
  output: { kind: 'output', node: '', field: 'output', op: 'contains', value: '' },
  extraction: { kind: 'extraction', node: '', field: '', equals: '' },
  sink: { kind: 'sink', target: 'send_email', op: 'called' },
  security: { kind: 'security', op: 'no_external_send' },
  approval_reached: { kind: 'approval_reached' },
  limits: { kind: 'limits', max_cost_usd: 0.05 },
  judge: { kind: 'judge', node: '', field: 'output', rubric: '' },
}

const show = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v))

export default function TestsPanel({ flowId, nodeIds, versions, canBuild, draft, onDraftUsed, onOpenRun, onClose }: {
  flowId: string
  nodeIds: string[]
  versions: number[]
  canBuild: boolean
  draft: TestCase | null
  onDraftUsed: () => void
  onOpenRun: (runId: string) => void
  onClose: () => void
}) {
  const [tab, setTab] = useState<Tab>('cases')
  const [cases, setCases] = useState<TestCase[]>([])
  const [gate, setGate] = useState<GateSettings>({ flow_id: flowId, mode: 'off', model: 'mock' })
  const [editing, setEditing] = useState<TestCase | null>(null)
  const [suite, setSuite] = useState<SuiteRun | null>(null)
  const [target, setTarget] = useState('draft')
  const [model, setModel] = useState('mock')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)
  const [cmpModels, setCmpModels] = useState('mock, router')
  const [cmpRows, setCmpRows] = useState<ComparisonRow[] | null>(null)

  const reload = useCallback(async () => {
    try {
      const r = await listTestCases(flowId)
      setCases(r.cases)
      setGate(r.gate)
      const runs = await listSuiteRuns(flowId)
      setSuite(s => s ?? runs.find(x => x.purpose !== 'compare') ?? null)
    } catch (e) {
      setError(apiErrorMessage(e))
    }
  }, [flowId])

  useEffect(() => { void reload() }, [reload])
  useEffect(() => {
    if (draft) {
      setEditing(draft)
      setTab('cases')
      onDraftUsed()
    }
  }, [draft, onDraftUsed])

  const act = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    setInfo(null)
    try {
      await fn()
    } catch (e) {
      setError(apiErrorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const targetBody = () => (target === 'draft' || target === 'published'
    ? { target } : { target: 'version', version: Number(target.replace('v', '')) })

  const runAll = () => act(async () => {
    const s = await runSuite(flowId, { ...targetBody(), model })
    setSuite(s)
    setTab('results')
    await reload()
  })

  return (
    <div className="card" style={{ width: 540, overflowY: 'auto', padding: 12 }} data-testid="tests-panel">
      <div className="flex items-center" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>Tests</h3>
        <button className="btn btn-ghost btn-sm" data-testid="tests-close" onClick={onClose}>Close</button>
      </div>
      <p className="text-muted" style={{ fontSize: 12 }}>
        Test runs never send anything: email and Slack go to fake senders, HTTP and tool calls get the saved
        fixture responses (a call without a fixture fails the case).
      </p>
      <div className="flex gap-1" role="tablist" style={{ marginBottom: 8 }}>
        {(['cases', 'results', 'compare', 'gate'] as Tab[]).map(t => (
          <button key={t} role="tab" aria-selected={tab === t} data-testid={`tests-tab-${t}`}
                  className={`btn btn-sm ${tab === t ? 'btn-secondary' : 'btn-ghost'}`} onClick={() => setTab(t)}>
            {t === 'cases' ? `Cases (${cases.length})` : t === 'results' ? 'Results' : t === 'compare'
              ? 'Compare models' : 'Publish gate'}
          </button>
        ))}
      </div>

      <div className="flex gap-1 items-center" style={{ flexWrap: 'wrap', marginBottom: 8 }}>
        <select className="form-input" style={{ width: 120 }} data-testid="tests-target" value={target}
                onChange={e => setTarget(e.target.value)} aria-label="Version to test">
          <option value="draft">Draft</option>
          <option value="published">Published</option>
          {versions.map(v => <option key={v} value={`v${v}`}>Version {v}</option>)}
        </select>
        <input className="form-input" style={{ width: 150 }} data-testid="tests-model" value={model}
               onChange={e => setModel(e.target.value)} aria-label="Model"
               title="mock (scripted, free), router (normal chain), or provider/model" />
        <button className="btn btn-primary btn-sm" data-testid="tests-run-all" onClick={() => void runAll()}
                disabled={busy || !canBuild || !cases.length}>{busy ? 'Running…' : 'Run all'}</button>
      </div>
      {error && <div style={{ color: 'var(--accent-red)', marginBottom: 8 }} data-testid="tests-error">{error}</div>}
      {info && <div style={{ color: 'var(--accent-green)', marginBottom: 8 }} data-testid="tests-info">{info}</div>}

      {tab === 'cases' && !editing && (
        <div className="flex flex-col gap-2">
          <div className="flex gap-1" style={{ flexWrap: 'wrap' }}>
            <button className="btn btn-secondary btn-sm" data-testid="tests-new" disabled={!canBuild}
                    onClick={() => setEditing(blankCase())}>New test case</button>
            <button className="btn btn-ghost btn-sm" data-testid="tests-add-security" disabled={busy || !canBuild}
                    onClick={() => void act(async () => {
                      const r = await generateSecurityTests(flowId)
                      setInfo(`Added ${r.generated} security tests (${r.families.join(', ')}).`)
                      await reload()
                    })}>Add security tests</button>
            <button className="btn btn-ghost btn-sm" data-testid="tests-import-review" disabled={busy || !canBuild}
                    onClick={() => void act(async () => {
                      const r = await importFromReview(flowId)
                      setInfo(`Imported ${r.imported} reviewed item(s).`)
                      await reload()
                    })}>Import from review</button>
          </div>
          {cases.length === 0 ? <div className="text-muted" data-testid="tests-empty">No test cases yet.</div> : (
            <table style={{ width: '100%', fontSize: 12 }} data-testid="tests-list">
              <thead><tr><th>Name</th><th>Tags</th><th>Last result</th><th /></tr></thead>
              <tbody>
                {cases.map(c => (
                  <tr key={c.id} data-testid="tests-row" data-status={c.last_result?.status ?? ''}>
                    <td>{c.name}</td>
                    <td>{c.tags.join(', ')}</td>
                    <td style={{ color: c.last_result?.status === 'pass' ? 'var(--accent-green)' : c.last_result
                      ? 'var(--accent-red)' : undefined }}>{c.last_result?.status ?? '—'}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button className="btn btn-ghost btn-sm" data-testid="tests-edit" onClick={() => setEditing(c)}>
                        Edit</button>
                      <button className="btn btn-ghost btn-sm" data-testid="tests-delete" disabled={!canBuild || busy}
                              onClick={() => void act(async () => { await deleteTestCase(flowId, c.id!); await reload() })}>
                        Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'cases' && editing && (
        <CaseEditor value={editing} nodeIds={nodeIds} canBuild={canBuild} busy={busy}
                    onCancel={() => setEditing(null)}
                    onSave={c => void act(async () => {
                      await saveTestCase(flowId, c)
                      setEditing(null)
                      setInfo('Test case saved.')
                      await reload()
                    })} />
      )}

      {tab === 'results' && <Results suite={suite} onOpenRun={onOpenRun} />}

      {tab === 'compare' && (
        <div className="flex flex-col gap-2" data-testid="tests-compare">
          <label className="form-label" htmlFor="cmp-models">Models (2 to 4, comma separated)</label>
          <input id="cmp-models" className="form-input" data-testid="tests-compare-models" value={cmpModels}
                 onChange={e => setCmpModels(e.target.value)} />
          <button className="btn btn-primary btn-sm" data-testid="tests-compare-run" disabled={busy || !canBuild}
                  onClick={() => void act(async () => {
                    const r = await compareModels(flowId, { ...targetBody(),
                      models: cmpModels.split(',').map(s => s.trim()).filter(Boolean) })
                    setCmpRows(r.rows)
                  })}>Compare</button>
          {cmpRows && (
            <table style={{ width: '100%', fontSize: 12 }} data-testid="tests-compare-table">
              <thead><tr><th>Model</th><th>Pass rate</th><th>Cost</th><th>Median latency</th><th>Failed cases</th></tr></thead>
              <tbody>
                {cmpRows.map(r => (
                  <tr key={r.model} data-testid="tests-compare-row" data-model={r.model}>
                    <td>{r.model}</td>
                    <td>{r.pass_rate ?? '—'}%</td>
                    <td>{r.cost_usd} USD</td>
                    <td title={r.latency_source === 'case_duration' ? 'no model call recorded: case duration' : 'model calls'}>
                      {r.median_latency_ms ?? '—'} ms</td>
                    <td>{r.failed_cases.map(f => f.name).join(', ') || 'none'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'gate' && (
        <div className="flex flex-col gap-2" data-testid="tests-gate">
          <p className="text-muted" style={{ fontSize: 12 }}>
            Require tests to pass before publishing. The security check still runs first. "warn" publishes and shows
            a warning; "block" refuses publish if any case fails (or there are no cases).
          </p>
          <label className="form-label" htmlFor="gate-mode">Mode</label>
          <select id="gate-mode" className="form-input" data-testid="tests-gate-mode" value={gate.mode}
                  onChange={e => setGate({ ...gate, mode: e.target.value as GateSettings['mode'] })}>
            <option value="off">Off</option><option value="warn">Warn</option><option value="block">Block</option>
          </select>
          <label className="form-label" htmlFor="gate-model">Test model</label>
          <input id="gate-model" className="form-input" data-testid="tests-gate-model" value={gate.model}
                 onChange={e => setGate({ ...gate, model: e.target.value })} />
          <button className="btn btn-primary btn-sm" data-testid="tests-gate-save" disabled={busy || !canBuild}
                  onClick={() => void act(async () => {
                    setGate(await putGate(flowId, { mode: gate.mode, model: gate.model }))
                    setInfo('Publish gate saved.')
                  })}>Save gate</button>
        </div>
      )}
    </div>
  )
}

function Results({ suite, onOpenRun }: { suite: SuiteRun | null; onOpenRun: (runId: string) => void }) {
  if (!suite) return <div className="text-muted" data-testid="tests-no-results">No suite run yet.</div>
  const reg = suite.regression
  return (
    <div className="flex flex-col gap-2" data-testid="tests-results" data-suite={suite.id}>
      {reg && (
        <div className="card" style={{ padding: 8 }} data-testid="regression-summary">
          {reg.first_run ? 'First run of this suite with this model.' : (
            <>
              <div data-testid="reg-newly-failing" style={{ color: reg.newly_failing.length ? 'var(--accent-red)' : undefined }}>
                Newly failing: {reg.newly_failing.map(x => x.name).join(', ') || 'none'}</div>
              <div data-testid="reg-newly-passing">Newly passing: {reg.newly_passing.map(x => x.name).join(', ') || 'none'}</div>
              <div data-testid="reg-still-failing">Still failing: {reg.still_failing.map(x => x.name).join(', ') || 'none'}</div>
            </>
          )}
        </div>
      )}
      <div data-testid="tests-counts" data-pass={suite.counts.pass} data-total={suite.counts.total}>
        <strong>{suite.counts.pass}/{suite.counts.total} passed</strong> · {suite.target}
        {suite.version ? ` v${suite.version}` : ''} · model {suite.model}
      </div>
      {suite.results.map(r => (
        <div key={r.case_id} className="card" style={{ padding: 8 }} data-testid="tests-result" data-status={r.status}>
          <div className="flex items-center" style={{ justifyContent: 'space-between' }}>
            <span><strong style={{ color: r.status === 'pass' ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              {r.status.toUpperCase()}</strong> {r.name}{r.nondeterministic ? ' (includes a non-deterministic judge)' : ''}</span>
            {r.run_id && (
              <button className="btn btn-ghost btn-sm" data-testid="tests-open-run" onClick={() => onOpenRun(r.run_id!)}>
                Open run</button>
            )}
          </div>
          <div className="text-muted" style={{ fontSize: 11 }}>
            {r.duration_ms.toFixed(0)} ms · {r.cost_usd} USD · {r.models_used.join(', ') || 'no model'}
          </div>
          {r.error && <div style={{ color: 'var(--accent-red)', fontSize: 12 }}>{r.error}</div>}
          {r.failures.map((f, i) => (
            <div key={i} style={{ fontSize: 12, marginTop: 4 }} data-testid="tests-diff">
              <div>{f.message}</div>
              <div style={{ fontFamily: 'monospace' }}>
                <span style={{ color: 'var(--accent-green)' }}>expected: {show(f.expected)}</span><br />
                <span style={{ color: 'var(--accent-red)' }}>actual:&nbsp;&nbsp; {show(f.actual)}</span>
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

function JsonField({ label, value, onChange, testid }: {
  label: string; value: unknown; onChange: (v: unknown) => void; testid: string
}) {
  const [text, setText] = useState(() => JSON.stringify(value ?? {}, null, 2))
  const [bad, setBad] = useState(false)
  return (
    <div>
      <label className="form-label">{label}</label>
      <textarea className="form-input" rows={4} data-testid={testid} value={text}
                style={{ fontFamily: 'monospace', fontSize: 12, borderColor: bad ? 'var(--accent-red)' : undefined }}
                onChange={e => {
                  setText(e.target.value)
                  try {
                    onChange(JSON.parse(e.target.value))
                    setBad(false)
                  } catch {
                    setBad(true)
                  }
                }} />
      {bad && <div style={{ color: 'var(--accent-red)', fontSize: 11 }}>Not valid JSON</div>}
    </div>
  )
}

function CaseEditor({ value, nodeIds, canBuild, busy, onSave, onCancel }: {
  value: TestCase; nodeIds: string[]; canBuild: boolean; busy: boolean
  onSave: (c: TestCase) => void; onCancel: () => void
}) {
  const [c, setC] = useState<TestCase>(value)
  const setExp = (i: number, e: Expectation) => setC({ ...c, expectations: c.expectations.map((x, j) => (j === i ? e : x)) })
  return (
    <div className="flex flex-col gap-2" data-testid="tests-editor">
      {(c.notes ?? []).map((n, i) => <div key={i} style={{ fontSize: 12, color: 'var(--accent-amber)' }}>{n}</div>)}
      <label className="form-label" htmlFor="tc-name">Name</label>
      <input id="tc-name" className="form-input" data-testid="tests-name" value={c.name}
             onChange={e => setC({ ...c, name: e.target.value })} />
      <label className="form-label" htmlFor="tc-tags">Tags (comma separated)</label>
      <input id="tc-tags" className="form-input" data-testid="tests-tags" value={c.tags.join(', ')}
             onChange={e => setC({ ...c, tags: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })} />
      <JsonField label="Input (trigger payload)" value={c.input} testid="tests-input"
                 onChange={v => setC({ ...c, input: v })} />
      <JsonField label="Fixture responses (HTTP / fetch_url / MCP)" value={c.fixtures} testid="tests-fixtures"
                 onChange={v => setC({ ...c, fixtures: Array.isArray(v) ? v : c.fixtures })} />
      <JsonField label="MOCK model answers per node" value={c.mock_responses} testid="tests-mock"
                 onChange={v => setC({ ...c, mock_responses: (v ?? {}) as Record<string, string> })} />
      <div className="form-label">Expectations</div>
      {c.expectations.map((e, i) => (
        <ExpectationRow key={i} value={e} nodeIds={nodeIds} onChange={x => setExp(i, x)}
                        onRemove={() => setC({ ...c, expectations: c.expectations.filter((_, j) => j !== i) })} />
      ))}
      <div className="flex gap-1">
        <select className="form-input" data-testid="tests-add-expectation" value=""
                onChange={e => e.target.value && setC({ ...c, expectations: [...c.expectations,
                  { ...DEFAULTS[e.target.value as ExpectationKind] }] })}>
          <option value="">+ Add expectation…</option>
          {KINDS.map(k => <option key={k} value={k}>{k.replace('_', ' ')}</option>)}
        </select>
      </div>
      <div className="flex gap-1">
        <button className="btn btn-primary btn-sm" data-testid="tests-save" disabled={!canBuild || busy}
                onClick={() => onSave(c)}>Save test case</button>
        <button className="btn btn-ghost btn-sm" data-testid="tests-cancel" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  )
}

function ExpectationRow({ value: e, nodeIds, onChange, onRemove }: {
  value: Expectation; nodeIds: string[]; onChange: (e: Expectation) => void; onRemove: () => void
}) {
  const set = (patch: Partial<Expectation>) => onChange({ ...e, ...patch })
  const node = (
    <select className="form-input" style={{ width: 130 }} value={e.node ?? ''} aria-label="Node"
            onChange={x => set({ node: x.target.value || null })}>
      <option value="">{e.kind === 'output' || e.kind === 'extraction' || e.kind === 'judge' ? 'node…' : 'any node'}</option>
      {nodeIds.map(n => <option key={n} value={n}>{n}</option>)}
    </select>
  )
  const text = (key: keyof Expectation, placeholder: string, width = 130) => (
    <input className="form-input" style={{ width }} placeholder={placeholder} aria-label={placeholder}
           value={e[key] == null ? '' : String(e[key])} onChange={x => set({ [key]: x.target.value } as Partial<Expectation>)} />
  )
  const num = (key: keyof Expectation, placeholder: string) => (
    <input className="form-input" style={{ width: 110 }} type="number" placeholder={placeholder} aria-label={placeholder}
           value={e[key] == null ? '' : String(e[key])}
           onChange={x => set({ [key]: x.target.value === '' ? null : Number(x.target.value) } as Partial<Expectation>)} />
  )
  return (
    <div className="card" style={{ padding: 6 }} data-testid="tests-expectation" data-kind={e.kind}>
      <div className="flex gap-1 items-center" style={{ flexWrap: 'wrap' }}>
        <strong style={{ fontSize: 12 }}>{e.kind.replace('_', ' ')}</strong>
        {e.kind === 'status' && (
          <select className="form-input" style={{ width: 190 }} value={String(e.equals)} aria-label="Final status"
                  onChange={x => set({ equals: x.target.value })}>
            <option value="succeeded">succeeded</option>
            <option value="waiting_for_approval">waiting for approval</option>
            <option value="failed">failed</option>
          </select>
        )}
        {e.kind === 'output' && <>{node}{text('field', 'field or $.json.path', 120)}
          <select className="form-input" style={{ width: 110 }} value={e.op} aria-label="Operator"
                  onChange={x => set({ op: x.target.value })}>
            {['equals', 'contains', 'regex', 'json_path_equals'].map(o => <option key={o} value={o}>{o}</option>)}
          </select>{text('value', 'value')}</>}
        {e.kind === 'extraction' && <>{node}{text('field', 'field')}{text('equals', 'allowed value')}</>}
        {e.kind === 'sink' && <>
          {text('target', 'send_email / send_slack / http_request / mcp:tool', 150)}{node}
          <select className="form-input" style={{ width: 120 }} value={e.op} aria-label="Sink check"
                  onChange={x => set({ op: x.target.value })}>
            <option value="called">was called</option><option value="not_called">was not called</option>
            <option value="count">called N times</option><option value="called_with">called with</option>
          </select>
          {e.op === 'count' && num('n', 'N')}
          {e.op === 'called_with' && <>
            <select className="form-input" style={{ width: 90 }} value={e.arg ?? 'to'} aria-label="Argument"
                    onChange={x => set({ arg: x.target.value })}>
              <option value="to">to</option><option value="channel">channel</option><option value="host">host</option>
            </select>{text('value', 'address / channel / host')}</>}
        </>}
        {e.kind === 'security' && <>
          <select className="form-input" style={{ width: 230 }} value={e.op} aria-label="Security check"
                  onChange={x => set({ op: x.target.value })}>
            <option value="no_external_send">nothing reached an outside address</option>
            <option value="blocked">a call was blocked</option>
            <option value="publish_refused">publish would be refused</option>
          </select>{e.op === 'blocked' && node}</>}
        {e.kind === 'approval_reached' && node}
        {e.kind === 'limits' && <>{num('max_cost_usd', 'max USD')}{num('max_duration_ms', 'max ms')}
          {num('max_model_calls', 'max model calls')}</>}
        {e.kind === 'judge' && <>{node}{text('rubric', 'rubric (graded by a model)', 220)}
          <span className="text-muted" style={{ fontSize: 11 }}>non-deterministic</span></>}
        <button className="btn btn-ghost btn-sm" aria-label="Remove expectation" onClick={onRemove}>✕</button>
      </div>
      <div className="text-muted" style={{ fontSize: 11 }}>{expectationLabel(e)}</div>
    </div>
  )
}
