// src/pages/DescribeFlow.tsx — 4.0 "Describe it": describe a flow in plain English, get a DRAFT that has passed
// (or failed, with one-click fixes) the same static security check as Publish. Nothing is saved until
// "Create draft", and nothing is ever published from here (the visual editor's Publish runs the check again).

import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { needs, useAuth } from '../components/AuthContext'
import { checkFlow, generateFlow } from '../api/builder'
import type { Answer, BuilderFlow, CheckResult, Explanation, FlowDiff, GenerateResult, OneClickFix } from '../api/builder'
import { apiErrorMessage, createFlow, getNodeSpecs, listFlows } from '../api/flows'
import { specMap } from '../flow/flowGraph'
import { CheckView, DiffView, ExplanationView, PreviewCanvas, asRecord } from '../flow/BuilderPreview'
import { DESCRIBE_EXAMPLES } from '../flow/describeExamples'

interface Draft {
  flow: BuilderFlow
  check: CheckResult
  explanation: Explanation
  diff?: FlowDiff
  modelCalls: number
}

export default function DescribeFlow() {
  const navigate = useNavigate()
  const canBuild = useAuth().can('build')
  const specsQ = useQuery({ queryKey: ['node-specs'], queryFn: getNodeSpecs, staleTime: Infinity })
  const specs = useMemo(() => specMap(specsQ.data), [specsQ.data])
  const [description, setDescription] = useState('')
  const [answers, setAnswers] = useState<Answer[]>([])
  const [questions, setQuestions] = useState<string[]>([])
  const [pending, setPending] = useState<Record<number, string>>({})
  const [draft, setDraft] = useState<Draft | null>(null)
  const [refine, setRefine] = useState('')
  const [flowId, setFlowId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const take = (r: GenerateResult) => {
    if (r.status === 'error') {
      setError(r.error ?? 'The model did not produce a valid draft.')
      return
    }
    if (r.status === 'questions') {
      setQuestions(r.questions ?? [])
      setPending({})
      return
    }
    setQuestions([])
    setDraft({ flow: r.flow!, check: r.check!, explanation: r.explanation!, diff: r.diff, modelCalls: r.model_calls })
    setFlowId(r.flow!.id)
  }

  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(apiErrorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const build = () => run(async () => {
    setDraft(null)
    take(await generateFlow({ description, answers }))
  })

  const answerAndContinue = () => run(async () => {
    const add = questions.map((q, i) => ({ question: q, answer: (pending[i] ?? '').trim() })).filter(a => a.answer)
    const next = [...answers, ...add].slice(-3)
    setAnswers(next)
    take(await generateFlow({ description, answers: next }))
  })

  const applyFix = (f: OneClickFix) => run(async () => {
    const r = await checkFlow(f.flow, description, answers)
    setDraft(d => (d ? { ...d, flow: r.flow, check: { ...r.check, fixed: d.check.fixed }, explanation: r.explanation } : d))
  })

  const doRefine = () => run(async () => {
    if (!draft) return
    take(await generateFlow({ description, answers, change_request: refine, base_flow: draft.flow }))
    setRefine('')
  })

  const startOver = () => {
    setDescription('')
    setAnswers([])
    setQuestions([])
    setDraft(null)
    setError(null)
    setRefine('')
  }

  const createDraft = () => run(async () => {
    if (!draft) return
    const id = flowId.trim()
    if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error('Flow id must use letters, digits, "_" or "-".')
    if ((await listFlows()).some(f => f.id === id)) throw new Error(`Flow "${id}" already exists; choose another id.`)
    await createFlow({ ...asRecord(draft.flow), id })
    navigate(`/flows/${encodeURIComponent(id)}`)
  })

  const violated = useMemo(() => new Set(draft?.check.violations.map(v => v.node_id) ?? []), [draft])

  return (
    <div className="flex flex-col gap-3">
      <div className="page-header">
        <Link to="/flows" className="btn btn-ghost btn-sm">← Flows</Link>
        <h1>Describe it</h1>
        <p className="text-muted">
          Describe a flow in plain English. AgentOS builds a draft and runs the same security check as Publish. The draft
          is only saved when you choose Create draft, and it is never published from here.
        </p>
      </div>

      <div className="card" style={{ padding: 12 }}>
        <label className="form-label" htmlFor="describe-text">What should the flow do?</label>
        <textarea
          id="describe-text"
          className="form-input"
          data-testid="describe-text"
          rows={4}
          maxLength={4000}
          value={description}
          disabled={busy}
          onChange={e => setDescription(e.target.value)}
          placeholder="When ..., then ... . Name every recipient (email address, Slack channel, URL)."
        />
        <div className="flex gap-2 flex-wrap items-center" style={{ marginTop: 8 }}>
          <span className="text-muted" style={{ fontSize: 12 }}>Examples:</span>
          {DESCRIBE_EXAMPLES.map(ex => (
            <button key={ex.key} className="btn btn-ghost btn-sm" data-testid={`example-${ex.key}`} disabled={busy}
                    onClick={() => setDescription(ex.text)}>
              {ex.label}
            </button>
          ))}
          <span style={{ flex: 1 }} />
          <span className="text-muted" style={{ fontSize: 12 }}>{description.length}/4000</span>
          <span title={canBuild ? undefined : needs('build')}>
            <button className="btn btn-primary" data-testid="describe-build" onClick={build}
                    disabled={busy || !description.trim() || !canBuild}>
              {busy ? 'Working…' : 'Build draft'}
            </button>
          </span>
        </div>
      </div>

      {error && <div className="card" style={{ padding: 10, color: 'var(--accent-red)' }} data-testid="describe-error">{error}</div>}

      {questions.length > 0 && (
        <div className="card" style={{ padding: 12 }} data-testid="describe-questions">
          <h3 style={{ marginTop: 0 }}>AgentOS needs to know (it will not guess recipients or targets)</h3>
          {questions.map((q, i) => (
            <div key={i} className="form-group">
              <label className="form-label" htmlFor={`answer-${i}`}>{q}</label>
              <input id={`answer-${i}`} className="form-input" data-testid={`answer-${i}`} maxLength={500}
                     value={pending[i] ?? ''} onChange={e => setPending(p => ({ ...p, [i]: e.target.value }))} />
            </div>
          ))}
          <button className="btn btn-primary" data-testid="describe-continue" onClick={answerAndContinue}
                  disabled={busy || !Object.values(pending).some(v => v.trim())}>
            Continue
          </button>
        </div>
      )}

      {draft && (
        <>
          <PreviewCanvas flow={draft.flow} specs={specs} explanation={draft.explanation} violated={violated} />
          <div className="flex gap-3 flex-wrap" style={{ alignItems: 'flex-start' }}>
            <div style={{ flex: '1 1 420px' }}><ExplanationView explanation={draft.explanation} /></div>
            <div style={{ flex: '1 1 380px' }} className="flex flex-col gap-3">
              <CheckView check={draft.check} onFix={applyFix} busy={busy} />
              {draft.diff && (
                <div className="card" style={{ padding: 12 }}>
                  <h3 style={{ marginTop: 0 }}>Changes from the refinement</h3>
                  <DiffView diff={draft.diff} />
                </div>
              )}
            </div>
          </div>
          <div className="card" style={{ padding: 12 }}>
            <div className="flex gap-2 items-end flex-wrap">
              <div className="form-group" style={{ flex: '1 1 320px' }}>
                <label className="form-label" htmlFor="refine-text">Refine (a follow-up instruction)</label>
                <input id="refine-text" className="form-input" data-testid="refine-text" maxLength={1000} value={refine}
                       onChange={e => setRefine(e.target.value)} placeholder="also notify Slack ops-alerts" />
              </div>
              <button className="btn btn-secondary" data-testid="describe-refine" onClick={doRefine}
                      disabled={busy || !refine.trim() || !canBuild}>Refine</button>
              <div className="form-group">
                <label className="form-label" htmlFor="draft-id">Flow id</label>
                <input id="draft-id" className="form-input" data-testid="draft-id" value={flowId}
                       onChange={e => setFlowId(e.target.value)} />
              </div>
              <button className="btn btn-primary" data-testid="describe-create" onClick={createDraft}
                      disabled={busy || !flowId.trim() || !canBuild}
                      title="Saves it as a normal draft and opens it in the visual editor (Publish runs the check again)">
                Create draft
              </button>
              <button className="btn btn-ghost" data-testid="describe-start-over" onClick={startOver} disabled={busy}>Start over</button>
            </div>
            {draft.check.status === 'failing' && (
              <div className="text-muted" style={{ fontSize: 12, marginTop: 6 }} data-testid="failing-note">
                This draft still fails the security check: you can save it as a draft, but Publish will refuse it until the
                violations are fixed.
              </div>
            )}
            <div className="text-muted" style={{ fontSize: 11, marginTop: 6 }}>Model calls used: {draft.modelCalls}</div>
          </div>
        </>
      )}
    </div>
  )
}
