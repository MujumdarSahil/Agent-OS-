// src/api/flowTests.ts — 4.2 flow test cases (/api/v2/flows/{id}/tests...). Test runs never cause real side effects:
// fake email/Slack senders and fixture responses for HTTP / fetch_url / MCP tools.

import { api } from './client'

export type ExpectationKind =
  | 'status' | 'output' | 'extraction' | 'sink' | 'security' | 'approval_reached' | 'limits' | 'judge'

export interface Expectation {
  kind: ExpectationKind
  note?: string | null
  equals?: unknown
  node?: string | null
  field?: string
  op?: string
  value?: unknown
  target?: string
  n?: number | null
  arg?: string | null
  max_cost_usd?: number | null
  max_duration_ms?: number | null
  max_model_calls?: number | null
  rubric?: string
  reasons?: string[]
  nondeterministic?: boolean
}

export interface Fixture {
  kind: 'http' | 'mcp'
  method?: string
  url?: string | null
  tool?: string | null
  status?: number
  body?: unknown
  content_type?: string
  recorded?: boolean
}

export interface TestCase {
  id?: string
  flow_id?: string
  name: string
  tags: string[]
  input: unknown
  fixtures: Fixture[]
  mock_responses: Record<string, string>
  approvals: { node?: string | null; approve: boolean }[]
  expectations: Expectation[]
  source?: 'manual' | 'run' | 'review' | 'security'
  attack?: Record<string, unknown> | null
  secret_values_included?: boolean
  notes?: string[]
  created_at?: number
  updated_at?: number
  created_by?: string | null
  last_result?: { status: 'pass' | 'fail' | 'error'; suite_run_id: string; at: number; model: string } | null
}

export interface Failure {
  expectation: Expectation | { kind: string }
  expected: unknown
  actual: unknown
  message: string
}

export interface CaseResult {
  case_id: string
  name: string
  tags: string[]
  status: 'pass' | 'fail' | 'error'
  failures: Failure[]
  error?: string | null
  run_id?: string | null
  run_status?: string | null
  cost_usd: number
  duration_ms: number
  model_calls: number
  models_used: string[]
  nondeterministic: boolean
}

export interface CaseRef { case_id: string; name: string }

export interface Regression {
  previous_run_id: string | null
  first_run: boolean
  newly_failing: CaseRef[]
  newly_passing: CaseRef[]
  still_failing: CaseRef[]
  new_cases: CaseRef[]
  removed_cases: CaseRef[]
}

export interface SuiteRun {
  id: string
  flow_id: string
  target: 'draft' | 'published' | 'version'
  version: number | null
  model: string
  tags: string[]
  live_tools: boolean
  started_at: number
  duration_ms: number
  counts: { total: number; pass: number; fail: number; error: number }
  results: CaseResult[]
  regression: Regression | null
  comparison_id?: string | null
  purpose?: string
}

export interface ComparisonRow {
  model: string
  suite_run_id: string
  pass_rate: number | null
  counts: SuiteRun['counts']
  cost_usd: number
  median_latency_ms: number | null
  latency_source: string
  failed_cases: { case_id: string; name: string; status: string }[]
}

export interface GateSettings { flow_id: string; mode: 'off' | 'warn' | 'block'; model: string }

export interface TestGateResult {
  mode: 'warn' | 'block'
  model: string
  passed: boolean
  suite_run_id: string | null
  counts: SuiteRun['counts']
  failed: string[]
  message: string
}

const base = (flowId: string) => `/v2/flows/${encodeURIComponent(flowId)}/tests`

export async function listTestCases(flowId: string): Promise<{ cases: TestCase[]; gate: GateSettings }> {
  return (await api.get(base(flowId))).data
}

/** Create or update; response-only and server-set fields are never sent. */
export async function saveTestCase(flowId: string, c: TestCase): Promise<TestCase> {
  const body: Record<string, unknown> = { ...c }
  for (const k of ['id', 'last_result', 'flow_id', 'created_at', 'updated_at', 'created_by']) delete body[k]
  return c.id
    ? (await api.put(`${base(flowId)}/${encodeURIComponent(c.id)}`, body)).data
    : (await api.post(base(flowId), body)).data
}

export async function deleteTestCase(flowId: string, id: string): Promise<void> {
  await api.delete(`${base(flowId)}/${encodeURIComponent(id)}`)
}

export async function caseFromRun(flowId: string, runId: string): Promise<TestCase> {
  return (await api.post(`${base(flowId)}/from-run`, { run_id: runId })).data
}

export async function importFromReview(flowId: string): Promise<{ imported: number }> {
  return (await api.post(`${base(flowId)}/from-review`, {})).data
}

export async function generateSecurityTests(flowId: string): Promise<{ generated: number; families: string[] }> {
  return (await api.post(`${base(flowId)}/security`)).data
}

export async function runSuite(flowId: string, body: { target: string; version?: number | null; model: string;
  tags?: string[] }): Promise<SuiteRun> {
  return (await api.post(`${base(flowId)}/run`, body)).data
}

export async function compareModels(flowId: string, body: { models: string[]; target: string;
  version?: number | null; tags?: string[] }): Promise<{ comparison_id: string; rows: ComparisonRow[] }> {
  return (await api.post(`${base(flowId)}/compare`, body)).data
}

export async function listSuiteRuns(flowId: string): Promise<SuiteRun[]> {
  return (await api.get(`${base(flowId)}/runs`)).data
}

export async function putGate(flowId: string, gate: { mode: string; model: string }): Promise<GateSettings> {
  return (await api.put(`${base(flowId)}/settings`, gate)).data
}

export async function testsSummary(): Promise<Record<string, { cases: number; last_pass_rate: number | null }>> {
  return (await api.get('/v2/flow-tests/summary')).data
}

export function blankCase(): TestCase {
  return { name: 'New test case', tags: [], input: {}, fixtures: [], mock_responses: {}, approvals: [],
    expectations: [{ kind: 'status', equals: 'succeeded' }] }
}

export function expectationLabel(e: Expectation): string {
  switch (e.kind) {
    case 'status': return `final status is ${String(e.equals)}`
    case 'output': return `${e.node}.${e.field ?? 'output'} ${e.op ?? 'equals'} ${JSON.stringify(e.value)}`
    case 'extraction': return `${e.node}.${e.field} = ${JSON.stringify(e.equals)}`
    case 'sink': {
      const where = `${e.target}${e.node ? ` (${e.node})` : ''}`
      if (e.op === 'not_called') return `${where} was not called`
      if (e.op === 'count') return `${where} called exactly ${e.n} time(s)`
      if (e.op === 'called_with') return `${where} called with ${e.arg ?? 'destination'} = ${String(e.value)}`
      return `${where} was called`
    }
    case 'security':
      return e.op === 'blocked' ? `a call was blocked${e.node ? ` at ${e.node}` : ''}`
        : e.op === 'publish_refused' ? 'publish would be refused'
          : 'nothing reached an address outside the internal domains'
    case 'approval_reached': return e.node ? `approval ${e.node} reached` : 'an approval was reached'
    case 'limits': return [e.max_cost_usd != null && `cost ≤ ${e.max_cost_usd} USD`,
      e.max_duration_ms != null && `duration ≤ ${e.max_duration_ms} ms`,
      e.max_model_calls != null && `model calls ≤ ${e.max_model_calls}`].filter(Boolean).join(', ')
    case 'judge': return `judge (non-deterministic): ${e.rubric}`
  }
}
