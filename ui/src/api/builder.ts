// src/api/builder.ts — 4.0 natural-language flow builder (/api/v2/flows/generate, /api/v2/flows/check).
// The server never saves or publishes here; "Create draft" uses the normal createFlow.

import { api } from './client'
import type { FlowRecord, Violation } from './flows'

export interface BuilderFlow {
  id: string
  name: string
  entrypoint: string
  nodes: FlowRecord['nodes']
  edges: FlowRecord['edges']
  loops: FlowRecord['loops']
}

export interface OneClickFix {
  id: string
  node_id: string
  target_arg: string
  kind: 'pin' | 'allowlist' | 'approval'
  label: string
  value: string
  flow: BuilderFlow
  passes: boolean
}

export interface RepairRound {
  round: number
  accepted: boolean
  why: string
  resolved?: string[]
  introduced?: string[]
}

export interface CheckResult {
  status: 'passed' | 'fixed' | 'failing'
  violations: (Violation & { rule: string })[]
  fixed: RepairRound[]
  fixes: OneClickFix[]
  refusals: string[]
}

export interface SecuritySummary {
  untrusted_inputs: { node_id: string; what: string }[]
  untrusted_flows: { sink: string; arg: string; from: string[] }[]
  pinned: { node_id: string; arg: string; value: unknown }[]
  approvals: { node_id: string; sink: string; args: string[] }[]
  external_sinks: { node_id: string; type: string; side_effect: string; recipient: unknown; via_agent_tools: string[] }[]
  node_trust: Record<string, 'trusted' | 'untrusted'>
}

export interface Explanation {
  steps: { node_id: string; type: string; text: string }[]
  model_summary: string
  security: SecuritySummary
}

export interface FlowDiff {
  nodes_added: string[]
  nodes_removed: string[]
  nodes_changed: { id: string; fields: string[] }[]
  edges_added: string[]
  edges_removed: string[]
  edges_changed: { key: string; from: Record<string, string>; to: Record<string, string> }[]
  entrypoint_changed: boolean
  empty: boolean
}

export interface GenerateResult {
  status: 'draft' | 'questions' | 'error'
  mode: 'new' | 'edit'
  questions?: string[]
  question_source?: 'model' | 'agentos'
  error?: string
  flow?: BuilderFlow
  check?: CheckResult
  explanation?: Explanation
  diff?: FlowDiff
  model_calls: number
  repair_rounds: number
  run_id: string
}

export interface Answer { question: string; answer: string }

export interface GenerateRequest {
  description?: string
  answers?: Answer[]
  flow_id?: string
  change_request?: string
  base_flow?: BuilderFlow
}

export const generateFlow = (body: GenerateRequest) =>
  api.post<GenerateResult>('/v2/flows/generate', body).then(r => r.data)

// ---- 4.1 "Attack my flow" (adversarial MOCK model, fake sinks; nothing saved or sent) ----

export interface AttackRow {
  id: string
  family: string
  variant: string
  target: 'outside' | 'lookalike'
  outcome: 'succeeded' | 'reached_flagged_sink' | 'stopped_at_approval' | 'blocked_at_runtime' | 'pinned_only' | 'no_effect'
  stopped: boolean
  why: string
  nodes: string[]
  paths: string[][]
}

export interface AttackReport {
  tried: number
  stopped: number
  succeeded: number
  score_pct: number | null
  attacks: AttackRow[]
  furthest: AttackRow | null
  violations: { node_id: string; target_arg: string; path: string[]; reason: string }[]
  not_run: string[]
  fixes: (Omit<OneClickFix, 'value'> & { flow: BuilderFlow })[]
  refusals: string[]
}

export const attackMyFlow = (flowId: string, flow: BuilderFlow) =>
  api.post<AttackReport>(`/v2/flows/${encodeURIComponent(flowId)}/attack-test`, { flow }).then(r => r.data)

export const checkFlow =(flow: BuilderFlow, description = '', answers: Answer[] = []) =>
  api.post<{ flow: BuilderFlow; check: CheckResult; explanation: Explanation }>('/v2/flows/check', { flow, description, answers })
    .then(r => r.data)
