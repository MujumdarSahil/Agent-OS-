// src/api/flows.ts — typed calls for the 2.0 flow builder (/api/v2/node-specs, /api/v2/flows)

import { api } from './client'

export type SideEffect = 'none' | 'read' | 'write' | 'external_send' | 'destructive'

export interface JSONSchema {
  type?: string
  properties?: Record<string, JSONSchema>
  required?: string[]
  items?: JSONSchema
  [k: string]: unknown
}

export interface SinkRule {
  required_integrity: 'trusted' | 'untrusted' | string
  allowlist_name: string | null
  condition: string | null
}

export interface NodeSpecInfo {
  type: string
  side_effect: SideEffect
  idempotent: boolean
  timeout_seconds: number | null
  config_schema: JSONSchema
  input_schema: JSONSchema
  output_schema: JSONSchema
  sink_rules: Record<string, SinkRule>
  constrained_fields: string[]
}

export interface FlowNodeDef {
  id: string
  type: string
  config: Record<string, unknown>
  pinned_args: Record<string, unknown>
  /** UI-only layout hint; ignored by the engine. */
  position?: { x: number; y: number }
}

export interface FlowEdgeDef {
  source: string
  target: string
  /** { target_arg: source_output_field } */
  arg_mapping: Record<string, string>
  /** 2.3: "true" | "false" from a condition node, "on_error" into an error_handler. */
  branch?: string | null
}

export interface LoopDef {
  max_iterations: number
  back_edge?: [string, string]
  [k: string]: unknown
}

export interface FlowRecord {
  id: string
  name: string
  status: 'draft' | 'published' | 'archived'
  version: number | null
  entrypoint: string
  nodes: Record<string, FlowNodeDef>
  edges: FlowEdgeDef[]
  loops: Record<string, LoopDef>
  content_sha256?: string | null
}

/** Stable publish-refusal item (see test_v2_node_specs.py). */
export interface Violation {
  node_id: string
  target_arg: string
  path: string[]
  reason: string
}

export class PublishRefusedError extends Error {
  violations: Violation[]
  constructor(violations: Violation[]) {
    super('Publish refused: security violations found')
    this.violations = violations
  }
}

export function apiErrorMessage(err: unknown): string {
  const e = err as { response?: { data?: { detail?: unknown } }; message?: string }
  const detail = e?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail && typeof detail === 'object') return JSON.stringify(detail)
  return e?.message || String(err)
}

export const getNodeSpecs = () => api.get<NodeSpecInfo[]>('/v2/node-specs').then(r => r.data)

export const listFlows = () => api.get<FlowRecord[]>('/v2/flows').then(r => r.data)
export const getFlow = (id: string) =>
  api.get<FlowRecord>(`/v2/flows/${encodeURIComponent(id)}`).then(r => r.data)
export const createFlow = (f: FlowRecord) => api.post<FlowRecord>('/v2/flows', f).then(r => r.data)
export const saveFlow = (f: FlowRecord) =>
  api.put<FlowRecord>(`/v2/flows/${encodeURIComponent(f.id)}`, f).then(r => r.data)
export const archiveFlow = (id: string) =>
  api.post<FlowRecord>(`/v2/flows/${encodeURIComponent(id)}/archive`).then(r => r.data)
export const listVersions = (id: string) =>
  api.get<FlowRecord[]>(`/v2/flows/${encodeURIComponent(id)}/versions`).then(r => r.data)

// ---- runs (2.4 run panel) -------------------------------------------------

export interface RunStartResponse {
  run_id: string
  flow_id: string
  version: number
  status: string
}

export interface RunInfo {
  run_id: string
  flow_id?: string | null
  flow_version?: number | null
  status: string
  error?: string | null
}

/** Inputs are labelled untrusted by the server (manual trigger). */
export const startRun = (flowId: string, inputs: Record<string, unknown>) =>
  api.post<RunStartResponse>(`/v2/flows/${encodeURIComponent(flowId)}/runs`, { inputs }).then(r => r.data)
export const getRun = (flowId: string, runId: string) =>
  api.get<RunInfo>(`/v2/flows/${encodeURIComponent(flowId)}/runs/${encodeURIComponent(runId)}`).then(r => r.data)
export const decideApproval = (flowId: string, runId: string, nodeId: string, approve: boolean) =>
  api
    .post(`/v2/flows/${encodeURIComponent(flowId)}/runs/${encodeURIComponent(runId)}/approve`, {
      node_id: nodeId,
      decision: approve ? true : 'reject',
    })
    .then(r => r.data)

/** WebSocket URL for run events; token travels in the subprotocol, never in the URL. */
export function runEventsUrl(flowId: string, runId: string, afterSeq: number): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}/api/v2/flows/${encodeURIComponent(flowId)}/runs/${encodeURIComponent(runId)}/events?after_seq=${afterSeq}`
}

export async function publishFlow(id: string): Promise<FlowRecord> {
  try {
    const r = await api.post<FlowRecord>(`/v2/flows/${encodeURIComponent(id)}/publish`)
    return r.data
  } catch (err) {
    const resp = (err as { response?: { status?: number; data?: { detail?: { violations?: Violation[] } } } })
      ?.response
    const violations = resp?.data?.detail?.violations
    if (resp?.status === 400 && Array.isArray(violations)) {
      throw new PublishRefusedError(violations)
    }
    throw err
  }
}
