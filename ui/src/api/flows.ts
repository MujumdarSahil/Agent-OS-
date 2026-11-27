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
  /** 2.5b quarantined_extraction only: the node declassifies, and the admin allowlist names (names only). */
  declassifies?: boolean
  allowlist_names?: string[]
  /** 3.5: sandbox code tools are agent tools only (never a flow step); the palette hides them. */
  agent_tool_only?: boolean
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
  published_by?: string | null
  /** 3.4: computed by the server on read: latest published version, and whether the draft differs from it */
  published_version?: number | null
  unpublished_changes?: boolean | null
  /** 4.2: response-only result of the "require tests to pass" publish gate */
  test_gate?: import('./flowTests').TestGateResult | null
}

/** "published v3" when the latest version matches the draft, "draft" when there are unpublished changes. */
export function flowStatusLabel(f: Pick<FlowRecord, 'status' | 'published_version' | 'unpublished_changes'>): string {
  if (f.status === 'archived') return 'archived'
  if (f.published_version && !f.unpublished_changes) return `published v${f.published_version}`
  if (f.published_version) return `draft (published v${f.published_version})`
  return 'draft'
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
  // structured details ({detail, retry}, 3.1) carry their own readable message
  const inner = (detail as { detail?: unknown } | null)?.detail
  if (typeof inner === 'string') return inner
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
  /** 2.4d: "manual" | "webhook" | "cron" | "subflow"; null on runs created before 2.4d. */
  trigger?: string | null
  mission_name?: string
  /** 3.6b: OpenTelemetry trace ID (32 hex characters) */
  trace_id?: string | null
  created_at?: string
  updated_at?: string
}

/** 2.4d: every run of a flow (manual, webhook, schedule), as returned by the server. */
export const listRuns = (flowId: string) =>
  api.get<RunInfo[]>(`/v2/flows/${encodeURIComponent(flowId)}/runs`).then(r => r.data)

/** Inputs are labelled untrusted by the server (manual trigger). */
export const startRun = (flowId: string, inputs: Record<string, unknown>) =>
  api.post<RunStartResponse>(`/v2/flows/${encodeURIComponent(flowId)}/runs`, { inputs }).then(r => r.data)
export const getRun = (flowId: string, runId: string) =>
  api.get<RunInfo>(`/v2/flows/${encodeURIComponent(flowId)}/runs/${encodeURIComponent(runId)}`).then(r => r.data)
/** 3.1: a 409 means the worker is still parking the run (it holds the lease for a moment after the run
 *  becomes visible as waiting). The decision was NOT applied, so it is retried a few times; the server
 *  applies a decision exactly once. */
export const APPROVAL_RETRIES = 5
export const APPROVAL_RETRY_MS = 400

export async function decideApproval(flowId: string, runId: string, nodeId: string, approve: boolean,
                                     confirmLookalike = false) {
  const url = `/v2/flows/${encodeURIComponent(flowId)}/runs/${encodeURIComponent(runId)}/approve`
  // 4.1b: confirm_lookalike is the second, explicit click for a card with look-alike destinations
  const body = { node_id: nodeId, decision: approve ? true : 'reject', ...(approve && confirmLookalike ? { confirm_lookalike: true } : {}) }
  for (let attempt = 0; ; attempt++) {
    try {
      return (await api.post(url, body)).data
    } catch (e) {
      const status = (e as { response?: { status?: number } })?.response?.status
      if (status !== 409 || attempt >= APPROVAL_RETRIES) throw e
      await new Promise(resolve => setTimeout(resolve, APPROVAL_RETRY_MS))
    }
  }
}

/** All events of one run (HTTP; used by list pages to build approval cards and provenance chains). */
export const getRunEvents = (flowId: string, runId: string) =>
  api
    .get<{ run_id: string; seq: number; type: string; data: Record<string, unknown>; ts?: string }[]>(
      `/v2/flows/${encodeURIComponent(flowId)}/runs/${encodeURIComponent(runId)}/events`,
    )
    .then(r => r.data)

// ---- triggers (2.4e list page; secret paths and keys are never requested or shown) ----

export interface WebhookInfo { webhook_id: string; name: string; flow_id: string; rate_limit_per_minute: number; enabled: boolean; created_at?: string }
export interface ScheduleInfo { schedule_id: string; name: string; flow_id: string; cron_expression: string; timezone: string; enabled: boolean; last_run_at?: string | null; next_run_at?: string | null }

export const listWebhooks = () =>
  api.get<WebhookInfo[]>('/v2/webhooks').then(r =>
    r.data.map(w => ({ webhook_id: w.webhook_id, name: w.name, flow_id: w.flow_id, rate_limit_per_minute: w.rate_limit_per_minute, enabled: w.enabled, created_at: w.created_at })))
export const listSchedules = () => api.get<ScheduleInfo[]>('/v2/schedules').then(r => r.data)

// ---- overview (2.4e) ------------------------------------------------------

export type OverviewWindow = '24h' | '7d'
export type ProviderHealth = 'healthy' | 'cooling' | 'disabled' | 'no_key' | 'not_running'

export interface OverviewData {
  window: OverviewWindow
  generated_at: string
  mode: 'standalone' | 'platform'
  version: string
  mock_llm: boolean
  truncated: boolean
  kpis: {
    runs: { total: number; succeeded: number; failed: number; waiting: number; running: number }
    attacks_blocked: number
    waiting_for_approval: number
    model_calls: { total: number; median_latency_ms: number | null; fallbacks: number }
  }
  needs_you: { waiting_approvals: number; attacks_blocked_today: number; providers_cooling: number; unacknowledged_alerts?: number }
  recent_runs: {
    run_id: string; flow_id: string; flow_version?: number | null; trigger: string; status: string
    answered_by: { provider?: string; model?: string; fallback: boolean; mock: boolean } | null
    started_at: string | null; duration_ms: number | null
  }[]
  waiting: { run_id: string; flow_id: string; node_id: string; since: string | null }[]
  blocked: { run_id: string; flow_id: string; seq: number; kind: string; node_id: string; tool_name?: string | null; reason: string; ts: string | null }[]
  providers: { name: string; display_name: string; order: number; state: ProviderHealth; cooling_s: number | null; cooling_reason: string | null; has_key: boolean }[]
  flows: { flow_id: string; name: string; latest_version: number | null; updated_at: string | null }[]
  getting_started: { key_added: boolean; flow_published: boolean; first_run: boolean; first_approval: boolean; webhook_created: boolean }
}

/** Read-only aggregate of runs, events, flows and provider health (metadata only). */
export const getOverview = (window: OverviewWindow) =>
  api.get<OverviewData>('/v2/overview', { params: { window } }).then(r => r.data)

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
