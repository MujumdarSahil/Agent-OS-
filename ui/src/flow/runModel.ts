// src/flow/runModel.ts — pure derivations from the append-only run event log:
// node statuses, the pending approval (exact args + labels), and blocked calls with provenance.

import type { NodeRunStatus } from './flowGraph'

export interface RunEvent {
  run_id: string
  seq: number
  type: string
  data: Record<string, unknown>
  ts?: string
}

export interface LabelInfo {
  integrity: 'trusted' | 'untrusted' | string
  confidentiality: string
  sources: string[]
}

export interface ApprovalArg {
  name: string
  value: unknown
  label?: LabelInfo
}

export interface PendingApproval {
  nodeId: string
  prompt: string
  sinkNode?: string
  args: ApprovalArg[]
  /** 2.4d-fix: every argument the sink will receive (pinned, via the approval, from other nodes). */
  sinkArgs?: SinkArg[]
  waitingSeq: number
}

export interface SinkArg extends ApprovalArg {
  pinned: boolean
  /** Comes from a node that has not run yet; its value is not known at approval time. */
  pending: boolean
  source?: string
}

type RawSinkArg = { value?: unknown; label?: LabelInfo; pinned?: boolean; via_approval?: boolean; pending?: boolean; source?: string }

export interface ProvenanceStep {
  text: string
  seq?: number
  untrusted?: boolean
}

export interface BlockedCall {
  seq: number
  nodeId: string
  kind: string
  reason: string
  chain: ProvenanceStep[]
}

const str = (v: unknown) => (typeof v === 'string' ? v : v === undefined || v === null ? '' : JSON.stringify(v))

/** Merge incoming events by seq (dedupe), keeping ascending order. */
export function mergeEvents(existing: RunEvent[], incoming: RunEvent[]): RunEvent[] {
  if (!incoming.length) return existing
  const bySeq = new Map(existing.map(e => [e.seq, e]))
  for (const e of incoming) bySeq.set(e.seq, e)
  return [...bySeq.values()].sort((a, b) => a.seq - b.seq)
}

/** Seqs missing between 1 and the highest seen seq (should always be empty). */
export function missingSeqs(events: RunEvent[]): number[] {
  const have = new Set(events.map(e => e.seq))
  const max = events.length ? events[events.length - 1].seq : 0
  const out: number[] = []
  for (let s = 1; s <= max; s++) if (!have.has(s)) out.push(s)
  return out
}

export function nodeStatuses(events: RunEvent[]): Record<string, NodeRunStatus> {
  const st: Record<string, NodeRunStatus> = {}
  for (const e of events) {
    const id = str(e.data.node_id ?? e.data.agent_node ?? e.data.sink_node)
    if (!id) continue
    switch (e.type) {
      case 'node_queued': st[id] = 'pending'; break
      case 'node_started': st[id] = 'running'; break
      case 'node_waiting': st[id] = 'waiting'; break
      case 'node_succeeded': st[id] = 'succeeded'; break
      case 'node_failed': st[id] = st[id] === 'blocked' ? 'blocked' : 'failed'; break
      case 'tool_call_blocked':
      case 'tool_call_rejected': st[id] = 'blocked'; break
    }
  }
  return st
}

export function runStatusFromEvents(events: RunEvent[]): string | undefined {
  let s: string | undefined
  for (const e of events) {
    if (e.type === 'run_started') s = 'running'
    else if (e.type === 'run_waiting') s = 'waiting'
    else if (e.type === 'approval_decision') s = 'running'
    else if (e.type === 'run_succeeded') s = 'succeeded'
    else if (e.type === 'run_failed') s = 'failed'
  }
  return s
}

function startedFor(events: RunEvent[], nodeId: string, beforeSeq: number): RunEvent | undefined {
  let found: RunEvent | undefined
  for (const e of events) {
    if (e.seq >= beforeSeq) break
    if (e.type === 'node_started' && e.data.node_id === nodeId) found = e
  }
  return found
}

function labelsOf(ev: RunEvent | undefined): Record<string, LabelInfo> {
  return ((ev?.data.input_labels as Record<string, LabelInfo>) ?? {})
}

/** The approval the run is waiting on: exact argument values from node_waiting, labels from node_started. */
export function pendingApproval(events: RunEvent[]): PendingApproval | undefined {
  let pending: PendingApproval | undefined
  for (const e of events) {
    if (e.type === 'node_waiting') {
      const nodeId = str(e.data.node_id)
      const labels = labelsOf(startedFor(events, nodeId, e.seq))
      const args = (e.data.arguments as Record<string, unknown>) ?? {}
      const approves = (e.data.approves as { sink_node?: string; args?: string[] }) ?? {}
      const names = approves.args?.length ? approves.args : Object.keys(args)
      const raw = e.data.sink_args as Record<string, RawSinkArg> | undefined
      const sinkArgs: SinkArg[] | undefined = raw && Object.keys(raw).length
        ? Object.entries(raw).map(([n, s]) =>
            s.via_approval
              ? { name: n, value: args[n], label: labels[n], pinned: false, pending: false, source: nodeId }
              : { name: n, value: s.value, label: s.label, pinned: !!s.pinned, pending: !!s.pending, source: s.source })
        : undefined
      pending = {
        nodeId,
        prompt: str(e.data.prompt),
        sinkNode: approves.sink_node,
        args: names.map(n => ({ name: n, value: args[n], label: labels[n] })),
        sinkArgs,
        waitingSeq: e.seq,
      }
    } else if (e.type === 'approval_decision' && pending && e.data.node_id === pending.nodeId) {
      pending = undefined
    }
  }
  return pending
}

function sourceSteps(events: RunEvent[], label: LabelInfo | undefined, beforeSeq: number): ProvenanceStep[] {
  const steps: ProvenanceStep[] = []
  for (const src of label?.sources ?? []) {
    let succ: RunEvent | undefined
    for (const e of events) {
      if (e.seq >= beforeSeq) break
      if (e.type === 'node_succeeded' && e.data.node_id === src) succ = e
    }
    steps.push({ text: `${src} (${succ ? 'node_succeeded' : 'source'})`, seq: succ?.seq, untrusted: label?.integrity !== 'trusted' })
  }
  return steps
}

/** Blocked or refused calls, each with a provenance chain built from event labels and seqs. */
export function blockedCalls(events: RunEvent[]): BlockedCall[] {
  const out: BlockedCall[] = []
  for (const e of events) {
    const isBlock = e.type === 'tool_call_blocked' || e.type === 'tool_call_rejected'
    const isNodeFail = e.type === 'node_failed'
    if (!isBlock && !isNodeFail) continue
    const nodeId = str(e.data.agent_node ?? e.data.node_id)
    const reason = str(e.data.reason ?? e.data.error)
    // A node_failed that repeats an earlier block on the same node adds nothing; an operator
    // rejection is not a security block.
    if (isNodeFail && (out.some(b => b.nodeId === nodeId) || reason === 'rejected_by_operator')) continue
    const started = startedFor(events, nodeId, e.seq)
    const labels = labelsOf(started)
    const m = /^\[[^:\]]+:([^\]]+)\]/.exec(reason)
    const argName = str(e.data.arg) || (m ? m[1] : '')
    const argKey = argName.includes('.') ? argName.split('.').pop()! : argName
    const relevant: [string, LabelInfo][] =
      argKey && labels[argKey] ? [[argKey, labels[argKey]]] : Object.entries(labels).filter(([k]) => k !== '*')
    const chain: ProvenanceStep[] = []
    for (const [k, lbl] of relevant) {
      for (const s of sourceSteps(events, lbl, e.seq)) if (!chain.some(c => c.text === s.text)) chain.push(s)
      chain.push({ text: `${nodeId}.${k} [${lbl.integrity}, ${lbl.confidentiality}] (node_started)`, seq: started?.seq, untrusted: lbl.integrity !== 'trusted' })
    }
    const tool = e.data.tool_name ? ` ${str(e.data.tool_name)}` : ''
    chain.push({ text: `${e.type}${tool}`, seq: e.seq })
    out.push({ seq: e.seq, nodeId, kind: e.type, reason, chain })
  }
  return out
}

/** One-line, plain-text event summary (values are never rendered as markup). */
/** "groq: RateLimitError -> openrouter_glm_5_2_free: ok" for an llm_call event (metadata only). */
export function llmHops(d: Record<string, unknown>): string {
  const attempts = Array.isArray(d.attempts) ? (d.attempts as { provider?: string; error_class?: string }[]) : []
  const hops = attempts.map(a => `${str(a.provider)}: ${str(a.error_class)}`)
  const status = str(d.status)
  if (status === 'ok') hops.push(`${str(d.provider)}: ok`)
  else if (status === 'refused') hops.push(`refused: ${str(d.reason)}`)
  else hops.push('all providers failed')
  const model = d.model ? ` (${str(d.model)})` : ''
  return `${hops.join(' -> ')}${model}${d.latency_ms !== undefined ? ` · ${str(d.latency_ms)} ms` : ''}`
}

// ---- 2.4d: run inspection (timeline, node input/output, duration, history) ----------------

const tsMs = (e?: RunEvent) => (e?.ts ? Date.parse(e.ts) : NaN)

export interface LlmInfo {
  provider: string
  model: string
  tokens: number
  hops: string
}

export interface Step {
  nodeId: string
  status: NodeRunStatus
  durationMs: number | null
  startSeq: number
  llm: LlmInfo[]
}

/** One row per executed node, in start order, with duration and any llm_call metadata. */
export function stepTimeline(events: RunEvent[]): Step[] {
  const statuses = nodeStatuses(events)
  const steps = new Map<string, Step & { start?: RunEvent; end?: RunEvent }>()
  for (const e of events) {
    const id = str(e.data.node_id)
    if (!id) continue
    if (e.type === 'node_started' && !steps.has(id)) {
      steps.set(id, { nodeId: id, status: statuses[id] ?? 'running', durationMs: null, startSeq: e.seq, llm: [], start: e })
    }
    const s = steps.get(id)
    if (!s) continue
    if (['node_succeeded', 'node_failed', 'node_waiting', 'node_skipped'].includes(e.type)) s.end = e
    if (e.type === 'llm_call') {
      s.llm.push({ provider: str(e.data.provider), model: str(e.data.model), tokens: Number(e.data.total_tokens ?? 0), hops: llmHops(e.data) })
    }
  }
  return [...steps.values()].map(({ start, end, ...s }) => {
    const d = tsMs(end) - tsMs(start)
    return { ...s, status: statuses[s.nodeId] ?? s.status, durationMs: Number.isFinite(d) ? d : null }
  })
}

export interface NodeIO {
  inputs?: Record<string, unknown>
  inputLabels: Record<string, LabelInfo>
  outputs?: Record<string, unknown>
  outputLabels: Record<string, LabelInfo>
  error?: string
}

/** Exact input and output values of a node, with their security labels (latest execution). */
export function nodeIO(events: RunEvent[], nodeId: string): NodeIO | undefined {
  let io: NodeIO | undefined
  for (const e of events) {
    if (e.data.node_id !== nodeId) continue
    if (e.type === 'node_started') {
      io = { inputs: e.data.inputs as Record<string, unknown>, inputLabels: labelsOf(e), outputLabels: {} }
    } else if (io && e.type === 'node_succeeded') {
      io.outputs = e.data.outputs as Record<string, unknown>
      io.outputLabels = (e.data.output_labels as Record<string, LabelInfo>) ?? {}
    } else if (io && e.type === 'node_failed') {
      io.error = str(e.data.error ?? e.data.reason)
    }
  }
  return io
}

/** Milliseconds from run_started to the last event (or now while it is still running). */
export function runDurationMs(events: RunEvent[], now = Date.now()): number | null {
  const start = tsMs(events.find(e => e.type === 'run_started'))
  if (!Number.isFinite(start)) return null
  const finished = ['run_succeeded', 'run_failed'].includes(events[events.length - 1]?.type ?? '')
  const end = finished ? tsMs(events[events.length - 1]) : now
  return Number.isFinite(end) ? Math.max(0, end - start) : null
}

export interface RunTiming {
  /** Time the run was actually executing (wall time minus time spent waiting). */
  activeMs: number | null
  /** Total time spent waiting (approval or timer), closed waits only plus an open one up to now. */
  waitingMs: number
  /** Set while the run is waiting right now: when the wait began (ISO timestamp). */
  waitingSince?: string
  finished: boolean
}

/** Active vs waiting time. A wait runs from run_waiting to the next event (the decision or timer resume). */
export function runTiming(events: RunEvent[], now = Date.now()): RunTiming {
  const startEv = events.find(e => e.type === 'run_started')
  const start = tsMs(startEv)
  const last = events[events.length - 1]
  const finished = ['run_succeeded', 'run_failed'].includes(last?.type ?? '')
  if (!Number.isFinite(start)) return { activeMs: null, waitingMs: 0, finished }
  let waitingMs = 0
  let openSince: RunEvent | undefined
  for (const e of events) {
    if (openSince && e.seq > openSince.seq) {
      const d = tsMs(e) - tsMs(openSince)
      if (Number.isFinite(d)) waitingMs += Math.max(0, d)
      openSince = undefined
    }
    if (e.type === 'run_waiting') openSince = e
  }
  // Still waiting: the counter stops at the moment the wait began.
  const end = openSince ? tsMs(openSince) : finished ? tsMs(last) : now
  const activeMs = Number.isFinite(end) ? Math.max(0, end - start - waitingMs) : null
  return { activeMs, waitingMs, waitingSince: openSince?.ts, finished }
}

/** Output of the last node that succeeded (the run's final output). */
export function finalOutput(events: RunEvent[]): { nodeId: string; outputs: unknown; labels: Record<string, LabelInfo> } | undefined {
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i]
    if (e.type === 'node_succeeded') {
      return { nodeId: str(e.data.node_id), outputs: e.data.outputs, labels: (e.data.output_labels as Record<string, LabelInfo>) ?? {} }
    }
  }
  return undefined
}

/** Trigger type for the history list; runs from before 2.4d have none and count as manual. */
export function triggerOf(run: { trigger?: string | null; mission_name?: string }): string {
  if (run.trigger) return run.trigger
  if (run.mission_name?.startsWith('Webhook ')) return 'webhook'
  if (run.mission_name?.startsWith('Cron ')) return 'cron'
  return 'manual'
}

export function formatMs(ms: number | null): string {
  if (ms === null) return '-'
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`
}

export function eventSummary(e: RunEvent): string {
  const d = e.data
  const node = str(d.node_id ?? d.agent_node ?? d.sink_node)
  if (e.type === 'llm_call') return [node, llmHops(d)].filter(Boolean).join(' · ')
  const extra = str(d.error ?? d.reason ?? (e.type === 'approval_decision' ? `decision=${str(d.raw_decision ?? d.decision)}` : ''))
  return [node, extra].filter(Boolean).join(' · ')
}
