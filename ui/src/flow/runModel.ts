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
  waitingSeq: number
}

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
      pending = {
        nodeId,
        prompt: str(e.data.prompt),
        sinkNode: approves.sink_node,
        args: names.map(n => ({ name: n, value: args[n], label: labels[n] })),
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

export function eventSummary(e: RunEvent): string {
  const d = e.data
  const node = str(d.node_id ?? d.agent_node ?? d.sink_node)
  if (e.type === 'llm_call') return [node, llmHops(d)].filter(Boolean).join(' · ')
  const extra = str(d.error ?? d.reason ?? (e.type === 'approval_decision' ? `decision=${str(d.raw_decision ?? d.decision)}` : ''))
  return [node, extra].filter(Boolean).join(' · ')
}
