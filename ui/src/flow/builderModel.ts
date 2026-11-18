// src/flow/builderModel.ts — pure builder helpers (2.4b): node categories, auto ids, rename,
// argument-mapping suggestions, config summaries, dagre auto-layout and undo/redo history.

import dagre from '@dagrejs/dagre'
import type { LoopDef, NodeSpecInfo } from '../api/flows'
import { inputArgs, outputFields, type CanvasEdge, type CanvasNode } from './flowGraph'

export type NodeCategory = 'trigger' | 'ai' | 'logic' | 'action' | 'human' | 'security' | 'error'

const CATEGORY: Record<string, NodeCategory> = {
  webhook_trigger: 'trigger',
  manual_trigger: 'trigger',
  agent: 'ai',
  llm: 'ai',
  condition: 'logic',
  merge: 'logic',
  wait: 'logic',
  loop: 'logic',
  subflow: 'logic',
  error_handler: 'error',
  send_email: 'action',
  http_request: 'action',
  fetch_url: 'action',
  tool: 'action',
  approval: 'human',
  validator: 'security',
}

export const categoryOf = (type: string): NodeCategory => CATEGORY[type] ?? 'action'
export const isTrigger = (type: string) => categoryOf(type) === 'trigger'

export const NODE_ID_RE = /^[A-Za-z0-9_-]+$/

/** Next free id of the form <type>_<n> (agent_1, http_request_2, ...). */
export function nextNodeId(type: string, existing: Iterable<string>): string {
  const taken = new Set(existing)
  let n = 1
  while (taken.has(`${type}_${n}`)) n += 1
  return `${type}_${n}`
}

/** Validation message for a new id, or null if it is acceptable. */
export function idError(newId: string, oldId: string, existing: Iterable<string>): string | null {
  const id = newId.trim()
  if (!NODE_ID_RE.test(id)) return 'Node id must use letters, digits, "_" or "-".'
  if (id !== oldId && new Set(existing).has(id)) return `Node id "${id}" already exists.`
  return null
}

export interface GraphState {
  nodes: CanvasNode[]
  edges: CanvasEdge[]
  entrypoint: string
  loops: Record<string, LoopDef>
}

/** Rename a node everywhere it is referenced (edges, entrypoint, loops, approval targets). */
export function renameNode(g: GraphState, oldId: string, newId: string): GraphState {
  const swap = (x: string) => (x === oldId ? newId : x)
  const nodes = g.nodes.map(n => {
    let def = n.id === oldId ? { ...n.data.def, id: newId } : n.data.def
    const approves = def.config?.approves as { sink_node?: string } | undefined
    if (approves?.sink_node === oldId) def = { ...def, config: { ...def.config, approves: { ...approves, sink_node: newId } } }
    return n.id === oldId ? { ...n, id: newId, data: { ...n.data, def } } : { ...n, data: { ...n.data, def } }
  })
  const edges = g.edges.map(e => {
    if (e.source !== oldId && e.target !== oldId) return e
    const source = swap(e.source)
    const target = swap(e.target)
    return { ...e, id: `${source}->${target}`, source, target }
  })
  const loops: Record<string, LoopDef> = {}
  for (const [k, l] of Object.entries(g.loops)) {
    const be = Array.isArray(l.back_edge) ? ([swap(String(l.back_edge[0])), swap(String(l.back_edge[1]))] as [string, string]) : undefined
    loops[swap(k)] = be ? { ...l, back_edge: be } : l
  }
  return { nodes, edges, entrypoint: swap(g.entrypoint), loops }
}

const PRIMARY_OUT = ['payload', 'output', 'completion', 'body', 'result', 'content', 'data', 'outputs', 'inputs']
const PRIMARY_IN = ['task', 'prompt', 'body', 'url', 'text', 'context']

/** Suggested {target_arg: source_field}: same-named fields first, else main output -> main input. */
export function suggestMapping(
  source: CanvasNode | undefined,
  target: CanvasNode | undefined,
  specs: Record<string, NodeSpecInfo>,
): Record<string, string> {
  if (!source || !target) return {}
  if (source.data.def.type === 'condition' || target.data.def.type === 'error_handler') return {}
  const outs = outputFields(source.data.def, specs[source.data.def.type])
  const ins = inputArgs(specs[target.data.def.type])
  if (!outs.length || !ins.length) return {}
  const pinned = target.data.def.pinned_args
  const mapping: Record<string, string> = {}
  for (const arg of ins) if (outs.includes(arg) && !(arg in pinned)) mapping[arg] = arg
  if (Object.keys(mapping).length) return mapping
  const out = PRIMARY_OUT.find(f => outs.includes(f)) ?? outs[0]
  const inp = PRIMARY_IN.find(f => ins.includes(f) && !(f in pinned)) ?? ins.find(f => !(f in pinned))
  return inp ? { [inp]: out } : {}
}

/** Branch implied by the source handle used to connect ("true"/"false"/"on_error"). */
export function branchForHandle(sourceHandle: string | null | undefined): string | null {
  return sourceHandle === 'true' || sourceHandle === 'false' || sourceHandle === 'on_error' ? sourceHandle : null
}

function hostOf(url: unknown): string {
  if (typeof url !== 'string' || !url) return ''
  if (url.includes('{{')) return 'templated URL'
  try {
    return new URL(url).host
  } catch {
    return url.slice(0, 30)
  }
}

const clip = (s: string, n = 34) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

/** One-line summary of a node's key configuration (plain text). */
export function configSummary(node: CanvasNode): string {
  const { type, config: c = {}, pinned_args: p = {} } = node.data.def
  switch (type) {
    case 'http_request':
      return clip(`${String(c.method ?? 'GET')} ${hostOf(p.url ?? c.url) || 'no URL'}`)
    case 'send_email':
      return clip(p.to ? `to ${String(p.to)}` : 'recipient not pinned')
    case 'agent':
      return clip([c.model, c.role].filter(Boolean).map(String).join(' · ') || 'agent')
    case 'llm':
      return clip(String(c.model ?? 'default model'))
    case 'condition':
      return clip(String(c.expression ?? 'no expression'))
    case 'wait':
      return `${String(c.delay_seconds ?? 0)}s`
    case 'subflow':
      return c.flow_id ? `${String(c.flow_id)} v${String(c.version ?? '?')}` : 'no flow'
    case 'merge':
      return `mode: ${String(c.mode ?? 'all')}`
    case 'validator':
      return clip(`${String(c.field ?? '')} as ${String(c.field_type ?? '?')}`)
    case 'approval':
      return clip(`approves ${String((c.approves as { sink_node?: string } | undefined)?.sink_node ?? '?')}`)
    case 'webhook_trigger':
      return clip(String(c.path ?? 'webhook'))
    default:
      return ''
  }
}

export const NODE_W = 230
export const NODE_H = 96

export type LayoutDir = 'LR' | 'TB'

/** Zoom at which the nodes' bounding box fits a w x h canvas (padding included); 1 when there are no nodes. */
export function fitZoom(nodes: CanvasNode[], w: number, h: number, padding = 0.08): number {
  if (!nodes.length || w <= 0 || h <= 0) return 1
  const xs = nodes.map(n => n.position.x)
  const ys = nodes.map(n => n.position.y)
  const bw = Math.max(...xs) - Math.min(...xs) + NODE_W
  const bh = Math.max(...ys) - Math.min(...ys) + NODE_H
  return Math.min((w * (1 - 2 * padding)) / bw, (h * (1 - 2 * padding)) / bh)
}

/** Below this fit zoom a left-to-right flow is hard to read; the editor opens it top to bottom (2.4e). */
export const READABLE_ZOOM = 0.6

/** Dagre layout, left-to-right (default) or top-to-bottom; returns a new node array with updated positions. */
export function autoLayout(nodes: CanvasNode[], edges: CanvasEdge[], dir: LayoutDir = 'LR'): CanvasNode[] {
  const g = new dagre.graphlib.Graph()
  // LR: ranksep leaves room for the "+" buttons and the mapping label between columns.
  // TB: rows are closer (labels sit beside vertical arrows), so tall flows stay readable.
  g.setGraph(dir === 'TB'
    ? { rankdir: 'TB', nodesep: 60, ranksep: 70, marginx: 20, marginy: 20 }
    : { rankdir: 'LR', nodesep: 50, ranksep: 170, marginx: 20, marginy: 20 })
  g.setDefaultEdgeLabel(() => ({}))
  for (const n of nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H })
  for (const e of edges) if (e.data?.loop === undefined) g.setEdge(e.source, e.target)
  dagre.layout(g)
  return nodes.map(n => {
    const p = g.node(n.id)
    return p ? { ...n, position: { x: Math.round(p.x - NODE_W / 2), y: Math.round(p.y - NODE_H / 2) } } : n
  })
}

/** Bounded undo/redo stack of graph snapshots. */
export class History<T> {
  private past: T[] = []
  private future: T[] = []
  private readonly limit: number

  constructor(limit = 100) {
    this.limit = limit
  }

  record(snapshot: T) {
    this.past.push(snapshot)
    if (this.past.length > this.limit) this.past.shift()
    this.future = []
  }

  undo(current: T): T | undefined {
    const prev = this.past.pop()
    if (prev !== undefined) this.future.push(current)
    return prev
  }

  redo(current: T): T | undefined {
    const next = this.future.pop()
    if (next !== undefined) this.past.push(current)
    return next
  }

  get canUndo() {
    return this.past.length > 0
  }

  get canRedo() {
    return this.future.length > 0
  }
}
