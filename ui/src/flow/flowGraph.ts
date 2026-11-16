// src/flow/flowGraph.ts — pure helpers: FlowRecord <-> canvas, client-side validation,
// and mapping publish violations to canvas highlights. No React, so it is easy to test.

import type { Edge, Node } from '@xyflow/react'
import type { FlowEdgeDef, FlowNodeDef, FlowRecord, JSONSchema, LoopDef, NodeSpecInfo, Violation } from '../api/flows'

export type NodeRunStatus = 'pending' | 'running' | 'waiting' | 'succeeded' | 'failed' | 'blocked'

export interface FlowNodeData extends Record<string, unknown> {
  def: FlowNodeDef
  spec?: NodeSpecInfo
  isEntrypoint: boolean
  violated: boolean
  status?: NodeRunStatus
}

export interface FlowEdgeData extends Record<string, unknown> {
  arg_mapping: Record<string, string>
  loop?: { loopNodeId: string; max_iterations: number }
  violated: boolean
}

export type CanvasNode = Node<FlowNodeData, 'flowNode'>
export type CanvasEdge = Edge<FlowEdgeData>

export interface ValidationIssue {
  nodeId?: string
  edgeId?: string
  message: string
}

export const edgeId = (source: string, target: string) => `${source}->${target}`

export function specMap(specs: NodeSpecInfo[] | undefined): Record<string, NodeSpecInfo> {
  const m: Record<string, NodeSpecInfo> = {}
  for (const s of specs ?? []) m[s.type] = s
  return m
}

function loopBackEdges(loops: Record<string, LoopDef>): Map<string, { loopNodeId: string; max_iterations: number }> {
  const m = new Map<string, { loopNodeId: string; max_iterations: number }>()
  for (const [loopNodeId, l] of Object.entries(loops ?? {})) {
    if (Array.isArray(l.back_edge) && l.back_edge.length === 2) {
      m.set(edgeId(String(l.back_edge[0]), String(l.back_edge[1])), { loopNodeId, max_iterations: Number(l.max_iterations) })
    }
  }
  return m
}

/** Simple layered layout for flows without stored positions. */
function autoLayout(flow: FlowRecord): Record<string, { x: number; y: number }> {
  const depth: Record<string, number> = {}
  const back = loopBackEdges(flow.loops)
  const fwd = flow.edges.filter(e => !back.has(edgeId(e.source, e.target)))
  const queue = [flow.entrypoint].filter(id => id in flow.nodes)
  if (queue.length) depth[queue[0]] = 0
  while (queue.length) {
    const cur = queue.shift()!
    for (const e of fwd) {
      if (e.source === cur && depth[e.target] === undefined) {
        depth[e.target] = depth[cur] + 1
        queue.push(e.target)
      }
    }
  }
  const perLayer: Record<number, number> = {}
  const pos: Record<string, { x: number; y: number }> = {}
  for (const id of Object.keys(flow.nodes)) {
    const d = depth[id] ?? 0
    const i = perLayer[d] ?? 0
    perLayer[d] = i + 1
    pos[id] = { x: 80 + i * 260, y: 60 + d * 150 }
  }
  return pos
}

export function makeEdge(e: FlowEdgeDef, loop?: { loopNodeId: string; max_iterations: number }): CanvasEdge {
  return {
    id: edgeId(e.source, e.target),
    source: e.source,
    target: e.target,
    data: { arg_mapping: { ...(e.arg_mapping ?? {}) }, loop, violated: false },
  }
}

export function toCanvas(flow: FlowRecord, specs: Record<string, NodeSpecInfo>): { nodes: CanvasNode[]; edges: CanvasEdge[] } {
  const layout = autoLayout(flow)
  const back = loopBackEdges(flow.loops)
  const nodes: CanvasNode[] = Object.values(flow.nodes).map(def => ({
    id: def.id,
    type: 'flowNode',
    position: def.position ?? layout[def.id] ?? { x: 0, y: 0 },
    data: {
      def: { id: def.id, type: def.type, config: def.config ?? {}, pinned_args: def.pinned_args ?? {} },
      spec: specs[def.type],
      isEntrypoint: def.id === flow.entrypoint,
      violated: false,
    },
  }))
  const edges = flow.edges.map(e => makeEdge(e, back.get(edgeId(e.source, e.target))))
  return { nodes, edges }
}

export function fromCanvas(
  meta: Pick<FlowRecord, 'id' | 'name' | 'entrypoint' | 'loops'>,
  nodes: CanvasNode[],
  edges: CanvasEdge[],
): FlowRecord {
  const outNodes: Record<string, FlowNodeDef> = {}
  for (const n of nodes) {
    outNodes[n.id] = {
      ...n.data.def,
      id: n.id,
      position: { x: Math.round(n.position.x), y: Math.round(n.position.y) },
    }
  }
  return {
    id: meta.id,
    name: meta.name,
    status: 'draft',
    version: null,
    entrypoint: meta.entrypoint,
    nodes: outNodes,
    edges: edges.map(e => ({ source: e.source, target: e.target, arg_mapping: { ...(e.data?.arg_mapping ?? {}) } })),
    loops: meta.loops ?? {},
  }
}

export function schemaProps(s: JSONSchema | undefined): string[] {
  return Object.keys(s?.properties ?? {})
}

/** Output fields a node exposes (validator nodes also expose their configured field). */
export function outputFields(def: FlowNodeDef, spec?: NodeSpecInfo): string[] {
  const out = new Set(schemaProps(spec?.output_schema))
  if (def.type === 'validator' && typeof def.config?.field === 'string' && def.config.field) out.add(def.config.field)
  return [...out]
}

export function inputArgs(spec?: NodeSpecInfo): string[] {
  return schemaProps(spec?.input_schema)
}

/** Pinnable arguments: the node's own inputs plus `<tool>.<arg>` for an agent's tools. */
export function pinnableArgs(def: FlowNodeDef, specs: Record<string, NodeSpecInfo>): string[] {
  const args = inputArgs(specs[def.type])
  if (def.type === 'agent' && Array.isArray(def.config?.tools)) {
    for (const t of def.config.tools as string[]) {
      for (const a of inputArgs(specs[t])) args.push(`${t}.${a}`)
    }
  }
  return args
}

/** Client-side checks mirroring the server's structural validation (the server stays authoritative). */
export function validateFlow(flow: FlowRecord, specs: Record<string, NodeSpecInfo>): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  const ids = Object.keys(flow.nodes)
  if (!ids.length) issues.push({ message: 'Flow has no nodes.' })
  if (!flow.entrypoint || !(flow.entrypoint in flow.nodes)) {
    issues.push({ message: `Entrypoint ${JSON.stringify(flow.entrypoint)} is not a node in this flow.` })
  }

  for (const def of Object.values(flow.nodes)) {
    const spec = specs[def.type]
    if (!spec) {
      issues.push({ nodeId: def.id, message: `Unknown node type ${JSON.stringify(def.type)}.` })
      continue
    }
    for (const req of spec.config_schema.required ?? []) {
      const v = def.config?.[req]
      if (v === undefined || v === null || v === '') {
        issues.push({ nodeId: def.id, message: `Config field "${req}" is required.` })
      }
    }
    if (def.type === 'agent' && Array.isArray(def.config?.tools)) {
      for (const t of def.config.tools as string[]) {
        if (!specs[t]) issues.push({ nodeId: def.id, message: `Agent tool "${t}" is not a known node spec.` })
      }
    }
    const pinnable = new Set(pinnableArgs(def, specs))
    for (const k of Object.keys(def.pinned_args ?? {})) {
      if (pinnable.size && !pinnable.has(k)) {
        issues.push({ nodeId: def.id, message: `Pinned arg "${k}" is not an input of this node or its tools.` })
      }
    }
  }

  const seen = new Set<string>()
  for (const e of flow.edges) {
    const id = edgeId(e.source, e.target)
    if (seen.has(id)) issues.push({ edgeId: id, message: `Duplicate edge ${id}.` })
    seen.add(id)
    const src = flow.nodes[e.source]
    const tgt = flow.nodes[e.target]
    if (!src || !tgt) {
      issues.push({ edgeId: id, message: `Edge ${id} references a missing node.` })
      continue
    }
    const outs = new Set(outputFields(src, specs[src.type]))
    const ins = new Set(inputArgs(specs[tgt.type]))
    for (const [targetArg, srcField] of Object.entries(e.arg_mapping ?? {})) {
      if (outs.size && !outs.has(srcField)) issues.push({ edgeId: id, message: `${e.source} has no output field "${srcField}".` })
      if (ins.size && !ins.has(targetArg)) issues.push({ edgeId: id, message: `${e.target} has no input argument "${targetArg}".` })
    }
  }

  // DAG check, ignoring declared bounded-loop back edges.
  const back = loopBackEdges(flow.loops)
  const indeg: Record<string, number> = Object.fromEntries(ids.map(i => [i, 0]))
  const adj: Record<string, string[]> = Object.fromEntries(ids.map(i => [i, []]))
  for (const e of flow.edges) {
    if (back.has(edgeId(e.source, e.target)) || !(e.source in adj) || !(e.target in indeg)) continue
    adj[e.source].push(e.target)
    indeg[e.target] += 1
  }
  const q = ids.filter(i => indeg[i] === 0)
  let visited = 0
  while (q.length) {
    const c = q.shift()!
    visited += 1
    for (const n of adj[c]) if (--indeg[n] === 0) q.push(n)
  }
  if (visited !== ids.length) issues.push({ message: 'Flow contains a cycle. Only DAGs and declared bounded loops are allowed.' })
  return issues
}

/** Nodes and edges on a violation's path. Path entries that are not nodes (e.g. tool names) are skipped. */
export function violationHighlights(violations: Violation[], nodeIds: Set<string>): { nodes: Set<string>; edges: Set<string> } {
  const nodes = new Set<string>()
  const edges = new Set<string>()
  for (const v of violations) {
    if (nodeIds.has(v.node_id)) nodes.add(v.node_id)
    const onPath = v.path.filter(p => nodeIds.has(p))
    onPath.forEach(p => nodes.add(p))
    for (let i = 0; i + 1 < onPath.length; i++) edges.add(edgeId(onPath[i], onPath[i + 1]))
  }
  return { nodes, edges }
}
