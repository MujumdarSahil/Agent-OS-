// src/pages/FlowEditor.tsx — visual flow builder (2.4).
// Palette and forms are generated from /api/v2/node-specs; nothing here hard-codes node types.
// Saving is explicit (Save button). Publish refusals highlight the violating path on the canvas.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ReactFlow, Background, Controls, addEdge, applyEdgeChanges, applyNodeChanges,
  type Connection, type EdgeChange, type NodeChange,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import Form from '@rjsf/core'
import validator from '@rjsf/validator-ajv8'
import type { RJSFSchema, UiSchema } from '@rjsf/utils'
import {
  PublishRefusedError, apiErrorMessage, createFlow, getFlow, getNodeSpecs, publishFlow, saveFlow,
  type FlowRecord, type JSONSchema, type LoopDef, type NodeSpecInfo, type Violation,
} from '../api/flows'
import {
  edgeId, fromCanvas, inputArgs, makeEdge, outputFields, pinnableArgs, specMap, toCanvas,
  validateFlow, violationHighlights, type CanvasEdge, type CanvasNode, type ValidationIssue,
} from '../flow/flowGraph'
import { StringListField, decorateEdge, nodeTypes } from '../flow/canvasParts'
import RunPanel from '../flow/RunPanel'
import type { NodeRunStatus } from '../flow/flowGraph'

type Selection = { kind: 'node'; id: string } | { kind: 'edge'; id: string } | null

const rjsfFields = { stringList: StringListField }

function uiSchemaFor(schema: JSONSchema): UiSchema {
  const ui: UiSchema = { 'ui:submitButtonOptions': { norender: true } }
  for (const [k, v] of Object.entries(schema.properties ?? {})) {
    if (v.type === 'array' && (v.items as JSONSchema | undefined)?.type === 'string') ui[k] = { 'ui:field': 'stringList' }
  }
  return ui
}

function loopEdgeOwner(loops: Record<string, LoopDef>, id: string): string | undefined {
  return Object.entries(loops).find(([, l]) => Array.isArray(l.back_edge) && edgeId(String(l.back_edge[0]), String(l.back_edge[1])) === id)?.[0]
}

export default function FlowEditor() {
  const { flowId = '' } = useParams()
  const [search] = useSearchParams()
  const isNew = search.get('new') === '1'

  const specsQ = useQuery({ queryKey: ['node-specs'], queryFn: getNodeSpecs, staleTime: Infinity })
  const flowQ = useQuery({ queryKey: ['flow', flowId], queryFn: () => getFlow(flowId), enabled: !isNew, retry: false })
  const specs = useMemo(() => specMap(specsQ.data), [specsQ.data])

  const [name, setName] = useState(search.get('name') || flowId)
  const [entrypoint, setEntrypoint] = useState('')
  const [loops, setLoops] = useState<Record<string, LoopDef>>({})
  const [nodes, setNodes] = useState<CanvasNode[]>([])
  const [edges, setEdges] = useState<CanvasEdge[]>([])
  const [persisted, setPersisted] = useState(!isNew)
  const [status, setStatus] = useState<FlowRecord['status']>('draft')
  const [dirty, setDirty] = useState(false)
  const [selection, setSelection] = useState<Selection>(null)
  const [issues, setIssues] = useState<ValidationIssue[]>([])
  const [violations, setViolations] = useState<Violation[]>([])
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [mode, setMode] = useState<'edit' | 'run'>('edit')
  const [runStatuses, setRunStatuses] = useState<Record<string, NodeRunStatus>>({})
  const onRunStatuses = useCallback((s: Record<string, NodeRunStatus>) => setRunStatuses(s), [])

  // Initialise canvas state once specs and the flow have loaded.
  useEffect(() => {
    if (loaded || !specsQ.data) return
    if (isNew) {
      setLoaded(true)
      return
    }
    if (!flowQ.data) return
    const f = flowQ.data
    const c = toCanvas(f, specs)
    setNodes(c.nodes)
    setEdges(c.edges)
    setName(f.name || f.id)
    setEntrypoint(f.entrypoint)
    setLoops(f.loops ?? {})
    setStatus(f.status)
    setLoaded(true)
  }, [loaded, isNew, specsQ.data, flowQ.data, specs])

  const markDirty = useCallback(() => {
    setDirty(true)
    setMessage(null)
  }, [])

  // ---- canvas callbacks --------------------------------------------------
  const onNodesChange = useCallback((changes: NodeChange<CanvasNode>[]) => {
    setNodes(ns => applyNodeChanges(changes, ns))
    if (changes.some(c => (c.type === 'position' && c.dragging === false) || c.type === 'remove')) markDirty()
  }, [markDirty])
  const onEdgesChange = useCallback((changes: EdgeChange<CanvasEdge>[]) => {
    setEdges(es => applyEdgeChanges(changes, es))
    if (changes.some(c => c.type === 'remove')) markDirty()
  }, [markDirty])
  const connect = useCallback((source: string, target: string) => {
    if (!source || !target || source === target) return
    setEdges(es => (es.some(e => e.id === edgeId(source, target)) ? es : addEdge(makeEdge({ source, target, arg_mapping: {} }), es)))
    setSelection({ kind: 'edge', id: edgeId(source, target) })
    markDirty()
  }, [markDirty])
  const onConnect = useCallback((c: Connection) => connect(c.source, c.target), [connect])

  const addNode = (spec: NodeSpecInfo, id: string): boolean => {
    const nodeId = id.trim()
    if (!/^[A-Za-z0-9_-]+$/.test(nodeId)) {
      setMessage({ kind: 'error', text: 'Node id must use letters, digits, "_" or "-".' })
      return false
    }
    if (nodes.some(n => n.id === nodeId)) {
      setMessage({ kind: 'error', text: `Node id "${nodeId}" already exists.` })
      return false
    }
    const count = nodes.length
    setNodes(ns => [
      ...ns,
      {
        id: nodeId,
        type: 'flowNode',
        position: { x: 80 + (count % 3) * 240, y: 60 + count * 110 },
        data: { def: { id: nodeId, type: spec.type, config: {}, pinned_args: {} }, spec, isEntrypoint: count === 0, violated: false },
      },
    ])
    if (count === 0) setEntrypoint(nodeId)
    setSelection({ kind: 'node', id: nodeId })
    markDirty()
    return true
  }

  const updateNodeDef = (id: string, patch: Partial<CanvasNode['data']['def']>) => {
    setNodes(ns => ns.map(n => (n.id === id ? { ...n, data: { ...n.data, def: { ...n.data.def, ...patch } } } : n)))
    markDirty()
  }
  const updateEdgeMapping = (id: string, mapping: Record<string, string>) => {
    setEdges(es => es.map(e => (e.id === id ? { ...e, data: { ...e.data!, arg_mapping: mapping } } : e)))
    markDirty()
  }
  const removeSelected = () => {
    if (!selection) return
    if (selection.kind === 'node') {
      setNodes(ns => ns.filter(n => n.id !== selection.id))
      setEdges(es => es.filter(e => e.source !== selection.id && e.target !== selection.id))
      if (entrypoint === selection.id) setEntrypoint('')
    } else {
      setEdges(es => es.filter(e => e.id !== selection.id))
    }
    setSelection(null)
    markDirty()
  }

  // ---- save / publish ----------------------------------------------------
  const onSave = async () => {
    const flow = fromCanvas({ id: flowId, name, entrypoint, loops }, nodes, edges)
    const found = validateFlow(flow, specs)
    setIssues(found)
    setViolations([])
    if (found.length) {
      setMessage({ kind: 'error', text: `Not saved: ${found.length} validation issue(s).` })
      return
    }
    setBusy(true)
    try {
      const saved = persisted ? await saveFlow(flow) : await createFlow(flow)
      setPersisted(true)
      setStatus(saved.status)
      setDirty(false)
      setMessage({ kind: 'ok', text: 'Saved draft.' })
    } catch (err) {
      setMessage({ kind: 'error', text: `Server rejected save: ${apiErrorMessage(err)}` })
    } finally {
      setBusy(false)
    }
  }

  /** Export the engine-relevant definition (no layout positions, no status/version). */
  const onExport = () => {
    const f = fromCanvas({ id: flowId, name, entrypoint, loops }, nodes, edges)
    const out = {
      id: f.id,
      name: f.name,
      entrypoint: f.entrypoint,
      nodes: Object.fromEntries(
        Object.entries(f.nodes).map(([k, n]) => [k, { id: n.id, type: n.type, config: n.config, pinned_args: n.pinned_args }]),
      ),
      edges: f.edges,
      loops: f.loops,
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(out, null, 2) + '\n'], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${flowId}.flow.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const onPublish = async () => {
    setBusy(true)
    setViolations([])
    try {
      const pub = await publishFlow(flowId)
      setStatus(pub.status)
      setMessage({ kind: 'ok', text: `Published version ${pub.version}.` })
    } catch (err) {
      if (err instanceof PublishRefusedError) {
        setViolations(err.violations)
        setMessage({ kind: 'error', text: `Publish refused: ${err.violations.length} security violation(s).` })
      } else {
        setMessage({ kind: 'error', text: `Publish failed: ${apiErrorMessage(err)}` })
      }
    } finally {
      setBusy(false)
    }
  }

  // ---- derived display state --------------------------------------------
  const highlights = useMemo(() => violationHighlights(violations, new Set(nodes.map(n => n.id))), [violations, nodes])
  const issueNodes = useMemo(() => new Set(issues.map(i => i.nodeId).filter((x): x is string => !!x)), [issues])
  const displayNodes = useMemo(
    () =>
      nodes.map(n => ({
        ...n,
        data: {
          ...n.data,
          spec: specs[n.data.def.type],
          isEntrypoint: n.id === entrypoint,
          violated: highlights.nodes.has(n.id) || issueNodes.has(n.id),
          status: mode === 'run' ? runStatuses[n.id] : undefined,
        },
      })),
    [nodes, specs, entrypoint, highlights, issueNodes, mode, runStatuses],
  )
  const displayEdges = useMemo(
    () =>
      edges.map(e => {
        const owner = loopEdgeOwner(loops, e.id)
        const loop = owner ? { loopNodeId: owner, max_iterations: Number(loops[owner].max_iterations) } : undefined
        return decorateEdge(
          { ...e, data: { ...e.data!, loop, violated: highlights.edges.has(e.id) } },
          selection?.kind === 'edge' && selection.id === e.id,
        )
      }),
    [edges, loops, highlights, selection],
  )

  if (specsQ.isLoading || (!isNew && flowQ.isLoading)) return <div className="empty-state">Loading…</div>
  if (specsQ.error) return <div className="empty-state">Could not load node specs: {apiErrorMessage(specsQ.error)}</div>
  if (!isNew && flowQ.error) return <div className="empty-state">Could not load flow: {apiErrorMessage(flowQ.error)}</div>

  const selectedNode = selection?.kind === 'node' ? nodes.find(n => n.id === selection.id) : undefined
  const selectedEdge = selection?.kind === 'edge' ? edges.find(e => e.id === selection.id) : undefined

  return (
    <div className="flex flex-col gap-3" style={{ height: 'calc(100vh - 48px)' }}>
      <div className="flex items-center gap-3 flex-wrap">
        <Link to="/flows" className="btn btn-ghost btn-sm">← Flows</Link>
        <h2 className="font-bold font-mono" data-testid="flow-id">{flowId}</h2>
        <input className="form-input" style={{ width: 220 }} aria-label="Flow name" value={name} onChange={e => { setName(e.target.value); markDirty() }} />
        <span className="badge badge-default" data-testid="flow-status">{status}</span>
        {dirty && <span className="text-muted" data-testid="unsaved">unsaved changes</span>}
        <div className="ml-auto flex gap-2">
          <button
            className="btn btn-ghost"
            data-testid="toggle-run-panel"
            onClick={() => setMode(m => (m === 'edit' ? 'run' : 'edit'))}
          >
            {mode === 'edit' ? 'Run panel' : 'Back to editing'}
          </button>
          <button className="btn btn-ghost" data-testid="export-flow" onClick={onExport} title="Download the flow definition as JSON">
            Export JSON
          </button>
          <button className="btn btn-secondary" data-testid="save-flow" onClick={onSave} disabled={busy}>Save</button>
          <button
            className="btn btn-primary"
            data-testid="publish-flow"
            onClick={onPublish}
            disabled={busy || dirty || !persisted}
            title={dirty || !persisted ? 'Save before publishing' : 'Run the static security check and publish'}
          >
            Publish
          </button>
        </div>
      </div>

      {message && (
        <div data-testid="editor-message" data-kind={message.kind} style={{ color: message.kind === 'ok' ? 'var(--accent-green)' : 'var(--accent-red)' }}>
          {message.text}
        </div>
      )}
      {issues.length > 0 && (
        <ul data-testid="validation-issues" className="card" style={{ padding: 10, margin: 0 }}>
          {issues.map((i, k) => (
            <li key={k}>{i.nodeId ? `[${i.nodeId}] ` : i.edgeId ? `[${i.edgeId}] ` : ''}{i.message}</li>
          ))}
        </ul>
      )}
      {violations.length > 0 && <ViolationList violations={violations} />}

      <div className="flex gap-3 flex-1" style={{ minHeight: 0 }}>
        <Palette specs={specsQ.data ?? []} onAdd={addNode} />
        <div className="card flex-1" style={{ padding: 0, minHeight: 360 }} data-testid="flow-canvas">
          <ReactFlow
            nodes={displayNodes}
            edges={displayEdges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={(_, n) => setSelection({ kind: 'node', id: n.id })}
            onEdgeClick={(_, e) => setSelection({ kind: 'edge', id: e.id })}
            onPaneClick={() => setSelection(null)}
            deleteKeyCode={null}
            fitView
          >
            <Background />
            <Controls />
          </ReactFlow>
        </div>
        <div className="card" style={{ width: mode === 'run' ? 420 : 340, overflowY: 'auto', padding: 12 }} data-testid="inspector">
          {mode === 'run' ? (
            <RunPanel flowId={flowId} canRun={persisted && !dirty} onStatuses={onRunStatuses} />
          ) : selectedNode ? (
            <NodeInspector
              key={selectedNode.id}
              node={selectedNode}
              specs={specs}
              isEntrypoint={selectedNode.id === entrypoint}
              onSetEntrypoint={() => { setEntrypoint(selectedNode.id); markDirty() }}
              onChange={patch => updateNodeDef(selectedNode.id, patch)}
              onRemove={removeSelected}
            />
          ) : selectedEdge ? (
            <EdgeInspector
              key={selectedEdge.id}
              edge={selectedEdge}
              nodes={nodes}
              specs={specs}
              loops={loops}
              onMapping={m => updateEdgeMapping(selectedEdge.id, m)}
              onLoops={l => { setLoops(l); markDirty() }}
              onRemove={removeSelected}
            />
          ) : (
            <AddEdgeForm nodes={nodes} onConnect={connect} />
          )}
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------

function Palette({ specs, onAdd }: { specs: NodeSpecInfo[]; onAdd: (s: NodeSpecInfo, id: string) => boolean }) {
  const [nodeId, setNodeId] = useState('')
  return (
    <div className="card" style={{ width: 210, overflowY: 'auto', padding: 12 }} data-testid="palette">
      <div className="form-label">New node id</div>
      <input className="form-input mb-2" data-testid="node-id-input" value={nodeId} placeholder="e.g. agent_node" onChange={e => setNodeId(e.target.value)} />
      <div className="form-label">Node types (from /node-specs)</div>
      <div className="flex flex-col gap-1">
        {specs.map(s => (
          <button
            key={s.type}
            className="btn btn-ghost btn-sm"
            style={{ justifyContent: 'space-between', display: 'flex' }}
            data-testid={`palette-${s.type}`}
            title={`side effect: ${s.side_effect}`}
            onClick={() => {
              if (onAdd(s, nodeId || `${s.type}_${Math.random().toString(36).slice(2, 6)}`)) setNodeId('')
            }}
          >
            <span>{s.type}</span>
            <span className="text-muted" style={{ fontSize: 10 }}>{s.side_effect}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

function NodeInspector(props: {
  node: CanvasNode
  specs: Record<string, NodeSpecInfo>
  isEntrypoint: boolean
  onSetEntrypoint: () => void
  onChange: (patch: Partial<CanvasNode['data']['def']>) => void
  onRemove: () => void
}) {
  const { node, specs } = props
  const def = node.data.def
  const spec = specs[def.type]
  const schema = (spec?.config_schema ?? { type: 'object' }) as JSONSchema
  const sinkRules = spec?.sink_rules ?? {}
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <strong className="font-mono">{def.id}</strong>
        <span className="text-muted">{def.type}</span>
      </div>
      <div className="flex gap-2">
        <button className="btn btn-secondary btn-sm" data-testid="set-entrypoint" disabled={props.isEntrypoint} onClick={props.onSetEntrypoint}>
          {props.isEntrypoint ? 'Entrypoint' : 'Set as entrypoint'}
        </button>
        <button className="btn btn-danger btn-sm" data-testid="remove-selected" onClick={props.onRemove}>Remove</button>
      </div>
      {Object.keys(sinkRules).length > 0 && (
        <div className="text-muted" style={{ fontSize: 11 }} data-testid="sink-rules">
          Sink rules:{' '}
          {Object.entries(sinkRules).map(([arg, r]) => `${arg} requires ${r.required_integrity}${r.condition ? ` (${r.condition})` : ''}`).join('; ')}
        </div>
      )}
      <div>
        <div className="form-label">Config</div>
        <div data-testid="config-form">
          <Form
            schema={schema as RJSFSchema}
            uiSchema={uiSchemaFor(schema)}
            fields={rjsfFields}
            formData={def.config}
            validator={validator}
            noHtml5Validate
            showErrorList={false}
            onChange={({ formData }) => {
              if (JSON.stringify(formData ?? {}) !== JSON.stringify(def.config ?? {})) props.onChange({ config: formData ?? {} })
            }}
          />
        </div>
      </div>
      <PinnedArgsEditor pinned={def.pinned_args} suggestions={pinnableArgs(def, specs)} onChange={p => props.onChange({ pinned_args: p })} />
    </div>
  )
}

function PinnedArgsEditor({ pinned, suggestions, onChange }: { pinned: Record<string, unknown>; suggestions: string[]; onChange: (p: Record<string, unknown>) => void }) {
  const [key, setKey] = useState('')
  const [value, setValue] = useState('')
  return (
    <div data-testid="pinned-args">
      <div className="form-label">Pinned args (author-fixed, trusted)</div>
      {Object.entries(pinned).map(([k, v]) => (
        <div key={k} className="flex items-center gap-2 mb-1" data-testid={`pinned-row-${k}`}>
          <code className="flex-1 truncate">{k} = {typeof v === 'string' ? v : JSON.stringify(v)}</code>
          <button className="btn btn-ghost btn-sm" aria-label={`Unpin ${k}`} onClick={() => { const n = { ...pinned }; delete n[k]; onChange(n) }}>×</button>
        </div>
      ))}
      <select className="form-select mb-1" data-testid="pinned-key-new" value={key} onChange={e => setKey(e.target.value)}>
        <option value="">argument…</option>
        {suggestions.map(s => <option key={s} value={s}>{s}</option>)}
      </select>
      <input className="form-input mb-1" data-testid="pinned-value-new" placeholder="value" value={value} onChange={e => setValue(e.target.value)} />
      <button
        className="btn btn-secondary btn-sm"
        data-testid="pinned-add"
        disabled={!key}
        onClick={() => { onChange({ ...pinned, [key]: value }); setKey(''); setValue('') }}
      >
        Pin argument
      </button>
      {suggestions.length === 0 && <div className="text-muted" style={{ fontSize: 11 }}>This node has no pinnable arguments.</div>}
    </div>
  )
}

function EdgeInspector(props: {
  edge: CanvasEdge
  nodes: CanvasNode[]
  specs: Record<string, NodeSpecInfo>
  loops: Record<string, LoopDef>
  onMapping: (m: Record<string, string>) => void
  onLoops: (l: Record<string, LoopDef>) => void
  onRemove: () => void
}) {
  const { edge, nodes, specs, loops } = props
  const src = nodes.find(n => n.id === edge.source)
  const tgt = nodes.find(n => n.id === edge.target)
  const outs = src ? outputFields(src.data.def, specs[src.data.def.type]) : []
  const ins = tgt ? inputArgs(specs[tgt.data.def.type]) : []
  const mapping = edge.data?.arg_mapping ?? {}
  const [targetArg, setTargetArg] = useState('')
  const [sourceField, setSourceField] = useState('')
  const loopNodes = nodes.filter(n => n.data.def.type === 'loop')
  const currentLoop = loopEdgeOwner(loops, edge.id) ?? ''

  const setLoopFor = (loopNodeId: string) => {
    const next: Record<string, LoopDef> = {}
    for (const [k, l] of Object.entries(loops)) {
      if (k === currentLoop) {
        const { back_edge: _drop, ...rest } = l
        void _drop
        next[k] = rest as LoopDef
      } else {
        next[k] = l
      }
    }
    if (loopNodeId) {
      const ln = nodes.find(n => n.id === loopNodeId)
      const max = Number(ln?.data.def.config?.max_iterations ?? next[loopNodeId]?.max_iterations ?? 1)
      next[loopNodeId] = { ...(next[loopNodeId] ?? {}), max_iterations: max, back_edge: [edge.source, edge.target] }
    }
    props.onLoops(next)
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <strong className="font-mono">{edge.source} → {edge.target}</strong>
        <button className="btn btn-danger btn-sm" data-testid="remove-selected" onClick={props.onRemove}>Remove</button>
      </div>
      <div data-testid="arg-mapping">
        <div className="form-label">Argument mapping (source output → target arg)</div>
        {Object.entries(mapping).map(([t, s]) => (
          <div key={t} className="flex items-center gap-2 mb-1" data-testid={`mapping-row-${t}`}>
            <code className="flex-1">{s} → {t}</code>
            <button className="btn btn-ghost btn-sm" aria-label={`Remove mapping ${t}`} onClick={() => { const n = { ...mapping }; delete n[t]; props.onMapping(n) }}>×</button>
          </div>
        ))}
        <select className="form-select mb-1" data-testid="mapping-source-new" value={sourceField} onChange={e => setSourceField(e.target.value)}>
          <option value="">source output field…</option>
          {outs.map(o => <option key={o} value={o}>{o}</option>)}
        </select>
        <select className="form-select mb-1" data-testid="mapping-target-new" value={targetArg} onChange={e => setTargetArg(e.target.value)}>
          <option value="">target argument…</option>
          {ins.map(i => <option key={i} value={i}>{i}</option>)}
        </select>
        <button
          className="btn btn-secondary btn-sm"
          data-testid="mapping-add"
          disabled={!targetArg || !sourceField}
          onClick={() => { props.onMapping({ ...mapping, [targetArg]: sourceField }); setTargetArg(''); setSourceField('') }}
        >
          Add mapping
        </button>
      </div>
      <div>
        <div className="form-label">Bounded loop back-edge</div>
        {loopNodes.length === 0 ? (
          <div className="text-muted" style={{ fontSize: 11 }}>Add a loop node to declare a bounded loop.</div>
        ) : (
          <select className="form-select" data-testid="loop-select" value={currentLoop} onChange={e => setLoopFor(e.target.value)}>
            <option value="">not a loop edge</option>
            {loopNodes.map(n => <option key={n.id} value={n.id}>back-edge of {n.id}</option>)}
          </select>
        )}
      </div>
    </div>
  )
}

function AddEdgeForm({ nodes, onConnect }: { nodes: CanvasNode[]; onConnect: (s: string, t: string) => void }) {
  const [s, setS] = useState('')
  const [t, setT] = useState('')
  return (
    <div className="flex flex-col gap-2">
      <div className="text-muted" style={{ fontSize: 12 }}>Select a node or edge to edit it, drag between handles to connect, or add an edge here.</div>
      <div className="form-label">Add edge</div>
      <select className="form-select" data-testid="edge-source" value={s} onChange={e => setS(e.target.value)}>
        <option value="">source node…</option>
        {nodes.map(n => <option key={n.id} value={n.id}>{n.id}</option>)}
      </select>
      <select className="form-select" data-testid="edge-target" value={t} onChange={e => setT(e.target.value)}>
        <option value="">target node…</option>
        {nodes.map(n => <option key={n.id} value={n.id}>{n.id}</option>)}
      </select>
      <button className="btn btn-secondary btn-sm" data-testid="edge-add" disabled={!s || !t || s === t} onClick={() => onConnect(s, t)}>
        Add edge
      </button>
    </div>
  )
}

function ViolationList({ violations }: { violations: Violation[] }) {
  return (
    <div className="card" style={{ padding: 10, borderColor: 'var(--accent-red)' }} data-testid="violation-list">
      <div className="font-semibold mb-1" style={{ color: 'var(--accent-red)' }}>Publish refused: security violations</div>
      <table style={{ width: '100%', fontSize: 12 }}>
        <thead>
          <tr><th align="left">Node</th><th align="left">Arg</th><th align="left">Path</th><th align="left">Reason</th></tr>
        </thead>
        <tbody>
          {violations.map((v, i) => (
            <tr key={i} data-testid="violation-item" data-node={v.node_id} data-arg={v.target_arg}>
              <td className="font-mono">{v.node_id}</td>
              <td className="font-mono">{v.target_arg}</td>
              <td className="font-mono">{v.path.join(' → ')}</td>
              <td>{v.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
