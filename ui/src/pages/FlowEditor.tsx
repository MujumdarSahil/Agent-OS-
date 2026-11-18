// src/pages/FlowEditor.tsx — visual flow builder (2.4, UX 2.4b).
// Palette and forms are generated from /api/v2/node-specs; nothing here hard-codes node types.
// Drag nodes from the palette (or click), connect left -> right with auto-suggested argument mapping,
// double-click a node for its config drawer, "+" on an output to add the next node, undo/redo,
// Delete key, auto-layout. Saving stays explicit; publish refusals highlight the violating path.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ReactFlow, ReactFlowProvider, Background, Controls, MiniMap, applyEdgeChanges, applyNodeChanges, useNodesInitialized, useReactFlow,
  type Connection, type EdgeChange, type NodeChange,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import Form from '@rjsf/core'
import validator from '@rjsf/validator-ajv8'
import type { RJSFSchema, UiSchema } from '@rjsf/utils'
import {
  PublishRefusedError, apiErrorMessage, createFlow, getFlow, getNodeSpecs, listVersions, publishFlow, saveFlow,
  type FlowRecord, type JSONSchema, type LoopDef, type NodeSpecInfo, type Violation,
} from '../api/flows'
import {
  edgeId, fromCanvas, inputArgs, makeEdge, outputFields, pinnableArgs, specMap, toCanvas,
  validateFlow, violationHighlights, type CanvasEdge, type CanvasNode, type NodeRunStatus, type ValidationIssue,
} from '../flow/flowGraph'
import { BuilderActions, CATEGORY_STYLE, StringListField, decorateEdge, nodeTypes } from '../flow/canvasParts'
import {
  History, autoLayout, branchForHandle, categoryOf, idError, nextNodeId, renameNode, suggestMapping,
  NODE_H, NODE_W, type GraphState,
} from '../flow/builderModel'
import ResultsPanel, { RunDialog } from '../flow/RunPanel'

type Drawer = { kind: 'node'; id: string } | { kind: 'edge'; id: string } | null
const DND_TYPE = 'application/agentos-node'
// 2.4d: on open, fit every node; never zoom in past 100% or out past this readable floor.
const MIN_READABLE_ZOOM = 0.35
const FIT = { padding: 0.08, maxZoom: 1, minZoom: MIN_READABLE_ZOOM }

/** True when any two node boxes overlap (stored positions are then replaced by auto-layout on open). */
function overlapping(nodes: CanvasNode[]): boolean {
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i].position
      const b = nodes[j].position
      if (Math.abs(a.x - b.x) < NODE_W && Math.abs(a.y - b.y) < NODE_H) return true
    }
  }
  return false
}
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

const isTyping = (t: EventTarget | null) =>
  t instanceof HTMLElement && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)

export default function FlowEditor() {
  return (
    <ReactFlowProvider>
      <Editor />
    </ReactFlowProvider>
  )
}

function Editor() {
  const { flowId = '' } = useParams()
  const [search] = useSearchParams()
  const isNew = search.get('new') === '1'
  const rf = useReactFlow()
  const canvasRef = useRef<HTMLDivElement>(null)

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
  const [drawer, setDrawer] = useState<Drawer>(null)
  const [picker, setPicker] = useState<{ from: string; branch: string | null } | null>(null)
  const [issues, setIssues] = useState<ValidationIssue[]>([])
  const [violations, setViolations] = useState<Violation[]>([])
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [loaded, setLoaded] = useState(false)
  // 2.4d run & inspect
  const [showResults, setShowResults] = useState(false)
  const [runId, setRunId] = useState<string | null>(null)
  const [inspectNode, setInspectNode] = useState<string | null>(null)
  const [runDialog, setRunDialog] = useState(false)
  const [showPalette, setShowPalette] = useState(isNew)
  const versionsQ = useQuery({ queryKey: ['versions', flowId], queryFn: () => listVersions(flowId), enabled: !isNew, retry: false })
  const hasPublished = (versionsQ.data?.length ?? 0) > 0
  const dragMoved = useRef(false)
  const [runStatuses, setRunStatuses] = useState<Record<string, NodeRunStatus>>({})
  const onRunStatuses = useCallback((s: Record<string, NodeRunStatus>) => setRunStatuses(s), [])
  const history = useRef(new History<GraphState>())
  const [showMinimap, setShowMinimap] = useState(true)
  const [, setHistoryTick] = useState(0)

  useEffect(() => {
    if (loaded || !specsQ.data) return
    if (isNew) {
      setLoaded(true)
      return
    }
    if (!flowQ.data) return
    const f = flowQ.data
    const c = toCanvas(f, specs)
    // Flows saved without layout positions (e.g. imported JSON), or whose stored positions overlap,
    // get a left-to-right auto-layout. This is display only: opening never marks the flow dirty.
    const hasPositions = Object.values(f.nodes).some(n => n.position)
    setNodes(hasPositions && !overlapping(c.nodes) ? c.nodes : autoLayout(c.nodes, c.edges))
    setEdges(c.edges)
    setName(f.name || f.id)
    setEntrypoint(f.entrypoint)
    setLoops(f.loops ?? {})
    setStatus(f.status)
    setLoaded(true)
    setPendingFit(true)
  }, [loaded, isNew, specsQ.data, flowQ.data, specs])

  // Centre the flow at a readable size (never zoomed in beyond 100%) once xyflow has measured the nodes.
  const nodesInitialized = useNodesInitialized()
  const [pendingFit, setPendingFit] = useState(false)
  useEffect(() => {
    if (pendingFit && nodesInitialized) {
      setPendingFit(false)
      // Short delay so a canvas resize (e.g. the violation table appearing) is measured first.
      window.setTimeout(() => void rf.fitView(FIT), 40)
    }
  }, [pendingFit, nodesInitialized, rf])

  // Opening or closing the results panel resizes the canvas: fit again so every node stays in view.
  // Only on an actual toggle (never on load, so a new canvas stays at zoom 1 for drops).
  const prevShowResults = useRef(showResults)
  useEffect(() => {
    if (prevShowResults.current !== showResults && nodes.length) setPendingFit(true)
    prevShowResults.current = showResults
  }, [showResults, nodes.length])

  // ---- history (undo/redo) --------------------------------------------------
  const graphRef = useRef<GraphState>({ nodes, edges, entrypoint, loops })
  graphRef.current = { nodes, edges, entrypoint, loops }

  const markDirty = useCallback(() => {
    setDirty(true)
    setMessage(null)
  }, [])

  const applyGraph = useCallback((g: GraphState) => {
    setNodes(g.nodes)
    setEdges(g.edges)
    setEntrypoint(g.entrypoint)
    setLoops(g.loops)
  }, [])

  /** Record the current graph for undo, then apply a change. */
  const commit = useCallback((change: (g: GraphState) => GraphState) => {
    const cur = graphRef.current
    history.current.record(cur)
    applyGraph(change(cur))
    setHistoryTick(t => t + 1)
    markDirty()
  }, [applyGraph, markDirty])

  const undo = useCallback(() => {
    const prev = history.current.undo(graphRef.current)
    if (prev) {
      applyGraph(prev)
      setHistoryTick(t => t + 1)
      markDirty()
    }
  }, [applyGraph, markDirty])

  const redo = useCallback(() => {
    const next = history.current.redo(graphRef.current)
    if (next) {
      applyGraph(next)
      setHistoryTick(t => t + 1)
      markDirty()
    }
  }, [applyGraph, markDirty])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || isTyping(e.target)) return
      const k = e.key.toLowerCase()
      if (k === 'z' && !e.shiftKey) {
        e.preventDefault()
        undo()
      } else if (k === 'y' || (k === 'z' && e.shiftKey)) {
        e.preventDefault()
        redo()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [undo, redo])

  // ---- unsaved-changes warning ----------------------------------------------
  useEffect(() => {
    if (!dirty) return
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    const onClick = (e: MouseEvent) => {
      const a = (e.target as HTMLElement | null)?.closest?.('a[href]') as HTMLAnchorElement | null
      if (!a || a.target === '_blank' || a.origin !== window.location.origin) return
      if (!window.confirm('You have unsaved changes. Leave without saving?')) {
        e.preventDefault()
        e.stopPropagation()
      }
    }
    window.addEventListener('beforeunload', onBeforeUnload)
    document.addEventListener('click', onClick, true)
    return () => {
      window.removeEventListener('beforeunload', onBeforeUnload)
      document.removeEventListener('click', onClick, true)
    }
  }, [dirty])

  // ---- adding and connecting ------------------------------------------------
  const edgeFor = useCallback(
    (g: GraphState, source: string, target: string, branch: string | null): CanvasEdge => {
      const src = g.nodes.find(n => n.id === source)
      const tgt = g.nodes.find(n => n.id === target)
      const e = makeEdge({ source, target, arg_mapping: suggestMapping(src, tgt, specs), branch })
      return branch ? { ...e, sourceHandle: branch } : e
    },
    [specs],
  )

  const connectionError = (g: GraphState, source: string, target: string, branch: string | null): string | null => {
    if (!source || !target || source === target) return 'A node cannot connect to itself.'
    if (g.edges.some(e => e.id === edgeId(source, target))) return `${source} is already connected to ${target}.`
    const tgt = g.nodes.find(n => n.id === target)
    if (branch === 'on_error' && tgt?.data.def.type !== 'error_handler') return 'The red "on error" output can only connect to an error_handler.'
    if (branch !== 'on_error' && tgt?.data.def.type === 'error_handler') return 'An error_handler is connected from a node\'s red "on error" output.'
    return null
  }

  const connect = useCallback((source: string, target: string, branch: string | null) => {
    const err = connectionError(graphRef.current, source, target, branch)
    if (err) {
      setMessage({ kind: 'error', text: err })
      return
    }
    commit(g => ({ ...g, edges: [...g.edges, edgeFor(g, source, target, branch)] }))
  }, [commit, edgeFor])

  const onConnect = useCallback((c: Connection) => connect(c.source, c.target, branchForHandle(c.sourceHandle)), [connect])

  const addNode = useCallback(
    (spec: NodeSpecInfo, position?: { x: number; y: number }, from?: { id: string; branch: string | null }) => {
      const g = graphRef.current
      const id = nextNodeId(spec.type, g.nodes.map(n => n.id))
      let pos = position
      const src = from ? g.nodes.find(n => n.id === from.id) : undefined
      if (!pos && src) pos = { x: src.position.x + NODE_W + 80, y: src.position.y + (from?.branch === 'false' ? NODE_H + 30 : 0) }
      if (!pos) {
        const rect = canvasRef.current?.getBoundingClientRect()
        const center = rect ? rf.screenToFlowPosition({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 }) : { x: 100, y: 100 }
        pos = { x: center.x - NODE_W / 2 + (g.nodes.length % 4) * 24, y: center.y - NODE_H / 2 + (g.nodes.length % 4) * 24 }
      }
      const node: CanvasNode = {
        id,
        type: 'flowNode',
        position: pos,
        data: { def: { id, type: spec.type, config: {}, pinned_args: {} }, spec, isEntrypoint: g.nodes.length === 0, violated: false },
      }
      commit(cur => {
        const withNode: GraphState = { ...cur, nodes: [...cur.nodes, node], entrypoint: cur.nodes.length === 0 ? id : cur.entrypoint }
        if (!from) return withNode
        const err = connectionError(withNode, from.id, id, from.branch)
        return err ? withNode : { ...withNode, edges: [...withNode.edges, edgeFor(withNode, from.id, id, from.branch)] }
      })
      setDrawer({ kind: 'node', id })
      return id
    },
    [commit, edgeFor, rf],
  )

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const type = e.dataTransfer.getData(DND_TYPE)
    const spec = specs[type]
    if (!spec) return
    const p = rf.screenToFlowPosition({ x: e.clientX, y: e.clientY })
    addNode(spec, { x: Math.round(p.x - NODE_W / 2), y: Math.round(p.y - NODE_H / 2) })
  }, [specs, rf, addNode])

  // ---- canvas changes (drag, select, delete) ----------------------------------
  const onNodesChange = useCallback((changes: NodeChange<CanvasNode>[]) => {
    const removed = changes.filter(c => c.type === 'remove').map(c => (c as { id: string }).id)
    if (removed.length) {
      commit(g => ({
        nodes: applyNodeChanges(changes, g.nodes),
        edges: g.edges.filter(e => !removed.includes(e.source) && !removed.includes(e.target)),
        entrypoint: removed.includes(g.entrypoint) ? '' : g.entrypoint,
        loops: g.loops,
      }))
      setDrawer(d => (d && removed.includes(d.id) ? null : d))
      return
    }
    setNodes(ns => applyNodeChanges(changes, ns))
    // Only a drag that actually moved a node is an edit (a click emits a drag-end with no movement).
    if (dragMoved.current && changes.some(c => c.type === 'position' && c.dragging === false)) {
      dragMoved.current = false
      markDirty()
    }
  }, [commit, markDirty])

  const onEdgesChange = useCallback((changes: EdgeChange<CanvasEdge>[]) => {
    if (changes.some(c => c.type === 'remove')) {
      commit(g => ({ ...g, edges: applyEdgeChanges(changes, g.edges) }))
      return
    }
    setEdges(es => applyEdgeChanges(changes, es))
  }, [commit])

  const updateNodeDef = (id: string, patch: Partial<CanvasNode['data']['def']>) =>
    commit(g => ({ ...g, nodes: g.nodes.map(n => (n.id === id ? { ...n, data: { ...n.data, def: { ...n.data.def, ...patch } } } : n)) }))
  const updateEdge = (id: string, patch: Partial<NonNullable<CanvasEdge['data']>>) =>
    commit(g => ({ ...g, edges: g.edges.map(e => (e.id === id ? { ...e, data: { ...e.data!, ...patch } } : e)) }))
  const removeNode = (id: string) => {
    commit(g => ({
      nodes: g.nodes.filter(n => n.id !== id),
      edges: g.edges.filter(e => e.source !== id && e.target !== id),
      entrypoint: g.entrypoint === id ? '' : g.entrypoint,
      loops: g.loops,
    }))
    setDrawer(null)
  }
  const removeEdge = (id: string) => {
    commit(g => ({ ...g, edges: g.edges.filter(e => e.id !== id) }))
    setDrawer(null)
  }
  const rename = (oldId: string, newId: string): string | null => {
    const err = idError(newId, oldId, nodes.map(n => n.id))
    if (err) return err
    if (newId.trim() === oldId) return null
    commit(g => renameNode(g, oldId, newId.trim()))
    setDrawer({ kind: 'node', id: newId.trim() })
    return null
  }
  const doLayout = () => {
    commit(g => ({ ...g, nodes: autoLayout(g.nodes, g.edges) }))
    setPendingFit(true)
  }

  // ---- save / publish / export ----------------------------------------------
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
      void versionsQ.refetch() // enables Run
    } catch (err) {
      if (err instanceof PublishRefusedError) {
        setViolations(err.violations)
        setMessage({ kind: 'error', text: `Publish refused: ${err.violations.length} security violation(s).` })
        setPendingFit(true) // the violation table shrinks the canvas: keep the highlighted path in view
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
          status: showResults && runId ? runStatuses[n.id] : undefined,
        },
      })),
    [nodes, specs, entrypoint, highlights, issueNodes, showResults, runId, runStatuses],
  )
  const displayEdges = useMemo(
    () =>
      edges.map(e => {
        const owner = loopEdgeOwner(loops, e.id)
        const loop = owner ? { loopNodeId: owner, max_iterations: Number(loops[owner].max_iterations) } : undefined
        return decorateEdge(
          { ...e, sourceHandle: e.data?.branch ?? e.sourceHandle, data: { ...e.data!, loop, violated: highlights.edges.has(e.id) } },
          drawer?.kind === 'edge' && drawer.id === e.id,
        )
      }),
    [edges, loops, highlights, drawer],
  )
  const actions = useMemo(() => ({ onAddNext: (id: string, branch: string | null) => setPicker({ from: id, branch }) }), [])

  if (specsQ.isLoading || (!isNew && flowQ.isLoading)) return <div className="empty-state">Loading…</div>
  if (specsQ.error) return <div className="empty-state">Could not load node specs: {apiErrorMessage(specsQ.error)}</div>
  if (!isNew && flowQ.error) return <div className="empty-state">Could not load flow: {apiErrorMessage(flowQ.error)}</div>

  const drawerNode = drawer?.kind === 'node' ? nodes.find(n => n.id === drawer.id) : undefined
  const drawerEdge = drawer?.kind === 'edge' ? edges.find(e => e.id === drawer.id) : undefined

  return (
    <div className="flex flex-col gap-3" style={{ height: 'calc(100vh - 48px)' }}>
      <div className="flex items-center gap-3 flex-wrap">
        <Link to="/flows" className="btn btn-ghost btn-sm">← Flows</Link>
        <h2 className="font-bold font-mono" data-testid="flow-id">{flowId}</h2>
        <input className="form-input" style={{ width: 220 }} aria-label="Flow name" value={name} onChange={e => { setName(e.target.value); markDirty() }} />
        <span className="badge badge-default" data-testid="flow-status">{status}</span>
        {dirty && <span className="text-muted" data-testid="unsaved">unsaved changes</span>}
        <div className="ml-auto flex gap-2">
          <button className="btn btn-ghost btn-sm" data-testid="undo" onClick={undo} disabled={!history.current.canUndo} title="Undo (Ctrl+Z)">Undo</button>
          <button className="btn btn-ghost btn-sm" data-testid="redo" onClick={redo} disabled={!history.current.canRedo} title="Redo (Ctrl+Y)">Redo</button>
          <button className="btn btn-ghost btn-sm" data-testid="auto-layout" onClick={doLayout} disabled={!nodes.length}>Auto-layout</button>
          <button className="btn btn-ghost btn-sm" data-testid="toggle-palette" aria-pressed={showPalette} onClick={() => setShowPalette(v => !v)}>
            {showPalette ? 'Hide nodes' : 'Add nodes'}
          </button>
          <button className="btn btn-ghost btn-sm" data-testid="fit-view" onClick={() => rf.fitView(FIT)}>Fit view</button>
          <button className="btn btn-ghost btn-sm" data-testid="toggle-minimap" aria-pressed={showMinimap} onClick={() => setShowMinimap(v => !v)}>
            {showMinimap ? 'Hide minimap' : 'Show minimap'}
          </button>
          <button className="btn btn-ghost" data-testid="toggle-run-panel" aria-pressed={showResults} onClick={() => setShowResults(v => !v)}>
            {showResults ? 'Hide results' : 'Results'}
          </button>
          <button className="btn btn-ghost" data-testid="export-flow" onClick={onExport} title="Download the flow definition as JSON">Export JSON</button>
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
          <span title={hasPublished ? 'Run the latest published version' : 'Publish the flow first: Run uses the latest published version'}>
            <button
              className="btn btn-primary"
              data-testid="run-open"
              onClick={() => setRunDialog(true)}
              disabled={!hasPublished}
              style={!hasPublished ? { pointerEvents: 'none' } : undefined}
            >
              ▶ Run
            </button>
          </span>
        </div>
      </div>
      {runDialog && (
        <RunDialog
          flowId={flowId}
          sample={nodes.find(n => n.id === entrypoint)?.data.def.config?.sample_input}
          onClose={() => setRunDialog(false)}
          onStarted={id => {
            setRunDialog(false)
            setRunId(id)
            setInspectNode(null)
            setShowResults(true)
          }}
        />
      )}

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
        {showPalette && <Palette specs={specsQ.data ?? []} onAdd={s => addNode(s)} />}
        <div
          ref={canvasRef}
          className="card flex-1"
          style={{ padding: 0, minHeight: 160, position: 'relative' }}
          data-testid="flow-canvas"
          onDragOver={e => {
            e.preventDefault()
            e.dataTransfer.dropEffect = 'move'
          }}
          onDrop={onDrop}
        >
          <BuilderActions.Provider value={actions}>
            <ReactFlow
              nodes={displayNodes}
              edges={displayEdges}
              nodeTypes={nodeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onNodeDragStart={() => {
                history.current.record(graphRef.current)
                setHistoryTick(t => t + 1)
              }}
              onNodeDrag={() => {
                dragMoved.current = true
              }}
              onNodeClick={(_, n) => {
                if (showResults && runId) setInspectNode(n.id)
              }}
              onNodeDoubleClick={(_, n) => setDrawer({ kind: 'node', id: n.id })}
              onEdgeClick={(_, e) => setDrawer({ kind: 'edge', id: e.id })}
              deleteKeyCode={['Delete']}
              zoomOnDoubleClick={false}
              // Fit only when opening an existing flow; a new canvas stays at zoom 1 so drops land under the cursor.
              fitView={!isNew}
              fitViewOptions={FIT}
              minZoom={0.2}
              colorMode="dark"
            >
              <Background />
              <Controls />
              {showMinimap && (
                <MiniMap
                  pannable
                  zoomable
                  position="bottom-right"
                  style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, width: 160, height: 110, margin: 12 }}
                  maskColor="rgba(0,0,0,0.35)"
                  nodeColor={n => CATEGORY_STYLE[categoryOf((n as CanvasNode).data.def.type)].color}
                />
              )}
            </ReactFlow>
          </BuilderActions.Provider>
          {picker && (
            <NextNodePicker
              specs={specsQ.data ?? []}
              from={picker.from}
              branch={picker.branch}
              onPick={s => {
                addNode(s, undefined, { id: picker.from, branch: picker.branch })
                setPicker(null)
              }}
              onClose={() => setPicker(null)}
            />
          )}
        </div>
        {(drawerNode || drawerEdge || isNew) && (
        <div className="card" style={{ width: 340, overflowY: 'auto', padding: 12 }} data-testid="inspector">
          {drawerNode ? (
            <NodeDrawer
              key={drawerNode.id}
              node={drawerNode}
              nodes={nodes}
              specs={specs}
              isEntrypoint={drawerNode.id === entrypoint}
              onSetEntrypoint={() => commit(g => ({ ...g, entrypoint: drawerNode.id }))}
              onChange={patch => updateNodeDef(drawerNode.id, patch)}
              onRename={newId => rename(drawerNode.id, newId)}
              onConnect={(target, branch) => connect(drawerNode.id, target, branch)}
              onRemove={() => removeNode(drawerNode.id)}
              onClose={() => setDrawer(null)}
            />
          ) : drawerEdge ? (
            <EdgeDrawer
              key={drawerEdge.id}
              edge={drawerEdge}
              nodes={nodes}
              specs={specs}
              loops={loops}
              onMapping={m => updateEdge(drawerEdge.id, { arg_mapping: m })}
              onBranch={b => updateEdge(drawerEdge.id, { branch: b })}
              onLoops={l => commit(g => ({ ...g, loops: l }))}
              onRemove={() => removeEdge(drawerEdge.id)}
              onClose={() => setDrawer(null)}
            />
          ) : (
            <div className="text-muted" style={{ fontSize: 12 }} data-testid="builder-help">
              Drag a node type onto the canvas (or click it). Drag from a node's right handle to another node to
              connect; the argument mapping is suggested and shown on the arrow. Use "+" to add the next node,
              double-click a node to configure it, click an arrow to edit its mapping. Delete removes the
              selection; Ctrl+Z / Ctrl+Y undo and redo.
            </div>
          )}
        </div>
        )}
      </div>
      {showResults && (
        <ResultsPanel
          flowId={flowId}
          runId={runId}
          onSelectRun={id => {
            setRunId(id)
            setInspectNode(null)
          }}
          inspectNode={inspectNode}
          onInspectNode={setInspectNode}
          onStatuses={onRunStatuses}
          onClose={() => setShowResults(false)}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------

function Palette({ specs, onAdd }: { specs: NodeSpecInfo[]; onAdd: (s: NodeSpecInfo) => void }) {
  return (
    <div className="card" style={{ width: 210, overflowY: 'auto', padding: 12 }} data-testid="palette">
      <div className="form-label">Node types (drag or click)</div>
      <div className="flex flex-col gap-1">
        {specs.map(s => {
          const st = CATEGORY_STYLE[categoryOf(s.type)]
          const Icon = st.icon
          return (
            <button
              key={s.type}
              className="btn btn-ghost btn-sm"
              style={{ justifyContent: 'space-between', display: 'flex', borderLeft: `3px solid ${st.color}`, cursor: 'grab' }}
              data-testid={`palette-${s.type}`}
              title={`${st.label} · side effect: ${s.side_effect}`}
              draggable
              onDragStart={e => {
                e.dataTransfer.setData(DND_TYPE, s.type)
                e.dataTransfer.effectAllowed = 'move'
              }}
              onClick={() => onAdd(s)}
            >
              <span className="flex items-center gap-1"><Icon size={12} color={st.color} />{s.type}</span>
              {s.side_effect !== 'none' && <span className="text-muted" style={{ fontSize: 10 }}>{s.side_effect}</span>}
            </button>
          )
        })}
      </div>
    </div>
  )
}

function NextNodePicker(props: {
  specs: NodeSpecInfo[]
  from: string
  branch: string | null
  onPick: (s: NodeSpecInfo) => void
  onClose: () => void
}) {
  const [q, setQ] = useState('')
  const list = props.specs.filter(s => !['webhook_trigger', 'manual_trigger'].includes(s.type) && s.type.includes(q.trim().toLowerCase()))
  return (
    <div
      className="card"
      data-testid="next-node-picker"
      style={{ position: 'absolute', top: 12, right: 12, width: 240, maxHeight: 340, overflowY: 'auto', padding: 10, zIndex: 10 }}
      onKeyDown={e => e.key === 'Escape' && props.onClose()}
    >
      <div className="flex items-center justify-between mb-1">
        <span style={{ fontSize: 12 }}>Add after <code>{props.from}</code>{props.branch ? ` (${props.branch})` : ''}</span>
        <button className="btn btn-ghost btn-sm" aria-label="Close" onClick={props.onClose}>×</button>
      </div>
      <input
        autoFocus
        className="form-input mb-1"
        data-testid="next-node-search"
        placeholder="Search node types…"
        value={q}
        onChange={e => setQ(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter' && list[0]) props.onPick(list[0])
        }}
      />
      {list.map(s => (
        <button key={s.type} className="btn btn-ghost btn-sm w-full" style={{ justifyContent: 'flex-start' }} data-testid={`next-node-option-${s.type}`} onClick={() => props.onPick(s)}>
          {s.type}
        </button>
      ))}
      {list.length === 0 && <div className="text-muted" style={{ fontSize: 12 }}>No matching node types.</div>}
    </div>
  )
}

function NodeDrawer(props: {
  node: CanvasNode
  nodes: CanvasNode[]
  specs: Record<string, NodeSpecInfo>
  isEntrypoint: boolean
  onSetEntrypoint: () => void
  onChange: (patch: Partial<CanvasNode['data']['def']>) => void
  onRename: (newId: string) => string | null
  onConnect: (target: string, branch: string | null) => void
  onRemove: () => void
  onClose: () => void
}) {
  const { node, specs } = props
  const def = node.data.def
  const spec = specs[def.type]
  const schema = (spec?.config_schema ?? { type: 'object' }) as JSONSchema
  const sinkRules = spec?.sink_rules ?? {}
  const [newId, setNewId] = useState(def.id)
  const [renameError, setRenameError] = useState<string | null>(null)
  const [target, setTarget] = useState('')
  const [branch, setBranch] = useState<string>(def.type === 'condition' ? 'true' : '')
  return (
    <div className="flex flex-col gap-3" data-testid="node-drawer">
      <div className="flex items-center justify-between">
        <strong className="font-mono">{def.id}</strong>
        <span className="text-muted">{def.type}</span>
        <button className="btn btn-ghost btn-sm" aria-label="Close" data-testid="close-drawer" onClick={props.onClose}>×</button>
      </div>
      <div>
        <label className="form-label" htmlFor="node-rename">Node id</label>
        <div className="flex gap-1">
          <input id="node-rename" className="form-input" data-testid="node-rename-input" value={newId} onChange={e => setNewId(e.target.value)} />
          <button className="btn btn-secondary btn-sm" data-testid="node-rename-apply" onClick={() => setRenameError(props.onRename(newId))}>Rename</button>
        </div>
        {renameError && <div style={{ color: 'var(--accent-red)', fontSize: 11 }} data-testid="rename-error">{renameError}</div>}
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
      <div data-testid="connect-output">
        <div className="form-label">Connect output to (keyboard alternative to dragging)</div>
        <select className="form-select mb-1" data-testid="connect-target" value={target} onChange={e => setTarget(e.target.value)}>
          <option value="">target node…</option>
          {props.nodes.filter(n => n.id !== def.id).map(n => <option key={n.id} value={n.id}>{n.id}</option>)}
        </select>
        <select className="form-select mb-1" data-testid="connect-branch" value={branch} onChange={e => setBranch(e.target.value)}>
          {def.type === 'condition' ? (
            <>
              <option value="true">true branch</option>
              <option value="false">false branch</option>
            </>
          ) : (
            <option value="">normal output</option>
          )}
          {!['webhook_trigger', 'manual_trigger', 'error_handler'].includes(def.type) && <option value="on_error">on error</option>}
        </select>
        <button className="btn btn-secondary btn-sm" data-testid="connect-add" disabled={!target} onClick={() => props.onConnect(target, branch || null)}>
          Connect
        </button>
      </div>
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

function EdgeDrawer(props: {
  edge: CanvasEdge
  nodes: CanvasNode[]
  specs: Record<string, NodeSpecInfo>
  loops: Record<string, LoopDef>
  onMapping: (m: Record<string, string>) => void
  onBranch: (b: string | null) => void
  onLoops: (l: Record<string, LoopDef>) => void
  onRemove: () => void
  onClose: () => void
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
    <div className="flex flex-col gap-3" data-testid="edge-drawer">
      <div className="flex items-center justify-between">
        <strong className="font-mono">{edge.source} → {edge.target}</strong>
        <button className="btn btn-danger btn-sm" data-testid="remove-selected" onClick={props.onRemove}>Remove</button>
        <button className="btn btn-ghost btn-sm" aria-label="Close" data-testid="close-drawer" onClick={props.onClose}>×</button>
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
      {(src?.data.def.type === 'condition' || tgt?.data.def.type === 'error_handler') && (
        <div>
          <div className="form-label">Branch</div>
          <select className="form-select" data-testid="edge-branch" value={edge.data?.branch ?? ''} onChange={e => props.onBranch(e.target.value || null)}>
            <option value="">(choose)</option>
            {src?.data.def.type === 'condition' && <option value="true">true</option>}
            {src?.data.def.type === 'condition' && <option value="false">false</option>}
            {tgt?.data.def.type === 'error_handler' && <option value="on_error">on_error</option>}
          </select>
        </div>
      )}
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
