// src/flow/BuilderPreview.tsx — 4.0 "Describe it" / "Edit with AI": read-only preview canvas coloured by label,
// explanation, security summary, check result with one-click fixes, and the flow diff. Model text is shown as
// plain text only (React escapes it; never rendered as HTML or markdown).

import { useMemo } from 'react'
import { Background, ReactFlow, ReactFlowProvider } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { BuilderFlow, CheckResult, Explanation, FlowDiff, OneClickFix } from '../api/builder'
import type { FlowRecord, NodeSpecInfo } from '../api/flows'
import { autoLayout } from './builderModel'
import { BuilderActions, decorateEdge, nodeTypes } from './canvasParts'
import { toCanvas } from './flowGraph'

export function asRecord(f: BuilderFlow): FlowRecord {
  return { ...f, status: 'draft', version: null }
}

const READ_ONLY_ACTIONS = { onAddNext: () => undefined, readOnly: true }

export function PreviewCanvas({ flow, specs, explanation, violated, height = 320 }: {
  flow: BuilderFlow
  specs: Record<string, NodeSpecInfo>
  explanation?: Explanation
  violated?: Set<string>
  height?: number
}) {
  const { nodes, edges } = useMemo(() => {
    const c = toCanvas(asRecord(flow), specs)
    const trust = explanation?.security.node_trust ?? {}
    const laid = autoLayout(c.nodes, c.edges).map(n => ({
      ...n,
      draggable: false,
      connectable: false,
      data: { ...n.data, trust: trust[n.id], violated: violated?.has(n.id) ?? false },
    }))
    return { nodes: laid, edges: c.edges.map(e => decorateEdge(e, false)) }
  }, [flow, specs, explanation, violated])
  return (
    <div className="card" style={{ height, padding: 0 }} data-testid="preview-canvas">
      <ReactFlowProvider>
        <BuilderActions.Provider value={READ_ONLY_ACTIONS}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.1, maxZoom: 1 }}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            minZoom={0.2}
            colorMode="dark"
          >
            <Background />
          </ReactFlow>
        </BuilderActions.Provider>
      </ReactFlowProvider>
    </div>
  )
}

export function ExplanationView({ explanation }: { explanation: Explanation }) {
  const s = explanation.security
  return (
    <div className="card" style={{ padding: 12 }} data-testid="builder-explanation">
      <h3 style={{ marginTop: 0 }}>What this flow does</h3>
      <ol style={{ margin: '0 0 8px 18px' }}>
        {explanation.steps.map(st => (
          <li key={st.node_id}><span className="font-mono">{st.node_id}</span>: {st.text}</li>
        ))}
      </ol>
      {explanation.model_summary && (
        <p className="text-muted" data-testid="model-summary" style={{ fontSize: 12 }}>
          Model summary (unverified): {explanation.model_summary}
        </p>
      )}
      <h3>Security summary</h3>
      <ul style={{ margin: '0 0 0 18px' }} data-testid="security-summary">
        <li>
          UNTRUSTED inputs:{' '}
          {s.untrusted_inputs.length ? s.untrusted_inputs.map(u => `${u.node_id} (${u.what})`).join(', ') : 'none'}
        </li>
        <li>
          Untrusted data reaches:{' '}
          {s.untrusted_flows.length ? s.untrusted_flows.map(f => `${f.sink}.${f.arg} (from ${f.from.join(', ') || '?'})`).join('; ') : 'no sink argument'}
        </li>
        <li>Pinned: {s.pinned.length ? s.pinned.map(p => `${p.node_id}.${p.arg} = ${String(p.value)}`).join('; ') : 'nothing'}</li>
        <li>Needs approval: {s.approvals.length ? s.approvals.map(a => `${a.sink} (${a.args.join(', ')}) via ${a.node_id}`).join('; ') : 'no step'}</li>
        <li>
          Sends outside:{' '}
          {s.external_sinks.length
            ? s.external_sinks.map(x => `${x.node_id} (${x.type}${x.recipient ? ` -> ${String(x.recipient)}` : ''})`).join('; ')
            : 'nothing'}
        </li>
      </ul>
    </div>
  )
}

export function CheckView({ check, onFix, busy }: { check: CheckResult; onFix?: (f: OneClickFix) => void; busy?: boolean }) {
  const color = check.status === 'failing' ? 'var(--accent-red)' : 'var(--accent-green)'
  const label = { passed: 'Passed the security check', fixed: 'Passed after automatic repair', failing: 'Still failing the security check' }[check.status]
  return (
    <div className="card" style={{ padding: 12 }} data-testid="builder-check" data-status={check.status}>
      <h3 style={{ marginTop: 0, color }}>{label}</h3>
      {check.fixed.length > 0 && (
        <ul data-testid="repair-rounds" style={{ margin: '0 0 8px 18px' }}>
          {check.fixed.map(r => (
            <li key={r.round}>
              Round {r.round}: {r.accepted ? `fixed ${r.resolved?.join(', ') || 'nothing'}` : 'not accepted'} ({r.why})
            </li>
          ))}
        </ul>
      )}
      {check.violations.length > 0 && (
        <ul data-testid="builder-violations" style={{ margin: '0 0 8px 18px' }}>
          {check.violations.map((v, i) => {
            const fixes = check.fixes.filter(f => f.node_id === v.node_id && f.target_arg === v.target_arg)
            return (
              <li key={i} data-testid={`violation-${v.node_id}-${v.target_arg}`}>
                <span className="font-mono">[{v.node_id}:{v.target_arg}]</span> {v.reason}
                <div className="flex gap-2 flex-wrap" style={{ marginTop: 4 }}>
                  {fixes.map(f => (
                    <button
                      key={f.id}
                      className="btn btn-secondary btn-sm"
                      data-testid={`fix-${f.kind}-${f.node_id}`}
                      disabled={busy || !onFix}
                      onClick={() => onFix?.(f)}
                      title={f.passes ? 'After this fix the draft passes the check' : 'This fix alone does not make the draft pass'}
                    >
                      {f.label}{f.passes ? ' ✓' : ''}
                    </button>
                  ))}
                </div>
              </li>
            )
          })}
        </ul>
      )}
      {check.refusals.length > 0 && (
        <ul data-testid="builder-refusals" style={{ margin: '0 0 0 18px', color: 'var(--accent-red)' }}>
          {check.refusals.map((r, i) => <li key={i}>{r}</li>)}
        </ul>
      )}
    </div>
  )
}

export function DiffView({ diff }: { diff: FlowDiff }) {
  if (diff.empty) return <div className="text-muted" data-testid="flow-diff">No changes proposed.</div>
  const row = (label: string, items: string[], color: string, kind: string) =>
    items.length > 0 && (
      <li>
        {label}:{' '}
        {items.map(x => (
          <span key={x} className="font-mono" data-testid={`diff-${kind}-${x}`} style={{ color, marginRight: 8 }}>{x}</span>
        ))}
      </li>
    )
  return (
    <ul data-testid="flow-diff" style={{ margin: '0 0 0 18px' }}>
      {row('Nodes added', diff.nodes_added, 'var(--accent-green)', 'node-added')}
      {row('Nodes removed', diff.nodes_removed, 'var(--accent-red)', 'node-removed')}
      {row('Nodes changed', diff.nodes_changed.map(c => `${c.id} (${c.fields.join(', ')})`), 'var(--accent-amber, #f59e0b)', 'node-changed')}
      {row('Edges added', diff.edges_added, 'var(--accent-green)', 'edge-added')}
      {row('Edges removed', diff.edges_removed, 'var(--accent-red)', 'edge-removed')}
      {row('Edges changed', diff.edges_changed.map(c => c.key), 'var(--accent-amber, #f59e0b)', 'edge-changed')}
      {diff.entrypoint_changed && <li>Entrypoint changed</li>}
    </ul>
  )
}
