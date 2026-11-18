// src/flow/canvasParts.tsx — canvas node cards (left -> right), edge decoration and a small rjsf field.
// All text is rendered as plain React text nodes (never HTML/markdown).

import { createContext, useContext } from 'react'
import { Handle, MarkerType, Position, type NodeProps } from '@xyflow/react'
import type { FieldProps } from '@rjsf/utils'
import { AlertTriangle, Bot, GitBranch, Send, ShieldCheck, UserCheck, Zap, type LucideIcon } from 'lucide-react'
import type { CanvasEdge, CanvasNode } from './flowGraph'
import { categoryOf, configSummary, isTrigger, type NodeCategory } from './builderModel'

const SIDE_EFFECT_COLOR: Record<string, string> = {
  none: 'var(--text-muted)',
  read: 'var(--accent-blue)',
  write: 'var(--accent-amber)',
  external_send: 'var(--accent-red)',
  destructive: 'var(--accent-red)',
}

const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--text-muted)',
  running: 'var(--accent-blue)',
  waiting: 'var(--accent-amber)',
  succeeded: 'var(--accent-green)',
  failed: 'var(--accent-red)',
  blocked: 'var(--accent-red)',
  skipped: 'var(--text-muted)',
}

export const CATEGORY_STYLE: Record<NodeCategory, { color: string; icon: LucideIcon; label: string }> = {
  trigger: { color: '#14b8a6', icon: Zap, label: 'Trigger' },
  ai: { color: '#8b5cf6', icon: Bot, label: 'AI' },
  logic: { color: '#3b82f6', icon: GitBranch, label: 'Logic' },
  action: { color: '#f97316', icon: Send, label: 'Action' },
  human: { color: '#eab308', icon: UserCheck, label: 'Human' },
  security: { color: '#22c55e', icon: ShieldCheck, label: 'Security' },
  error: { color: '#ef4444', icon: AlertTriangle, label: 'Error' },
}

/** Callbacks the editor provides to node cards (kept out of node data so it stays serialisable). */
export const BuilderActions = createContext<{ onAddNext: (nodeId: string, branch: string | null) => void; vertical?: boolean }>({
  onAddNext: () => undefined,
  vertical: false,
})

/** `top` is the position along the output side: right edge (left-to-right) or bottom edge (top-to-bottom). */
function PlusButton({ nodeId, branch, top }: { nodeId: string; branch: string | null; top: string }) {
  const { onAddNext, vertical } = useContext(BuilderActions)
  const place = vertical
    ? { left: top === '35%' ? '30%' : top === '72%' ? '70%' : '50%', bottom: -30, transform: 'translateX(-50%)' }
    : { right: -34, top, transform: 'translateY(-50%)' }
  return (
    <button
      type="button"
      className="nodrag nopan"
      data-testid={`add-next-${nodeId}${branch ? `-${branch}` : ''}`}
      aria-label={`Add a node after ${nodeId}${branch ? ` (${branch})` : ''}`}
      title="Add and connect the next node"
      onClick={e => {
        e.stopPropagation()
        onAddNext(nodeId, branch)
      }}
      style={{
        position: 'absolute', ...place, width: 20, height: 20,
        borderRadius: 10, border: '1px solid var(--border)', background: 'var(--bg-card)',
        color: 'var(--text-secondary)', fontSize: 14, lineHeight: '16px', padding: 0, cursor: 'pointer',
      }}
    >
      +
    </button>
  )
}

export function FlowNodeView({ id, data, selected }: NodeProps<CanvasNode>) {
  const type = data.def.type
  const category = categoryOf(type)
  const style = CATEGORY_STYLE[category]
  const Icon = style.icon
  const sideEffect = data.spec?.side_effect ?? 'unknown'
  const summary = configSummary({ id, data } as CanvasNode)
  const border = data.violated ? '2px solid var(--accent-red)' : selected ? '2px solid var(--border-focus)' : '1px solid var(--border)'
  const isCondition = type === 'condition'
  const canFail = !isTrigger(type) && type !== 'error_handler'
  const { vertical } = useContext(BuilderActions)
  const inPos = vertical ? Position.Top : Position.Left
  const outPos = vertical ? Position.Bottom : Position.Right
  const branchStyle = (at: '35%' | '72%', color: string) =>
    vertical ? { left: at === '35%' ? '30%' : '70%', background: color } : { top: at, background: color }
  const branchLabel = (at: '35%' | '72%') =>
    vertical
      ? { position: 'absolute' as const, bottom: 2, left: at === '35%' ? '30%' : '70%', transform: 'translateX(-50%)' }
      : { position: 'absolute' as const, right: 6, top: at, transform: 'translateY(-50%)' }
  return (
    <div
      data-testid={`flow-node-${id}`}
      data-violated={data.violated ? 'true' : 'false'}
      data-status={data.status ?? ''}
      data-category={category}
      className={data.violated ? 'flow-node violated' : 'flow-node'}
      style={{
        position: 'relative', width: 230, padding: '8px 10px 8px 12px', borderRadius: 8,
        background: data.violated ? 'rgba(239,68,68,0.12)' : 'var(--bg-card)', border,
        borderLeft: `5px solid ${data.violated ? 'var(--accent-red)' : style.color}`,
        boxShadow: data.violated ? '0 0 0 4px rgba(239,68,68,0.25)' : 'var(--shadow-sm)',
        color: 'var(--text-primary)', fontSize: 12,
      }}
    >
      {!isTrigger(type) && <Handle type="target" position={inPos} />}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <Icon size={14} color={style.color} aria-label={style.label} />
        <strong className="font-mono truncate" style={{ flex: 1 }}>{id}</strong>
        {data.isEntrypoint && <span title="Entrypoint" style={{ color: 'var(--accent-teal)', fontSize: 10 }}>entry</span>}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginTop: 3 }}>
        <span style={{ color: 'var(--text-secondary)' }}>{type}</span>
        {sideEffect !== 'none' && (
          <span
            data-testid={`side-effect-${id}`}
            style={{ color: SIDE_EFFECT_COLOR[sideEffect] ?? 'var(--text-muted)', fontSize: 10, border: '1px solid currentColor', borderRadius: 4, padding: '0 4px' }}
            title="side-effect class"
          >
            {sideEffect}
          </span>
        )}
      </div>
      {summary && (
        <div data-testid={`node-summary-${id}`} className="truncate" style={{ marginTop: 3, color: 'var(--text-muted)', fontSize: 11 }}>
          {summary}
        </div>
      )}
      {data.status && (
        <div data-testid={`flow-node-status-${id}`} style={{ marginTop: 3, color: STATUS_COLOR[data.status] }}>
          ● {data.status}
        </div>
      )}
      {isCondition ? (
        <>
          <Handle type="source" id="true" position={outPos} style={branchStyle('35%', 'var(--accent-green)')} />
          <span style={{ ...branchLabel('35%'), fontSize: 9, color: 'var(--accent-green)' }}>true</span>
          <PlusButton nodeId={id} branch="true" top="35%" />
          <Handle type="source" id="false" position={outPos} style={branchStyle('72%', 'var(--text-muted)')} />
          <span style={{ ...branchLabel('72%'), fontSize: 9, color: 'var(--text-muted)' }}>false</span>
          <PlusButton nodeId={id} branch="false" top="72%" />
        </>
      ) : (
        <>
          <Handle type="source" position={outPos} />
          <PlusButton nodeId={id} branch={null} top="50%" />
        </>
      )}
      {canFail && (
        <Handle
          type="source"
          id="on_error"
          position={vertical ? Position.Right : Position.Bottom}
          title="on error -> error_handler"
          style={vertical ? { top: '80%', background: 'var(--accent-red)', width: 9, height: 9 } : { left: '85%', background: 'var(--accent-red)', width: 9, height: 9 }}
        />
      )}
    </div>
  )
}

export const nodeTypes = { flowNode: FlowNodeView }

/** Visual styling for edges: mapping label, branch, distinct loop/on_error look, violation highlight. */
export function decorateEdge(e: CanvasEdge, selected: boolean): CanvasEdge {
  const d = e.data
  const mappingText = Object.entries(d?.arg_mapping ?? {}).map(([t, s]) => `${s}→${t}`).join(', ')
  const mapping = [d?.branch ? `[${d.branch}]` : '', mappingText].filter(Boolean).join(' ')
  const loop = d?.loop
  const onError = d?.branch === 'on_error'
  const stroke = d?.violated
    ? 'var(--accent-red)'
    : onError
      ? '#ef4444'
      : loop
        ? 'var(--accent-amber)'
        : selected
          ? 'var(--border-focus)'
          : 'var(--text-secondary)'
  return {
    ...e,
    className: [d?.violated ? 'violated' : '', loop ? 'loop-edge' : '', onError ? 'error-edge' : ''].filter(Boolean).join(' '),
    label: loop ? `loop ≤${loop.max_iterations}${mapping ? ` · ${mapping}` : ''}` : mapping || undefined,
    animated: !!loop,
    // Dark-theme label chip sized to its text (SVG text, so it is never truncated).
    labelStyle: { fill: 'var(--text-primary)', fontSize: 11, fontFamily: 'ui-monospace, monospace' },
    labelShowBg: true,
    labelBgStyle: { fill: 'var(--bg-surface)', stroke: d?.violated ? 'var(--accent-red)' : 'var(--border)', strokeWidth: 1 },
    labelBgPadding: [6, 3] as [number, number],
    labelBgBorderRadius: 4,
    markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
    style: {
      stroke,
      strokeWidth: d?.violated ? 3 : selected ? 2 : 1.5,
      strokeDasharray: loop || onError ? '6 4' : undefined,
    },
  }
}

/** rjsf field for `array<string>` config values (e.g. agent tools): a comma-separated text input. */
export function StringListField(props: FieldProps) {
  const value = Array.isArray(props.formData) ? (props.formData as string[]).join(', ') : ''
  const id = props.fieldPathId.$id
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {props.schema.title ?? props.name} (comma-separated)
      </label>
      <input
        id={id}
        className="form-input"
        defaultValue={value}
        onBlur={ev => {
          const list = ev.target.value.split(',').map(s => s.trim()).filter(Boolean)
          props.onChange(list, props.fieldPathId.path)
        }}
      />
    </div>
  )
}
