// src/flow/canvasParts.tsx — canvas node view, edge decoration and a small rjsf field.
// All text is rendered as plain React text nodes (never HTML/markdown).

import { Handle, MarkerType, Position, type NodeProps } from '@xyflow/react'
import type { FieldProps } from '@rjsf/utils'
import type { CanvasEdge, CanvasNode } from './flowGraph'

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
}

export function FlowNodeView({ id, data, selected }: NodeProps<CanvasNode>) {
  const sideEffect = data.spec?.side_effect ?? 'unknown'
  const border = data.violated
    ? '2px solid var(--accent-red)'
    : selected
      ? '2px solid var(--border-focus)'
      : '1px solid var(--border)'
  return (
    <div
      data-testid={`flow-node-${id}`}
      data-violated={data.violated ? 'true' : 'false'}
      data-status={data.status ?? ''}
      className={data.violated ? 'flow-node violated' : 'flow-node'}
      style={{
        minWidth: 170,
        padding: '8px 10px',
        borderRadius: 8,
        background: data.violated ? 'rgba(239,68,68,0.12)' : 'var(--bg-card)',
        border,
        boxShadow: data.violated ? '0 0 0 4px rgba(239,68,68,0.25)' : 'var(--shadow-sm)',
        color: 'var(--text-primary)',
        fontSize: 12,
      }}
    >
      <Handle type="target" position={Position.Top} />
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
        <strong className="font-mono">{id}</strong>
        {data.isEntrypoint && <span title="Entrypoint" style={{ color: 'var(--accent-teal)' }}>entry</span>}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginTop: 4 }}>
        <span style={{ color: 'var(--text-secondary)' }}>{data.def.type}</span>
        <span style={{ color: SIDE_EFFECT_COLOR[sideEffect] ?? 'var(--text-muted)' }} title="side-effect class">
          {sideEffect}
        </span>
      </div>
      {data.status && (
        <div data-testid={`flow-node-status-${id}`} style={{ marginTop: 4, color: STATUS_COLOR[data.status] }}>
          ● {data.status}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}

export const nodeTypes = { flowNode: FlowNodeView }

/** Visual styling for edges: mapping label, distinct bounded-loop look, violation highlight. */
export function decorateEdge(e: CanvasEdge, selected: boolean): CanvasEdge {
  const d = e.data
  const mappingText = Object.entries(d?.arg_mapping ?? {}).map(([t, s]) => `${s}→${t}`).join(', ')
  const mapping = [d?.branch ? `[${d.branch}]` : '', mappingText].filter(Boolean).join(' ')
  const loop = d?.loop
  const stroke = d?.violated ? 'var(--accent-red)' : loop ? 'var(--accent-amber)' : selected ? 'var(--border-focus)' : 'var(--text-secondary)'
  return {
    ...e,
    className: [d?.violated ? 'violated' : '', loop ? 'loop-edge' : ''].filter(Boolean).join(' '),
    label: loop ? `loop ≤${loop.max_iterations}${mapping ? ` · ${mapping}` : ''}` : mapping || undefined,
    animated: !!loop,
    markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
    style: {
      stroke,
      strokeWidth: d?.violated ? 3 : selected ? 2 : 1.5,
      strokeDasharray: loop ? '6 4' : undefined,
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
