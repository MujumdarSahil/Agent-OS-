// src/flow/ExtractionConfig.tsx — 2.5b quarantined extraction: the config form (field builder with the
// fixed constrained types only; there is no free-text type and no user regex) and the label helpers the
// run panel uses to show "trusted · declassified by extraction". The server stays authoritative: the
// JSON Schema and the publish-time analyzer check every config again.

import { useState } from 'react'
import type { LabelInfo } from './runModel'

export type FieldType = 'enum' | 'bool' | 'int_range' | 'pattern' | 'allowlist'
export interface ExtractionField {
  name: string
  type: FieldType
  values?: string[]
  min?: number
  max?: number
  pattern?: string
  allowlist_name?: string
}
export interface ExtractionConfig {
  input?: string
  fields: ExtractionField[]
  on_invalid?: 'fail' | 'default'
  defaults?: Record<string, string | number | boolean>
  model?: string
  max_input_chars?: number
}

export const FIELD_TYPES: FieldType[] = ['enum', 'bool', 'int_range', 'pattern', 'allowlist']
export const PATTERNS = ['iso_date', 'sha256', 'ticket_id', 'uuid'] as const
const ENUM_VALUE_RE = /^[A-Za-z0-9 _.-]{1,64}$/
const MAX_FIELDS = 10
export const MARKER_PREFIX = 'declassified:quarantined_extraction:'

export function defaultExtractionConfig(): ExtractionConfig {
  return { fields: [{ name: 'category', type: 'enum', values: ['a', 'b'] }] }
}

/** A field with its type-specific keys only (the server rejects any extra key). */
function retype(f: ExtractionField, type: FieldType): ExtractionField {
  switch (type) {
    case 'enum': return { name: f.name, type, values: f.values?.length ? f.values : ['a', 'b'] }
    case 'bool': return { name: f.name, type }
    case 'int_range': return { name: f.name, type, min: f.min ?? 0, max: f.max ?? 10 }
    case 'pattern': return { name: f.name, type, pattern: f.pattern ?? 'ticket_id' }
    case 'allowlist': return { name: f.name, type, allowlist_name: f.allowlist_name ?? '' }
  }
}

export function ExtractionConfigForm({ config, allowlistNames, models, onChange }: {
  config: Partial<ExtractionConfig>
  allowlistNames: string[]
  models?: string[]
  onChange: (c: ExtractionConfig) => void
}) {
  const cfg: ExtractionConfig = { ...config, fields: config.fields ?? [] }
  const set = (patch: Partial<ExtractionConfig>) => {
    const next: ExtractionConfig = { ...cfg, ...patch }
    for (const k of Object.keys(next) as (keyof ExtractionConfig)[]) if (next[k] === undefined) delete next[k]
    onChange(next)
  }
  const setField = (i: number, f: ExtractionField) => set({ fields: cfg.fields.map((x, j) => (j === i ? f : x)) })
  const usedNames = new Set(cfg.fields.map(f => f.name))
  const newName = () => { let n = cfg.fields.length + 1; while (usedNames.has(`field_${n}`)) n += 1; return `field_${n}` }

  return (
    <div data-testid="extraction-config" className="flex flex-col gap-2" style={{ fontSize: 12 }}>
      <div className="text-muted" style={{ fontSize: 11 }}>
        Declassifies untrusted text: the model may only fill these constrained fields; every value is validated and
        only validated values leave the node (labelled trusted). There is no free-text field.
      </div>
      {cfg.fields.map((f, i) => (
        <FieldEditor key={i} field={f} allowlistNames={allowlistNames} onChange={nf => setField(i, nf)}
          onRemove={cfg.fields.length > 1 ? () => set({ fields: cfg.fields.filter((_, j) => j !== i) }) : undefined} />
      ))}
      <button className="btn btn-secondary btn-sm" data-testid="extraction-add-field" disabled={cfg.fields.length >= MAX_FIELDS}
        onClick={() => set({ fields: [...cfg.fields, { name: newName(), type: 'bool' }] })}>
        Add field ({cfg.fields.length}/{MAX_FIELDS})
      </button>
      <label className="form-label" htmlFor="qx-on-invalid">On invalid model output</label>
      <select id="qx-on-invalid" className="form-select" data-testid="extraction-on-invalid" value={cfg.on_invalid ?? 'fail'}
        onChange={e => set({ on_invalid: e.target.value as 'fail' | 'default', defaults: e.target.value === 'default' ? cfg.defaults ?? {} : undefined })}>
        <option value="fail">fail the node</option>
        <option value="default">use the default values below</option>
      </select>
      {cfg.on_invalid === 'default' && cfg.fields.map(f => (
        <DefaultInput key={f.name} field={f} value={cfg.defaults?.[f.name]}
          onChange={v => set({ defaults: { ...(cfg.defaults ?? {}), [f.name]: v } })} />
      ))}
      <label className="form-label" htmlFor="qx-max-input">Max input characters (longer text is truncated)</label>
      <input id="qx-max-input" className="form-input" type="number" min={1} max={100000} data-testid="extraction-max-input"
        value={cfg.max_input_chars ?? 20000}
        onChange={e => set({ max_input_chars: Math.min(100000, Math.max(1, Math.trunc(Number(e.target.value) || 1))) })} />
      <label className="form-label" htmlFor="qx-model">Model (optional)</label>
      <select id="qx-model" className="form-select" data-testid="extraction-model" value={cfg.model ?? ''}
        onChange={e => set({ model: e.target.value || undefined })}>
        <option value="">default router chain</option>
        {(models ?? []).map(m => <option key={m} value={m}>{m}</option>)}
      </select>
    </div>
  )
}

/** One constrained field (type + its constraint). Shared by the extraction field list and the validator form:
 *  both nodes accept exactly the same types and limits (one implementation server side, too). */
export function FieldEditor({ field: f, allowlistNames, onChange, onRemove, nameLabel = 'Field name' }: {
  field: ExtractionField
  allowlistNames: string[]
  onChange: (f: ExtractionField) => void
  onRemove?: () => void
  nameLabel?: string
}) {
  return (
    <div className="card" style={{ padding: 6 }} data-testid="extraction-field" data-field={f.name}>
      <div className="flex gap-1 items-center">
        <input className="form-input" aria-label={nameLabel} data-testid="extraction-field-name" value={f.name}
          onChange={e => onChange({ ...f, name: e.target.value })} style={{ flex: 1 }} />
        <select className="form-select" aria-label="Field type" data-testid="extraction-field-type" value={f.type}
          onChange={e => onChange(retype(f, e.target.value as FieldType))} style={{ width: 110 }}>
          {!FIELD_TYPES.includes(f.type) && <option value={f.type}>{String(f.type)} (not allowed)</option>}
          {FIELD_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        {onRemove !== undefined && (
          <button className="btn btn-ghost btn-sm" aria-label={`Remove field ${f.name}`} data-testid="extraction-field-remove"
            onClick={onRemove}>×</button>
        )}
      </div>
      {f.type === 'enum' && <EnumChips values={f.values ?? []} onChange={values => onChange({ ...f, values })} />}
      {f.type === 'int_range' && (
        <div className="flex gap-1 mt-1">
          <input className="form-input" type="number" aria-label="Minimum" data-testid="extraction-min" value={f.min ?? 0}
            onChange={e => onChange({ ...f, min: Math.trunc(Number(e.target.value)) })} />
          <input className="form-input" type="number" aria-label="Maximum" data-testid="extraction-max" value={f.max ?? 0}
            onChange={e => onChange({ ...f, max: Math.trunc(Number(e.target.value)) })} />
        </div>
      )}
      {f.type === 'pattern' && (
        <select className="form-select mt-1" aria-label="Pattern" data-testid="extraction-pattern" value={f.pattern}
          onChange={e => onChange({ ...f, pattern: e.target.value })}>
          {PATTERNS.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
      )}
      {f.type === 'allowlist' && (
        <select className="form-select mt-1" aria-label="Allowlist" data-testid="extraction-allowlist" value={f.allowlist_name ?? ''}
          onChange={e => onChange({ ...f, allowlist_name: e.target.value })}>
          <option value="">{allowlistNames.length ? 'admin allowlist…' : 'no admin allowlists configured'}</option>
          {allowlistNames.map(n => <option key={n} value={n}>{n}</option>)}
        </select>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------- validator (2.5b hardening)

/** Legacy validator names still accepted where safe: allowlist_match = allowlist, bounded_number = int_range. */
const LEGACY_VALIDATOR_TYPES: Record<string, FieldType> = { allowlist_match: 'allowlist', bounded_number: 'int_range' }

export interface ValidatorConfig {
  field: string
  field_type: string
  values?: string[]
  min?: number
  max?: number
  pattern?: string
  allowlist_name?: string
}

export function validatorToField(c: Partial<ValidatorConfig>): ExtractionField {
  const raw = c.field_type ?? 'enum'
  const type = (LEGACY_VALIDATOR_TYPES[raw] ?? raw) as FieldType
  const f: ExtractionField = { name: c.field ?? 'data', type }
  if (c.values !== undefined) f.values = c.values
  if (c.min !== undefined) f.min = c.min
  if (c.max !== undefined) f.max = c.max
  if (c.pattern !== undefined) f.pattern = c.pattern
  if (c.allowlist_name !== undefined) f.allowlist_name = c.allowlist_name
  return f
}

export function fieldToValidator(f: ExtractionField): ValidatorConfig {
  const { name, type, ...rest } = f
  return { field: name, field_type: type, ...rest }
}

export function defaultValidatorConfig(): ValidatorConfig {
  return { field: 'data', field_type: 'enum', values: ['a', 'b'] }
}

/** Validator config form: ONE constrained field, same editor as extraction. Legacy names are shown as their new
 *  type and saved with the new name once edited; unknown or incomplete configs are refused at publish. */
export function ValidatorConfigForm({ config, allowlistNames, onChange }: {
  config: Partial<ValidatorConfig>
  allowlistNames: string[]
  onChange: (c: ValidatorConfig) => void
}) {
  const field = validatorToField(config)
  return (
    <div data-testid="validator-config" className="flex flex-col gap-2" style={{ fontSize: 12 }}>
      <div className="text-muted" style={{ fontSize: 11 }}>
        Declassifies one input value: only a value that passes this constraint leaves the node (labelled trusted, same
        confidentiality). There is no free-text type. The input still chooses WHICH allowed value comes out.
      </div>
      <FieldEditor field={field} allowlistNames={allowlistNames} nameLabel="Input field"
        onChange={f => onChange(fieldToValidator(f))} />
    </div>
  )
}

function EnumChips({ values, onChange }: { values: string[]; onChange: (v: string[]) => void }) {
  const [draft, setDraft] = useState('')
  const valid = ENUM_VALUE_RE.test(draft) && !values.includes(draft)
  return (
    <div className="mt-1" data-testid="extraction-enum">
      <div className="flex gap-1" style={{ flexWrap: 'wrap' }}>
        {values.map(v => (
          <span key={v} className="badge badge-default" data-testid="extraction-enum-chip">
            {v}
            <button className="btn btn-ghost btn-sm" aria-label={`Remove value ${v}`} style={{ padding: '0 2px' }}
              onClick={() => onChange(values.filter(x => x !== v))}>×</button>
          </span>
        ))}
      </div>
      <div className="flex gap-1 mt-1">
        <input className="form-input" aria-label="New allowed value" data-testid="extraction-enum-new" value={draft}
          placeholder="allowed value (letters, digits, space _ . -)" onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && valid) { onChange([...values, draft]); setDraft('') } }} />
        <button className="btn btn-secondary btn-sm" data-testid="extraction-enum-add" disabled={!valid || values.length >= 50}
          onClick={() => { onChange([...values, draft]); setDraft('') }}>Add</button>
      </div>
      {values.length < 2 && <div style={{ color: 'var(--accent-red)', fontSize: 11 }}>An enum needs at least 2 values.</div>}
    </div>
  )
}

function DefaultInput({ field, value, onChange }: {
  field: ExtractionField; value: string | number | boolean | undefined; onChange: (v: string | number | boolean) => void
}) {
  const label = `Default for ${field.name}`
  const common = { 'aria-label': label, 'data-testid': `extraction-default-${field.name}` }
  return (
    <div className="flex gap-1 items-center">
      <span className="font-mono" style={{ width: 110 }}>{field.name}</span>
      {field.type === 'bool' ? (
        <input type="checkbox" {...common} checked={value === true} onChange={e => onChange(e.target.checked)} />
      ) : field.type === 'enum' ? (
        <select className="form-select" {...common} value={typeof value === 'string' ? value : ''} onChange={e => onChange(e.target.value)}>
          <option value="">choose…</option>
          {(field.values ?? []).map(v => <option key={v} value={v}>{v}</option>)}
        </select>
      ) : field.type === 'int_range' ? (
        <input className="form-input" type="number" {...common} value={typeof value === 'number' ? value : ''}
          onChange={e => onChange(Math.trunc(Number(e.target.value)))} />
      ) : (
        <input className="form-input" {...common} value={typeof value === 'string' ? value : ''} onChange={e => onChange(e.target.value)} />
      )}
    </div>
  )
}

export const VALIDATOR_MARKER_PREFIX = 'declassified:validator:'

/** Nodes that declassified this label (validator or quarantined extraction), from the markers in its sources. */
export function declassifiedBy(label?: LabelInfo): { kind: 'extraction' | 'validator'; node: string }[] {
  const out = new Map<string, { kind: 'extraction' | 'validator'; node: string }>()
  for (const s of label?.sources ?? []) {
    const hit = s.startsWith(MARKER_PREFIX) ? { kind: 'extraction' as const, rest: s.slice(MARKER_PREFIX.length) }
      : s.startsWith(VALIDATOR_MARKER_PREFIX) ? { kind: 'validator' as const, rest: s.slice(VALIDATOR_MARKER_PREFIX.length) }
      : null
    if (hit) {
      const node = hit.rest.split(':')[0]
      out.set(`${hit.kind}:${node}`, { kind: hit.kind, node })
    }
  }
  return [...out.values()]
}

/** "declassified by extraction (extract)", "declassified by validator (val)"; empty when not declassified. */
export function declassificationText(label?: LabelInfo): string {
  const by = declassifiedBy(label)
  const kinds = [...new Set(by.map(b => b.kind))]
  return kinds.map(k => `declassified by ${k} (${by.filter(b => b.kind === k).map(b => b.node).join(', ')})`).join('; ')
}

/** The sources to show for a label, without the declassification markers. */
export function visibleSources(label?: LabelInfo): string[] {
  return (label?.sources ?? []).filter(s => !s.startsWith(MARKER_PREFIX) && !s.startsWith(VALIDATOR_MARKER_PREFIX))
}
