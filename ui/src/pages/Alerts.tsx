// src/pages/Alerts.tsx — 3.3: Watch > Alerts. Fired alerts with their delivery status per channel (sent / retrying
// / failed / no channel), acknowledge (audited), and the alert rules (admin, audited). Alert text is written by
// AgentOS from metadata only (rule, flow, run, counts, an AgentOS reason): never payload text. Fetched on open and
// after an action; no polling.

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bell, Check } from 'lucide-react'
import {
  acknowledgeAlert, errorText, listAlerts, listChannels, listRules, putRule, type Alert, type AlertRule,
} from '../api/notify'

const STATUS: Record<string, { label: string; color: string }> = {
  sent: { label: 'sent', color: 'var(--accent-teal)' },
  pending: { label: 'pending', color: 'var(--accent-amber)' },
  retrying: { label: 'retrying', color: 'var(--accent-amber)' },
  failed: { label: 'failed', color: 'var(--accent-red)' },
  partial: { label: 'partly sent', color: 'var(--accent-amber)' },
  no_channel: { label: 'no channel', color: 'var(--text-muted)' },
}

function RuleRow({ rule, channels }: { rule: AlertRule; channels: string[] }) {
  const qc = useQueryClient()
  const [draft, setDraft] = useState(rule)
  const [err, setErr] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => putRule(rule.id, { enabled: draft.enabled, channels: draft.channels, cooldown_min: draft.cooldown_min, params: draft.params }),
    onSuccess: () => { setErr(null); qc.invalidateQueries({ queryKey: ['alert-rules'] }) },
    onError: e => setErr(errorText(e)),
  })
  const dirty = JSON.stringify(draft) !== JSON.stringify(rule)
  return (
    <tr data-testid="rule-row" data-rule={rule.id}>
      <td><input type="checkbox" aria-label={`Enable ${rule.title}`} checked={draft.enabled} onChange={e => setDraft({ ...draft, enabled: e.target.checked })} /></td>
      <td><strong>{rule.title}</strong>
        {rule.id === 'approval_waiting' && (
          <div style={{ fontSize: 12 }}>after <input className="form-input" style={{ width: 64, display: 'inline-block' }} aria-label="Minutes" type="number" min={1} value={draft.params.minutes ?? 30}
            onChange={e => setDraft({ ...draft, params: { minutes: Number(e.target.value) } })} /> min</div>
        )}
      </td>
      <td style={{ fontSize: 12 }}>
        {channels.length === 0 ? <span className="text-muted">add a channel first</span> : channels.map(c => (
          <label key={c} style={{ marginRight: 8 }}>
            <input type="checkbox" aria-label={`${rule.title} to ${c}`} checked={draft.channels.includes(c)}
              onChange={e => setDraft({ ...draft, channels: e.target.checked ? [...draft.channels, c] : draft.channels.filter(x => x !== c) })} /> {c}
          </label>
        ))}
      </td>
      <td><input className="form-input" style={{ width: 70 }} type="number" min={0} aria-label={`Cooldown of ${rule.title}`} value={draft.cooldown_min}
        onChange={e => setDraft({ ...draft, cooldown_min: Number(e.target.value) })} /> min</td>
      <td>
        <button className="btn btn-secondary btn-sm" disabled={!dirty || save.isPending} data-testid={`save-rule-${rule.id}`} onClick={() => save.mutate()}>Save</button>
        {err && <div style={{ fontSize: 12, color: 'var(--accent-red)' }}>{err}</div>}
      </td>
    </tr>
  )
}

function AlertRow({ a }: { a: Alert }) {
  const qc = useQueryClient()
  const ack = useMutation({ mutationFn: () => acknowledgeAlert(a.id), onSuccess: () => {
    qc.invalidateQueries({ queryKey: ['alerts'] }); qc.invalidateQueries({ queryKey: ['overview'] })
  } })
  const s = STATUS[a.status] ?? STATUS.failed
  return (
    <tr data-testid="alert-row" data-rule={a.rule} data-status={a.status}>
      <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{new Date(a.created_at).toLocaleString()}</td>
      <td><strong>{a.title}</strong><div className="font-mono text-muted" style={{ fontSize: 11 }}>{a.target}</div></td>
      <td style={{ fontSize: 12 }}>{a.reason}{a.count > 1 && <span className="badge badge-default" style={{ marginLeft: 6 }}>×{a.count}</span>}</td>
      <td style={{ fontSize: 12 }}>
        {a.flow_id && <div className="font-mono">{a.flow_id}</div>}
        {a.run_id && a.flow_id && <Link to={`/runs/${a.run_id}`} className="font-mono" style={{ fontSize: 11 }}>{a.run_id}</Link>}
      </td>
      <td style={{ fontSize: 12 }}>
        <span data-testid="alert-status" style={{ color: s.color }}>{s.label}</span>
        {a.deliveries.map(d => (
          <div key={d.channel} className="text-muted" title={d.error ?? ''} style={{ fontSize: 11 }}>
            {d.channel}: {d.status}{d.attempts ? ` (${d.attempts})` : ''}{d.error ? ` · ${d.error}` : ''}
          </div>
        ))}
      </td>
      <td>
        {a.acknowledged ? <span className="text-muted" style={{ fontSize: 12 }}><Check size={12}/> acknowledged</span> : (
          <button className="btn btn-secondary btn-sm" data-testid="ack" onClick={() => ack.mutate()}>Acknowledge</button>
        )}
      </td>
    </tr>
  )
}

export default function Alerts() {
  const [onlyOpen, setOnlyOpen] = useState(false)
  const alerts = useQuery({ queryKey: ['alerts', onlyOpen], queryFn: () => listAlerts(onlyOpen ? { acknowledged: false } : {}) })
  const rules = useQuery({ queryKey: ['alert-rules'], queryFn: listRules })
  const channels = useQuery({ queryKey: ['notify-channels'], queryFn: listChannels })
  const names = (channels.data ?? []).map(c => c.name)
  return (
    <div data-testid="alerts-page">
      <div className="page-header flex items-center gap-3">
        <div>
          <h2>Alerts</h2>
          <p>Written by AgentOS from metadata only (never message or payload text). Nothing is sent until a rule has a channel: <Link to="/notifications">Notification channels</Link>.</p>
        </div>
        <label className="ml-auto" style={{ fontSize: 12 }}>
          <input type="checkbox" checked={onlyOpen} onChange={e => setOnlyOpen(e.target.checked)} data-testid="only-unacked" /> only unacknowledged
        </label>
      </div>
      <div className="card">
        <div className="ov-card-title"><Bell size={13}/> Fired alerts {alerts.data ? `· ${alerts.data.unacknowledged} unacknowledged` : ''}</div>
        {alerts.isLoading ? <div className="spinner" /> : !alerts.data?.alerts.length ? (
          <div className="text-muted" data-testid="alerts-empty">No alerts.</div>
        ) : (
          <div className="table-container">
            <table data-testid="alerts-table">
              <thead><tr><th>When</th><th>Rule</th><th>Reason</th><th>Flow / run</th><th>Delivery</th><th></th></tr></thead>
              <tbody>{alerts.data.alerts.map(a => <AlertRow key={a.id} a={a} />)}</tbody>
            </table>
          </div>
        )}
      </div>
      <div className="card" style={{ marginTop: 12 }}>
        <div className="ov-card-title">Rules (admin; changes are audited)</div>
        {rules.isLoading ? <div className="spinner" /> : (
          <div className="table-container">
            <table data-testid="rules-table">
              <thead><tr><th>On</th><th>Rule</th><th>Channels</th><th>Cooldown</th><th></th></tr></thead>
              <tbody>{(rules.data ?? []).map(r => <RuleRow key={`${r.id}:${JSON.stringify(r)}`} rule={r} channels={names} />)}</tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
