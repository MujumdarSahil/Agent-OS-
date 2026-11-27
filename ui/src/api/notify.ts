// src/api/notify.ts — 3.3 notification channels, alert rules and alerts (/api/v2/notify/*, /api/v2/alerts*), and
// the per-provider billing plan. Secrets are write-only: responses only say password_set / webhook_set.

import { api } from './client'

export interface EmailChannel {
  type: 'email'
  name: string
  enabled: boolean
  host: string
  port: number
  security: 'starttls' | 'ssl' | 'none'
  allow_insecure_local: boolean
  username: string | null
  password_secret: string | null
  password_set?: boolean
  from_address: string
  allowed_recipient_domains: string[]
  alert_recipients: string[]
  use_for_flows: boolean
}

export interface SlackChannel {
  type: 'slack'
  name: string
  enabled: boolean
  webhook_secret: string | null
  webhook_set?: boolean
  display_channel: string
  internal: boolean
}

export type Channel = EmailChannel | SlackChannel

export interface AlertRule {
  id: string
  title: string
  enabled: boolean
  channels: string[]
  cooldown_min: number
  params: { minutes?: number }
}

export interface Delivery { channel: string; status: string; attempts: number; error: string | null; sent_at: string | null }

export interface Alert {
  id: string
  rule: string
  title: string
  target: string
  flow_id: string | null
  run_id: string | null
  reason: string
  count: number
  created_at: string
  last_seen: string
  link: string | null
  acknowledged: boolean
  ack_at: string | null
  status: 'sent' | 'pending' | 'retrying' | 'failed' | 'partial' | 'no_channel'
  deliveries: Delivery[]
}

export const listChannels = () => api.get<{ channels: Channel[] }>('/v2/notify/channels').then(r => r.data.channels)
export const createChannel = (body: Record<string, unknown>) => api.post<Channel>('/v2/notify/channels', body).then(r => r.data)
export const updateChannel = (name: string, body: Record<string, unknown>) =>
  api.put<Channel>(`/v2/notify/channels/${encodeURIComponent(name)}`, body).then(r => r.data)
export const deleteChannel = (name: string) => api.delete(`/v2/notify/channels/${encodeURIComponent(name)}`).then(r => r.data)
export const testChannel = (name: string) =>
  api.post<{ ok: boolean; error?: string }>(`/v2/notify/channels/${encodeURIComponent(name)}/test`).then(r => r.data)

export const listRules = () => api.get<{ rules: AlertRule[] }>('/v2/alerts/rules').then(r => r.data.rules)
export const putRule = (id: string, body: Partial<AlertRule>) => api.put<AlertRule>(`/v2/alerts/rules/${id}`, body).then(r => r.data)
export const listAlerts = (params: { rule?: string; acknowledged?: boolean; status?: string } = {}) =>
  api.get<{ alerts: Alert[]; unacknowledged: number }>('/v2/alerts', { params }).then(r => r.data)
export const acknowledgeAlert = (id: string) => api.post<Alert>(`/v2/alerts/${id}/acknowledge`).then(r => r.data)

export const putBillingPlan = (provider: string, plan: 'free' | 'paid' | 'default') =>
  api.put<{ name: string; billing_plan: string | null }>(`/v2/providers/${encodeURIComponent(provider)}/billing-plan`, { plan })
    .then(r => r.data)

export const errorText = (e: unknown): string => {
  const d = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : 'Request failed'
}
