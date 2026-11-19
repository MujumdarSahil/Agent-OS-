// src/api/audit.ts — 3.1 audit log (/api/v2/audit). Read-only: there is no API to change audit entries.

import { api } from './client'

export interface AuditEntry {
  seq: number
  ts: string
  actor: string
  source: 'ui' | 'api' | 'cli' | 'system' | 'webhook' | 'scheduler'
  action: string
  target: { type: string; id: string }
  outcome: 'ok' | 'refused' | 'failed'
  details: Record<string, unknown>
  prev_hash: string
  hash: string
}

export interface AuditPage {
  entries: AuditEntry[]
  next_before_seq: number | null
}

export interface AuditVerify {
  status: 'ok' | 'broken' | 'empty'
  entries_checked: number
  first_broken_seq: number | null
  reason: string | null
  partial_tail_ignored?: boolean
}

export interface AuditFilters {
  action?: string
  actor?: string
  target_type?: string
  target_id?: string
  outcome?: string
  since?: string
  until?: string
  before_seq?: number
  limit?: number
}

export const listAudit = (filters: AuditFilters) => {
  const params = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined && v !== ''))
  return api.get<AuditPage>('/v2/audit', { params }).then(r => r.data)
}

export const verifyAudit = () => api.get<AuditVerify>('/v2/audit/verify').then(r => r.data)

/** The chain as JSONL text, exactly as stored (saved by the browser as agentos-audit.jsonl). */
export const exportAudit = () =>
  api.get<string>('/v2/audit/export', { responseType: 'text', transformResponse: r => r }).then(r => r.data)
