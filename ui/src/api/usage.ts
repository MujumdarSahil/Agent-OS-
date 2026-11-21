// src/api/usage.ts — 3.2 usage, cost and budgets (/api/v2/usage, /api/v2/budgets). Costs are estimates from the
// price table; the provider's bill is the truth.

import { api } from './client'

export interface UsageRow {
  day?: string
  flow_id?: string
  provider?: string
  model?: string
  calls: number
  errors: number
  fallbacks: number
  prompt_tokens: number
  completion_tokens: number
  cost_usd: number
  cost_unknown_calls: number
  latency_avg_ms: number | null
}

export interface UsageReport {
  group_by: string[]
  since: string
  until: string
  rows: UsageRow[]
  totals: Omit<UsageRow, 'latency_avg_ms'>
  latency: { provider: string; p50_ms: number | null; p95_ms: number | null; samples: number }[]
}

export interface BudgetStatus { name: string; limit_usd: number; spent_usd: number; pct_used: number }

export interface UsageSettings {
  run_limits: {
    max_model_calls: number
    max_total_tokens: number
    /** 3.5: python_exec / shell_exec / file_* calls per run */
    max_sandbox_calls?: number
    flows: Record<string, { max_model_calls?: number | null; max_total_tokens?: number | null; max_sandbox_calls?: number | null }>
  }
  budgets: {
    global_daily: number | null
    global_monthly: number | null
    flow_daily: Record<string, number>
    provider_monthly: Record<string, number>
  }
}

export interface BudgetsResponse {
  settings: UsageSettings
  budgets: BudgetStatus[]
  spend?: { today_usd: number; month_usd: number }
}

export const getUsage = (groupBy: string, since?: string, until?: string) =>
  api.get<UsageReport>('/v2/usage', { params: { group_by: groupBy, ...(since ? { since } : {}), ...(until ? { until } : {}) } })
    .then(r => r.data)

export const getBudgets = () => api.get<BudgetsResponse>('/v2/budgets').then(r => r.data)

export const putBudgets = (settings: UsageSettings) => api.put<BudgetsResponse>('/v2/budgets', settings).then(r => r.data)

export const usd = (v: number | null | undefined) =>
  v === null || v === undefined ? 'unknown' : v < 0.01 && v > 0 ? `$${v.toFixed(4)}` : `$${v.toFixed(2)}`
