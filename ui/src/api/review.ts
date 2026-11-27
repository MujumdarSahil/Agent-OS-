// src/api/review.ts — 3.6a: Human Review Queue API client
import { api } from './client'

export type ReviewStatus = 'pending' | 'reviewed' | 'skipped'
export type ReviewVerdict = 'good' | 'bad'
export type ReviewReason = 'wrong' | 'incomplete' | 'unsafe' | 'made_up' | 'formatting' | 'other'

export const REVIEW_REASONS: { key: ReviewReason; label: string }[] = [
  { key: 'wrong', label: 'Wrong / incorrect' },
  { key: 'incomplete', label: 'Incomplete' },
  { key: 'unsafe', label: 'Unsafe' },
  { key: 'made_up', label: 'Made up / hallucinated' },
  { key: 'formatting', label: 'Formatting issue' },
  { key: 'other', label: 'Other' },
]

export interface ReviewItem {
  item_id: string
  run_id: string
  flow_id: string
  flow_version?: number | null
  node_id: string
  status: ReviewStatus
  created_at: string
  inputs: Record<string, unknown>
  input_labels: Record<string, any>
  outputs: Record<string, unknown>
  output_labels: Record<string, any>
  verdict?: ReviewVerdict | null
  reasons: ReviewReason[]
  corrected_output?: string | null
  note?: string | null
  reviewer_id?: string | null
  reviewed_at?: string | null
}

export type ReviewSamplingMode = 'off' | 'all' | 'percentage' | 'rules'
export type ReviewSamplingRule = 'failed' | 'fallback_used' | 'rejected_input' | 'approval_rejected' | 'sink_blocked'

export const REVIEW_SAMPLING_RULES: { key: ReviewSamplingRule; label: string }[] = [
  { key: 'failed', label: 'Run failed' },
  { key: 'fallback_used', label: 'Fallback model used' },
  { key: 'rejected_input', label: 'Input rejected by validator/extraction' },
  { key: 'approval_rejected', label: 'Approval rejected' },
  { key: 'sink_blocked', label: 'Sink call blocked' },
]

export interface ReviewSamplingConfig {
  flow_id: string
  mode: ReviewSamplingMode
  percentage: number
  rules: ReviewSamplingRule[]
  node_ids: string[]
  updated_at?: string | null
  updated_by?: string | null
}

export interface ReviewReasonCount {
  reason: string
  count: number
}

export interface ReviewMetrics {
  flow_id: string
  flow_version?: number | null
  total_reviewed: number
  good_count: number
  bad_count: number
  pct_good: number
  top_bad_reasons: ReviewReasonCount[]
}

export interface ListReviewItemsParams {
  flow_id?: string
  status?: string
  verdict?: string
  limit?: number
  offset?: number
}

export interface ListReviewItemsResponse {
  items: ReviewItem[]
  total: number
}

export async function listReviewItems(params?: ListReviewItemsParams): Promise<ListReviewItemsResponse> {
  const res = await api.get<ListReviewItemsResponse>('/v2/review/items', { params })
  return res.data
}

export async function getReviewItem(itemId: string): Promise<ReviewItem> {
  const res = await api.get<ReviewItem>(`/v2/review/items/${encodeURIComponent(itemId)}`)
  return res.data
}

export async function submitVerdict(
  itemId: string,
  data: {
    verdict: ReviewVerdict
    reasons?: ReviewReason[]
    corrected_output?: string
    note?: string
  },
): Promise<ReviewItem> {
  const res = await api.post<ReviewItem>(`/v2/review/items/${encodeURIComponent(itemId)}/verdict`, data)
  return res.data
}

export async function skipReviewItem(itemId: string, note?: string): Promise<ReviewItem> {
  const res = await api.post<ReviewItem>(`/v2/review/items/${encodeURIComponent(itemId)}/skip`, { note })
  return res.data
}

export async function getSamplingConfig(flowId: string): Promise<ReviewSamplingConfig> {
  const res = await api.get<ReviewSamplingConfig>(`/v2/review/sampling/${encodeURIComponent(flowId)}`)
  return res.data
}

export async function updateSamplingConfig(
  flowId: string,
  config: Partial<ReviewSamplingConfig>,
): Promise<ReviewSamplingConfig> {
  const res = await api.put<ReviewSamplingConfig>(`/v2/review/sampling/${encodeURIComponent(flowId)}`, config)
  return res.data
}

export async function sendToReview(data: { run_id: string; node_id?: string }): Promise<{
  item_id: string
  run_id: string
  node_id: string
  flow_id: string
  flow_version?: number | null
}> {
  const res = await api.post('/v2/review/send-to-review', data)
  return res.data
}

export async function getReviewMetrics(flowId: string, version?: number): Promise<ReviewMetrics> {
  const res = await api.get<ReviewMetrics>(`/v2/review/metrics/${encodeURIComponent(flowId)}`, {
    params: version !== undefined ? { version } : undefined,
  })
  return res.data
}

export async function exportReviews(params?: {
  flow_id?: string
  version?: number
  include_secrets?: boolean
}): Promise<string> {
  const res = await api.get<string>('/v2/review/export', {
    params,
    responseType: 'text',
  })
  return res.data
}
