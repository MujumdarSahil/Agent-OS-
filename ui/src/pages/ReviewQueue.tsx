// src/pages/ReviewQueue.tsx — 3.6a: Work > Review queue.
// Inspect AI run outputs, assign quality verdicts (good/bad + reasons),
// capture corrected outputs (never fed to live runs), export test sets.

import { useCallback, useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  SkipForward,
  Download,
  RefreshCw,
  Eye,
  Check,
  X,
  AlertTriangle,
  Info,
} from 'lucide-react'
import { useAuth } from '../components/AuthContext'
import {
  exportReviews,
  listReviewItems,
  REVIEW_REASONS,
  skipReviewItem,
  submitVerdict,
  type ReviewItem,
  type ReviewReason,
  type ReviewVerdict,
} from '../api/review'
import { listFlows } from '../api/flows'
import { LabelBadge, UntrustedText } from '../flow/RunPanel'
import type { LabelInfo } from '../flow/runModel'

const VERDICT_COLOR: Record<string, string> = {
  good: 'var(--accent-teal)',
  bad: 'var(--accent-red)',
}

const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--accent-amber)',
  reviewed: 'var(--accent-teal)',
  skipped: 'var(--text-muted)',
}

function isTyping(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false
  return (
    t.tagName === 'INPUT' ||
    t.tagName === 'TEXTAREA' ||
    t.tagName === 'SELECT' ||
    t.isContentEditable
  )
}

function LabelledField({
  label,
  value,
  meta,
}: {
  label: string
  value: unknown
  meta?: { confidentiality?: string; integrity?: string; sources?: string[] }
}) {
  const isUntrusted = meta?.integrity !== 'trusted'
  const isSecret = meta?.confidentiality === 'secret'
  const labelInfo: LabelInfo | undefined = meta
    ? {
        confidentiality: (meta.confidentiality as any) ?? 'public',
        integrity: (meta.integrity as any) ?? 'untrusted',
        sources: meta.sources ?? [],
      }
    : undefined

  return (
    <div style={{ marginBottom: 10 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          marginBottom: 4,
          fontSize: 12,
        }}
      >
        <strong className="font-mono">{label}</strong>
        {labelInfo && <LabelBadge label={labelInfo} />}
        {isSecret && (
          <span
            className="badge"
            data-testid="secret-badge"
            style={{ background: 'rgba(239,68,68,0.2)', color: 'var(--accent-red)' }}
          >
            SECRET
          </span>
        )}
      </div>
      <UntrustedText value={value} untrusted={isUntrusted} />
    </div>
  )
}

function ReviewModal({
  item,
  onClose,
  onSaved,
  onSkip,
}: {
  item: ReviewItem
  onClose: () => void
  onSaved: (nextId?: string) => void
  onSkip: (nextId?: string) => void
}) {
  const { can, me } = useAuth()
  const canReview = can('review') || me?.role === 'approver' || me?.role === 'builder' || me?.role === 'admin'

  const [verdict, setVerdict] = useState<ReviewVerdict | null>(item.verdict ?? null)
  const [reasons, setReasons] = useState<ReviewReason[]>(item.reasons ?? [])
  const [correctedOutput, setCorrectedOutput] = useState<string>(item.corrected_output ?? '')
  const [note, setNote] = useState<string>(item.note ?? '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const toggleReason = (r: ReviewReason) => {
    setReasons(prev => (prev.includes(r) ? prev.filter(x => x !== r) : [...prev, r]))
  }

  const handleSaveAndNext = useCallback(async () => {
    if (!verdict) {
      setError('Please select a verdict (Good or Bad).')
      return
    }
    setSaving(true)
    setError(null)
    try {
      await submitVerdict(item.item_id, {
        verdict,
        reasons: verdict === 'bad' ? reasons : [],
        corrected_output: correctedOutput.trim() || undefined,
        note: note.trim() || undefined,
      })
      onSaved()
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to submit review')
    } finally {
      setSaving(false)
    }
  }, [item.item_id, verdict, reasons, correctedOutput, note, onSaved])

  const handleSkip = useCallback(async () => {
    setSaving(true)
    setError(null)
    try {
      await skipReviewItem(item.item_id, note.trim() || undefined)
      onSkip()
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to skip review')
    } finally {
      setSaving(false)
    }
  }, [item.item_id, note, onSkip])

  // Keyboard shortcuts: G (good), B (bad), N (save and next)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (isTyping(e.target)) return
      const k = e.key.toLowerCase()
      if (k === 'g') {
        e.preventDefault()
        setVerdict('good')
      } else if (k === 'b') {
        e.preventDefault()
        setVerdict('bad')
      } else if (k === 'n') {
        e.preventDefault()
        void handleSaveAndNext()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [handleSaveAndNext])

  const inputKeys = Object.keys(item.inputs || {})
  const outputKeys = Object.keys(item.outputs || {})

  return (
    <div
      className="modal-backdrop"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: 20,
      }}
      data-testid="review-modal"
    >
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: 960,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          padding: 0,
          overflow: 'hidden',
          boxShadow: '0 8px 30px rgba(0,0,0,0.4)',
        }}
      >
        {/* Modal Header */}
        <div
          style={{
            padding: '12px 18px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--bg-secondary)',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <h3 style={{ margin: 0, fontSize: 16 }}>Review Item</h3>
              <span className="badge badge-default" data-testid="review-node-id">
                {item.node_id}
              </span>
              <span
                className="badge"
                data-testid="review-status-badge"
                style={{
                  background: 'var(--bg-input)',
                  color: STATUS_COLOR[item.status] || 'inherit',
                }}
              >
                {item.status}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
              Flow: <code>{item.flow_id}</code>
              {item.flow_version ? ` v${item.flow_version}` : ''} · Run:{' '}
              <code>{item.run_id}</code> · {new Date(item.created_at).toLocaleString()}
            </div>
          </div>
          <button
            className="btn btn-ghost btn-sm"
            data-testid="review-close-btn"
            onClick={onClose}
          >
            <X size={16} />
          </button>
        </div>

        {/* Modal Body */}
        <div
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '16px 20px',
            display: 'grid',
            gridTemplateColumns: '1.2fr 1fr',
            gap: 20,
          }}
        >
          {/* Left Column: Inputs & Outputs with security labels */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Inputs */}
            <div>
              <div
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  marginBottom: 8,
                  color: 'var(--text-secondary)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                }}
              >
                Node Inputs
              </div>
              {inputKeys.length === 0 ? (
                <div className="text-muted" style={{ fontSize: 12 }}>
                  None
                </div>
              ) : (
                inputKeys.map(k => (
                  <LabelledField
                    key={k}
                    label={k}
                    value={item.inputs[k]}
                    meta={item.input_labels?.[k]}
                  />
                ))
              )}
            </div>

            {/* Outputs */}
            <div>
              <div
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  marginBottom: 8,
                  color: 'var(--text-secondary)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                }}
              >
                Node Outputs
              </div>
              {outputKeys.length === 0 ? (
                <div className="text-muted" style={{ fontSize: 12 }}>
                  None
                </div>
              ) : (
                outputKeys.map(k => (
                  <LabelledField
                    key={k}
                    label={k}
                    value={item.outputs[k]}
                    meta={item.output_labels?.[k]}
                  />
                ))
              )}
            </div>
          </div>

          {/* Right Column: Verdict, Reasons, Corrected Output, Note */}
          <div
            style={{
              borderLeft: '1px solid var(--border)',
              paddingLeft: 20,
              display: 'flex',
              flexDirection: 'column',
              gap: 14,
            }}
          >
            {/* Verdict Selection */}
            <div>
              <div className="form-label" style={{ marginBottom: 6 }}>
                Verdict <span className="text-muted" style={{ fontWeight: 400 }}>(shortcuts: [G] Good, [B] Bad)</span>
              </div>
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  type="button"
                  data-testid="verdict-good-btn"
                  className={`btn ${verdict === 'good' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{
                    flex: 1,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 6,
                    borderColor: verdict === 'good' ? 'var(--accent-teal)' : undefined,
                    backgroundColor: verdict === 'good' ? 'rgba(45,212,191,0.2)' : undefined,
                    color: verdict === 'good' ? 'var(--accent-teal)' : undefined,
                  }}
                  disabled={!canReview || saving}
                  onClick={() => setVerdict('good')}
                >
                  <Check size={16} /> Good <kbd style={{ fontSize: 10, opacity: 0.7 }}>G</kbd>
                </button>
                <button
                  type="button"
                  data-testid="verdict-bad-btn"
                  className={`btn ${verdict === 'bad' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{
                    flex: 1,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 6,
                    borderColor: verdict === 'bad' ? 'var(--accent-red)' : undefined,
                    backgroundColor: verdict === 'bad' ? 'rgba(239,68,68,0.2)' : undefined,
                    color: verdict === 'bad' ? 'var(--accent-red)' : undefined,
                  }}
                  disabled={!canReview || saving}
                  onClick={() => setVerdict('bad')}
                >
                  <X size={16} /> Bad <kbd style={{ fontSize: 10, opacity: 0.7 }}>B</kbd>
                </button>
              </div>
            </div>

            {/* Reasons (if Bad) */}
            {verdict === 'bad' && (
              <div data-testid="bad-reasons-container" style={{ animation: 'fadeIn 0.15s ease' }}>
                <div className="form-label" style={{ marginBottom: 6 }}>
                  Why is this bad? <span className="text-muted" style={{ fontWeight: 400 }}>(select all that apply)</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                  {REVIEW_REASONS.map(r => (
                    <label
                      key={r.key}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6,
                        fontSize: 12,
                        cursor: canReview ? 'pointer' : 'default',
                      }}
                    >
                      <input
                        type="checkbox"
                        data-testid={`reason-${r.key}`}
                        checked={reasons.includes(r.key)}
                        disabled={!canReview || saving}
                        onChange={() => toggleReason(r.key)}
                      />
                      <span>{r.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {/* Corrected Output */}
            <div>
              <div className="form-label" style={{ marginBottom: 2 }}>
                Corrected Output
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
                What the AI should have produced. Saved and exported for test cases;{' '}
                <strong style={{ color: 'var(--accent-amber)' }}>never fed back to live run</strong>.
              </div>
              <textarea
                className="form-input"
                data-testid="corrected-output-input"
                rows={4}
                value={correctedOutput}
                disabled={!canReview || saving}
                onChange={e => setCorrectedOutput(e.target.value)}
                placeholder="Enter the ideal / ground-truth output text..."
                style={{ width: '100%', resize: 'vertical', fontSize: 12 }}
              />
            </div>

            {/* Reviewer Note */}
            <div>
              <div className="form-label" style={{ marginBottom: 2 }}>
                Reviewer Note
              </div>
              <textarea
                className="form-input"
                data-testid="reviewer-note-input"
                rows={2}
                value={note}
                disabled={!canReview || saving}
                onChange={e => setNote(e.target.value)}
                placeholder="Optional notes or context for audit log..."
                style={{ width: '100%', resize: 'vertical', fontSize: 12 }}
              />
            </div>

            {error && (
              <div
                style={{
                  color: 'var(--accent-red)',
                  fontSize: 12,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
                data-testid="review-error-msg"
              >
                <AlertTriangle size={14} /> {error}
              </div>
            )}

            {!canReview && (
              <div
                className="text-muted"
                style={{ fontSize: 11, fontStyle: 'italic' }}
                data-testid="viewer-only-notice"
              >
                <Info size={12} style={{ display: 'inline', marginRight: 4 }} />
                Viewer access: read-only. An approver, builder, or admin role is required to submit reviews.
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div
          style={{
            padding: '12px 20px',
            borderTop: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--bg-secondary)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {canReview && (
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                data-testid="review-skip-btn"
                disabled={saving}
                onClick={handleSkip}
                title="Skip this item and move to next"
              >
                <SkipForward size={14} /> Skip
              </button>
            )}
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Keyboard: <kbd>G</kbd> Good · <kbd>B</kbd> Bad · <kbd>N</kbd> Save &amp; Next
            </span>
          </div>

          <div style={{ display: 'flex', gap: 10 }}>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              data-testid="review-cancel-btn"
              onClick={onClose}
              disabled={saving}
            >
              Close
            </button>
            {canReview && (
              <button
                type="button"
                className="btn btn-primary btn-sm"
                data-testid="review-save-next-btn"
                disabled={saving || !verdict}
                onClick={handleSaveAndNext}
              >
                {saving ? 'Saving…' : 'Save and next'} <kbd style={{ fontSize: 10, marginLeft: 4 }}>N</kbd>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function ExportModal({
  onClose,
  flows,
}: {
  onClose: () => void
  flows: { id: string; name: string }[]
}) {
  const [selectedFlow, setSelectedFlow] = useState<string>('')
  const [includeSecrets, setIncludeSecrets] = useState<boolean>(false)
  const [exporting, setExporting] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)

  const handleDownload = async () => {
    setExporting(true)
    setError(null)
    try {
      const data = await exportReviews({
        flow_id: selectedFlow || undefined,
        include_secrets: includeSecrets,
      })
      const blob = new Blob([data], { type: 'application/x-jsonlines;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `agentos-review-export${selectedFlow ? `-${selectedFlow}` : ''}.jsonl`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
      onClose()
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Export failed')
    } finally {
      setExporting(false)
    }
  }

  return (
    <div
      className="modal-backdrop"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: 20,
      }}
      data-testid="export-modal"
    >
      <div
        className="card"
        style={{ width: '100%', maxWidth: 480, padding: 20, boxShadow: '0 8px 30px rgba(0,0,0,0.4)' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <h3 style={{ margin: 0, fontSize: 16 }}>Export Reviewed Items</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
          Exports reviewed runs and node outputs as JSONL. This dataset serves as starting test cases for flow evals.
        </p>

        <div className="form-group" style={{ marginBottom: 14 }}>
          <label className="form-label" htmlFor="export-flow-select">
            Filter by flow (optional)
          </label>
          <select
            id="export-flow-select"
            className="form-select"
            data-testid="export-flow-select"
            value={selectedFlow}
            onChange={e => setSelectedFlow(e.target.value)}
          >
            <option value="">All flows</option>
            {flows.map(f => (
              <option key={f.id} value={f.id}>
                {f.name || f.id} ({f.id})
              </option>
            ))}
          </select>
        </div>

        <div style={{ marginBottom: 20 }}>
          <label
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8,
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            <input
              type="checkbox"
              data-testid="export-include-secrets-checkbox"
              checked={includeSecrets}
              onChange={e => setIncludeSecrets(e.target.checked)}
              style={{ marginTop: 2 }}
            />
            <div>
              <strong>Include secret values</strong>
              <div style={{ color: 'var(--accent-amber)', fontSize: 11, marginTop: 2 }}>
                WARNING: Values labeled SECRET will be included in the clear. This action is audited.
              </div>
            </div>
          </label>
        </div>

        {error && (
          <div style={{ color: 'var(--accent-red)', fontSize: 12, marginBottom: 12 }} data-testid="export-error">
            {error}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
          <button className="btn btn-ghost btn-sm" onClick={onClose} disabled={exporting}>
            Cancel
          </button>
          <button
            className="btn btn-primary btn-sm"
            data-testid="export-download-btn"
            disabled={exporting}
            onClick={handleDownload}
          >
            <Download size={14} /> {exporting ? 'Exporting…' : 'Download JSONL'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function ReviewQueue() {
  const qc = useQueryClient()
  const { can, me } = useAuth()
  const canExport = can('admin') || me?.role === 'admin'

  const [flowFilter, setFlowFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [verdictFilter, setVerdictFilter] = useState<string>('')
  const [activeItem, setActiveItem] = useState<ReviewItem | null>(null)
  const [showExportModal, setShowExportModal] = useState<boolean>(false)

  const flowsQ = useQuery({ queryKey: ['flows'], queryFn: listFlows })
  const reviewQ = useQuery({
    queryKey: ['review-items', flowFilter, statusFilter, verdictFilter],
    queryFn: () =>
      listReviewItems({
        flow_id: flowFilter || undefined,
        status: statusFilter || undefined,
        verdict: verdictFilter || undefined,
        limit: 100,
      }),
  })

  const items = reviewQ.data?.items ?? []
  const total = reviewQ.data?.total ?? 0

  const openNextPending = useCallback(
    async (currentId?: string) => {
      await qc.invalidateQueries({ queryKey: ['review-items'] })
      const res = await qc.fetchQuery({
        queryKey: ['review-items', flowFilter, statusFilter, verdictFilter],
        queryFn: () =>
          listReviewItems({
            flow_id: flowFilter || undefined,
            status: statusFilter || undefined,
            verdict: verdictFilter || undefined,
            limit: 100,
          }),
      })
      const remaining = (res?.items ?? []).filter(
        i => i.status === 'pending' && i.item_id !== currentId,
      )
      if (remaining.length > 0) {
        setActiveItem(remaining[0])
      } else {
        setActiveItem(null)
      }
    },
    [flowFilter, statusFilter, verdictFilter, qc],
  )

  return (
    <div data-testid="review-queue-page">
      {/* Page Header */}
      <div
        className="page-header"
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
      >
        <div>
          <h2>Review queue</h2>
          <p>
            Evaluate AI outputs, mark quality verdicts, record human-corrected answers, and train flow test cases.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {canExport && (
            <button
              className="btn btn-secondary btn-sm"
              data-testid="review-export-btn"
              onClick={() => setShowExportModal(true)}
            >
              <Download size={14} /> Export JSONL
            </button>
          )}
          <button
            className="btn btn-ghost btn-sm"
            data-testid="review-refresh-btn"
            onClick={() => reviewQ.refetch()}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card mb-4" style={{ padding: '10px 14px' }}>
        <div className="flex items-center gap-3" style={{ flexWrap: 'wrap' }}>
          <label style={{ fontSize: 12 }}>
            Flow{' '}
            <select
              className="form-select"
              data-testid="filter-flow"
              value={flowFilter}
              onChange={e => setFlowFilter(e.target.value)}
              style={{ width: 'auto', display: 'inline-block' }}
            >
              <option value="">All flows</option>
              {(flowsQ.data ?? []).map(f => (
                <option key={f.id} value={f.id}>
                  {f.name || f.id}
                </option>
              ))}
            </select>
          </label>

          <label style={{ fontSize: 12 }}>
            Status{' '}
            <select
              className="form-select"
              data-testid="filter-status"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              style={{ width: 'auto', display: 'inline-block' }}
            >
              <option value="">All statuses</option>
              <option value="pending">Pending</option>
              <option value="reviewed">Reviewed</option>
              <option value="skipped">Skipped</option>
            </select>
          </label>

          <label style={{ fontSize: 12 }}>
            Verdict{' '}
            <select
              className="form-select"
              data-testid="filter-verdict"
              value={verdictFilter}
              onChange={e => setVerdictFilter(e.target.value)}
              style={{ width: 'auto', display: 'inline-block' }}
            >
              <option value="">All verdicts</option>
              <option value="good">Good</option>
              <option value="bad">Bad</option>
            </select>
          </label>

          <span
            className="text-muted ml-auto"
            style={{ fontSize: 12 }}
            data-testid="review-count-label"
          >
            {items.length} of {total} item{total === 1 ? '' : 's'}
          </span>
        </div>
      </div>

      {/* Items Table */}
      <div className="card" style={{ padding: 0 }}>
        {reviewQ.isLoading ? (
          <div className="empty-state">Loading reviews…</div>
        ) : items.length === 0 ? (
          <div className="empty-state" data-testid="review-empty">
            No review items match the current filters.
          </div>
        ) : (
          <table className="ov-table" data-testid="review-items-table">
            <thead>
              <tr>
                <th>Flow</th>
                <th>Run</th>
                <th>Node</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Created</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map(item => (
                <tr
                  key={item.item_id}
                  data-testid="review-row"
                  data-item-id={item.item_id}
                  data-flow={item.flow_id}
                  data-status={item.status}
                  data-verdict={item.verdict ?? 'none'}
                >
                  <td>
                    <strong>{item.flow_id}</strong>
                    {item.flow_version ? (
                      <span className="text-muted"> v{item.flow_version}</span>
                    ) : null}
                  </td>
                  <td>
                    <code>{item.run_id}</code>
                  </td>
                  <td>
                    <span className="badge badge-default">{item.node_id}</span>
                  </td>
                  <td>
                    <span
                      style={{
                        color: STATUS_COLOR[item.status] || 'inherit',
                        fontWeight: 600,
                        fontSize: 12,
                      }}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td>
                    {item.verdict ? (
                      <span
                        className="badge"
                        style={{
                          color: VERDICT_COLOR[item.verdict] || 'inherit',
                          background:
                            item.verdict === 'good'
                              ? 'rgba(45,212,191,0.15)'
                              : 'rgba(239,68,68,0.15)',
                        }}
                      >
                        {item.verdict}
                      </span>
                    ) : (
                      <span className="text-muted">-</span>
                    )}
                  </td>
                  <td style={{ fontSize: 12 }}>
                    {item.created_at ? new Date(item.created_at).toLocaleString() : '-'}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-ghost btn-sm"
                      data-testid={`review-item-btn-${item.item_id}`}
                      onClick={() => setActiveItem(item)}
                    >
                      <Eye size={13} /> {item.status === 'pending' ? 'Review' : 'View'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Review Modal */}
      {activeItem && (
        <ReviewModal
          item={activeItem}
          onClose={() => setActiveItem(null)}
          onSaved={() => openNextPending(activeItem.item_id)}
          onSkip={() => openNextPending(activeItem.item_id)}
        />
      )}

      {/* Export Modal */}
      {showExportModal && (
        <ExportModal
          flows={flowsQ.data ?? []}
          onClose={() => setShowExportModal(false)}
        />
      )}
    </div>
  )
}
