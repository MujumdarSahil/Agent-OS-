import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { previewAgent, confirmAgent, previewTool, confirmTool, previewCrew, confirmCrew } from '../api/client'
import { Wand2, CheckCircle, XCircle, Loader } from 'lucide-react'

type BuilderType = 'agent' | 'tool' | 'crew'

const PLACEHOLDERS: Record<BuilderType, string> = {
  agent: 'A senior Python security code reviewer who audits code for vulnerabilities',
  tool: 'A tool that searches GitHub issues and returns the top 5 relevant results',
  crew: 'A content marketing crew that researches topics, writes articles, and optimizes for SEO',
}

export default function Builder() {
  const [tab, setTab] = useState<BuilderType>('agent')
  const [desc, setDesc] = useState('')
  const [preview, setPreview] = useState<Record<string, unknown> | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const [confirmedPath, setConfirmedPath] = useState('')

  const previewFns = { agent: previewAgent, tool: previewTool, crew: previewCrew }
  const confirmFns = { agent: confirmAgent, tool: confirmTool, crew: confirmCrew }

  const previewMut = useMutation({
    mutationFn: () => previewFns[tab](desc),
    onSuccess: (data) => { setPreview(data.config); setConfirmed(false) }
  })
  const confirmMut = useMutation({
    mutationFn: () => confirmFns[tab](preview!),
    onSuccess: (data) => { setConfirmed(true); setConfirmedPath(data.file_path) }
  })

  const reset = () => { setPreview(null); setConfirmed(false); setDesc('') }

  return (
    <div>
      <div className="page-header">
        <h2>Natural Language Builder</h2>
        <p>Describe what you need — preview the generated config before writing any files</p>
      </div>

      <div className="tabs">
        {(['agent', 'tool', 'crew'] as BuilderType[]).map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => { setTab(t); reset() }}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      <div className="card mb-4">
        <div className="form-group">
          <label className="form-label">Describe your {tab} in plain English</label>
          <textarea
            id="builder-description"
            className="form-textarea"
            rows={3}
            value={desc}
            onChange={e => setDesc(e.target.value)}
            placeholder={PLACEHOLDERS[tab]}
          />
        </div>
        <button
          id="builder-preview-btn"
          className="btn btn-primary"
          disabled={!desc || previewMut.isPending}
          onClick={() => previewMut.mutate()}
        >
          {previewMut.isPending ? <><Loader size={14}/> Generating...</> : <><Wand2 size={14}/> Generate Preview</>}
        </button>

        {previewMut.isError && (
          <div style={{ marginTop: 12, color: 'var(--accent-red)', fontSize: 13 }}>
            <XCircle size={14} style={{ marginRight: 6 }}/>{String(previewMut.error)}
          </div>
        )}
      </div>

      {preview && !confirmed && (
        <div className="card mb-4">
          <h3 style={{ fontWeight: 700, marginBottom: 12, fontSize: 14 }}>Preview — Nothing written yet</h3>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
            Review the generated config below. Click Confirm to write it to disk, or Discard to regenerate.
          </p>
          <div className="code-block" style={{ marginBottom: 16 }}>
            {JSON.stringify(preview, null, 2)}
          </div>
          <div className="flex gap-3">
            <button
              id="builder-confirm-btn"
              className="btn btn-primary"
              disabled={confirmMut.isPending}
              onClick={() => confirmMut.mutate()}
            >
              {confirmMut.isPending ? <><Loader size={14}/> Writing...</> : <><CheckCircle size={14}/> Confirm & Write</>}
            </button>
            <button className="btn btn-secondary" onClick={reset}>Discard</button>
          </div>
        </div>
      )}

      {confirmed && (
        <div className="card" style={{ borderColor: 'var(--accent-green)' }}>
          <div className="flex items-center gap-2" style={{ color: 'var(--accent-green)', marginBottom: 8 }}>
            <CheckCircle size={18}/><strong>Written to disk!</strong>
          </div>
          <div className="code-block" style={{ fontSize: 12 }}>{confirmedPath}</div>
          <button className="btn btn-secondary" style={{ marginTop: 12 }} onClick={reset}>
            Generate Another
          </button>
        </div>
      )}
    </div>
  )
}
