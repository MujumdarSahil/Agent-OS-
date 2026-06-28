import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getTemplates, installTemplate } from '../api/client'
import { LayoutGrid, Download, ShieldAlert, Check } from 'lucide-react'

export default function Templates() {
  const qc = useQueryClient()
  const [installingName, setInstallingName] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [forceInstallName, setForceInstallName] = useState<string | null>(null)

  const { data: templates = [], isLoading, error } = useQuery({
    queryKey: ['templates'],
    queryFn: getTemplates
  })

  const install = useMutation({
    mutationFn: ({ name, force }: { name: string; force: boolean }) => installTemplate(name, force),
    onMutate: (variables) => {
      setInstallingName(variables.name)
      setSuccessMsg(null)
      setErrorMsg(null)
    },
    onSuccess: (_, variables) => {
      setInstallingName(null)
      setForceInstallName(null)
      setSuccessMsg(`Successfully installed template "${variables.name}"!`)
      // Invalidate relevant queries to update list counts (agents, tools, crews, missions)
      qc.invalidateQueries({ queryKey: ['agents'] })
      qc.invalidateQueries({ queryKey: ['crews'] })
      qc.invalidateQueries({ queryKey: ['missions'] })
      qc.invalidateQueries({ queryKey: ['health'] })
    },
    onError: (err: any, variables) => {
      setInstallingName(null)
      const detail = err.response?.data?.detail || err.message || 'Unknown error'
      if (err.response?.status === 409) {
        // Conflict - file already exists
        setForceInstallName(variables.name)
        setErrorMsg(`Conflict: Some files for template "${variables.name}" already exist.`)
      } else {
        setErrorMsg(`Failed to install template: ${detail}`)
      }
    }
  })

  const handleInstall = (name: string, force = false) => {
    install.mutate({ name, force })
  }

  return (
    <div>
      <div className="page-header-row">
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2>Crew Templates</h2>
          <p>Instant, production-ready agent crews you can install into your workspace</p>
        </div>
      </div>

      {successMsg && (
        <div className="card mb-4" style={{ borderLeft: '4px solid var(--accent-green)', background: 'rgba(16, 185, 129, 0.1)', padding: '12px 16px' }}>
          <div className="flex items-center gap-2" style={{ color: 'var(--accent-green)' }}>
            <Check size={16} />
            <span>{successMsg}</span>
          </div>
        </div>
      )}

      {errorMsg && (
        <div className="card mb-4" style={{ borderLeft: '4px solid var(--accent-red)', background: 'rgba(239, 68, 68, 0.1)', padding: '12px 16px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="flex items-center gap-2" style={{ color: 'var(--accent-red)', fontWeight: 600 }}>
              <ShieldAlert size={16} />
              <span>{errorMsg}</span>
            </div>
            {forceInstallName && (
              <div className="flex gap-2" style={{ marginTop: 4 }}>
                <button
                  className="btn btn-primary"
                  style={{ background: 'var(--accent-red)', borderColor: 'var(--accent-red)' }}
                  onClick={() => handleInstall(forceInstallName, true)}
                  disabled={install.isPending}
                >
                  Overwrite (Force)
                </button>
                <button className="btn btn-secondary" onClick={() => { setErrorMsg(null); setForceInstallName(null); }}>
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="empty-state"><div className="spinner" /></div>
      ) : error ? (
        <div className="empty-state">
          <ShieldAlert size={40} color="var(--accent-red)" />
          <h3>Failed to load templates</h3>
          <p>{(error as any).message || 'API is not running'}</p>
        </div>
      ) : templates.length === 0 ? (
        <div className="empty-state">
          <LayoutGrid size={40} />
          <h3>No templates available</h3>
          <p>Check if the API server is running and templates are built.</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '20px' }}>
          {templates.map(tmpl => {
            const isInstalling = installingName === tmpl.name
            return (
              <div key={tmpl.name} className="card" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                    <h3 style={{ fontSize: '16px', fontWeight: 700, margin: 0 }}>{tmpl.display_name}</h3>
                    <span className="badge" style={{ textTransform: 'uppercase', fontSize: '10px' }}>
                      {tmpl.license_type}
                    </span>
                  </div>

                  <p className="text-muted" style={{ fontSize: '13px', lineHeight: 1.5, marginBottom: '16px' }}>
                    {tmpl.description}
                  </p>

                  <div style={{ marginBottom: '16px' }}>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                      Crews & Agents Included
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {tmpl.agents.map(a => (
                        <span key={a} style={{ fontSize: '11px', background: 'var(--bg-hover)', color: 'var(--text-primary)', padding: '2px 8px', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
                          🤖 {a}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div style={{ marginBottom: '16px' }}>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                      Missions
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-primary)' }}>
                      🎯 {tmpl.missions.join(', ')}
                    </div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '16px', marginTop: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                    {tmpl.tags.map(t => (
                      <span key={t} style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>
                        #{t}
                      </span>
                    ))}
                  </div>

                  <button
                    className="btn btn-primary"
                    style={{ fontSize: '12px', padding: '6px 12px' }}
                    onClick={() => handleInstall(tmpl.name)}
                    disabled={isInstalling}
                  >
                    {isInstalling ? (
                      <span className="flex items-center gap-1"><div className="spinner" style={{ width: 12, height: 12 }} /> Installing...</span>
                    ) : (
                      <span className="flex items-center gap-1"><Download size={12} /> Install</span>
                    )}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
