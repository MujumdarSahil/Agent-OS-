import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { buildPack, signPack, verifyPack, installPack } from '../api/client'
import { Package, Key, CheckCircle, XCircle, Download, Shield, Loader } from 'lucide-react'

export default function Packaging() {
  const [tab, setTab] = useState<'build' | 'sign' | 'verify' | 'install'>('build')

  // Build state
  const [agents, setAgents] = useState('')
  const [tools, setTools] = useState('')
  const [crews, setCrews] = useState('')
  const [outputName, setOutputName] = useState('bundle.agentpack')

  // Sign state
  const [signPath, setSignPath] = useState('')
  const [privKey, setPrivKey] = useState('')

  // Verify state
  const [verifyPath, setVerifyPath] = useState('')

  // Install state
  const [installPath, setInstallPath] = useState('')
  const [targetPath, setTargetPath] = useState('')
  const [force, setForce] = useState(false)
  const [licenseKey, setLicenseKey] = useState('')

  const buildMut = useMutation({ mutationFn: () => buildPack({
    include_agents: agents.split(',').map(s => s.trim()).filter(Boolean),
    include_tools: tools.split(',').map(s => s.trim()).filter(Boolean),
    include_crews: crews.split(',').map(s => s.trim()).filter(Boolean),
    output_name: outputName,
  })})

  const signMut = useMutation({ mutationFn: () => signPack(signPath, privKey) })
  const verifyMut = useMutation({ mutationFn: () => verifyPack(verifyPath) })
  const installMut = useMutation({ mutationFn: () => installPack(installPath, targetPath, force, licenseKey || undefined) })

  return (
    <div>
      <div className="page-header">
        <h2>Packaging</h2>
        <p>Build, sign, verify, and install <code className="font-mono">.agentpack</code> bundles</p>
      </div>

      <div className="tabs">
        {(['build', 'sign', 'verify', 'install'] as const).map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'build' && (
        <div className="card">
          <h3 style={{ fontWeight: 700, marginBottom: 16, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Package size={16}/> Build Pack
          </h3>
          <div className="form-group"><label className="form-label">Agents (comma-separated names)</label><input className="form-input" value={agents} onChange={e => setAgents(e.target.value)} placeholder="ResearchAgent, WriterAgent"/></div>
          <div className="form-group"><label className="form-label">Tools (comma-separated names)</label><input className="form-input" value={tools} onChange={e => setTools(e.target.value)} placeholder="web_search, code_runner"/></div>
          <div className="form-group"><label className="form-label">Crews (comma-separated names)</label><input className="form-input" value={crews} onChange={e => setCrews(e.target.value)} placeholder="research_crew"/></div>
          <div className="form-group"><label className="form-label">Output filename</label><input className="form-input" value={outputName} onChange={e => setOutputName(e.target.value)} placeholder="bundle.agentpack"/></div>
          <button id="pack-build-btn" className="btn btn-primary" disabled={buildMut.isPending} onClick={() => buildMut.mutate()}>
            {buildMut.isPending ? <><Loader size={14}/> Building...</> : <><Package size={14}/> Build Pack</>}
          </button>
          {buildMut.isSuccess && <div className="code-block mt-4">Built: {buildMut.data.pack_path} ({buildMut.data.size_bytes} bytes)</div>}
          {buildMut.isError && <div style={{ color: 'var(--accent-red)', marginTop: 12 }}>{String(buildMut.error)}</div>}
        </div>
      )}

      {tab === 'sign' && (
        <div className="card">
          <h3 style={{ fontWeight: 700, marginBottom: 16, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Key size={16}/> Sign Pack
          </h3>
          <div className="form-group"><label className="form-label">Pack path</label><input id="pack-sign-path" className="form-input" value={signPath} onChange={e => setSignPath(e.target.value)} placeholder="/path/to/bundle.agentpack"/></div>
          <div className="form-group"><label className="form-label">Private key path</label><input className="form-input" value={privKey} onChange={e => setPrivKey(e.target.value)} placeholder="~/.agentos/keys/private.pem"/></div>
          <button id="pack-sign-btn" className="btn btn-primary" disabled={!signPath || !privKey || signMut.isPending} onClick={() => signMut.mutate()}>
            {signMut.isPending ? <><Loader size={14}/> Signing...</> : <><Shield size={14}/> Sign Pack</>}
          </button>
          {signMut.isSuccess && <div style={{ color: 'var(--accent-green)', marginTop: 12, display: 'flex', alignItems: 'center', gap: 8 }}><CheckCircle size={16}/> Signed successfully</div>}
          {signMut.isError && <div style={{ color: 'var(--accent-red)', marginTop: 12 }}>{String(signMut.error)}</div>}
        </div>
      )}

      {tab === 'verify' && (
        <div className="card">
          <h3 style={{ fontWeight: 700, marginBottom: 16, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <CheckCircle size={16}/> Verify Pack
          </h3>
          <div className="form-group"><label className="form-label">Pack path</label><input id="pack-verify-path" className="form-input" value={verifyPath} onChange={e => setVerifyPath(e.target.value)} placeholder="/path/to/bundle.agentpack"/></div>
          <button id="pack-verify-btn" className="btn btn-primary" disabled={!verifyPath || verifyMut.isPending} onClick={() => verifyMut.mutate()}>
            {verifyMut.isPending ? <><Loader size={14}/> Verifying...</> : <><Shield size={14}/> Verify</>}
          </button>
          {verifyMut.isSuccess && (
            <div className="card mt-4" style={{ borderColor: verifyMut.data.valid ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              <div className="flex items-center gap-2" style={{ color: verifyMut.data.valid ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                {verifyMut.data.valid ? <CheckCircle size={18}/> : <XCircle size={18}/>}
                <strong>{verifyMut.data.valid ? 'Valid signature' : 'Invalid or unsigned'}</strong>
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8 }}>{verifyMut.data.detail}</p>
              {verifyMut.data.signer_fingerprint && <div className="code-block mt-4">Signer: {verifyMut.data.signer_fingerprint}</div>}
            </div>
          )}
        </div>
      )}

      {tab === 'install' && (
        <div className="card">
          <h3 style={{ fontWeight: 700, marginBottom: 16, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Download size={16}/> Install Pack
          </h3>
          <div className="form-group"><label className="form-label">Pack path</label><input id="pack-install-path" className="form-input" value={installPath} onChange={e => setInstallPath(e.target.value)} placeholder="/path/to/bundle.agentpack"/></div>
          <div className="form-group"><label className="form-label">Target project path</label><input className="form-input" value={targetPath} onChange={e => setTargetPath(e.target.value)} placeholder="/path/to/my-project"/></div>
          <div className="form-group"><label className="form-label">License key (optional, for commercial packs)</label><textarea className="form-textarea" rows={2} value={licenseKey} onChange={e => setLicenseKey(e.target.value)} placeholder="Paste your license key here..."/></div>
          <div className="flex items-center gap-2 mb-4">
            <input type="checkbox" id="force-install" checked={force} onChange={e => setForce(e.target.checked)}/>
            <label htmlFor="force-install" style={{ fontSize: 13, color: 'var(--text-secondary)', cursor: 'pointer' }}>Force overwrite existing files</label>
          </div>
          <button id="pack-install-btn" className="btn btn-primary" disabled={!installPath || !targetPath || installMut.isPending} onClick={() => installMut.mutate()}>
            {installMut.isPending ? <><Loader size={14}/> Installing...</> : <><Download size={14}/> Install Pack</>}
          </button>
          {installMut.isSuccess && <div className="code-block mt-4">{JSON.stringify(installMut.data, null, 2)}</div>}
          {installMut.isError && <div style={{ color: 'var(--accent-red)', marginTop: 12 }}>{String(installMut.error)}</div>}
        </div>
      )}
    </div>
  )
}
