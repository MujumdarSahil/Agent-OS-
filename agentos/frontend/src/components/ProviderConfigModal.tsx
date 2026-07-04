import React, { useState, useEffect } from 'react'
import { X, ExternalLink, Loader2, Trash2, CheckCircle2, AlertCircle } from 'lucide-react'
import {
  getProviders,
  saveProviderKeys,
  deleteProviderKeys,
  testProvider,
} from '../api/client'
import type { ProviderStatus } from '../api/client'

interface ProviderConfigModalProps {
  isOpen: boolean
  onClose: () => void
  providerName?: string // If editing a specific provider
  onSaved: () => void
}

const API_KEY_URLS: Record<string, string> = {
  openai_gpt4o: 'https://platform.openai.com/api-keys',
  openai_gpt4o_mini: 'https://platform.openai.com/api-keys',
  anthropic_claude_sonnet: 'https://console.anthropic.com/settings/keys',
  gemini_flash: 'https://aistudio.google.com/app/apikey',
  groq_llama3_3: 'https://console.groq.com/keys',
  groq_llama3_1_instant: 'https://console.groq.com/keys',
  groq_gemma2: 'https://console.groq.com/keys',
  openrouter_claude_sonnet: 'https://openrouter.ai/keys',
  openrouter_gpt4o: 'https://openrouter.ai/keys',
  openrouter_llama3_1_free: 'https://openrouter.ai/keys',
  together_llama3_3_70b: 'https://api.together.xyz/settings/api-keys',
  together_qwen2_5_72b: 'https://api.together.xyz/settings/api-keys',
  fireworks_llama3_1_70b: 'https://fireworks.ai/account/api-keys',
  fireworks_qwen2_5_72b: 'https://fireworks.ai/account/api-keys',
  deepseek_v4_flash: 'https://platform.deepseek.com/api_keys',
}

export default function ProviderConfigModal({
  isOpen,
  onClose,
  providerName,
  onSaved,
}: ProviderConfigModalProps) {
  const [providers, setProviders] = useState<ProviderStatus[]>([])
  const [selectedName, setSelectedName] = useState<string>('')
  const [apiKey, setApiKey] = useState<string>('')
  const [baseUrl, setBaseUrl] = useState<string>('')
  const [modelName, setModelName] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [testing, setTesting] = useState<boolean>(false)

  useEffect(() => {
    if (isOpen) {
      loadProviders()
    }
  }, [isOpen])

  const loadProviders = async () => {
    try {
      const data = await getProviders()
      setProviders(data)
      const initialName = providerName || data[0]?.name || ''
      setSelectedName(initialName)
      setupFields(initialName, data)
    } catch (e) {
      console.error(e)
    }
  }

  const setupFields = (name: string, list: ProviderStatus[]) => {
    const prov = list.find((p) => p.name === name)
    setTestResult(null)
    if (prov) {
      setApiKey('')
      setBaseUrl('')
      setModelName('')
      if (name === 'openai_compatible') {
        setBaseUrl(localStorage.getItem('openai_compatible_base') || '')
        setModelName(localStorage.getItem('openai_compatible_model') || '')
      } else if (prov.is_local) {
        setBaseUrl(localStorage.getItem('ollama_base') || 'http://localhost:11434')
      }
    }
  }

  useEffect(() => {
    if (selectedName && providers.length > 0) {
      setupFields(selectedName, providers)
    }
  }, [selectedName, providers])

  if (!isOpen) return null

  const selectedProv = providers.find((p) => p.name === selectedName)
  const isCloud = selectedProv && !selectedProv.is_local && selectedProv.name !== 'openai_compatible'
  const isOllama = selectedProv?.is_local
  const isOpenAICompatible = selectedProv?.name === 'openai_compatible'

  const handleSaveAndTest = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedProv) return

    setLoading(true)
    setTestResult(null)

    try {
      // Save
      await saveProviderKeys({
        provider_name: selectedName,
        api_key: apiKey || undefined,
        api_base_url: baseUrl || undefined,
        model_name: modelName || undefined,
      })

      // Store local cache for convenience in UI fields
      if (isOpenAICompatible) {
        if (baseUrl) localStorage.setItem('openai_compatible_base', baseUrl)
        if (modelName) localStorage.setItem('openai_compatible_model', modelName)
      } else if (isOllama && baseUrl) {
        localStorage.setItem('ollama_base', baseUrl)
      }

      setTesting(true)
      // Test
      const testRes = await testProvider(selectedName)
      setTesting(false)

      if (testRes.success) {
        setTestResult({
          success: true,
          message: `Connection successful! Latency: ${testRes.latency_ms}ms. Response: "${testRes.response}"`,
        })
        setTimeout(() => {
          onSaved()
          onClose()
        }, 1500)
      } else {
        setTestResult({
          success: false,
          message: `Test Failed: ${testRes.error || 'Unknown connection failure'}`,
        })
      }
    } catch (err: any) {
      setTesting(false)
      setTestResult({
        success: false,
        message: `Error saving or testing provider: ${err?.response?.data?.detail || err.message || err}`,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleRemove = async () => {
    if (!selectedProv) return
    if (!confirm(`Are you sure you want to remove the credentials for ${selectedProv.display_name}?`)) return

    setLoading(true)
    try {
      await deleteProviderKeys(selectedName)
      onSaved()
      onClose()
    } catch (err: any) {
      alert(`Error removing: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const handleTestConnectionOnly = async () => {
    if (!selectedProv) return
    setTesting(true)
    setTestResult(null)
    try {
      const res = await testProvider(selectedName)
      if (res.success) {
        setTestResult({
          success: true,
          message: `Connection successful! Latency: ${res.latency_ms}ms. Response: "${res.response}"`,
        })
      } else {
        setTestResult({
          success: false,
          message: `Test Connection Failed: ${res.error || 'Connection timeout'}`,
        })
      }
    } catch (err: any) {
      setTestResult({
        success: false,
        message: `Test Connection Error: ${err?.response?.data?.detail || err.message || err}`,
      })
    } finally {
      setTesting(false)
    }
  }

  const clouds = providers.filter((p) => !p.is_local && p.name !== 'openai_compatible')
  const locals = providers.filter((p) => p.is_local)
  const compat = providers.filter((p) => p.name === 'openai_compatible')

  return (
    <div className="modal-overlay">
      <div className="modal-content card" style={{ maxWidth: 500, width: '100%', position: 'relative' }}>
        <button className="modal-close" onClick={onClose} aria-label="Close modal">
          <X size={18} />
        </button>

        <h3 className="mb-4" style={{ fontWeight: 700, fontSize: 16 }}>
          {providerName ? 'Configure Provider' : 'Add LLM Provider'}
        </h3>

        <form onSubmit={handleSaveAndTest}>
          <div className="mb-4">
            <label className="form-label">Select Provider</label>
            <select
              className="form-input"
              value={selectedName}
              onChange={(e) => setSelectedName(e.target.value)}
              disabled={!!providerName || loading}
            >
              <optgroup label="Cloud Providers">
                {clouds.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.display_name} ({p.litellm_model})
                  </option>
                ))}
              </optgroup>
              <optgroup label="Local Providers">
                {locals.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.display_name} ({p.litellm_model})
                  </option>
                ))}
              </optgroup>
              <optgroup label="OpenAI-Compatible">
                {compat.map((p) => (
                  <option key={p.name} value={p.name}>
                    Custom OpenAI-Compatible Endpoints
                  </option>
                ))}
              </optgroup>
            </select>
          </div>

          {selectedProv && (
            <div className="mb-4 text-xs font-mono text-muted">
              Env var name: {selectedProv.api_key_env || 'None'}
            </div>
          )}

          {isCloud && selectedProv && (
            <div className="mb-4">
              <div className="flex items-center justify-between mb-1">
                <label className="form-label mb-0">API Key</label>
                {API_KEY_URLS[selectedProv.name] && (
                  <a
                    href={API_KEY_URLS[selectedProv.name]}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs flex items-center gap-1 link"
                    style={{ color: '#8b5cf6' }}
                  >
                    Get API Key <ExternalLink size={10} />
                  </a>
                )}
              </div>
              <input
                type="password"
                className="form-input font-mono"
                placeholder={selectedProv.api_key_configured ? 'Configured ✓ (enter to overwrite)' : 'Enter API Key'}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                disabled={loading}
                required={!selectedProv.api_key_configured}
              />
            </div>
          )}

          {isOllama && (
            <div className="mb-4">
              <label className="form-label">Base URL</label>
              <input
                type="text"
                className="form-input font-mono"
                placeholder="http://localhost:11434"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                disabled={loading}
              />
              <p className="text-xs text-muted mt-1">
                Ensure Ollama is running on your local machine. No API key is required.
              </p>
            </div>
          )}

          {isOpenAICompatible && (
            <>
              <div className="mb-3">
                <label className="form-label">Base URL</label>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="https://api.deepseek.com/v1"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  disabled={loading}
                  required
                />
              </div>
              <div className="mb-3">
                <label className="form-label">API Key</label>
                <input
                  type="password"
                  className="form-input font-mono"
                  placeholder={selectedProv?.api_key_configured ? 'Configured ✓ (enter to overwrite)' : 'Enter API Key'}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  disabled={loading}
                  required={!selectedProv?.api_key_configured}
                />
              </div>
              <div className="mb-4">
                <label className="form-label">Model Name</label>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="deepseek-coder"
                  value={modelName}
                  onChange={(e) => setModelName(e.target.value)}
                  disabled={loading}
                  required
                />
                <p className="text-xs text-muted mt-1">
                  Covers DeepSeek, OpenRouter, Together AI, Fireworks, Kimi, etc.
                </p>
              </div>
            </>
          )}

          {testResult && (
            <div
              className={`p-3 rounded text-xs mb-4 flex items-start gap-2 ${
                testResult.success
                  ? 'bg-success-subtle text-success border border-success'
                  : 'bg-failed-subtle text-failed border border-failed'
              }`}
              style={{
                backgroundColor: testResult.success ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                borderColor: testResult.success ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)',
                color: testResult.success ? '#22c55e' : '#ef4444',
              }}
            >
              {testResult.success ? <CheckCircle2 size={14} className="mt-0.5" /> : <AlertCircle size={14} className="mt-0.5" />}
              <div>{testResult.message}</div>
            </div>
          )}

          <div className="flex justify-between items-center gap-2 mt-6">
            <div>
              {selectedProv && (selectedProv.api_key_configured || isOllama) && (
                <button
                  type="button"
                  onClick={handleRemove}
                  className="btn btn-secondary flex items-center gap-1.5"
                  style={{ color: '#ef4444', borderColor: 'rgba(239,68,68,0.2)' }}
                  disabled={loading}
                >
                  <Trash2 size={14} /> Remove
                </button>
              )}
            </div>

            <div className="flex gap-2">
              {isOllama && (
                <button
                  type="button"
                  onClick={handleTestConnectionOnly}
                  className="btn btn-secondary flex items-center gap-1"
                  disabled={loading || testing}
                >
                  {testing && <Loader2 size={12} className="animate-spin" />} Test Connection
                </button>
              )}
              <button
                type="submit"
                className="btn btn-primary flex items-center gap-1.5"
                disabled={loading || testing}
              >
                {loading && <Loader2 size={14} className="animate-spin" />}
                {testing ? 'Testing...' : 'Save & Test'}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}
