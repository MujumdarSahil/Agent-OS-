// src/api/sandbox.ts — 3.5 code sandbox (/api/v2/sandbox). Settings changes are audited on the server.

import { api } from './client'

export interface SandboxLimits {
  timeout_s: number
  memory_mb: number
  cpus: number
  pids: number
  stdout_kb: number
  stderr_kb: number
  workspace_mb: number
  file_mb: number
}

export interface SandboxImage { ref: string; note: string }

export interface SandboxSettings {
  backend: 'auto' | 'docker' | 'wasm' | 'off'
  limits: SandboxLimits
  images: SandboxImage[]
  default_image: string
}

export interface BackendStatus {
  available: boolean
  detail?: string
  kinds: string[]
  client?: string | null
  server?: string | null
  wasmtime?: string | null
  build?: 'installed' | 'missing' | 'tampered'
  build_sha256?: string
}

export interface SandboxStatus {
  mode: SandboxSettings['backend']
  summary: string
  docker: BackendStatus
  wasm: BackendStatus
  effective: { python: string | null; shell: string | null }
  tools: string[]
  limits: SandboxLimits
  images: SandboxImage[]
  default_image: string
}

export interface SandboxTestResult {
  ok: boolean
  backend: string | null
  exit_code?: number | null
  limit_hit?: string | null
  duration_ms?: number
  stdout?: string
  stderr?: string
  error?: string | null
}

export const getSandboxStatus = () => api.get<SandboxStatus>('/v2/sandbox/status').then(r => r.data)
export const getSandboxSettings = () => api.get<SandboxSettings>('/v2/sandbox/settings').then(r => r.data)
export const putSandboxSettings = (s: SandboxSettings) => api.put<SandboxSettings>('/v2/sandbox/settings', s).then(r => r.data)
export const testSandbox = () => api.post<SandboxTestResult>('/v2/sandbox/test').then(r => r.data)
export const installWasm = () => api.post<{ installed: boolean; sha256: string }>('/v2/sandbox/wasm/install').then(r => r.data)
