// src/api/client.ts — Typed fetch wrappers for all AgentOS API resources (v1 & v2)

import axios from 'axios'

// ---------------------------------------------------------------------------
// 1. Auth Token & Interceptors
// ---------------------------------------------------------------------------

// 3.4: the browser is logged in with an HttpOnly session cookie (the page never sees it). State-changing requests
// also carry the per-session CSRF token from /api/v2/auth/me, kept only in memory (never in storage or the URL).
// The legacy local API token is for scripts only; the UI no longer reads it from the URL or stores it.
let csrfToken: string | null = null
let onUnauthorized: (() => void) | null = null

export function setCsrfToken(token: string | null): void {
  csrfToken = token
}

/** Called once by the auth provider: a 401 from the API means the session ended (expired, revoked, logged out). */
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn
}

export const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
  // 3.1: tells the audit log that the action came from the UI (source "ui"; scripts are "api")
  headers: { 'Content-Type': 'application/json', 'X-AgentOS-Client': 'ui' },
})

const UNSAFE = new Set(['post', 'put', 'patch', 'delete'])
api.interceptors.request.use(config => {
  if (csrfToken && UNSAFE.has((config.method || 'get').toLowerCase())) {
    config.headers.set('X-AgentOS-CSRF', csrfToken)
  }
  return config
})

api.interceptors.response.use(
  r => r,
  err => {
    const url = String(err?.config?.url || '')
    if (err?.response?.status === 401 && !url.startsWith('/v2/auth/') && onUnauthorized) onUnauthorized()
    return Promise.reject(err)
  },
)

// ---------------------------------------------------------------------------
// 2. WebSocket Stream Helper (the session cookie authenticates the upgrade; Origin is checked server-side)
// ---------------------------------------------------------------------------

export function createRunStreamWebSocket(runId: string): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const url = `${protocol}//${host}/api/runs/${runId}/stream`
  return new WebSocket(url, ['agentos.v1'])
}

// ---------------------------------------------------------------------------
// 3. Types Mirroring Server Models (v1)
// ---------------------------------------------------------------------------

export interface Agent {
  name: string
  role: string
  goal: string
  backstory: string
  llm_tags: string[]
  tool_refs: string[]
  memory_ref: string | null
}

export interface Tool {
  name: string
  file: string
}

export interface Crew {
  name: string
  agents: string[]
  process: string
}

export interface Task {
  description: string
  assigned_agent: string | null
}

export interface Mission {
  name: string
  goal: string
  description: string
  crew: string
  tasks: Task[]
}

export interface RunStatus {
  run_id: string
  mission_name: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  task_index: number
  outputs: string[]
  error: string | null
  provider: string | null
}

export interface Policy {
  id: string
  name: string
  policy_type: string
  priority: number
}

export interface MCPPlugin {
  name: string
  version: string
  author: string
  permissions: string[]
  entrypoint: string
  mcp_server_url: string | null
}

export interface Checkpoint {
  mission_id: string
  task_index: number
  status: string
  timestamp: string
  provider?: string
}

export interface HealthStatus {
  status: string
  version?: string
  project: string
  has_project: boolean
  agents: number
  tools: number
  crews: number
  missions: number
  last_used_model?: string
  fallback_events?: number
}

export interface TemplateInfo {
  name: string
  display_name: string
  description: string
  agents: string[]
  crews: string[]
  missions: string[]
  license_type: string
  tags: string[]
  pack_available: boolean
}

export interface TemplateInstallResult {
  installed: Record<string, string[]>
  pack: string | null
  version: string | null
  template_name: string
}

export interface ProviderStatus {
  name: string
  display_name: string
  litellm_model: string
  priority: number
  tags: string[]
  api_key_configured: boolean
  api_key_env: string | null
  api_base_env: string | null
  status: 'active' | 'unconfigured' | 'probe_failed'
  is_local: boolean
}

export interface FallbackChainItem {
  order: number
  name: string
  display_name: string
  litellm_model: string
  status: string
}

export interface ProviderTestResponse {
  success: boolean
  latency_ms: number
  response: string | null
  error: string | null
}

// ---------------------------------------------------------------------------
// 4. Types for v2 Core Resources
// ---------------------------------------------------------------------------

export interface V2AgentConfig {
  name: string
  role: string
  goal: string
  backstory?: string
  type?: string
  tools?: string[]
  tool_refs?: string[]
  verbose?: boolean
  llm?: string
  cache?: boolean
  allow_delegation?: boolean
  allow_code_execution?: boolean
  llm_tags?: string[]
  memory_ref?: string | null
}

export interface V2Squad {
  name: string
  agents: string[]
  process: string
  roles: Record<string, string>
}

export interface V2Tool {
  name: string
  description: string
  language: 'python'
  code: string
  origin: 'stored' | 'project'
}

export interface V2MCPServer {
  name: string
  transport: 'stdio' | 'sse' | 'http'
  command?: string
  args: string[]
  url?: string
  env: Record<string, string>
  secret_env: Record<string, string>
  enabled: boolean
}

export interface V2SecretInfo {
  name: string
  provider?: string | null
  hint: string
  key_id: string
  created_at: string
  updated_at: string
}

export interface V2Provider {
  name: string
  display_name: string
  litellm_model: string
  priority: number
  tags: string[]
  api_key_configured: boolean
  api_key_env: string | null
  api_base_env: string | null
  is_local: boolean
  billing_plan?: 'free' | 'paid' | null // 3.3: admin billing plan (null = default)
}

export interface V2ProviderTestResult {
  ok: boolean
  error_class?: string | null
  message?: string | null
}

export interface V2FallbackPolicyItem {
  name: string
  order: number
  enabled: boolean
  timeout_s?: number | null
  display_name?: string | null
  litellm_model?: string | null
}

// ---------------------------------------------------------------------------
// 5. v1 API Calls
// ---------------------------------------------------------------------------

export const getHealth = () => api.get<HealthStatus>('/health').then(r => r.data)

export const getAgents = () => api.get<Agent[]>('/agents').then(r => r.data)
export const getAgent = (name: string) => api.get<Agent>(`/agents/${name}`).then(r => r.data)
export const createAgent = (a: Agent) => api.post<Agent>('/agents', a).then(r => r.data)
export const updateAgent = (name: string, a: Agent) => api.put<Agent>(`/agents/${name}`, a).then(r => r.data)
export const deleteAgent = (name: string) => api.delete(`/agents/${name}`)

export const getTools = () => api.get<Tool[]>('/tools').then(r => r.data)
export const createTool = (name: string, description?: string) =>
  api.post<Tool>('/tools', { name, description }).then(r => r.data)

export const getCrews = () => api.get<Crew[]>('/crews').then(r => r.data)
export const createCrew = (c: Crew) => api.post<Crew>('/crews', c).then(r => r.data)

export const getMissions = () => api.get<Mission[]>('/missions').then(r => r.data)
export const createMission = (m: Mission) => api.post<Mission>('/missions', m).then(r => r.data)
export const runMission = (name: string, resume = false, licenseKey?: string) =>
  api.post<{ run_id: string; mission_name: string; status: string }>(
    `/missions/${name}/run`,
    { resume, license_key: licenseKey ?? null },
    { params: { resume } }
  ).then(r => r.data)

export const getRunStatus = (runId: string) => api.get<RunStatus>(`/runs/${runId}/status`).then(r => r.data)

export const getCheckpoints = (missionName?: string) =>
  missionName
    ? api.get<Checkpoint[]>(`/checkpoints/${missionName}`).then(r => r.data)
    : api.get<Checkpoint[]>('/checkpoints').then(r => r.data)

export const getPolicies = () => api.get<Policy[]>('/governance/policies').then(r => r.data)
export const createPolicy = (p: { name: string; policy_type: string; denied_keywords: string[]; allowed_keywords: string[]; priority: number }) =>
  api.post<Policy>('/governance/policies', p).then(r => r.data)
export const deletePolicy = (id: string) => api.delete(`/governance/policies/${id}`)

export const getMCPPlugins = () => api.get<MCPPlugin[]>('/mcp-plugins').then(r => r.data)
export const createMCPPlugin = (name: string) => api.post<MCPPlugin>('/mcp-plugins', { name }).then(r => r.data)

export const previewAgent = (description: string) =>
  api.post<{ config: Record<string, unknown>; preview_token: string }>('/builder/agent', { description }).then(r => r.data)
export const confirmAgent = (config: Record<string, unknown>) =>
  api.post<{ file_path: string; config: Record<string, unknown> }>('/builder/agent/confirm', { config }).then(r => r.data)
export const previewTool = (description: string) =>
  api.post<{ config: Record<string, unknown>; preview_token: string }>('/builder/tool', { description }).then(r => r.data)
export const confirmTool = (config: Record<string, unknown>) =>
  api.post<{ file_path: string; config: Record<string, unknown> }>('/builder/tool/confirm', { config }).then(r => r.data)
export const previewCrew = (description: string) =>
  api.post<{ config: Record<string, unknown>; preview_token: string }>('/builder/crew', { description }).then(r => r.data)
export const confirmCrew = (config: Record<string, unknown>) =>
  api.post<{ file_path: string; config: Record<string, unknown> }>('/builder/crew/confirm', { config }).then(r => r.data)

export const buildPack = (data: { include_agents: string[]; include_tools: string[]; include_crews: string[]; output_name: string }) =>
  api.post<{ pack_path: string; size_bytes: number }>('/packaging/build', data).then(r => r.data)
export const signPack = (pack_path: string, private_key_path: string) =>
  api.post('/packaging/sign', { pack_path, private_key_path }).then(r => r.data)
export const verifyPack = (pack_path: string) =>
  api.post<{ valid: boolean; signer_fingerprint: string | null; detail: string }>('/packaging/verify', { pack_path }).then(r => r.data)
export const installPack = (pack_path: string, target_project_path: string, force = false, license_key?: string) =>
  api.post('/packaging/install', { pack_path, target_project_path, force, license_key: license_key ?? null }).then(r => r.data)

export const getTemplates = () => api.get<TemplateInfo[]>('/templates').then(r => r.data)
export const installTemplate = (name: string, force = false) =>
  api.post<TemplateInstallResult>(`/templates/${name}/install`, { force }).then(r => r.data)

export const getProviders = () => api.get<ProviderStatus[]>('/providers').then(r => r.data)
export const saveProviderKeys = (data: { provider_name: string; api_key?: string; api_base_url?: string; model_name?: string }) =>
  api.post<{ success: boolean; provider_name: string; key_env_var: string }>('/providers/keys', data).then(r => r.data)
export const deleteProviderKeys = (name: string) => api.delete<{ success: boolean }>(`/providers/keys/${name}`).then(r => r.data)
export const getFallbackChain = () => api.get<FallbackChainItem[]>('/providers/fallback-chain').then(r => r.data)
export const testProvider = (name: string) => api.post<ProviderTestResponse>(`/providers/test/${name}`).then(r => r.data)

// ---------------------------------------------------------------------------
// 6. v2 Core Resource API Calls (/api/v2/*)
// ---------------------------------------------------------------------------

// Agents v2
export const getV2Agents = () => api.get<V2AgentConfig[]>('/v2/agents').then(r => r.data)
export const getV2Agent = (name: string) => api.get<V2AgentConfig>(`/v2/agents/${name}`).then(r => r.data)
export const createV2Agent = (agent: Partial<V2AgentConfig> & { name: string; role: string; goal: string }) =>
  api.post<V2AgentConfig>('/v2/agents', agent).then(r => r.data)
export const deleteV2Agent = (name: string) => api.delete(`/v2/agents/${name}`).then(r => r.data)

// Squads v2
export const getV2Squads = () => api.get<V2Squad[]>('/v2/squads').then(r => r.data)
export const getV2Squad = (name: string) => api.get<V2Squad>(`/v2/squads/${name}`).then(r => r.data)
export const createV2Squad = (squad: V2Squad) => api.post<V2Squad>('/v2/squads', squad).then(r => r.data)
export const deleteV2Squad = (name: string) => api.delete(`/v2/squads/${name}`).then(r => r.data)

// Tools v2
export const getV2Tools = () => api.get<V2Tool[]>('/v2/tools').then(r => r.data)

/** 3.1: tools an agent may be given: exactly what the server's tool catalog resolves (built-in agent tools and
 *  admin-approved MCP tools). The picker offers nothing else. */
export interface AgentToolOption {
  name: string
  kind: 'builtin' | 'mcp'
  side_effect: string
  server: string | null
  description: string
}
export const getAgentToolOptions = () =>
  api.get<AgentToolOption[]>('/v2/agents/tool-options').then(r => r.data)
export const getV2Tool = (name: string) => api.get<V2Tool>(`/v2/tools/${name}`).then(r => r.data)
export const createV2Tool = (tool: { name: string; description?: string; code?: string; language?: 'python' }) =>
  api.post<V2Tool>('/v2/tools', tool).then(r => r.data)
export const deleteV2Tool = (name: string) => api.delete(`/v2/tools/${name}`).then(r => r.data)

// External MCP Servers v2
export const getV2MCPServers = () => api.get<V2MCPServer[]>('/v2/mcp-servers').then(r => r.data)
export const getV2MCPServer = (name: string) => api.get<V2MCPServer>(`/v2/mcp-servers/${name}`).then(r => r.data)
export const createV2MCPServer = (server: V2MCPServer) =>
  api.post<V2MCPServer>('/v2/mcp-servers', server).then(r => r.data)
export const deleteV2MCPServer = (name: string) => api.delete(`/v2/mcp-servers/${name}`).then(r => r.data)

// 2.5a: discovery and review. Tool descriptions and schemas are server-controlled UNTRUSTED text:
// render them only as plain text.
export type MCPToolStatus = 'unreviewed' | 'approved' | 'changed' | 'missing'
export type MCPSideEffect = 'read' | 'write' | 'external_send' | 'destructive'
export interface MCPToolState {
  snapshot: { name: string; description: string; input_schema: Record<string, unknown>; sha256: string; label: 'untrusted' }
  approval: null | {
    approved_sha256: string
    side_effect: MCPSideEffect
    untrusted_ok_args: string[]
    output_confidentiality: string
    replacement_description: string | null
  }
  missing: boolean
  warnings: string[]
  status: MCPToolStatus
  canonical_name: string
  wire_name: string
}
export interface V2MCPServerView extends V2MCPServer {
  tools?: Record<string, MCPToolState>
  last_discovery?: { at: number; tool_count: number; rejected?: { tool: string; reason: string }[] } | null
}
export interface MCPLaunchPreview {
  transport: string
  command_line?: string
  argv?: string[]
  cwd?: string
  env_names?: string[]
  secret_env?: Record<string, string>
  inherits_parent_env?: boolean
  url?: string
  note?: string
}
export interface MCPApproveBody {
  expected_sha256: string
  side_effect: MCPSideEffect
  untrusted_ok_args: string[]
  output_confidentiality: string
  replacement_description?: string | null
}
const mcpPath = (name: string) => `/v2/mcp-servers/${encodeURIComponent(name)}`
export const getMCPServersView = () => api.get<V2MCPServerView[]>('/v2/mcp-servers').then(r => r.data)
export const getMCPLaunchPreview = (name: string) =>
  api.get<MCPLaunchPreview>(`${mcpPath(name)}/launch-preview`).then(r => r.data)
export const setMCPEnabled = (name: string, enabled: boolean) =>
  api.post<{ server: V2MCPServerView; launch_preview: MCPLaunchPreview }>(`${mcpPath(name)}/enable`, { enabled }).then(r => r.data)
export const discoverMCPServer = (name: string) =>
  api.post<V2MCPServerView>(`${mcpPath(name)}/discover`).then(r => r.data)
export const approveMCPTool = (name: string, tool: string, body: MCPApproveBody) =>
  api.post<V2MCPServerView>(`${mcpPath(name)}/tools/${encodeURIComponent(tool)}/approve`, body).then(r => r.data)
export const revokeMCPTool = (name: string, tool: string) =>
  api.post<V2MCPServerView>(`${mcpPath(name)}/tools/${encodeURIComponent(tool)}/revoke`).then(r => r.data)

// Vault v2
export const getV2VaultKeys = () => api.get<V2SecretInfo[]>('/v2/vault/keys').then(r => r.data)
export const saveV2VaultKey = (data: { name: string; secret: string; provider?: string }) =>
  api.post<V2SecretInfo>('/v2/vault/keys', data).then(r => r.data)
export const deleteV2VaultKey = (name: string) => api.delete(`/v2/vault/keys/${name}`).then(r => r.data)

// Providers v2
export const getV2Providers = () => api.get<V2Provider[]>('/v2/providers').then(r => r.data)
export const testV2ProviderConnection = (providerName: string, apiKey?: string, apiBaseUrl?: string) =>
  api.post<V2ProviderTestResult>('/v2/providers/test-connection', {
    provider_name: providerName,
    api_key: apiKey || null,
    api_base_url: apiBaseUrl || null,
  }).then(r => r.data)

export const getV2FallbackPolicy = () => api.get<V2FallbackPolicyItem[]>('/v2/providers/fallback').then(r => r.data)
export const updateV2FallbackPolicy = (items: V2FallbackPolicyItem[]) =>
  api.put<V2FallbackPolicyItem[]>('/v2/providers/fallback', { items }).then(r => r.data)
