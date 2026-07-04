// src/api/client.ts — Typed fetch wrappers for all AgentOS API resources

import axios from 'axios'

export const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

// Types mirroring agentos/server/models.py

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

// ---- Health ----
export const getHealth = () => api.get<HealthStatus>('/health').then(r => r.data)

// ---- Agents ----
export const getAgents = () => api.get<Agent[]>('/agents').then(r => r.data)
export const getAgent = (name: string) => api.get<Agent>(`/agents/${name}`).then(r => r.data)
export const createAgent = (a: Agent) => api.post<Agent>('/agents', a).then(r => r.data)
export const updateAgent = (name: string, a: Agent) => api.put<Agent>(`/agents/${name}`, a).then(r => r.data)
export const deleteAgent = (name: string) => api.delete(`/agents/${name}`)

// ---- Tools ----
export const getTools = () => api.get<Tool[]>('/tools').then(r => r.data)
export const createTool = (name: string, description?: string) =>
  api.post<Tool>('/tools', { name, description }).then(r => r.data)

// ---- Crews ----
export const getCrews = () => api.get<Crew[]>('/crews').then(r => r.data)
export const createCrew = (c: Crew) => api.post<Crew>('/crews', c).then(r => r.data)

// ---- Missions ----
export const getMissions = () => api.get<Mission[]>('/missions').then(r => r.data)
export const createMission = (m: Mission) => api.post<Mission>('/missions', m).then(r => r.data)
export const runMission = (name: string, resume = false, licenseKey?: string) =>
  api.post<{ run_id: string; mission_name: string; status: string }>(
    `/missions/${name}/run`,
    { resume, license_key: licenseKey ?? null },
    { params: { resume } }
  ).then(r => r.data)

// ---- Runs ----
export const getRunStatus = (runId: string) => api.get<RunStatus>(`/runs/${runId}/status`).then(r => r.data)

// ---- Checkpoints ----
export const getCheckpoints = (missionName?: string) =>
  missionName
    ? api.get<Checkpoint[]>(`/checkpoints/${missionName}`).then(r => r.data)
    : api.get<Checkpoint[]>('/checkpoints').then(r => r.data)

// ---- Governance ----
export const getPolicies = () => api.get<Policy[]>('/governance/policies').then(r => r.data)
export const createPolicy = (p: { name: string; policy_type: string; denied_keywords: string[]; allowed_keywords: string[]; priority: number }) =>
  api.post<Policy>('/governance/policies', p).then(r => r.data)
export const deletePolicy = (id: string) => api.delete(`/governance/policies/${id}`)

// ---- MCP Plugins ----
export const getMCPPlugins = () => api.get<MCPPlugin[]>('/mcp-plugins').then(r => r.data)
export const createMCPPlugin = (name: string) => api.post<MCPPlugin>('/mcp-plugins', { name }).then(r => r.data)

// ---- Builder ----
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

// ---- Packaging ----
export const buildPack = (data: { include_agents: string[]; include_tools: string[]; include_crews: string[]; output_name: string }) =>
  api.post<{ pack_path: string; size_bytes: number }>('/packaging/build', data).then(r => r.data)
export const signPack = (pack_path: string, private_key_path: string) =>
  api.post('/packaging/sign', { pack_path, private_key_path }).then(r => r.data)
export const verifyPack = (pack_path: string) =>
  api.post<{ valid: boolean; signer_fingerprint: string | null; detail: string }>('/packaging/verify', { pack_path }).then(r => r.data)
export const installPack = (pack_path: string, target_project_path: string, force = false, license_key?: string) =>
  api.post('/packaging/install', { pack_path, target_project_path, force, license_key: license_key ?? null }).then(r => r.data)

// ---- Templates ----
export const getTemplates = () => api.get<TemplateInfo[]>('/templates').then(r => r.data)
export const installTemplate = (name: string, force = false) =>
  api.post<TemplateInstallResult>(`/templates/${name}/install`, { force }).then(r => r.data)

// ---- LLM Providers ----
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

export const getProviders = () => api.get<ProviderStatus[]>('/providers').then(r => r.data)
export const saveProviderKeys = (data: { provider_name: string; api_key?: string; api_base_url?: string; model_name?: string }) =>
  api.post<{ success: boolean; provider_name: string; key_env_var: string }>('/providers/keys', data).then(r => r.data)
export const deleteProviderKeys = (name: string) => api.delete<{ success: boolean }>(`/providers/keys/${name}`).then(r => r.data)
export const getFallbackChain = () => api.get<FallbackChainItem[]>('/providers/fallback-chain').then(r => r.data)
export const testProvider = (name: string) => api.post<ProviderTestResponse>(`/providers/test/${name}`).then(r => r.data)
