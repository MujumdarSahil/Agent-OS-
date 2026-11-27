// src/api/environments.ts — 4.3 versions, environments (staging / production), promote, rollback, version diffs.
// Permissions are enforced by the server: viewer reads; builder promotes / rolls back staging; admin production.

import { api } from './client'
import type { FlowDiff } from './builder'
import type { EnvironmentName } from './flows'

export interface DeploymentInfo {
  flow_id: string
  environment: EnvironmentName
  version: number
  previous_version: number | null
  action: 'migrate' | 'publish' | 'promote' | 'rollback'
  deployed_by: string | null
  deployed_at: string
  note: string
}

export interface EnvironmentSettings {
  flow_id: string
  auto_deploy_staging: boolean
  auto_deploy_production: boolean
  promote_test_gate: 'off' | 'warn' | 'block'
  second_person: boolean
  legacy: boolean
}

export interface EnvironmentsInfo {
  flow_id: string
  environments: Record<EnvironmentName, DeploymentInfo | null>
  settings: EnvironmentSettings
  archived_versions: number[]
}

export interface VersionRow {
  version: number
  change_note: string | null
  published_by: string | null
  published_at: string | null
  test_pass_rate: number | null
  test_run_id: string | null
  security: { passed: boolean; violations: number; policy_changed: boolean }
  environments: EnvironmentName[]
  archived: boolean
  runs: number
}

export interface VersionsSummary {
  flow_id: string
  versions: VersionRow[]
  environments: Record<EnvironmentName, number | null>
}

export interface SecurityChange { kind: string; node: string; detail: string; from?: unknown; to?: unknown }

export interface VersionDiff extends FlowDiff {
  from: string
  to: string
  security: SecurityChange[]
  nodes_changed_detail: { id: string; fields: string[]; config?: Record<string, [unknown, unknown]>; pinned_args?: Record<string, [unknown, unknown]> }[]
  analysis: { before: { passed: boolean; violations: string[] }; after: { passed: boolean; violations: string[] } }
}

export interface DeployCheck { name: string; passed: boolean; [k: string]: unknown }
export interface DeployResult { environment: EnvironmentName; from: number | null; to: number; checks: DeployCheck[]; warnings: string[] }

const F = (id: string) => `/v2/flows/${encodeURIComponent(id)}`

export const getEnvironments = (flowId: string) => api.get<EnvironmentsInfo>(`${F(flowId)}/environments`).then(r => r.data)
export const getVersionsSummary = (flowId: string) =>
  api.get<VersionsSummary>(`${F(flowId)}/versions/summary`).then(r => r.data)
export const getVersionDiff = (flowId: string, from: string | number, to: string | number) =>
  api.get<VersionDiff>(`${F(flowId)}/diff`, { params: { from: String(from), to: String(to) } }).then(r => r.data)

/** expectedVersion: the version the user saw in the environment (null = empty); a 409 means someone else changed it. */
export const deploy = (flowId: string, env: EnvironmentName, action: 'promote' | 'rollback', version: number,
                       expectedVersion: number | null, note = '') =>
  api.post<DeployResult>(`${F(flowId)}/environments/${env}/${action}`,
    { version, expected_version: expectedVersion, note }).then(r => r.data)

export const archiveVersion = (flowId: string, version: number) =>
  api.post(`${F(flowId)}/versions/${version}/archive`).then(r => r.data)

export const putStagingSettings = (flowId: string, autoDeployStaging: boolean) =>
  api.put<EnvironmentSettings>(`${F(flowId)}/environments/settings/staging`, { auto_deploy_staging: autoDeployStaging })
    .then(r => r.data)
export const putProductionSettings = (flowId: string,
  body: Partial<Pick<EnvironmentSettings, 'auto_deploy_production' | 'second_person' | 'promote_test_gate'>>) =>
  api.put<EnvironmentSettings>(`${F(flowId)}/environments/settings/production`, body).then(r => r.data)

export const setTriggerEnvironment = (kind: 'webhooks' | 'schedules', id: string, environment: EnvironmentName) =>
  api.put(`/v2/${kind}/${encodeURIComponent(id)}/environment`, { environment }).then(r => r.data)

/** The server's refusal text (409 checks, conflicts) or the generic message. */
export function deployError(err: unknown): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (d && typeof d === 'object' && 'error' in (d as Record<string, unknown>)) return String((d as { error: unknown }).error)
  if (typeof d === 'string') return d
  return (err as Error)?.message ?? 'request failed'
}
