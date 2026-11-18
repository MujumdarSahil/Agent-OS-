// src/flow/allRuns.ts — 2.4e: runs across all flows, built on the existing per-flow endpoints
// (GET /v2/flows, GET /v2/flows/{id}/runs). Fetched on page open; no polling.

import { useQuery } from '@tanstack/react-query'
import { listFlows, listRuns, type RunInfo } from '../api/flows'

export interface FlowRun extends RunInfo {
  flow_id: string
  flow_name: string
}

export async function fetchAllRuns(): Promise<FlowRun[]> {
  const flows = await listFlows()
  const byId = new Map<string, string>()
  for (const f of flows) if (!byId.has(f.id)) byId.set(f.id, f.name || f.id)
  const lists = await Promise.all(
    [...byId.entries()].map(async ([id, name]) => {
      try {
        return (await listRuns(id)).map(r => ({ ...r, flow_id: id, flow_name: name }))
      } catch {
        return [] as FlowRun[]
      }
    }),
  )
  return lists.flat().sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')))
}

export function useAllRuns() {
  return useQuery({ queryKey: ['all-runs'], queryFn: fetchAllRuns })
}

/** Link to a run in the existing results view of the flow editor. */
export const runHref = (flowId: string, runId: string) =>
  `/flows/${encodeURIComponent(flowId)}?run=${encodeURIComponent(runId)}`
