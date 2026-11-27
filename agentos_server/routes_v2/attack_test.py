"""4.1 "Attack my flow" (design: docs/evidence/4.1.md D10, D11).

POST /api/v2/flows/{flow_id}/attack-test (build): runs the attack families that fit the flow against an isolated copy
(temp storage, adversarial MOCK model, fake recording sinks). No real model, no cost, no real send, nothing saved to
the flow. Audited as flow.attack_test with counts only.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from agentos.builder.service import base_flow_dict
from agentos.flows.policy import SecurityPolicy
from agentos_server.audit_support import audit

router = APIRouter(prefix="/flows", tags=["v2-attack-test"])


class AttackTestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flow: Optional[Dict[str, Any]] = None  # the editor's current (possibly unsaved) graph; else the stored draft


@router.post("/{flow_id}/attack-test")
async def attack_test(flow_id: str, request: Request, body: Optional[AttackTestBody] = None) -> Dict[str, Any]:
    from agentos.flows.tool_catalog import ToolCatalog
    from agentos.redteam.myflow import attack_my_flow

    storage = request.app.state.storage
    if body is not None and body.flow is not None:
        rec = {**body.flow, "id": flow_id}
    else:
        draft = await storage.flows.get_draft(flow_id)
        if draft is None:
            versions = await storage.flows.list_versions(flow_id)
            draft = versions[-1] if versions else None
        if draft is None:
            raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found")
        rec = draft.model_dump(mode="json")
    if not rec.get("entrypoint") or not rec.get("nodes"):
        raise HTTPException(status_code=400, detail="The flow needs nodes and an entrypoint")
    flow = base_flow_dict(rec)
    policy = getattr(request.app.state, "security_policy", None) or SecurityPolicy()
    repo = getattr(storage, "mcp_servers", None)
    catalog = ToolCatalog(await repo.list() if repo is not None else [])
    try:
        report = await attack_my_flow(flow, policy, catalog)
    except ValueError as err:  # FlowDefinition refused the graph
        raise HTTPException(status_code=400, detail=f"The flow is not valid: {err}")
    # counts only (never payloads, addresses or flow content)
    await audit(request, "flow.attack_test", "flow", flow_id, details={
        "tried": report["tried"], "stopped": report["stopped"], "succeeded": report["succeeded"],
        "families": len({a["family"] for a in report["attacks"]}), "violations": len(report["violations"]),
    })
    return report
