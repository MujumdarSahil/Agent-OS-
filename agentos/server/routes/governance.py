"""Governance routes — list policies and add keyword-based policies."""
import logging
from typing import List

from fastapi import APIRouter, HTTPException, Request

from agentos.core.governance import GovernanceEngine
from agentos.server.models import PolicyInfo, PolicyCreateRequest

logger = logging.getLogger(__name__)
router = APIRouter(tags=["governance"])


def _gov(request: Request) -> GovernanceEngine:
    return request.app.state.governance


@router.get("/governance/policies", response_model=List[PolicyInfo])
async def get_policies(request: Request):
    gov = _gov(request)
    return [
        PolicyInfo(
            id=p.id,
            name=p.name,
            policy_type=p.policy_type.value,
            priority=p.priority,
        )
        for p in gov.policies.values()
    ]


@router.post("/governance/policies", response_model=PolicyInfo, status_code=201)
async def create_policy(body: PolicyCreateRequest, request: Request):
    """
    Add a keyword-based action policy.
    Uses GovernanceEngine.create_action_policy with denied/allowed keyword lists.
    A governance block during a mission run returns HTTP 400 with the policy reason.
    """
    gov = _gov(request)
    try:
        policy = gov.create_action_policy(
            name=body.name,
            denied_actions=body.denied_keywords or None,
            allowed_actions=body.allowed_keywords or None,
            priority=body.priority,
        )
        gov.register_policy(policy, group="user_policies")
        return PolicyInfo(
            id=policy.id,
            name=policy.name,
            policy_type=policy.policy_type.value,
            priority=policy.priority,
        )
    except Exception as e:
        logger.exception("create_policy failed")
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/governance/policies/{policy_id}", status_code=204)
async def delete_policy(policy_id: str, request: Request):
    gov = _gov(request)
    removed = gov.remove_policy(policy_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found")
