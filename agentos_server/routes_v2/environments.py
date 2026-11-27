"""4.3: versions, environments (staging / production), promote, rollback, version diffs (/api/v2).

Design: docs/evidence/4.3.md. Permissions are decided by the route table (agentos_server/permissions_table.py):
viewer reads; builder promotes / rolls back STAGING and sets staging auto-deploy; admin promotes / rolls back
PRODUCTION, changes the production settings and the staging channel mapping. Environment-specific actions are
separate literal paths so the table (deny by default) decides by capability.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from agentos.flows.environments import (
    DeploymentService,
    EnvError,
    environment_version,
    resolve_subflow_summaries,
    settings_for,
    static_check,
)
from agentos.flows.policy import SecurityPolicy
from agentos.storage.models import ENVIRONMENTS, StagingChannels, utcnow
from agentos_server.audit_support import actor_of, audit, audit_best_effort, source_of

router = APIRouter(tags=["v2-environments"])

_UNSET: Any = object()


class DeployRequest(BaseModel):
    version: int = Field(..., ge=1)
    # the version the caller saw in the environment (None = it was empty); omitted = whatever is current
    expected_version: Optional[int] = Field(default=None)
    note: str = Field(default="", max_length=500)


class StagingSettingsRequest(BaseModel):
    auto_deploy_staging: bool


class ProductionSettingsRequest(BaseModel):
    auto_deploy_production: Optional[bool] = None
    second_person: Optional[bool] = None
    promote_test_gate: Optional[Literal["off", "warn", "block"]] = None


class StagingChannelsRequest(BaseModel):
    email_channel: Optional[str] = Field(default=None, max_length=100)
    slack_channels: List[str] = Field(default_factory=list, max_length=20)


def _policy(request: Request) -> Any:
    return getattr(request.app.state, "security_policy", None) or SecurityPolicy()


def _who(request: Request) -> Optional[Dict[str, Any]]:
    p = getattr(request.state, "principal", None)
    if p is None:
        return None
    return {"user_id": p.actor_id, "username": p.username or p.actor, "via": p.kind}


def _storage(request: Request) -> Any:
    storage = request.app.state.storage
    if getattr(storage, "deployments", None) is None:
        raise HTTPException(status_code=501, detail="this storage backend has no environments")
    return storage


def deployment_service(request: Request) -> DeploymentService:
    """The DeploymentService of this request, with the 4.2 suite as the promote test gate (MOCK model by default,
    fake transports only)."""
    storage = _storage(request)

    async def gate(flow_id: str, version: int, mode: str) -> Dict[str, Any]:
        from agentos.flowtests import flowtests_store_for
        from agentos.flowtests.service import version_gate
        from agentos_server.routes_v2.flow_tests import test_env

        who = _who(request) or {}
        return await version_gate(flowtests_store_for(storage), await test_env(request), flow_id, version,
                                  started_by=who.get("username"))

    return DeploymentService(storage, _policy(request), test_gate_runner=gate)


async def _flow_exists(storage: Any, flow_id: str) -> None:
    if await storage.flows.get_draft(flow_id) is None and not await storage.flows.list_versions(flow_id):
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found")


# ------------------------------------------------------------------------------------------------ environments


@router.get("/flows/{flow_id}/environments")
async def get_environments(flow_id: str, request: Request) -> Dict[str, Any]:
    storage = _storage(request)
    await _flow_exists(storage, flow_id)
    await environment_version(storage, flow_id, "production")  # legacy migration if this flow predates 4.3
    cur = await storage.deployments.current(flow_id)
    return {
        "flow_id": flow_id,
        "environments": {env: (cur[env].model_dump(mode="json") if env in cur else None) for env in ENVIRONMENTS},
        "settings": (await settings_for(storage, flow_id)).model_dump(mode="json"),
        "archived_versions": await storage.deployments.archived_versions(flow_id),
    }


@router.get("/flows/{flow_id}/environments/history")
async def get_environment_history(flow_id: str, request: Request,
                                  limit: int = Query(100, ge=1, le=500)) -> List[Dict[str, Any]]:
    storage = _storage(request)
    return [r.model_dump(mode="json") for r in await storage.deployments.history(flow_id, limit)]


async def _deploy(request: Request, flow_id: str, environment: str, action: str, body: DeployRequest) -> Dict[str, Any]:
    from agentos.flows.environments import _check_summary

    storage = _storage(request)
    await _flow_exists(storage, flow_id)
    svc = deployment_service(request)
    audit_action = "flow.promote" if action == "promote" else "flow.rollback"

    async def before_commit(details: Dict[str, Any]) -> None:
        # audited BEFORE the environment changes (503 and no change if the entry cannot be written)
        await audit(request, audit_action, "flow", flow_id, details={**details, "note_chars": len(body.note)})

    kwargs: Dict[str, Any] = {"actor": _who(request), "action": action, "note": body.note,
                              "before_commit": before_commit}
    if "expected_version" in body.model_fields_set:
        kwargs["expected_version"] = body.expected_version
    try:
        return await svc.deploy(flow_id, environment, body.version, **kwargs)
    except EnvError as err:
        d = err.detail
        await audit_best_effort(request.app, audit_action, "flow", flow_id, outcome="refused", details={
            "environment": environment, "from": d.get("from"), "to": body.version, "reason": str(err)[:300],
            "checks": _check_summary(d.get("checks") or [])}, actor=actor_of(request), source=source_of(request))
        raise HTTPException(status_code=err.status, detail=d)


@router.post("/flows/{flow_id}/environments/staging/promote")
async def promote_staging(flow_id: str, body: DeployRequest, request: Request) -> Dict[str, Any]:
    return await _deploy(request, flow_id, "staging", "promote", body)


@router.post("/flows/{flow_id}/environments/production/promote")
async def promote_production(flow_id: str, body: DeployRequest, request: Request) -> Dict[str, Any]:
    return await _deploy(request, flow_id, "production", "promote", body)


@router.post("/flows/{flow_id}/environments/staging/rollback")
async def rollback_staging(flow_id: str, body: DeployRequest, request: Request) -> Dict[str, Any]:
    return await _deploy(request, flow_id, "staging", "rollback", body)


@router.post("/flows/{flow_id}/environments/production/rollback")
async def rollback_production(flow_id: str, body: DeployRequest, request: Request) -> Dict[str, Any]:
    return await _deploy(request, flow_id, "production", "rollback", body)


# ------------------------------------------------------------------------------------------------ settings


async def _put_settings(request: Request, flow_id: str, changes: Dict[str, Any], scope: str) -> Dict[str, Any]:
    storage = _storage(request)
    await _flow_exists(storage, flow_id)
    await environment_version(storage, flow_id, "production")  # a pre-4.3 flow keeps its legacy defaults
    cur = await settings_for(storage, flow_id)
    if not changes:
        return cur.model_dump(mode="json")
    new = cur.model_copy(update={**changes, "updated_by": (_who(request) or {}).get("username"),
                                 "updated_at": utcnow()})
    await audit(request, "flow.env_settings", "flow", flow_id, details={
        "scope": scope, "changes": {k: [getattr(cur, k), v] for k, v in changes.items()}})
    await storage.deployments.put_settings(new)
    return new.model_dump(mode="json")


@router.put("/flows/{flow_id}/environments/settings/staging")
async def put_staging_settings(flow_id: str, body: StagingSettingsRequest, request: Request) -> Dict[str, Any]:
    return await _put_settings(request, flow_id, {"auto_deploy_staging": body.auto_deploy_staging}, "staging")


@router.put("/flows/{flow_id}/environments/settings/production")
async def put_production_settings(flow_id: str, body: ProductionSettingsRequest, request: Request) -> Dict[str, Any]:
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    return await _put_settings(request, flow_id, changes, "production")


@router.get("/environments/staging-channels")
async def get_staging_channels(request: Request) -> Dict[str, Any]:
    return (await _storage(request).deployments.get_staging_channels()).model_dump(mode="json")


@router.put("/environments/staging-channels")
async def put_staging_channels(body: StagingChannelsRequest, request: Request) -> Dict[str, Any]:
    storage = _storage(request)
    notify = getattr(request.app.state, "notify", None)
    if notify is not None:  # only existing channels of the right kind can be mapped
        from agentos.notify.channels import EmailChannel, SlackChannel

        if body.email_channel and not isinstance(await notify.channel(body.email_channel), EmailChannel):
            raise HTTPException(status_code=400, detail=f"{body.email_channel!r} is not an email channel")
        for name in body.slack_channels:
            if not isinstance(await notify.channel(name), SlackChannel):
                raise HTTPException(status_code=400, detail=f"{name!r} is not a Slack channel")
    new = StagingChannels(email_channel=body.email_channel or None, slack_channels=sorted(set(body.slack_channels)),
                          updated_by=(_who(request) or {}).get("username"))
    await audit(request, "env.staging_channels", "environment", "staging", details={
        "email_channel": new.email_channel, "slack_channels": new.slack_channels})
    await storage.deployments.put_staging_channels(new)
    return new.model_dump(mode="json")


# ------------------------------------------------------------------------------------------------ versions


@router.get("/flows/{flow_id}/versions/summary")
async def versions_summary(flow_id: str, request: Request) -> Dict[str, Any]:
    """D8: every published version with its note, publisher, test pass rate, security check status against the
    CURRENT policy, environment badges, archived flag and number of runs."""
    from agentos.flowtests import flowtests_store_for

    storage = _storage(request)
    await _flow_exists(storage, flow_id)
    await environment_version(storage, flow_id, "production")
    cur = await storage.deployments.current(flow_id)
    archived = set(await storage.deployments.archived_versions(flow_id))
    suite_runs = await flowtests_store_for(storage).list_runs(flow_id)
    runs = [r for r in await storage.runs.list(limit=1000) if r.flow_id == flow_id]
    policy = _policy(request)
    out = []
    for v in reversed(await storage.flows.list_versions(flow_id)):
        latest = next((s for s in suite_runs if s.version == v.version), None)
        sc = await static_check(storage, policy, v)
        out.append({
            "version": v.version, "change_note": v.change_note, "published_by": v.published_by,
            "published_at": v.published_at, "content_sha256": v.content_sha256,
            "test_pass_rate": latest.pass_rate() if latest else None,
            "test_run_id": latest.id if latest else None,
            "security": {"passed": sc["passed"], "violations": len(sc["violations"]),
                         "policy_changed": sc["policy_changed"]},
            "environments": sorted(e for e, rec in cur.items() if rec.version == v.version),
            "archived": v.version in archived,
            "runs": sum(1 for r in runs if r.flow_version == v.version),
        })
    return {"flow_id": flow_id, "versions": out,
            "environments": {e: (cur[e].version if e in cur else None) for e in ENVIRONMENTS}}


@router.post("/flows/{flow_id}/versions/{version}/archive")
async def archive_version(flow_id: str, version: int, request: Request) -> Dict[str, Any]:
    """Archive a version (versions are never deleted). Refused while an environment points to it."""
    storage = _storage(request)
    if await storage.flows.get_version(flow_id, version) is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} version {version} not found")
    cur = await storage.deployments.current(flow_id)
    used = sorted(e for e, rec in cur.items() if rec.version == version)
    if used:
        await audit_best_effort(request.app, "flow.version_archive", "flow", flow_id, outcome="refused",
                                details={"version": version, "environments": used},
                                actor=actor_of(request), source=source_of(request))
        raise HTTPException(status_code=409, detail=f"v{version} is deployed to {', '.join(used)}; "
                                                    "deploy another version there first")
    await audit(request, "flow.version_archive", "flow", flow_id, details={"version": version})
    await storage.deployments.archive_version(flow_id, version)
    return {"flow_id": flow_id, "version": version, "archived": True}


async def _flow_side(storage: Any, flow_id: str, ref: str) -> Dict[str, Any]:
    from agentos.flowtests.runner import flow_dict

    if ref == "draft":
        rec = await storage.flows.get_draft(flow_id)
        if rec is None:
            raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} has no draft")
    else:
        try:
            v = int(ref.lstrip("v"))
        except ValueError:
            raise HTTPException(status_code=400, detail="from/to must be a version number or 'draft'")
        rec = await storage.flows.get_version(flow_id, v)
        if rec is None:
            raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} version {v} not found")
    return flow_dict(rec)


@router.get("/flows/{flow_id}/diff")
async def diff_versions(flow_id: str, request: Request, from_: str = Query(..., alias="from"),
                        to: str = Query(...)) -> Dict[str, Any]:
    """D7: diff between two versions (or the draft and a version), security-relevant changes first."""
    from agentos.flows.environments import flow_definition, tool_catalog
    from agentos.flows.version_diff import version_diff

    storage = request.app.state.storage
    old, new = await _flow_side(storage, flow_id, from_), await _flow_side(storage, flow_id, to)

    async def summaries(flow: Dict[str, Any]) -> Optional[Dict[Any, Any]]:
        try:
            return await resolve_subflow_summaries(storage, flow_definition(flow))
        except Exception:
            return None

    diff = version_diff(old, new, _policy(request), await tool_catalog(storage),
                        await summaries(old), await summaries(new))
    return {"flow_id": flow_id, "from": from_, "to": to, **diff}
