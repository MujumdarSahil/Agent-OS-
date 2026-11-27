"""4.3: environments (staging / production) per flow: migration, what runs where, promote / rollback with checks,
auto-deploy after publish, and the staging send simulation. Design: docs/evidence/4.3.md (D2-D6).

Domain code only (no FastAPI / Mongo imports). The API (agentos_server/routes_v2/environments.py) and the CLI
(``agentos flows ...``) both call :class:`DeploymentService`, so the checks are the same everywhere.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from agentos.storage.models import (
    ENVIRONMENTS,
    DeploymentRecord,
    EnvironmentSettings,
    FlowRecord,
)
from agentos.storage.ports import DeploymentConflict

logger = logging.getLogger(__name__)

MIGRATION_ACTOR = "system:migration-4.3"
RUN_ENVIRONMENTS = ("draft", "staging", "production")
NOTE_MAX = 500
_UNSET: Any = object()


class EnvError(ValueError):
    """Base class: ``status`` is the HTTP status the API returns, ``detail`` the JSON body."""

    status = 400

    def __init__(self, message: str, **detail: Any) -> None:
        super().__init__(message)
        self.detail = {"error": message, **detail}


class EnvNotFound(EnvError):
    status = 404


class DeploymentRefused(EnvError):
    """A check failed (static check against the current policy, test gate, second person, archived version)."""

    status = 409


class DeploymentRaced(EnvError):
    """Another promote / rollback changed the environment first (compare-and-set lost)."""

    status = 409


# --------------------------------------------------------------------------------------------- helpers


def policy_hash(policy: Any) -> str:
    return hashlib.sha256(json.dumps(policy.model_dump(mode="json"), sort_keys=True).encode("utf-8")).hexdigest()


def actor_id(actor: Optional[Dict[str, Any]]) -> Optional[str]:
    if not actor:
        return None
    return actor.get("user_id") or actor.get("username")


def actor_name(actor: Optional[Dict[str, Any]]) -> Optional[str]:
    if not actor:
        return None
    return actor.get("username") or actor.get("user_id")


def _repo(storage: Any) -> Any:
    repo = getattr(storage, "deployments", None)
    if repo is None:
        raise EnvNotFound("this storage backend has no environments")
    return repo


# --------------------------------------------------------------------------------------------- migration (D2)


async def migrate_flow(storage: Any, flow_id: str) -> bool:
    """Treat a flow without a settings record as a flow from before 4.3: production = its latest published version
    (staging empty), auto-deploy to production on publish stays on (today's behaviour). Idempotent; True if this call
    migrated the flow."""
    repo = getattr(storage, "deployments", None)
    if repo is None or await repo.get_settings(flow_id) is not None:
        return False
    created = await repo.create_settings(EnvironmentSettings(
        flow_id=flow_id, auto_deploy_staging=True, auto_deploy_production=True, legacy=True,
        updated_by=MIGRATION_ACTOR))
    if not created:
        return False
    versions = await storage.flows.list_versions(flow_id)
    if versions and await repo.get(flow_id, "production") is None:
        try:
            await repo.set(DeploymentRecord(flow_id=flow_id, environment="production", version=versions[-1].version,
                                            action="migrate", deployed_by=MIGRATION_ACTOR,
                                            note="4.3 migration: production = latest published version"), None)
        except DeploymentConflict:
            pass  # someone deployed it meanwhile: theirs stands
    return True


async def migrate_all(storage: Any) -> int:
    """Startup migration: every flow that exists without a settings record. Returns the number migrated."""
    if getattr(storage, "deployments", None) is None or getattr(storage, "flows", None) is None:
        return 0
    n = 0
    for f in await storage.flows.list_flows():
        try:
            n += int(await migrate_flow(storage, f.id))
        except Exception as e:  # one broken flow never blocks startup
            logger.warning("4.3 migration skipped flow %r: %s", f.id, type(e).__name__)
    return n


async def ensure_new_flow_settings(storage: Any, flow_id: str, actor: Optional[Dict[str, Any]] = None) -> None:
    """A flow first saved or published through 4.3 is a NEW flow: auto-deploy to production off."""
    repo = getattr(storage, "deployments", None)
    if repo is not None and await repo.get_settings(flow_id) is None:
        await repo.create_settings(EnvironmentSettings(flow_id=flow_id, updated_by=actor_name(actor)))


async def settings_for(storage: Any, flow_id: str) -> EnvironmentSettings:
    s = await _repo(storage).get_settings(flow_id)
    return s or EnvironmentSettings(flow_id=flow_id)


# --------------------------------------------------------------------------------------------- what runs where (D3)


async def environment_version(storage: Any, flow_id: str, environment: str) -> Optional[int]:
    """The version an environment points to right now (None = empty). Applies the legacy migration first for a flow
    that has no settings record (pre-4.3 data that appeared at repository level, e.g. a restored backup)."""
    repo = getattr(storage, "deployments", None)
    if repo is None:  # a storage without environments behaves as before 4.3
        versions = await storage.flows.list_versions(flow_id)
        return versions[-1].version if versions and environment == "production" else None
    settings = await repo.get_settings(flow_id)
    if settings is None:
        await migrate_flow(storage, flow_id)
        settings = await repo.get_settings(flow_id)
    rec = await repo.get(flow_id, environment)
    if rec is None and environment == "production" and settings is not None and settings.legacy             and settings.auto_deploy_production:
        # a flow from before 4.3 whose first version was published at repository level (not through the API, so no
        # auto-deploy ran): production follows its latest version, exactly as before 4.3
        versions = await storage.flows.list_versions(flow_id)
        if versions:
            try:
                rec = await repo.set(DeploymentRecord(
                    flow_id=flow_id, environment="production", version=versions[-1].version, action="migrate",
                    deployed_by=MIGRATION_ACTOR, note="4.3 migration: production = latest published version"), None)
            except DeploymentConflict:
                rec = await repo.get(flow_id, environment)
    return rec.version if rec else None


async def resolve_run_target(storage: Any, flow_id: str, environment: Optional[str] = None,
                             version: Optional[int] = None) -> Tuple[Optional[int], Optional[str]]:
    """Manual run target -> (version, environment). ``draft`` returns (None, "draft"); neither given -> production
    if set, else the latest published version (environment None: API compatibility)."""
    if environment is not None and environment not in RUN_ENVIRONMENTS:
        raise EnvError(f"unknown environment {environment!r}")
    if environment is not None and version is not None:
        raise EnvError("give either an environment or a version, not both")
    if environment == "draft":
        return None, "draft"
    has_envs = getattr(storage, "deployments", None) is not None
    if version is not None:
        if await storage.flows.get_version(flow_id, version) is None:
            raise EnvNotFound(f"Flow {flow_id!r} version {version} not found")
        if has_envs and version in await storage.deployments.archived_versions(flow_id):
            raise DeploymentRefused(f"version {version} is archived; archived versions cannot start new runs")
        return version, None
    if environment is not None:
        v = await environment_version(storage, flow_id, environment)
        if v is None:
            raise EnvError(f"Cannot run flow {flow_id!r}: {environment} has no version yet")
        return v, environment
    prod = await environment_version(storage, flow_id, "production")
    if prod is not None:
        return prod, "production"
    versions = await storage.flows.list_versions(flow_id)
    if not versions:
        raise EnvError(f"Cannot run flow {flow_id!r}: no published versions exist")
    return versions[-1].version, None


# --------------------------------------------------------------------------------------------- checks (D6)


class SubflowError(ValueError):
    pass


MAX_SUBFLOW_DEPTH = 5


async def resolve_subflow_summaries(storage: Any, flow_def: Any) -> Dict[Any, Any]:
    """Load published analysis summaries of referenced subflows; detect cycles and deep nesting (2.3)."""
    summaries: Dict[Any, Any] = {}

    async def visit(refs: List[tuple], stack: List[tuple], depth: int) -> None:
        for key in refs:
            if key in stack or key[0] == flow_def.id:
                chain = " -> ".join(f"{k[0]}@v{k[1]}" for k in stack + [key])
                raise SubflowError(f"Subflow cycle detected: {flow_def.id} -> {chain}")
            if depth > MAX_SUBFLOW_DEPTH:
                raise SubflowError(f"Subflow nesting deeper than {MAX_SUBFLOW_DEPTH}")
            rec = await storage.flows.get_version(key[0], key[1])
            if rec is None:
                raise SubflowError(f"Subflow {key[0]!r} v{key[1]} is not published")
            summaries[key] = rec.analysis  # None for versions published before 2.3 -> treated as unknown
            child_refs = [
                (n["config"]["flow_id"], int(n["config"]["version"]))
                for n in (rec.nodes or {}).values()
                if isinstance(n, dict) and n.get("type") == "subflow"
            ]
            await visit(child_refs, stack + [key], depth + 1)

    top = [(n.config["flow_id"], int(n.config["version"])) for n in flow_def.nodes.values() if n.type == "subflow"]
    await visit(top, [], 1)
    return summaries


def flow_definition(rec: Any) -> Any:
    from agentos.flows.models import FlowDefinition

    d = rec if isinstance(rec, dict) else rec.model_dump()
    return FlowDefinition(id=d["id"], name=d.get("name") or "", entrypoint=d["entrypoint"], nodes=d.get("nodes") or {},
                          edges=d.get("edges") or [], loops=d.get("loops") or {})


async def tool_catalog(storage: Any) -> Any:
    from agentos.flows.tool_catalog import ToolCatalog

    repo = getattr(storage, "mcp_servers", None)
    return ToolCatalog(await repo.list() if repo is not None else [])


async def static_check(storage: Any, policy: Any, rec: Any) -> Dict[str, Any]:
    """Re-run the publish-time static security check on ``rec`` (a version or a draft) against the CURRENT policy
    and tool catalog. Same analyzer, subflow summaries and tool lookup as publish."""
    from agentos.flows.static_analyzer import StaticFlowAnalyzer

    current = policy_hash(policy)
    stored = rec.get("policy_hash") if isinstance(rec, dict) else getattr(rec, "policy_hash", None)
    out: Dict[str, Any] = {"policy_hash_stored": stored, "policy_hash_current": current,
                           "policy_changed": bool(stored) and stored != current}
    try:
        fd = flow_definition(rec)
        summaries = await resolve_subflow_summaries(storage, fd)
    except Exception as e:
        return {**out, "passed": False, "violations": [{"node_id": "(flow)", "target_arg": "(definition)",
                                                        "path": [], "reason": str(e)[:300]}]}
    res = StaticFlowAnalyzer(flow=fd, policy=policy, subflow_summaries=summaries,
                             tool_catalog=await tool_catalog(storage)).verify()
    return {**out, "passed": res.is_valid,
            "violations": [{"node_id": v.node_id, "target_arg": v.target_arg, "path": v.path, "reason": v.reason}
                           for v in res.violations]}


# --------------------------------------------------------------------------------------------- service (D5, D6)


def _check_summary(checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Audit-safe check results: names, pass/fail, counts and hashes (no violation paths or payloads)."""
    out = []
    for c in checks:
        row = {"name": c.get("name"), "passed": c.get("passed")}
        if c.get("name") == "static_check":
            row.update(violations=len(c.get("violations") or []), policy_changed=c.get("policy_changed"))
        if c.get("name") == "test_gate":
            row.update(mode=c.get("mode"), suite_run_id=c.get("suite_run_id"))
        out.append(row)
    return out


TestGateRunner = Callable[[str, int, str], Awaitable[Dict[str, Any]]]


class DeploymentService:
    """Promote / rollback / auto-deploy. ``test_gate_runner(flow_id, version, mode)`` runs the 4.2 suite against an
    exact version and returns {passed, message, suite_run_id, counts}; None = no test runner available (the gate then
    fails: refused in block mode, a warning in warn mode)."""

    def __init__(self, storage: Any, policy: Any, test_gate_runner: Optional[TestGateRunner] = None) -> None:
        self.storage = storage
        self.policy = policy
        self.repo = _repo(storage)
        self.test_gate_runner = test_gate_runner

    async def _version(self, flow_id: str, version: int) -> FlowRecord:
        rec = await self.storage.flows.get_version(flow_id, version)
        if rec is None:
            raise EnvNotFound(f"Flow {flow_id!r} version {version} not found")
        return rec

    async def _test_gate(self, flow_id: str, version: int, mode: str) -> Dict[str, Any]:
        if self.test_gate_runner is None:
            return {"name": "test_gate", "mode": mode, "passed": False, "message": "no test runner available"}
        try:
            res = await self.test_gate_runner(flow_id, version, mode)
        except Exception as e:
            res = {"passed": False, "message": f"test run failed: {str(e)[:200]}"}
        return {"name": "test_gate", "mode": mode, **res}

    async def deploy(self, flow_id: str, environment: str, version: int, *, actor: Optional[Dict[str, Any]],
                     action: str = "promote", note: str = "", expected_version: Any = _UNSET,
                     before_commit: Optional[Callable[[Dict[str, Any]], Awaitable[Any]]] = None) -> Dict[str, Any]:
        """Point ``environment`` at ``version`` after the checks (D6). Raises DeploymentRefused / DeploymentRaced /
        EnvNotFound; on success returns {environment, from, to, checks, warnings, record}."""
        if environment not in ENVIRONMENTS:
            raise EnvError(f"unknown environment {environment!r}")
        if action not in ("promote", "rollback"):
            raise EnvError(f"unknown action {action!r}")
        note = (note or "").strip()
        if len(note) > NOTE_MAX:
            raise EnvError(f"note longer than {NOTE_MAX} characters")
        await environment_version(self.storage, flow_id, environment)  # legacy migration if needed
        current = await self.repo.get(flow_id, environment)
        cur_v = current.version if current else None
        expected = cur_v if expected_version is _UNSET else expected_version
        base = {"flow_id": flow_id, "environment": environment, "action": action, "from": cur_v, "to": version}
        checks: List[Dict[str, Any]] = []
        warnings: List[str] = []

        rec = await self._version(flow_id, version)
        if version in await self.repo.archived_versions(flow_id):
            raise DeploymentRefused(f"version {version} is archived", **base,
                                    checks=[{"name": "archived", "passed": False}])
        if action == "rollback" and cur_v is not None and version >= cur_v:
            raise DeploymentRefused(f"rollback needs an earlier version than v{cur_v}", **base, checks=[])

        sc = await static_check(self.storage, self.policy, rec)
        checks.append({"name": "static_check", **sc})
        if not sc["passed"]:
            why = "; ".join(f"{v['node_id']}.{v['target_arg']}: {v['reason']}" for v in sc["violations"][:5])
            raise DeploymentRefused(
                f"v{version} fails the security check against the current policy"
                + (" (the policy changed since it was published)" if sc["policy_changed"] else "") + f": {why}",
                **base, checks=checks)

        settings = await settings_for(self.storage, flow_id)
        if environment == "production" and action == "promote":
            if settings.promote_test_gate != "off":
                tg = await self._test_gate(flow_id, version, settings.promote_test_gate)
                checks.append(tg)
                if not tg["passed"]:
                    if settings.promote_test_gate == "block":
                        raise DeploymentRefused(f"tests did not pass for v{version}: {tg.get('message')}",
                                                **base, checks=checks)
                    warnings.append(f"tests did not pass for v{version} (warn mode): {tg.get('message')}")
            if settings.second_person:
                who = actor_id(actor)
                publisher = rec.published_by
                same = publisher is not None and who is not None and publisher == who
                checks.append({"name": "second_person", "passed": not same, "published_by": publisher})
                if same:
                    raise DeploymentRefused(
                        f"second-person rule: v{version} was published by you; another person must promote it",
                        **base, checks=checks)
                if publisher is None:
                    warnings.append("second-person rule: the publisher of this version is unknown "
                                    "(published before 3.4)")

        if before_commit is not None:  # the API audits here (fail closed: no change if the entry cannot be written)
            await before_commit({**base, "checks": _check_summary(checks), "warnings": warnings})
        try:
            stored = await self.repo.set(DeploymentRecord(
                flow_id=flow_id, environment=environment, version=version, action=action,
                deployed_by=actor_name(actor), note=note), expected)
        except DeploymentConflict as e:
            raise DeploymentRaced(
                f"{environment} changed meanwhile (expected v{e.expected}, now v{e.current}); reload and try again",
                **base, current=e.current, checks=checks)
        return {**base, "checks": checks, "warnings": warnings, "record": stored.model_dump(mode="json")}

    async def after_publish(self, flow_id: str, version: int, *, actor: Optional[Dict[str, Any]],
                            note: str = "") -> Dict[str, Any]:
        """Auto-deploy after publish (D5). Publishing never fails because of this; each environment reports
        {deployed: bool, version | reason}. The static check just ran at publish, so it is not repeated."""
        await ensure_new_flow_settings(self.storage, flow_id, actor)
        settings = await settings_for(self.storage, flow_id)
        out: Dict[str, Any] = {}
        for env, on in (("staging", settings.auto_deploy_staging), ("production", settings.auto_deploy_production)):
            if not on:
                out[env] = {"deployed": False, "reason": "auto-deploy is off"}
                continue
            if env == "production" and settings.second_person:
                out[env] = {"deployed": False, "reason": "second-person rule is on: another person must promote"}
                continue
            if env == "production" and settings.promote_test_gate != "off":
                tg = await self._test_gate(flow_id, version, settings.promote_test_gate)
                if not tg["passed"] and settings.promote_test_gate == "block":
                    out[env] = {"deployed": False, "reason": f"tests did not pass: {tg.get('message')}"}
                    continue
            cur = await self.repo.get(flow_id, env)
            try:
                await self.repo.set(DeploymentRecord(flow_id=flow_id, environment=env, version=version,
                                                     action="publish", deployed_by=actor_name(actor),
                                                     note=(note or "")[:NOTE_MAX]),
                                    cur.version if cur else None)
                out[env] = {"deployed": True, "version": version}
            except DeploymentConflict as e:
                out[env] = {"deployed": False, "reason": f"{env} changed meanwhile (now v{e.current})"}
        return out


# --------------------------------------------------------------------------------------------- staging sends (D4)


STAGING_REASON = "staging: simulated, not sent (no staging channel mapped)"
DRAFT_REASON = "draft run: simulated, not sent"


class SimulatedSendTransport:
    """send_email / send_slack in a staging or draft run: nothing leaves the process. Arguments are still checked
    for header injection (same code as the real email channel), so a staging run cannot hide such a payload."""

    retry_safe = True

    def __init__(self, kind: str, reason: str) -> None:
        self.kind = kind
        self.reason = reason
        self.sent_calls: List[Dict[str, Any]] = []

    async def avalidate(self, args: Dict[str, Any]) -> None:
        from agentos.notify.channels import SinkArgumentRejected, validate_email_args, validate_slack_args

        if self.kind == "send_email":
            try:
                validate_email_args(args, None)
            except SinkArgumentRejected as err:
                msg = str(err)
                if "control characters" in msg or "cannot be set by a flow" in msg:
                    raise
        elif self.kind == "send_slack":
            try:
                validate_slack_args(args)
            except SinkArgumentRejected as err:
                if "control characters" in str(err):
                    raise

    async def asend(self, idempotency_key: str, **args: Any) -> Dict[str, Any]:
        self.sent_calls.append({"idempotency_key": idempotency_key})  # counted, never delivered
        return {"status": "simulated", "reason": self.reason, "environment_simulated": True,
                "idempotency_key": idempotency_key}


StagingFactory = Callable[[str, Dict[str, Any]], Awaitable[Dict[str, Any]]]


async def simulated_registry(environment: str, registry: Dict[str, Any]) -> Dict[str, Any]:
    """Default staging/draft registry: every send simulated (no channel mapping available)."""
    reason = DRAFT_REASON if environment == "draft" else STAGING_REASON
    return {**registry, "send_email": SimulatedSendTransport("send_email", reason),
            "send_slack": SimulatedSendTransport("send_slack", reason)}


async def run_flow_and_registry(storage: Any, run: Any, flow_id: str, version: Optional[int],
                                base_registry: Dict[str, Any],
                                staging_factory: Optional[StagingFactory] = None) -> Tuple[Optional[Any], Dict[str, Any]]:
    """The flow definition a run executes and the transports it may use, for every path that runs or resumes a run
    (worker, approval). A draft run uses its snapshot; staging and draft runs get simulated sends unless the admin
    mapped staging channels. Returns (None, registry) when the version does not exist."""
    env = getattr(run, "environment", None)
    snap = getattr(run, "flow_snapshot", None)
    if env == "draft" and snap and isinstance(snap.get("flow"), dict):
        flow_def = flow_definition(snap["flow"])
    else:
        rec = await storage.flows.get_version(flow_id, version) if version else None
        flow_def = flow_definition(rec) if rec is not None else None
    registry = dict(base_registry or {})
    if env in ("staging", "draft"):
        registry = await (staging_factory or simulated_registry)(env, registry)
    return flow_def, registry
