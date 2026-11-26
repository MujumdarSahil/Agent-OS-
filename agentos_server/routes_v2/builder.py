"""4.0 natural-language flow builder routes (design: docs/evidence/4.0.md).

- POST /api/v2/flows/generate: description (+ answers, or an existing flow + change request) -> a DRAFT, its static
  check, repairs, one-click fixes and explanation. One model call (plus at most one retry and two repair rounds)
  through the AgentOS router: fallback, budgets, run limits and llm_call events apply, usage counted under the pseudo
  flow id "builder" (one pseudo run per request). Audited as flow.generate with metadata only (never the text).
- POST /api/v2/flows/check: the same check and one-click fixes for a flow the UI holds; never saves.
Nothing here saves or publishes a flow.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agentos.builder import BuilderInputError, BuilderRequest, NLFlowBuilder, check_report
from agentos.builder.repair import violations_of
from agentos.builder.schema import MAX_ANSWER, MAX_CHANGE_REQUEST, MAX_DESCRIPTION, BuilderOutputError, normalize_flow
from agentos.builder.service import base_flow_dict, explanation
from agentos.flows.policy import SecurityPolicy
from agentos.storage.models import RunRecord
from agentos_server.audit_support import actor_of, audit, audit_best_effort, source_of

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/flows", tags=["v2-builder"])

BUILDER_FLOW_ID = "builder"


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field("", max_length=300)
    answer: str = Field(..., max_length=MAX_ANSWER)


class GenerateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str = Field("", max_length=MAX_DESCRIPTION)
    answers: List[Answer] = Field(default_factory=list, max_length=3)
    flow_id: Optional[str] = Field(None, max_length=128)
    change_request: Optional[str] = Field(None, max_length=MAX_CHANGE_REQUEST)
    # Edit mode: the editor's current (possibly unsaved) graph; else the stored draft of flow_id is used.
    base_flow: Optional[Dict[str, Any]] = None


class CheckBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flow: Dict[str, Any]
    description: str = Field("", max_length=MAX_DESCRIPTION)
    answers: List[Answer] = Field(default_factory=list, max_length=3)


async def _catalog(request: Request) -> Any:
    from agentos.flows.tool_catalog import ToolCatalog

    repo = getattr(request.app.state.storage, "mcp_servers", None)
    return ToolCatalog(await repo.list() if repo is not None else [])


def _policy(request: Request) -> SecurityPolicy:
    return getattr(request.app.state, "security_policy", None) or SecurityPolicy()


def _who(request: Request) -> Optional[Dict[str, Any]]:
    p = getattr(request.state, "principal", None)
    if p is None:
        return None
    return {"user_id": p.actor_id, "username": p.username or p.actor, "via": p.kind}


async def _base_flow(request: Request, body: GenerateBody) -> Optional[Dict[str, Any]]:
    if body.flow_id is None and body.base_flow is None:
        return None
    if body.base_flow is not None:
        rec = dict(body.base_flow)
        if body.flow_id:
            rec["id"] = body.flow_id
        if not rec.get("id") or not rec.get("entrypoint"):
            raise HTTPException(status_code=400, detail="base_flow needs an id and an entrypoint")
        return base_flow_dict(rec)
    storage = request.app.state.storage
    rec = await storage.flows.get_draft(body.flow_id)
    if rec is None:
        versions = await storage.flows.list_versions(body.flow_id)
        rec = versions[-1] if versions else None
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Flow {body.flow_id!r} not found")
    return base_flow_dict(rec.model_dump(mode="json"))


class _RouterModel:
    """The builder's model: AgentOSRouterLLM without tools, a RunGuard for flow "builder", and llm_call events +
    ledger rows on one pseudo run (the same recording as the flow engine)."""

    def __init__(self, request: Request, run_id: str) -> None:
        self.app = request.app
        self.run_id = run_id
        self.loop = asyncio.get_running_loop()
        self.guard: Any = None
        self.usage = getattr(self.app.state, "usage", None)

    async def start(self, request: Request) -> None:
        from agentos.usage.guard import RunGuard, UsageContext

        if self.usage is None:
            self.usage = UsageContext.default()
        settings = await self.usage.get_settings()
        storage = self.app.state.storage
        await storage.runs.put(RunRecord(run_id=self.run_id, mission_name=BUILDER_FLOW_ID, flow_id=BUILDER_FLOW_ID,
                                         status="running", trigger="builder", started_by=_who(request)))

        def emit(type_: str, data: dict[str, Any]) -> None:
            asyncio.run_coroutine_threadsafe(storage.events.append(self.run_id, type_, data), self.loop).result(10)

        self.guard = RunGuard(self.usage, self.run_id, BUILDER_FLOW_ID, settings, loop=self.loop, emit=emit)

    async def finish(self, status: str, error: Optional[str] = None) -> None:
        storage = self.app.state.storage
        rec = await storage.runs.get(self.run_id)
        if rec is not None:
            await storage.runs.put(rec.model_copy(update={"status": status, "error": error}))

    def _with_cost(self, record: dict[str, Any]) -> dict[str, Any]:
        from agentos.usage.ledger import today_utc
        from agentos.usage.pricing import cost_usd

        out = {**record, "day": today_utc()}
        if record.get("status") == "ok":
            price = self.usage.price(record.get("provider"), record.get("model"))
            out["cost_usd"] = cost_usd(price, int(record.get("prompt_tokens") or 0),
                                       int(record.get("completion_tokens") or 0))
            out["price_source"] = price.source
        else:
            out["cost_usd"], out["price_source"] = 0.0, "no_tokens"
        return out

    async def _record(self, record: dict[str, Any]) -> None:
        storage = self.app.state.storage
        await storage.events.append(self.run_id, "llm_call", record)
        ledger = getattr(self.usage, "ledger", None)
        if ledger is not None:
            from agentos.usage.ledger import increments

            try:
                await ledger.add(increments(record, BUILDER_FLOW_ID, record.get("day")))
            except Exception as e:  # the event is written; the ledger is rebuildable from events
                logger.warning("usage ledger update failed: %s", type(e).__name__)
        if self.guard is not None:
            self.guard.after_record(record)

    def _llm(self) -> Any:
        from agentos.llm.router_llm import AgentOSRouterLLM

        vault = getattr(self.app.state, "vault", None)
        loop = self.loop

        def on_call(record: dict[str, Any]) -> None:
            asyncio.run_coroutine_threadsafe(self._record(self._with_cost(record)), loop).result(timeout=10)

        def key_lookup(provider: str, env_name: Optional[str]) -> Optional[str]:
            if vault is None or not env_name:
                return None
            try:
                secret = vault.reveal(env_name)
                if asyncio.iscoroutine(secret):
                    return asyncio.run_coroutine_threadsafe(secret, loop).result(timeout=5)
                return secret
            except Exception:
                return None

        return AgentOSRouterLLM(key_lookup=key_lookup, on_call=on_call, node_id="builder", guard=self.guard)

    async def __call__(self, messages: list[dict[str, str]]) -> str:
        llm = self._llm()
        return await asyncio.to_thread(llm.call, messages, None)  # tools=None: the model gets no tools


def _model_error(err: Exception) -> tuple[int, str]:
    from agentos.llm.router_llm import AllProvidersFailedError, LLMRefusedError
    from agentos.usage.guard import BudgetExceeded, RunLimitExceeded

    if isinstance(err, (RunLimitExceeded, BudgetExceeded)):
        return 429, f"The builder stopped: {err}."
    if isinstance(err, LLMRefusedError):
        return 503, f"No model is available: {err}."
    if isinstance(err, AllProvidersFailedError):
        return 503, "Every configured model provider failed; see Models for their status."
    return 500, f"The builder failed ({type(err).__name__})."


@router.post("/generate")
async def generate_flow(body: GenerateBody, request: Request) -> Dict[str, Any]:
    base = await _base_flow(request, body)
    req = BuilderRequest(description=body.description, answers=[a.model_dump() for a in body.answers],
                         change_request=body.change_request, base_flow=base)
    text = req.stated_text()
    details: Dict[str, Any] = {"mode": req.mode, "description_chars": len(body.description),
                               "description_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                               "answers": len(body.answers)}
    try:
        req.validate()
    except BuilderInputError as err:
        await audit(request, "flow.generate", "flow", BUILDER_FLOW_ID, outcome="refused",
                    details={**details, "reason": err.reason})
        raise HTTPException(status_code=400, detail=str(err))
    run_id = f"builder_{uuid.uuid4().hex[:12]}"
    # 3.1 rule: audited before the model call (503 and no call if the entry cannot be written)
    await audit(request, "flow.generate", "flow", BUILDER_FLOW_ID, details={**details, "run_id": run_id})
    model = _RouterModel(request, run_id)
    await model.start(request)
    builder = NLFlowBuilder(_policy(request), await _catalog(request), model)
    try:
        result = await builder.generate(req)
    except Exception as err:
        status, message = _model_error(err)
        await model.finish("failed", message)
        await audit_best_effort(request.app, "flow.generate", "flow", BUILDER_FLOW_ID, outcome="failed",
                                details={"run_id": run_id, "model_calls": builder.model_calls,
                                         "error": type(err).__name__},
                                actor=actor_of(request), source=source_of(request))
        raise HTTPException(status_code=status, detail={"detail": message, "run_id": run_id,
                                                        "model_calls": builder.model_calls})
    await model.finish("succeeded" if result["status"] != "error" else "failed", result.get("error"))
    check = result.get("check") or {}
    await audit_best_effort(request.app, "flow.generate", "flow", BUILDER_FLOW_ID,
                            outcome="ok" if result["status"] != "error" else "failed",
                            details={"run_id": run_id, "status": result["status"],
                                     "check": check.get("status", "-"), "model_calls": result["model_calls"],
                                     "repair_rounds": result.get("repair_rounds", 0),
                                     "violations": len(check.get("violations") or [])},
                            actor=actor_of(request), source=source_of(request))
    return {**result, "run_id": run_id, "published": False, "saved": False}


@router.post("/check")
async def check_flow(body: CheckBody, request: Request) -> Dict[str, Any]:
    """Static check + one-click fixes for a flow held by the UI. Never saves or publishes."""
    policy, catalog = _policy(request), await _catalog(request)
    fid = str(body.flow.get("id") or "draft")
    try:
        flow = normalize_flow(base_flow_dict({**body.flow, "id": fid}), flow_id=fid)
        viols = violations_of(flow, policy, catalog)
    except (BuilderOutputError, KeyError, TypeError, ValueError) as err:
        raise HTTPException(status_code=400, detail=f"The flow is not valid: {err}")
    stated = "\n".join([body.description] + [a.answer for a in body.answers])
    return {"flow": flow, "check": {"status": "passed" if not viols else "failing", "fixed": [],
                                    **check_report(flow, viols, stated, policy, catalog)},
            "explanation": explanation(flow, "", policy, catalog), "published": False, "saved": False}
