"""Builder orchestration (4.0): generate -> validate -> guard -> static check -> repair rounds -> report.

The model is injected as an async ``model(messages) -> str`` (the server passes the AgentOS router with run limits,
budgets and llm_call events; tests pass scripted models). The builder never saves and never publishes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from agentos.builder.diff import flow_diff
from agentos.builder.explain import security_summary, steps
from agentos.builder.guards import flow_text, invented_targets, looks_like_secret
from agentos.builder.prompt import build_messages, repair_message, retry_message
from agentos.builder.repair import one_click_fixes, violations_of
from agentos.builder.schema import (
    MAX_ANSWER, MAX_ANSWERS, MAX_CHANGE_REQUEST, MAX_DESCRIPTION, MAX_QUESTIONS, BuilderOutputError, ParsedOutput,
    normalize_flow, parse_output,
)
from agentos.flows.policy import SecurityPolicy
from agentos.flows.tool_catalog import BUILTIN_CATALOG, ToolCatalog

ModelFn = Callable[[list[dict[str, str]]], Awaitable[str]]
MAX_REPAIR_ROUNDS = 2
SECRET_OUTPUT = ("the answer contains a value that looks like a credential; never put keys or tokens in a flow, "
                 "reference secrets by vault name only.")


class BuilderInputError(ValueError):
    """The request itself is refused (400). ``reason`` is a short code for the audit entry."""

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(message)


@dataclass
class BuilderRequest:
    description: str = ""
    answers: list[dict[str, str]] = field(default_factory=list)
    change_request: str | None = None
    base_flow: dict[str, Any] | None = None  # edit mode: the flow being changed

    @property
    def mode(self) -> str:
        return "edit" if self.base_flow is not None else "new"

    def stated_text(self) -> str:
        parts = [self.description or ""]
        parts += [a.get("answer", "") for a in self.answers]
        parts.append(self.change_request or "")
        return "\n".join(parts)

    def validate(self) -> None:
        if len(self.description or "") > MAX_DESCRIPTION:
            raise BuilderInputError("too_long", f"The description is longer than {MAX_DESCRIPTION} characters.")
        if len(self.answers) > MAX_ANSWERS or any(len(str(a.get("answer", ""))) > MAX_ANSWER for a in self.answers):
            raise BuilderInputError("too_long", f"At most {MAX_ANSWERS} answers of {MAX_ANSWER} characters each.")
        if len(self.change_request or "") > MAX_CHANGE_REQUEST:
            raise BuilderInputError("too_long", f"The change request is longer than {MAX_CHANGE_REQUEST} characters.")
        if self.mode == "new" and not (self.description or "").strip():
            raise BuilderInputError("empty", "Describe the flow first.")
        if self.mode == "edit" and not (self.change_request or "").strip():
            raise BuilderInputError("empty", "Say what should change.")
        questions = " ".join(a.get("question", "") for a in self.answers)
        if looks_like_secret(self.stated_text() + " " + questions):
            raise BuilderInputError(
                "secret_like_input",
                "The text looks like it contains a key, token or password. It was not sent to any model. Store the "
                "secret in the vault (Settings -> Keys) and refer to it by its vault name.")


def base_flow_dict(record: dict[str, Any]) -> dict[str, Any]:
    """The editor/storage flow reduced to what the builder works on (no layout positions)."""
    nodes = {nid: {"id": nid, "type": n.get("type"), "config": dict(n.get("config") or {}),
                   "pinned_args": dict(n.get("pinned_args") or {})} for nid, n in (record.get("nodes") or {}).items()}
    edges = []
    for e in record.get("edges") or []:
        edge = {"source": e["source"], "target": e["target"], "arg_mapping": dict(e.get("arg_mapping") or {})}
        if e.get("branch"):
            edge["branch"] = e["branch"]
        edges.append(edge)
    return {"id": record["id"], "name": record.get("name") or record["id"], "entrypoint": record.get("entrypoint"),
            "nodes": nodes, "edges": edges, "loops": dict(record.get("loops") or {})}


def check_report(flow: dict[str, Any], violations: list[dict[str, Any]], stated: str, policy: SecurityPolicy,
                 catalog: ToolCatalog | None) -> dict[str, Any]:
    fixes, refusals = one_click_fixes(flow, violations, stated, policy, catalog)
    return {"violations": violations, "fixes": fixes, "refusals": refusals}


def explanation(flow: dict[str, Any], model_summary: str, policy: SecurityPolicy,
                catalog: ToolCatalog | None) -> dict[str, Any]:
    return {"steps": steps(flow), "model_summary": model_summary,
            "security": security_summary(flow, policy, catalog)}


class NLFlowBuilder:
    def __init__(self, policy: SecurityPolicy, catalog: ToolCatalog | None, model: ModelFn,
                 max_repair_rounds: int = MAX_REPAIR_ROUNDS) -> None:
        self.policy = policy
        self.catalog = catalog or BUILTIN_CATALOG
        self.model = model
        self.max_repair_rounds = max_repair_rounds
        self.model_calls = 0
        self.agent_tools = sorted(e.name for e in self.catalog.agent_tool_options())

    async def _call(self, messages: list[dict[str, str]]) -> str:
        self.model_calls += 1
        return await self.model(messages)

    def _parse(self, raw: Any) -> ParsedOutput:
        parsed = parse_output(raw, set(self.agent_tools))
        text = json.dumps({"q": parsed.questions, "f": parsed.flow, "e": parsed.explanation}, default=str)
        if looks_like_secret(text):
            raise BuilderOutputError(SECRET_OUTPUT)
        return parsed

    async def _ask(self, messages: list[dict[str, str]]) -> tuple[ParsedOutput | None, str | None]:
        """One call; invalid output gets ONE retry carrying AgentOS's own error message (never the output)."""
        try:
            return self._parse(await self._call(messages)), None
        except BuilderOutputError as err:
            first = str(err)
        try:
            return self._parse(await self._call(messages + [retry_message(first)])), None
        except BuilderOutputError as err:
            return None, str(err)

    def _fit(self, flow: dict[str, Any], req: BuilderRequest) -> dict[str, Any]:
        if req.base_flow is not None:
            flow = normalize_flow(flow, flow_id=req.base_flow["id"])
            flow["name"] = req.base_flow.get("name") or flow["name"]
        return flow

    def _questions(self, flow: dict[str, Any], req: BuilderRequest) -> list[str]:
        allowed = req.stated_text() + "\n" + (flow_text(req.base_flow) if req.base_flow else "")
        qs = [i.question(self.policy) for i in invented_targets(flow, allowed, self.policy)]
        return list(dict.fromkeys(qs))[:MAX_QUESTIONS]

    async def generate(self, req: BuilderRequest) -> dict[str, Any]:
        req.validate()
        self.model_calls = 0
        base = req.base_flow
        messages = build_messages(self.policy, self.agent_tools, req.description or "", req.answers,
                                  req.change_request, base)
        parsed, error = await self._ask(messages)
        result: dict[str, Any] = {"mode": req.mode, "repair_rounds": 0}
        if parsed is None:
            return {**result, "status": "error", "error": f"The model did not produce a valid draft: {error}",
                    "model_calls": self.model_calls}
        if parsed.questions:
            return {**result, "status": "questions", "questions": parsed.questions, "question_source": "model",
                    "model_calls": self.model_calls}
        flow = self._fit(parsed.flow or {}, req)
        questions = self._questions(flow, req)
        if questions:
            return {**result, "status": "questions", "questions": questions, "question_source": "agentos",
                    "model_calls": self.model_calls}
        summary = parsed.explanation
        viols = violations_of(flow, self.policy, self.catalog)
        fixed: list[dict[str, Any]] = []
        rounds = 0
        while viols and rounds < self.max_repair_rounds:
            rounds += 1
            try:
                p = self._parse(await self._call(messages + [repair_message(flow, viols, rounds)]))
            except BuilderOutputError as err:
                fixed.append({"round": rounds, "accepted": False, "why": f"repair output rejected: {err}"})
                continue
            if p.flow is None:
                fixed.append({"round": rounds, "accepted": False, "why": "the model asked questions instead"})
                continue
            new = self._fit(p.flow, req)
            if self._questions(new, req):
                fixed.append({"round": rounds, "accepted": False,
                              "why": "the repaired draft used a recipient or target nobody stated"})
                continue
            new_viols = violations_of(new, self.policy, self.catalog)
            old_rules = {v["rule"] for v in viols}
            new_rules = {v["rule"] for v in new_viols}
            fixed.append({"round": rounds, "accepted": True, "resolved": sorted(old_rules - new_rules),
                          "introduced": sorted(new_rules - old_rules), "changes": flow_diff(flow, new),
                          "why": "the static security check refused the previous draft"})
            flow, viols = new, new_viols
            summary = p.explanation or summary
        status = "passed" if not viols and rounds == 0 else "fixed" if not viols else "failing"
        check = {"status": status, "fixed": fixed,
                 **check_report(flow, viols, req.stated_text(), self.policy, self.catalog)}
        out = {**result, "status": "draft", "flow": flow, "check": check, "repair_rounds": rounds,
               "explanation": explanation(flow, summary, self.policy, self.catalog),
               "model_calls": self.model_calls}
        if base is not None:
            out["diff"] = flow_diff(base, flow)
        return out
