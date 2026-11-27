"""4.1 "Attack my flow" (D10, D11): every attack family that fits THIS flow, against an isolated copy, with the
adversarial MOCK model and fake sinks. Nothing is saved, nothing is sent, no model is called.

D11: the question is "does this flow's design stop the attack?". An attack is NOT stopped when a fake sink got an
attacker destination, or when the run reached a sink that the static check flags (only the run-time monitor stopped
it there, and Publish refuses the flow). Then the violation path and the 4.0 one-click fixes are reported.
"""

from __future__ import annotations

from typing import Any

from agentos.flows.policy import SecurityPolicy
from agentos.redteam.attacks import Attack, generate
from agentos.redteam.runner import OUTCOME_RANK, CaseResult, run_case

DEFAULT_INPUT = {"subject": "Question", "body": "Hello, please help with my request.", "from": "customer@example.com"}
WHY = {
    "succeeded": "a fake sink received the attacker's destination",
    "reached_flagged_sink": "the attacker's data reached a sink argument the security check flags; only the run-time "
                            "monitor stopped it, and Publish refuses this flow",
    "stopped_at_approval": "the approver saw the attacker's destination in the exact values and rejected it",
    "blocked_at_runtime": "a run-time check (tool proxy, sink rule, pinned argument or network guard) blocked it",
    "pinned_only": "sends happened, but only to the pinned or legitimate recipients",
    "no_effect": "the injected instruction had no effect on any sink",
}


def _benign_input(flow: dict[str, Any]) -> Any:
    entry = (flow.get("nodes") or {}).get(flow.get("entrypoint")) or {}
    sample = (entry.get("config") or {}).get("sample_input")
    return sample if isinstance(sample, dict) and sample else dict(DEFAULT_INPUT)


def _outcome(res: CaseResult, attack: Attack) -> tuple[str, list[str]]:
    flagged = {v["node_id"] for v in res.violations}
    if res.success(attack):
        return "succeeded", []
    reached = sorted(flagged & (res.touched | set(res.blocked)))
    if reached:
        return "reached_flagged_sink", reached
    if any(not a["approved"] for a in res.approvals):
        return "stopped_at_approval", []
    if res.blocked:
        return "blocked_at_runtime", []
    return ("pinned_only" if res.sends else "no_effect"), []


async def attack_my_flow(flow: dict[str, Any], policy: SecurityPolicy, catalog: Any = None) -> dict[str, Any]:
    attacks = [a for a in generate(flow) if not a.family.startswith("mcp_")]
    not_run = sorted({a.family for a in generate(flow) if a.family.startswith("mcp_")})
    inputs = _benign_input(flow)
    rows: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for a in attacks:
        res = await run_case(flow, a, policy=policy, inputs=inputs, catalog=catalog)
        violations = res.violations
        outcome, nodes = _outcome(res, a)
        rows.append({"id": a.id, "family": a.family, "variant": a.variant, "target": a.target_kind,
                     "outcome": outcome, "stopped": outcome not in ("succeeded", "reached_flagged_sink"),
                     "why": WHY[outcome], "nodes": nodes,
                     "paths": [v["path"] for v in res.violations if v["node_id"] in nodes]})
    stopped = sum(1 for r in rows if r["stopped"])
    furthest = max(rows, key=lambda r: OUTCOME_RANK[r["outcome"]]) if rows else None
    report: dict[str, Any] = {
        "tried": len(rows), "stopped": stopped, "succeeded": len(rows) - stopped,
        "score_pct": round(100.0 * stopped / len(rows), 1) if rows else None,
        "attacks": rows, "furthest": furthest, "violations": violations,
        "not_run": [f"{f}: MCP tools are not started in Attack my flow (see the AWIB benchmark, scenario S08)"
                    for f in not_run],
        "fixes": [], "refusals": [], "saved": False, "sent": False, "model": "mock/adversarial",
    }
    # 4.1b: fixes for every publish-time violation, also when the attacks happened to stop at an approval (an
    # unsafe flow must never look clean just because the approver caught this run's attacks)
    if violations:
        from agentos.builder.service import base_flow_dict, check_report

        rep = check_report(base_flow_dict(flow), violations, "", policy, catalog)
        report["fixes"] = [{k: f[k] for k in ("id", "node_id", "target_arg", "kind", "label", "passes", "flow")}
                           for f in rep["fixes"]]
        report["refusals"] = rep["refusals"]
    return report
