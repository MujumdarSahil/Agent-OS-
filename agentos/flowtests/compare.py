"""4.2 D7 (model comparison) and D8 (regression against the previous suite run)."""

from __future__ import annotations

import statistics
from typing import Any, Optional

from agentos.flowtests.models import SuiteRun


def regression(prev: Optional[SuiteRun], cur: SuiteRun) -> dict[str, Any]:
    """Newly failing (pass -> fail/error), newly passing, still failing, new and removed cases."""
    now = {r.case_id: r for r in cur.results}
    if prev is None:
        return {"previous_run_id": None, "newly_failing": [], "newly_passing": [], "still_failing": [],
                "new_cases": [], "removed_cases": [], "first_run": True}
    before = {r.case_id: r for r in prev.results}

    def row(cid: str) -> dict[str, Any]:
        r = now.get(cid) or before.get(cid)
        return {"case_id": cid, "name": r.name if r else cid}

    newly_failing = [row(c) for c, r in now.items() if r.status != "pass" and c in before
                     and before[c].status == "pass"]
    newly_passing = [row(c) for c, r in now.items() if r.status == "pass" and c in before
                     and before[c].status != "pass"]
    still_failing = [row(c) for c, r in now.items() if r.status != "pass" and c in before
                     and before[c].status != "pass"]
    return {"previous_run_id": prev.id, "previous_started_at": prev.started_at,
            "newly_failing": newly_failing, "newly_passing": newly_passing, "still_failing": still_failing,
            "new_cases": [row(c) for c in now if c not in before],
            "removed_cases": [row(c) for c in before if c not in now], "first_run": False}


def comparison_row(run: SuiteRun) -> dict[str, Any]:
    lat = [x for r in run.results for x in r.latencies_ms]
    if not lat:  # MOCK / no model call recorded: the case durations
        lat = [r.duration_ms for r in run.results if r.status != "error"]
    return {
        "model": run.model, "suite_run_id": run.id, "pass_rate": run.pass_rate(), "counts": run.counts,
        "cost_usd": round(sum(r.cost_usd for r in run.results), 6),
        "median_latency_ms": round(statistics.median(lat), 1) if lat else None,
        "latency_source": "model_calls" if any(r.latencies_ms for r in run.results) else "case_duration",
        "failed_cases": [{"case_id": r.case_id, "name": r.name, "status": r.status}
                         for r in run.results if r.status != "pass"],
    }
