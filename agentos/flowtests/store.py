"""4.2 D2: test cases, suite runs (history) and gate settings.

File backend: ``<project>/.agentos/state/flow_test_cases.json``, ``flow_test_runs.json``, ``flow_test_settings.json``
(agentos.notify.store.FileDocs). Mongo backend: ``flow_test_cases``, ``flow_test_runs``, ``flow_test_settings``
(agentos.storage.mongo.notify.MongoDocs). Same interface for both.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

from agentos.flowtests.models import GateSettings, SuiteRun, TestCase

KEEP_RUNS_PER_FLOW = 50


class FlowTestStore:
    def __init__(self, cases: Any, runs: Any, settings: Any) -> None:
        self.cases = cases
        self.runs = runs
        self.settings = settings

    # ------------------------------------------------------------------ cases
    async def list_cases(self, flow_id: str, tags: Optional[list[str]] = None) -> list[TestCase]:
        out = [TestCase.model_validate(d) for d in await self.cases.list() if d.get("flow_id") == flow_id]
        if tags:
            want = set(tags)
            out = [c for c in out if want & set(c.tags)]
        return sorted(out, key=lambda c: (c.created_at, c.id))

    async def get_case(self, case_id: str) -> Optional[TestCase]:
        d = await self.cases.get(case_id)
        return TestCase.model_validate(d) if d else None

    async def put_case(self, case: TestCase) -> TestCase:
        case = case.model_copy(update={"updated_at": time.time()})
        await self.cases.put(case.model_dump(mode="json"))
        return case

    async def delete_case(self, case_id: str) -> bool:
        return await self.cases.delete(case_id)

    # ------------------------------------------------------------------ suite runs (history)
    async def list_runs(self, flow_id: str, limit: int = KEEP_RUNS_PER_FLOW) -> list[SuiteRun]:
        runs = [SuiteRun.model_validate(d) for d in await self.runs.list() if d.get("flow_id") == flow_id]
        runs.sort(key=lambda r: r.started_at, reverse=True)
        return runs[:limit]

    async def get_run(self, suite_run_id: str) -> Optional[SuiteRun]:
        d = await self.runs.get(suite_run_id)
        return SuiteRun.model_validate(d) if d else None

    async def previous_run(self, flow_id: str, model: str) -> Optional[SuiteRun]:
        """The latest stored suite run of this flow with the same model (D8)."""
        return next((r for r in await self.list_runs(flow_id) if r.model == model), None)

    async def save_run(self, run: SuiteRun) -> None:
        await self.runs.put(run.model_dump(mode="json"))
        runs = await self.list_runs(run.flow_id, limit=10_000)
        for old in runs[KEEP_RUNS_PER_FLOW:]:
            await self.runs.delete(old.id)

    # ------------------------------------------------------------------ gate settings
    async def get_gate(self, flow_id: str) -> GateSettings:
        d = await self.settings.get(f"gate:{flow_id}")
        if not d:
            return GateSettings(flow_id=flow_id)
        d = {k: v for k, v in d.items() if k != "id"}
        return GateSettings.model_validate(d)

    async def put_gate(self, gate: GateSettings) -> GateSettings:
        gate = gate.model_copy(update={"updated_at": time.time()})
        await self.settings.put({"id": f"gate:{gate.flow_id}", **gate.model_dump(mode="json")})
        return gate

    # ------------------------------------------------------------------ overview
    async def summary(self) -> dict[str, dict[str, Any]]:
        """Per flow: number of cases and the pass rate of the latest suite run (flow card / overview)."""
        out: dict[str, dict[str, Any]] = {}
        for d in await self.cases.list():
            fid = d.get("flow_id")
            if fid:
                out.setdefault(fid, {"cases": 0, "last_pass_rate": None, "last_run_at": None})["cases"] += 1
        latest: dict[str, dict[str, Any]] = {}
        for d in await self.runs.list():
            fid = d.get("flow_id")
            if fid in out and (fid not in latest or d.get("started_at", 0) > latest[fid].get("started_at", 0)):
                latest[fid] = d
        for fid, d in latest.items():
            run = SuiteRun.model_validate(d)
            out[fid]["last_pass_rate"] = run.pass_rate()
            out[fid]["last_run_at"] = run.started_at
        return out


def flowtests_store_for(storage: Any) -> FlowTestStore:
    if getattr(storage, "backend", "file") == "mongo":
        from agentos.storage.mongo.notify import MongoDocs

        db = storage.runs._c.database
        return FlowTestStore(MongoDocs(db.flow_test_cases), MongoDocs(db.flow_test_runs),
                             MongoDocs(db.flow_test_settings))
    from agentos.notify.store import FileDocs

    base = Path(storage.location) / ".agentos" / "state"
    return FlowTestStore(FileDocs(base / "flow_test_cases.json"), FileDocs(base / "flow_test_runs.json"),
                         FileDocs(base / "flow_test_settings.json"))
