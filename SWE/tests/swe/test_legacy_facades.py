"""Legacy agentos_swe facade packages stay importable but emit a DeprecationWarning (2.0 cleanup)."""

import importlib
import sys

import pytest

FACADES = {
    "repair": "remediation.repair",
    "incident": "operations.incident",
    "drift": "intelligence.drift",
    "pr": "remediation.pr",
    "controlplane": "operations.controlplane",
    "attackpath": "intelligence.attackpath",
    "monitoring": "operations.monitoring",
    "history": "intelligence.history",
    "graph": "analysis.graph",
    "semantic": "analysis.semantic",
    "learning": "intelligence.learning",
    "correlation": "remediation.correlation",
    "agents": "core.agents",
    "verification": "analysis.verification",
    "simulation": "remediation.simulation",
    "orchestration": "operations.orchestration",
    "knowledge": "intelligence.knowledge",
}


@pytest.mark.parametrize("old,new", sorted(FACADES.items()))
def test_facade_warns_and_reexports(old, new):
    name = f"agentos_swe.{old}"
    sys.modules.pop(name, None)
    with pytest.warns(DeprecationWarning, match=rf"agentos_swe\.{new}.*separate pack"):
        facade = importlib.import_module(name)
    real = importlib.import_module(f"agentos_swe.{new}")
    public = [n for n in dir(real) if not n.startswith("_")]
    assert all(hasattr(facade, n) for n in public)
