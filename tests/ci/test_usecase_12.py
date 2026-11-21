"""CI test for Use Case 12: data analysis in the sandbox (MOCK scripted model; the sandbox itself is LIVE).

Runs the fail-closed scenario always, and the benign + attack scenarios on every sandbox backend available:
wasm (python-ci installs the extra and the pinned build and sets AGENTOS_REQUIRE_WASM=1, so a missing backend FAILS
there) and Docker (sandbox-docker job).
"""

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "12-data-analysis-sandbox"


def _load(name: str, file: str):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, USECASE_DIR / file)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_usecase_12_data_analysis_sandbox():
    """benign stats on every available backend; every attack fails safely; no backend -> refused (fail closed)."""
    require = os.environ.get("AGENTOS_REQUIRE_WASM") == "1" or os.environ.get("AGENTOS_REQUIRE_DOCKER") == "1"
    assert asyncio.run(_load("usecase_12_run", "run.py")._run_usecase_async(require_backend=require)) is True


def test_usecase_12_flow_and_attack_list():
    flow = json.loads((USECASE_DIR / "flows" / "data_analysis.flow.json").read_text(encoding="utf-8"))
    assert flow["nodes"]["analyst"]["config"]["tools"] == ["file_write", "python_exec", "file_read"]
    attacks = _load("uc12_attacks", "attacks.py")
    expected = {"network_exfiltration", "read_host_home", "read_environment", "write_outside_workspace",
                "path_traversal_names", "symlink_escape", "fork_bomb", "memory_bomb", "infinite_loop", "huge_output"}
    with tempfile.TemporaryDirectory() as td:
        ctx = attacks.HostCtx(Path(td))
        try:
            assert set(attacks.scenarios(ctx)) == expected
        finally:
            ctx.close()
