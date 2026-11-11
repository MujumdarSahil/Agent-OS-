"""
test_restructure_1_1b.py - Guards for the 2.0 server package move (sub-milestone 1.1b).

Pins:
  - Import matrix: every v1 ``agentos.server.*`` path resolves to the identical
    ``agentos_server.*`` module object and warns once per process.
  - The v1 ``/api/*`` route table is unchanged.
  - Boundary: the core ``agentos`` package never imports ``agentos_server`` or
    any web framework.

All tests run offline with mock LLM [MOCK].
"""

import ast
import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTOS_DIR = REPO_ROOT / "agentos"

ROUTE_MODULES = [
    "agents", "builder", "checkpoints", "crews", "federation", "governance", "health",
    "mcp_plugins", "missions", "packaging", "providers", "runs", "templates", "tools",
]
SERVER_MODULES = ["", ".app", ".models", ".run_manager", ".routes"] + [f".routes.{m}" for m in ROUTE_MODULES]

# v1 /api route table as of 2.0 / 1.1a. Changing it is a public API break (CLAUDE.md rule 3).
V1_API_ROUTES = sorted([
    ("/api/agent-types", "GET"), ("/api/agents", "GET"), ("/api/agents", "POST"),
    ("/api/agents/{name}", "DELETE"), ("/api/agents/{name}", "GET"), ("/api/agents/{name}", "PUT"),
    ("/api/builder/agent", "POST"), ("/api/builder/agent/confirm", "POST"),
    ("/api/builder/crew", "POST"), ("/api/builder/crew/confirm", "POST"),
    ("/api/builder/tool", "POST"), ("/api/builder/tool/confirm", "POST"),
    ("/api/checkpoints", "GET"), ("/api/checkpoints/{mission_name}", "GET"),
    ("/api/crews", "GET"), ("/api/crews", "POST"), ("/api/crews/{name}", "GET"),
    ("/api/federation/missions", "GET"), ("/api/federation/missions", "POST"),
    ("/api/federation/missions/{name}/run", "POST"), ("/api/federation/runs/{run_id}/status", "GET"),
    ("/api/governance/policies", "GET"), ("/api/governance/policies", "POST"),
    ("/api/governance/policies/{policy_id}", "DELETE"), ("/api/health", "GET"),
    ("/api/mcp-plugins", "GET"), ("/api/mcp-plugins", "POST"),
    ("/api/missions", "GET"), ("/api/missions", "POST"), ("/api/missions/{name}", "GET"),
    ("/api/missions/{name}/run", "POST"),
    ("/api/packaging/build", "POST"), ("/api/packaging/install", "POST"),
    ("/api/packaging/sign", "POST"), ("/api/packaging/verify", "POST"),
    ("/api/providers", "GET"), ("/api/providers/fallback-chain", "GET"),
    ("/api/providers/keys", "POST"), ("/api/providers/keys/{provider_name}", "DELETE"),
    ("/api/providers/test/{provider_name}", "POST"),
    ("/api/runs/{run_id}/status", "GET"), ("/api/runs/{run_id}/stream", "WS"),
    ("/api/templates", "GET"), ("/api/templates/{name}/install", "POST"),
    ("/api/tool-types", "GET"), ("/api/tools", "GET"), ("/api/tools", "POST"),
])

FORBIDDEN_IN_CORE = {"agentos_server", "fastapi", "starlette", "uvicorn"}


def _run_python(code: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "AGENTOS_MOCK_LLM": "1", "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=180,
    )


def _route_table(app):
    table = set()
    for route in app.routes:
        if not route.path.startswith("/api"):
            continue
        for method in sorted(getattr(route, "methods", None) or ["WS"]):
            if method != "HEAD":
                table.add((route.path, method))
    return sorted(table)


# ---------------------------------------------------------------------------
# Import matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("suffix", SERVER_MODULES)
def test_old_import_path_is_same_module(suffix):
    new = importlib.import_module("agentos_server" + suffix)
    old = importlib.import_module("agentos.server" + suffix)
    if suffix:
        assert old is new
    else:
        # The package itself is the shim; its submodules are aliases.
        assert old.__name__ == "agentos.server"


def test_old_from_imports_return_same_objects():
    from agentos.server.app import create_app as old_create_app
    from agentos.server.run_manager import RunManager as OldRunManager
    from agentos_server.app import create_app
    from agentos_server.run_manager import RunManager

    assert old_create_app is create_app
    assert OldRunManager is RunManager


def test_shim_warns_exactly_once_per_process():
    proc = _run_python(
        "import warnings\n"
        "with warnings.catch_warnings(record=True) as caught:\n"
        "    warnings.simplefilter('always')\n"
        "    import agentos.server.app\n"
        "    import agentos.server.routes.runs\n"
        "    from agentos.server import models\n"
        "msgs = [str(w.message) for w in caught if 'agentos.server is deprecated' in str(w.message)]\n"
        "print(len(msgs), all(issubclass(w.category, DeprecationWarning) for w in caught\n"
        "      if 'agentos.server is deprecated' in str(w.message)))\n"
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == "1 True"


def test_importing_shim_package_is_lazy():
    proc = _run_python(
        "import sys, agentos.server\n"
        "print('agentos_server' in sys.modules)\n"
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == "False"


def test_old_uvicorn_factory_path_resolves():
    # uvicorn resolves "module:attr" via importlib; this is the same lookup.
    module_name, attr = "agentos.server.app:create_app".split(":")
    factory = getattr(importlib.import_module(module_name), attr)
    from agentos_server.app import create_app
    assert factory is create_app


# ---------------------------------------------------------------------------
# /api route table
# ---------------------------------------------------------------------------

def test_v1_api_route_table_unchanged(tmp_path):
    from agentos_server.app import create_app
    assert _route_table(create_app(str(tmp_path))) == V1_API_ROUTES


def test_api_route_table_same_via_old_path(tmp_path):
    from agentos.server.app import create_app as old_create_app
    from agentos_server.app import create_app
    assert _route_table(old_create_app(str(tmp_path))) == _route_table(create_app(str(tmp_path)))


# ---------------------------------------------------------------------------
# Boundary: agentos never imports agentos_server or a web framework
# ---------------------------------------------------------------------------

def _imported_top_level_names(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module.split(".")[0]


def test_core_source_has_no_server_or_web_framework_imports():
    offenders = []
    for path in AGENTOS_DIR.rglob("*.py"):
        # Test suites may import the server to exercise it; only library code is bound.
        if any(part in {"__pycache__", "frontend", "node_modules", "tests"} for part in path.parts):
            continue
        for lineno, name in _imported_top_level_names(path):
            if name in FORBIDDEN_IN_CORE:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno} imports {name}")
    assert offenders == []


def test_importing_agentos_does_not_load_agentos_server():
    # Note: fastapi itself IS loaded at runtime, transitively by crewai
    # (crewai/a2a/auth/server_schemes.py). That is a third-party import and is
    # covered by the AST check above for our own code.
    proc = _run_python("import sys, agentos; print('agentos_server' in sys.modules)")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == "False"
