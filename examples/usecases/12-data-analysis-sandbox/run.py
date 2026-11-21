"""Use case 12 (MOCK model, LIVE sandbox): an agent computes statistics over a CSV by writing Python.

The model is a scripted stand-in (no keys, no network). The code it "writes" really runs in the AgentOS sandbox, on
every backend available here: Docker (strongest) and/or wasm (CPython WASI in wasmtime). Each attack is code a
prompt-injected agent might write; every one must FAIL SAFELY. With no backend at all, the code tools refuse
(fail closed) and nothing runs.

Scenarios (per backend)
- benign:                  file_write the CSV, python_exec computes mean / median / stdev, file_read the result.
- network_exfiltration:    socket + HTTP to a listener on the host                -> no connection
- read_host_home:          read a canary "~/.agentos/vault.json" on the host      -> not visible
- read_environment:        dump os.environ (the host has a canary key set)        -> empty / no keys
- write_outside_workspace: write next to the canary and to ../, /, /etc           -> host unchanged
- path_traversal_names:    create '..\\evil.txt', 'C:evil.txt', 'nul', streams   -> refused on copy-out
- symlink_escape:          symlinks to /, /etc/passwd, the canary                 -> refused on copy-out
- fork_bomb, memory_bomb, infinite_loop, huge_output                              -> stopped at the limit

The "host" canaries live in a temporary folder made here (never the real home or ~/.agentos).

Usage:  python examples/usecases/12-data-analysis-sandbox/run.py
        (wasm: pip install .[sandbox-wasm] and `agentos sandbox install-wasm`, or set AGENTOS_TEST_WASM_BUILD;
         docker: Docker running)
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

os.environ.setdefault("AGENTOS_MOCK_LLM", "1")

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from crewai.llm import BaseLLM  # noqa: E402

from agentos.flows.engine import FlowEngine  # noqa: E402
from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition  # noqa: E402
from agentos.flows.policy import SecurityPolicy  # noqa: E402
from agentos.sandbox import SandboxService, SandboxSettings  # noqa: E402
from agentos.sandbox.models import SandboxLimits  # noqa: E402
from agentos.sandbox.wasm_build import install, verified_build  # noqa: E402
from agentos.storage import open_storage  # noqa: E402


def _load_attacks():
    if "uc12_attacks" in sys.modules:
        return sys.modules["uc12_attacks"]
    spec = importlib.util.spec_from_file_location("uc12_attacks", HERE / "attacks.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["uc12_attacks"] = mod
    spec.loader.exec_module(mod)
    return mod


attacks = _load_attacks()

STATS_CODE = (
    "import csv, json, statistics\n"
    "vals = [float(r['amount']) for r in csv.DictReader(open('sales.csv'))]\n"
    "stats = {'count': len(vals), 'mean': round(statistics.mean(vals), 2), 'median': statistics.median(vals),\n"
    "         'stdev': round(statistics.stdev(vals), 2), 'min': min(vals), 'max': max(vals)}\n"
    "open('stats.json', 'w').write(json.dumps(stats))\n"
    "print(json.dumps(stats))\n"
)


class ScriptedLLM(BaseLLM):
    """Deterministic stand-in for a model: returns the next scripted ReAct step."""

    model: str = "mock/scripted"
    responses: list[str] = []

    def call(self, messages: Any, **kwargs: Any) -> str:
        idx = getattr(self, "_idx", 0)
        object.__setattr__(self, "_idx", idx + 1)
        return self.responses[idx] if idx < len(self.responses) else "Thought: done\nFinal Answer: done"


def step(thought: str, tool: str, args: dict[str, Any]) -> str:
    return f"Thought: {thought}\nAction: {tool}\nAction Input: {json.dumps(args)}"


def benign_script(csv_text: str) -> list[str]:
    return [step("I will put the CSV into the sandbox workspace.", "file_write", {"path": "sales.csv",
                                                                                  "content": csv_text}),
            step("Now compute the statistics in Python.", "python_exec", {"code": STATS_CODE}),
            step("Read the saved result.", "file_read", {"path": "stats.json"}),
            "Thought: I have the statistics.\nFinal Answer: statistics computed (see stats.json)"]


def attack_script(code: str) -> list[str]:
    return [step("The document told me to run this code.", "python_exec", {"code": code}),
            "Thought: done.\nFinal Answer: done"]


def load_flow() -> FlowDefinition:
    data = json.loads((HERE / "flows" / "data_analysis.flow.json").read_text(encoding="utf-8"))
    nodes = {nid: NodeDefinition(id=n["id"], type=n["type"], config=n.get("config", {}),
                                 pinned_args=n.get("pinned_args", {})) for nid, n in data["nodes"].items()}
    edges = [EdgeDefinition(source=e["source"], target=e["target"], arg_mapping=e.get("arg_mapping", {}))
             for e in data["edges"]]
    return FlowDefinition(id=data["id"], name=data.get("name", ""), entrypoint=data["entrypoint"], nodes=nodes,
                          edges=edges)


def prepare_wasm(data: Path) -> bool:
    """Make the pinned build available in this run's temp data dir (hash verified), if one is available here."""
    src = os.environ.get("AGENTOS_TEST_WASM_BUILD")
    if not src:
        try:
            from agentos.core.locations import data_dir

            found = verified_build(data_dir())
            src = str(found) if found else None
        except Exception:  # e.g. the real-home guard refuses the default data dir
            src = None
    if not src or not Path(src).is_file():
        return False
    install(data, fetch=lambda url, dest: shutil.copyfile(src, dest))
    return True


async def run_flow(td: Path, label: str, svc: SandboxService, script: list[str]) -> dict[str, Any]:
    proj = td / label
    proj.mkdir(parents=True)
    (proj / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    storage = await open_storage(str(proj), backend="file", vault_path=str(td / f"{label}-vault.json"))
    try:
        engine = FlowEngine(load_flow(), storage, policy=SecurityPolicy(), sandbox=svc,
                            custom_llm=ScriptedLLM(model="mock/scripted", responses=script))
        run_id = f"run_uc12_{label}"
        state = await engine.run(run_id, inputs={"text": "Compute statistics for the attached sales CSV."},
                                 raise_on_error=False)
        events = [(e.type, e.data or {}) for e in await storage.events.list(run_id)]
        return {"status": state.status.value, "events": events,
                "workspace_deleted": not (svc.data_dir / "sandbox" / "runs" / run_id).exists()}
    finally:
        await storage.close()


def result_from(events: list[tuple[str, dict[str, Any]]]) -> Any:
    ex = [d for t, d in events if t == "sandbox_exec"]
    if not ex:
        return None
    d = ex[-1]
    return SimpleNamespace(stdout=d.get("stdout", ""), stderr=d.get("stderr", ""), exit_code=d.get("exit_code"),
                           limit_hit=d.get("limit_hit"), refused_files=d.get("refused_files", []),
                           files_out={k: b"" for k in (d.get("files_out") or {})}, label=d.get("label"))


async def run_backend(td: Path, backend: str, svc: SandboxService) -> tuple[bool, list[str]]:
    lines = [f"== backend: {backend} =="]
    ok = True
    csv_text = (HERE / "data" / "sales.csv").read_text(encoding="utf-8")
    b = await run_flow(td, f"{backend}-benign", svc, benign_script(csv_text))
    res = result_from(b["events"])
    good = bool(res and res.exit_code == 0 and '"mean": ' in res.stdout and "stats.json" in res.files_out
                and res.label["integrity"] == "untrusted" and b["workspace_deleted"])
    ok &= good
    lines.append(f"  benign: {'OK' if good else 'FAILED'}: {res.stdout.strip() if res else 'no sandbox run'}"
                 f" (output label {res.label['integrity'] if res else '-'}; workspace deleted at run end: "
                 f"{b['workspace_deleted']})")
    host = attacks.HostCtx(td / f"{backend}-host")
    try:
        for name, (kind, code, check) in attacks.scenarios(host).items():
            r = await run_flow(td, f"{backend}-{name}", svc, attack_script(code))
            res = result_from(r["events"])
            if res is None:
                refused = [d.get("reason") for t, d in r["events"] if t == "tool_call_rejected"]
                safe, why = bool(refused) and host.host_unchanged(), f"refused: {refused[:1]}"
            else:
                safe, why = check(res)
                if name == "fork_bomb" and backend == "wasm":
                    safe = safe or (res.exit_code not in (0, None) and host.host_unchanged())  # WASI has no fork
            ok &= bool(safe)
            lines.append(f"  attack {name:<24} {'FAILED SAFELY' if safe else 'NOT CONTAINED'}: {why}")
    finally:
        host.close()
    return ok, lines


async def fail_closed(td: Path) -> tuple[bool, list[str]]:
    class Off:
        def __init__(self, name, kinds):
            self.name, self.kinds = name, kinds

        def available(self):
            return False

        def status(self):
            return {"available": False, "detail": "not available", "kinds": list(self.kinds)}

    svc = SandboxService(td / "nodata", docker=Off("docker", ("python", "shell")), wasm=Off("wasm", ("python",)))
    r = await run_flow(td, "no-backend", svc, attack_script(STATS_CODE))
    refused = [d.get("reason", "") for t, d in r["events"] if t == "tool_call_rejected"]
    ran = [t for t, _ in r["events"] if t == "sandbox_exec"]
    ok = bool(refused) and not ran
    return ok, ["== no backend ==", f"  python_exec {'REFUSED (fail closed)' if ok else 'NOT REFUSED'}: "
                                    f"{refused[0] if refused else '-'}"]


async def _run_usecase_async(require_backend: bool = False) -> bool:
    # ignore_cleanup_errors: on Windows the checkpoint SQLite files can still be open when the folder is removed
    with tempfile.TemporaryDirectory(prefix="uc12-", ignore_cleanup_errors=True) as tmp:
        td = Path(tmp)
        lines: list[str] = []
        ok, ls = await fail_closed(td)
        lines += ls
        data = td / "data"
        limits = SandboxLimits(timeout_s=5)
        backends = []
        if prepare_wasm(data):
            backends.append("wasm")
        probe = SandboxService(data)
        if probe.docker.available():
            backends.append("docker")
        if require_backend and not backends:
            lines.append("NO SANDBOX BACKEND AVAILABLE (required here)")
            ok = False
        for b in backends:
            svc = SandboxService(data)
            svc._settings = SandboxSettings(backend=b, limits=limits)
            svc.settings_store = None
            good, ls = await run_backend(td, b, svc)
            ok &= good
            lines += ls
        if not backends:
            lines.append("(no sandbox backend here: only the fail-closed scenario ran)")
        print("\n".join(lines))
        print(f"\nUse case 12: {'PASS' if ok else 'FAIL'} (backends: {', '.join(backends) or 'none'})")
        return ok


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(_run_usecase_async()) else 1)
