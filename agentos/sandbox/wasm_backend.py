"""wasm backend: Python only, no Docker needed, works on Windows (3.5, D5).

The user's code never runs on the host: it is a file in the per-call workspace, executed by the pinned CPython WASI
build inside wasmtime, in a child process that runs only ``_wasm_child.py`` (minimal environment, killed if it outlives
the time limit, so no orphans).
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from agentos.sandbox import paths
from agentos.sandbox.models import SandboxLimits, SandboxResult, SandboxUnavailable
from agentos.sandbox.wasm_build import WASM_SHA256, build_state, verified_build, wasmtime_version

CHILD = Path(__file__).with_name("_wasm_child.py")
COMPILE_GRACE_S = 30.0  # first start compiles the module (later starts load the cached compiled module)


def wasmtime_importable() -> bool:
    import importlib.util

    return importlib.util.find_spec("wasmtime") is not None


def _child_env() -> dict[str, str]:
    """Nothing from the host environment except what Windows needs to start Python."""
    env: dict[str, str] = {}
    if os.name == "nt":
        # platform.machine() (used by wasmtime to find its library) reads PROCESSOR_ARCHITECTURE on Windows
        for k in ("SYSTEMROOT", "WINDIR", "PROCESSOR_ARCHITECTURE"):
            if os.environ.get(k):
                env[k] = os.environ[k]
    return env


class WasmBackend:
    name = "wasm"
    kinds = ("python",)

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)

    def status(self) -> dict[str, Any]:
        wt = wasmtime_version() if wasmtime_importable() else None
        state = build_state(self.data_dir)
        ok = bool(wt) and state == "installed"
        if not wt:
            detail = "wasmtime is not installed (pip install agentos[sandbox-wasm])"
        elif state == "missing":
            detail = "the CPython WASI build is not installed (agentos sandbox install-wasm, or Settings -> Sandbox)"
        elif state == "tampered":
            detail = "the installed CPython WASI build does not match the pinned sha256; it is never used (reinstall)"
        else:
            detail = "ready"
        return {"available": ok, "wasmtime": wt, "build": state, "build_sha256": WASM_SHA256, "detail": detail,
                "kinds": list(self.kinds)}

    def available(self) -> bool:
        return bool(self.status()["available"])

    def run(self, kind: str, payload: str, files_in: dict[str, bytes], limits: SandboxLimits,
            run_label: str = "") -> SandboxResult:
        if kind not in self.kinds:
            raise SandboxUnavailable("the wasm backend runs Python only; shell needs the Docker backend")
        if not wasmtime_importable():
            raise SandboxUnavailable("wasmtime is not installed")
        build = verified_build(self.data_dir)  # sha256 checked on every load
        if build is None:
            raise SandboxUnavailable("the CPython WASI build is missing or does not match the pinned sha256")
        base = self.data_dir / "sandbox" / "tmp"
        base.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="wasm-", dir=base))
        try:
            ws = tmp / "workspace"
            ws.mkdir()
            tag = secrets.token_hex(6)
            main_name, code_name = f".agentos_run_{tag}.py", f".agentos_code_{tag}.py"
            paths.write_files(ws, files_in, limits.file_bytes, limits.workspace_bytes)
            (ws / code_name).write_text(payload, encoding="utf-8")
            # the guest starts in "/": a tiny AgentOS runner makes /workspace the current folder, then runs the code
            (ws / main_name).write_text(
                "import os, runpy, sys\nos.chdir('/workspace')\nsys.argv = ['main.py']\n"
                f"runpy.run_path('/workspace/{code_name}', run_name='__main__')\n", encoding="utf-8")
            spec = {
                "wasm": str(build), "cache": str(build.with_suffix(f".{wasmtime_version()}.cwasm")),
                "workspace": str(ws), "main": main_name, "timeout_s": limits.timeout_s,
                "memory_bytes": limits.memory_mb * 1024 * 1024, "stdout_cap": limits.stdout_bytes,
                "stderr_cap": limits.stderr_bytes, "workspace_cap": limits.workspace_bytes,
            }
            started = time.monotonic()
            proc = subprocess.Popen([sys.executable, "-I", str(CHILD)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=_child_env(), cwd=str(tmp))
            limit_hit: Optional[str] = None
            try:
                out, err = proc.communicate(json.dumps(spec).encode("utf-8"),
                                            timeout=limits.timeout_s + COMPILE_GRACE_S)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                limit_hit = "timeout"
            duration = (time.monotonic() - started) * 1000
            try:
                res = json.loads(out.decode("utf-8").strip().splitlines()[-1]) if out else {}
            except (ValueError, IndexError):
                res = {}
            if not res:
                return SandboxResult(exit_code=None, stdout="", stderr="", limit_hit=limit_hit,
                                     duration_ms=duration, backend=self.name, runtime_id=WASM_SHA256,
                                     error="the wasm runtime did not return a result"
                                           + ("" if limit_hit else f" ({err.decode('utf-8', 'replace')[-300:]})"))
            limit_hit = limit_hit or res.get("limit_hit")
            for n in (main_name, code_name):
                if not (ws / n).is_symlink():
                    (ws / n).unlink(missing_ok=True)
            if limit_hit == "workspace":
                files = paths.CopyOut()
            else:
                files = paths.collect_dir(ws, limits.file_bytes, limits.workspace_bytes)
                if files.over_cap:
                    limit_hit, files = "workspace", paths.CopyOut()
            exit_code = res.get("exit_code")
            return SandboxResult(
                exit_code=exit_code if exit_code is not None else (None if res.get("trap") else 0),
                stdout=res.get("stdout", ""), stderr=res.get("stderr", ""), files_out=files.files,
                limit_hit=limit_hit, duration_ms=float(res.get("duration_ms") or duration), backend=self.name,
                runtime_id=WASM_SHA256, stdout_truncated=bool(res.get("stdout_truncated")),
                stderr_truncated=bool(res.get("stderr_truncated")), refused_files=files.refused,
                error=None if not res.get("trap") or limit_hit else f"wasm trap: {res['trap']}",
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
