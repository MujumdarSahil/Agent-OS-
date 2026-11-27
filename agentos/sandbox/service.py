"""SandboxService: backend choice, per-run workspaces and the tool operations (3.5, D3/D6/D7).

Backend choice (admin setting ``backend``): ``auto`` = docker if available, else wasm (Python only); ``docker``;
``wasm``; ``off``. When nothing can run the requested kind the call is REFUSED (``SandboxUnavailable``): code is never
run as a plain subprocess on the host.

Per-run workspace (host): ``<data dir>/sandbox/runs/<run>/``. It is the input of every exec in the run and is
replaced by the validated output; ``file_read`` / ``file_write`` operate on it directly (no code runs). It is deleted
when the run ends, and workspaces older than 24 h are swept at start-up.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Optional

from agentos.sandbox import paths
from agentos.sandbox.docker_backend import DockerBackend
from agentos.sandbox.models import SandboxLimits, SandboxResult, SandboxSettings, SandboxUnavailable
from agentos.sandbox.wasm_backend import WasmBackend

KINDS = ("python", "shell")
TOOL_KIND = {"python_exec": "python", "shell_exec": "shell"}
SANDBOX_TOOLS = ("python_exec", "shell_exec", "file_read", "file_write")
_RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class SandboxService:
    def __init__(self, data_dir: Path, settings_store: Any = None, docker: Any = None, wasm: Any = None) -> None:
        self.data_dir = Path(data_dir)
        self.settings_store = settings_store
        self.docker = docker if docker is not None else DockerBackend()
        self.wasm = wasm if wasm is not None else WasmBackend(self.data_dir)
        self._settings = SandboxSettings()
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    # ------------------------------------------------------------------ settings
    async def get_settings(self) -> SandboxSettings:
        if self.settings_store is not None:
            self._settings = await self.settings_store.get()
        return self._settings

    async def put_settings(self, settings: SandboxSettings) -> None:
        if self.settings_store is not None:
            await self.settings_store.put(settings)
        self._settings = settings

    @property
    def settings(self) -> SandboxSettings:
        """Last loaded settings (refreshed by get_settings; used from worker threads without I/O)."""
        return self._settings

    # ------------------------------------------------------------------ status
    def backend_for(self, kind: str, settings: Optional[SandboxSettings] = None) -> Optional[Any]:
        mode = (settings or self._settings).backend
        if mode == "off":
            return None
        order = {"auto": [self.docker, self.wasm], "docker": [self.docker], "wasm": [self.wasm]}[mode]
        for b in order:
            if kind in b.kinds and b.available():
                return b
        return None

    def status(self, settings: Optional[SandboxSettings] = None) -> dict[str, Any]:
        s = settings or self._settings
        py = self.backend_for("python", s)
        sh = self.backend_for("shell", s)
        if s.backend == "off":
            summary = "off (code tools are disabled by the admin)"
        elif py is None:
            summary = "none: code tools are unavailable and refuse every call"
        else:
            summary = f"python: {py.name}; shell: {sh.name if sh else 'unavailable (needs Docker)'}"
        return {
            "mode": s.backend, "summary": summary,
            "docker": self.docker.status(), "wasm": self.wasm.status(),
            "effective": {"python": py.name if py else None, "shell": sh.name if sh else None},
            "tools": self.available_tools(s),
            "limits": s.limits.model_dump(), "images": [i.model_dump() for i in s.images],
            "default_image": s.default_image,
        }

    def available_tools(self, settings: Optional[SandboxSettings] = None) -> list[str]:
        s = settings or self._settings
        py = self.backend_for("python", s) is not None
        sh = self.backend_for("shell", s) is not None
        out = []
        if py:
            out += ["python_exec", "file_read", "file_write"]
        if sh:
            out.insert(1, "shell_exec")
        return out

    # ------------------------------------------------------------------ run
    def run(self, kind: str, payload: str, files_in: Optional[dict[str, bytes]] = None,
            limits: Optional[SandboxLimits] = None, run_label: str = "") -> SandboxResult:
        """The sandbox interface: run(kind, payload, files_in, limits) -> SandboxResult. Fails closed."""
        if kind not in KINDS:
            raise SandboxUnavailable(f"unknown sandbox kind {kind!r}")
        if not isinstance(payload, str) or not payload.strip():
            raise SandboxUnavailable("nothing to run (empty code)")
        s = self._settings
        backend = self.backend_for(kind, s)
        if backend is None:
            if s.backend == "off":
                raise SandboxUnavailable("code tools are disabled by the admin (Settings -> Sandbox)")
            need = "Docker" if kind == "shell" else "Docker or the wasm runtime"
            raise SandboxUnavailable(f"no sandbox backend is available for {kind} code ({need} is required); "
                                     f"the code was NOT run")
        limits = limits or s.limits
        if backend is self.docker:
            return backend.run(kind, payload, files_in or {}, limits, run_label=run_label, image=s.default_image)
        return backend.run(kind, payload, files_in or {}, limits, run_label=run_label)

    # ------------------------------------------------------------------ per-run workspace
    def _key(self, run_id: str) -> str:
        return run_id if _RUN_ID.match(run_id) else hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:40]

    def workspace(self, run_id: str) -> Path:
        d = self.data_dir / "sandbox" / "runs" / self._key(run_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def lock(self, run_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(self._key(run_id), threading.Lock())

    def cleanup_run(self, run_id: str) -> None:
        shutil.rmtree(self.data_dir / "sandbox" / "runs" / self._key(run_id), ignore_errors=True)
        with self._locks_guard:
            self._locks.pop(self._key(run_id), None)

    def sweep(self, max_age_s: float = 24 * 3600) -> int:
        base = self.data_dir / "sandbox" / "runs"
        removed = 0
        if base.is_dir():
            now = time.time()
            for d in base.iterdir():
                try:
                    if d.is_dir() and not d.is_symlink() and now - d.stat().st_mtime > max_age_s:
                        shutil.rmtree(d, ignore_errors=True)
                        removed += 1
                except OSError:
                    pass
        tmp = self.data_dir / "sandbox" / "tmp"
        if tmp.is_dir():
            shutil.rmtree(tmp, ignore_errors=True)
        return removed

    # ------------------------------------------------------------------ tool operations (blocking; call in a thread)
    def exec_in_run(self, run_id: str, kind: str, payload: str, files: Optional[dict[str, str]] = None) -> SandboxResult:
        """python_exec / shell_exec: run against the run's workspace and keep the validated output."""
        limits = self._settings.limits
        with self.lock(run_id):
            ws = self.workspace(run_id)
            if files:
                paths.write_files(ws, _encode_files(files), limits.file_bytes, limits.workspace_bytes)
            res = self.run(kind, payload, paths.read_dir(ws), limits, run_label=run_id)
            if res.error is None and res.limit_hit != "workspace":
                shutil.rmtree(ws, ignore_errors=True)
                ws.mkdir(parents=True, exist_ok=True)
                paths.write_files(ws, res.files_out, limits.file_bytes, limits.workspace_bytes)
            return res

    def write_file(self, run_id: str, path: str, content: str) -> tuple[str, int]:
        limits = self._settings.limits
        rel = paths.safe_rel_path(path)
        data = (content if isinstance(content, str) else str(content)).encode("utf-8")
        with self.lock(run_id):
            paths.write_files(self.workspace(run_id), {rel: data}, limits.file_bytes, limits.workspace_bytes)
        return rel, len(data)

    def read_file(self, run_id: str, path: str) -> tuple[str, str, bool]:
        """(path, text, truncated). Text is capped at the stdout cap."""
        limits = self._settings.limits
        with self.lock(run_id):
            target = paths.host_path(self.workspace(run_id), path)
            if not target.is_file() or target.is_symlink():
                raise paths.PathRefused(f"{paths.safe_rel_path(path)}: no such file in the sandbox workspace")
            data = target.read_bytes()
        cap = limits.stdout_bytes
        return paths.safe_rel_path(path), data[:cap].decode("utf-8", "replace"), len(data) > cap


def _encode_files(files: dict[str, Any]) -> dict[str, bytes]:
    if not isinstance(files, dict):
        raise paths.PathRefused("files must be an object of {relative path: text}")
    out = {}
    for k, v in files.items():
        out[paths.safe_rel_path(k)] = (v if isinstance(v, str) else str(v)).encode("utf-8")
    return out
