"""Minimal environment for stdio MCP server processes (2.5a, threat T4).

The child's environment is built from scratch; ``os.environ`` is never inherited. That matters
because AgentOS copies vault provider keys into its own environment at startup
(``export_vault_provider_keys``), and the API token and master key may be there too.

Windows
- copied from the parent if present: SYSTEMROOT, WINDIR, SYSTEMDRIVE, COMSPEC, PATH, PATHEXT,
  PROCESSOR_ARCHITECTURE, NUMBER_OF_PROCESSORS
- pointed at the per-server folder <project>/.agentos/mcp/<server>/home:
  USERPROFILE, HOME, APPDATA (home/AppData/Roaming), LOCALAPPDATA (home/AppData/Local), TEMP, TMP (home/tmp)
POSIX
- copied: PATH; set: HOME and TMPDIR (per-server folder), LANG=C.UTF-8
Both
- PYTHONIOENCODING=utf-8 and PYTHONUTF8=1 so the JSON-RPC stream is UTF-8
- then the record's ``env`` (names validated: never AGENTOS_* and never a provider key/base variable)
- then ``secret_env`` values resolved from the vault for this server only
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Mapping

WINDOWS_COPIED = (
    "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATH", "PATHEXT",
    "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
)
POSIX_COPIED = ("PATH",)
FIXED = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}


class MCPEnvError(ValueError):
    pass


def provider_env_names() -> set[str]:
    """Every provider key/base variable name in the registry (names only)."""
    from agentos.llm.provider_registry import PROVIDER_REGISTRY

    names: set[str] = set()
    for p in PROVIDER_REGISTRY:
        for k in ("api_key_env", "api_base_env"):
            if p.get(k):
                names.add(str(p[k]).upper())
    return names


def validate_env_names(env: Mapping[str, str], secret_env: Mapping[str, str]) -> None:
    """Plain ``env`` must not carry AgentOS settings or provider keys (those go through the vault)."""
    forbidden = provider_env_names()
    for name in list(env) + list(secret_env):
        if not name or "=" in name or "\x00" in name:
            raise MCPEnvError(f"invalid environment variable name {name!r}")
    for name in env:
        up = name.upper()
        if up.startswith("AGENTOS_"):
            raise MCPEnvError(f"env {name!r}: AGENTOS_* variables are never passed to MCP servers")
        if up in forbidden:
            raise MCPEnvError(f"env {name!r} is a provider key variable; use secret_env with a vault name")
    for name in secret_env:
        if name.upper().startswith("AGENTOS_"):
            raise MCPEnvError(f"secret_env {name!r}: AGENTOS_* variables are never passed to MCP servers")


def server_dir(project_path: str | Path, server: str) -> Path:
    return Path(project_path) / ".agentos" / "mcp" / server


def build_child_env(
    server: str,
    project_path: str | Path,
    env: Mapping[str, str],
    secrets: Mapping[str, str],
    parent_env: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> tuple[dict[str, str], Path]:
    """(environment, working directory) for a stdio MCP server. Creates the per-server folders."""
    parent = os.environ if parent_env is None else parent_env
    plat = platform or sys.platform
    base = server_dir(project_path, server)
    home = base / "home"
    out: dict[str, str] = {}
    if plat == "win32":
        upper = {k.upper(): v for k, v in parent.items()}
        for name in WINDOWS_COPIED:
            if name in upper:
                out[name] = upper[name]
        roaming, local, tmp = home / "AppData" / "Roaming", home / "AppData" / "Local", home / "tmp"
        for d in (roaming, local, tmp):
            d.mkdir(parents=True, exist_ok=True)
        out.update({
            "USERPROFILE": str(home), "HOME": str(home), "APPDATA": str(roaming),
            "LOCALAPPDATA": str(local), "TEMP": str(tmp), "TMP": str(tmp),
        })
    else:
        for name in POSIX_COPIED:
            if name in parent:
                out[name] = parent[name]
        tmp = home / "tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        out.update({"HOME": str(home), "TMPDIR": str(tmp), "LANG": "C.UTF-8"})
    out.update(FIXED)
    out.update(dict(env))
    out.update(dict(secrets))
    return out, base
