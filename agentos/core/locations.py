"""Where AgentOS keeps its data: ONE resolver shared by the launcher (main.py), the server and the CLI (3.5 Part 0b).

Before 3.5 the CLI (``agentos users create-admin``) and the server could pick different locations, so an admin
created with the CLI was invisible to the server ("No users yet").

- Project folder: ``--project``, else ``AGENTOS_PROJECT`` (main.py always sets it for the server), else the current
  folder when it has ``agentos.config.yaml``, else the default workspace ``~/.agentos/workspace``.
- Storage: MongoDB iff ``AGENTOS_MONGO_URI`` is set (database ``AGENTOS_MONGO_DB``, default ``agentos``), else
  file storage in the project folder. This is the server's rule; the CLI follows it.
- Data dir (sandbox runtime, per-run sandbox workspaces): ``AGENTOS_DATA_DIR``, else ``~/.agentos/data``.

Every path goes through the real-home guard (``AGENTOS_FORBID_REAL_HOME``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from agentos.core.home_guard import check_path, checked

CONFIG_FILE = "agentos.config.yaml"


def default_workspace() -> Path:
    return Path.home() / ".agentos" / "workspace"


def resolve_project_dir(project_arg: Optional[str] = None, create_default: bool = False) -> str:
    """The project folder, resolved exactly like the launcher does for the server."""
    if project_arg:
        path = os.path.abspath(project_arg)
    elif os.environ.get("AGENTOS_PROJECT"):
        path = os.path.abspath(os.environ["AGENTOS_PROJECT"])
    elif os.path.exists(os.path.join(os.getcwd(), CONFIG_FILE)):
        path = os.getcwd()
    else:
        ws = checked(default_workspace(), "default workspace")
        if create_default:
            ws.mkdir(parents=True, exist_ok=True)
            cfg = ws / CONFIG_FILE
            if not cfg.exists():
                cfg.write_text("preferred_tags: []\n", encoding="utf-8")
        path = str(ws)
    check_path(path, "project folder")
    return path


def mongo_settings() -> Optional[tuple[str, str]]:
    """(uri, db name) when Platform (Mongo) storage is configured, else None."""
    uri = os.environ.get("AGENTOS_MONGO_URI")
    if not uri:
        return None
    from agentos.storage.mongo import DEFAULT_DB

    return uri, os.environ.get("AGENTOS_MONGO_DB") or DEFAULT_DB


def describe_data_location(project_dir: str) -> str:
    """Human-readable data location: a path or a Mongo database name (never the URI: it may hold credentials)."""
    m = mongo_settings()
    if m is not None:
        return f"MongoDB database {m[1]!r} (AGENTOS_MONGO_URI is set)"
    return f"{project_dir} (file storage)"


async def open_app_storage(project_dir: str) -> Any:
    """The storage the server uses for this project: Mongo iff AGENTOS_MONGO_URI, else file storage."""
    m = mongo_settings()
    if m is not None:
        from agentos.storage.mongo import open_mongo_storage

        return await open_mongo_storage(m[0], m[1])
    from agentos.storage.file import open_file_storage

    return open_file_storage(project_dir)


def data_dir() -> Path:
    """AgentOS data dir (not inside a project): sandbox runtime cache and per-run sandbox workspaces."""
    raw = os.environ.get("AGENTOS_DATA_DIR")
    return checked(Path(raw) if raw else Path.home() / ".agentos" / "data", "data dir")
