"""The one place AgentOS loads ``.env`` files (Part 0a of 3.4).

Called at startup only (server ``create_app``, CLI commands that run projects), never at import time.
``AGENTOS_SKIP_DOTENV=1`` disables it completely (e2e, screenshot and recording servers, MOCK demos), so a
developer's provider keys in a repo-root ``.env`` never reach such a process.

Order: the repository root ``.env`` (source checkouts only), then ``<project>/.env`` which overrides it.
Only file paths are logged, never values.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SKIP_ENV = "AGENTOS_SKIP_DOTENV"
_REPO_ROOT = Path(__file__).resolve().parents[2]


def dotenv_disabled() -> bool:
    return os.environ.get(SKIP_ENV) == "1"


def load_env_files(project_path: Optional[str] = None, *, include_repo_root: bool = True) -> list[str]:
    """Load ``.env`` files into ``os.environ``; returns the files loaded (paths only)."""
    if dotenv_disabled():
        return []
    try:
        from dotenv import load_dotenv
    except ImportError:
        return []
    loaded: list[str] = []
    if include_repo_root:
        root_env = _REPO_ROOT / ".env"
        if root_env.is_file():
            load_dotenv(root_env)
            loaded.append(str(root_env))
    if project_path:
        project_env = Path(project_path) / ".env"
        if project_env.is_file() and str(project_env) not in loaded:
            load_dotenv(project_env, override=True)
            loaded.append(str(project_env))
    if loaded:
        logger.info("Loaded environment from %s", ", ".join(loaded))
    return loaded
