"""
JobsConfig - Pydantic v2 configuration schema and loader for Job Application Agent.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


def get_repo_root() -> Path:
    """Detects the root of the repository by walking up to find .git or pyproject.toml."""
    cur = Path(__file__).resolve().parent
    for p in [cur] + list(cur.parents):
        if (p / ".git").exists() or (p / "pyproject.toml").exists():
            return p.resolve()
    return Path.cwd().resolve()


def get_default_db_path() -> Path:
    """Returns the default SQLite DB path outside the repository."""
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data and local_app_data.strip():
            base = Path(local_app_data.strip())
        else:
            base = Path.home() / "AppData" / "Local"
        return base / "AgentOS" / "jobs" / "jobs.db"
    return Path.home() / ".local" / "share" / "agentos" / "jobs" / "jobs.db"


def is_path_inside_repo(target_path: Path, repo_root: Path) -> bool:
    """Returns True if target_path resolves to a location inside repo_root."""
    resolved_target = target_path.resolve()
    resolved_repo = repo_root.resolve()
    try:
        resolved_target.relative_to(resolved_repo)
        return True
    except ValueError:
        # Cross-platform case normalization fallback
        target_str = os.path.normcase(str(resolved_target))
        repo_str = os.path.normcase(str(resolved_repo))
        if target_str == repo_str or target_str.startswith(repo_str + os.sep):
            return True
        return False


class JobsConfig(BaseModel):
    """
    Pydantic v2 schema for AgentOS Job Application Agent configuration.
    """
    enabled: bool = False
    roles: List[str] = Field(default_factory=list)
    experience_min: Optional[int] = Field(default=None, ge=0)
    experience_max: Optional[int] = Field(default=None, ge=0)
    locations: List[str] = Field(default_factory=list)
    salary_min: Optional[int] = Field(default=None, ge=0)
    salary_max: Optional[int] = Field(default=None, ge=0)
    sources: List[str] = Field(default_factory=list)
    allowed_providers: List[str] = Field(default_factory=list)
    max_llm_calls_per_run: int = Field(default=0, ge=0)
    run_timeout_seconds: int = Field(default=300, gt=0)
    db_path: str = Field(default_factory=lambda: str(get_default_db_path()))
    notify_email_enabled: bool = False
    greenhouse_boards: List[str] = Field(default_factory=list)

    @field_validator("greenhouse_boards", mode="after")
    @classmethod
    def validate_greenhouse_boards(cls, v: List[str]) -> List[str]:
        import re
        for board in v:
            if not re.match(r"^[a-z0-9_-]{1,64}$", board):
                raise ValueError(
                    f"Invalid Greenhouse board token '{board}'. "
                    f"Must match ^[a-z0-9_-]{{1,64}}$ to prevent URL injection."
                )
        return v

    @field_validator("db_path", mode="after")
    @classmethod
    def validate_db_path(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("db_path must not be empty.")
        path = Path(v).expanduser().resolve()
        repo_root = get_repo_root()
        if is_path_inside_repo(path, repo_root):
            raise ValueError(
                f"Database path '{v}' resolves inside the repository root ('{repo_root}'). "
                f"Database files must be stored outside the repository directory."
            )
        return str(path)

    @model_validator(mode="after")
    def validate_ranges(self) -> JobsConfig:
        if (
            self.experience_min is not None
            and self.experience_max is not None
            and self.experience_min > self.experience_max
        ):
            raise ValueError(
                f"experience_min ({self.experience_min}) cannot exceed experience_max ({self.experience_max})."
            )
        if (
            self.salary_min is not None
            and self.salary_max is not None
            and self.salary_min > self.salary_max
        ):
            raise ValueError(
                f"salary_min ({self.salary_min}) cannot exceed salary_max ({self.salary_max})."
            )
        return self


def load_jobs_config(config_path: str | Path) -> JobsConfig:
    """
    Reads a YAML file, validates it against JobsConfig, and returns the config instance.
    Raises clear errors on file missing, unparseable YAML, or validation failure.
    """
    path = Path(config_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Jobs configuration file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Jobs configuration path is not a file: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ValueError(f"Error parsing YAML from {path}: {exc}") from exc

    if data is None:
        data = {}
    elif not isinstance(data, dict):
        raise ValueError(f"Jobs configuration root must be a YAML mapping, got {type(data).__name__}")

    return JobsConfig.model_validate(data)
