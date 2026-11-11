"""
Importer / exporter between a v1 YAML project and any storage backend (sub-milestone 1.3).

import_project(project_dir, target)  v1 project -> target (usually Mongo)
export_project(source, out_dir)      source -> a v1-compatible project directory

What moves:
  agentos.config.yaml, agents, crews (squads, incl. roles), missions,
  v1 tools/*.py (as origin="project" tools; exported back to tools/*.py),
  2.0 entities (stored tools, MCP servers, provider configs) -> .agentos/*.json on export.
Lossy or skipped, always listed in the report:
  mcp_plugins/ (local plugin code) are not imported; run history, checkpoints and
  events are not migrated; credentials are never exported.
Secrets: provider API keys found in the project's .env are encrypted into the vault on
import. Other .env variables are reported by name only. No value is ever logged.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from agentos.core import project_ops
from agentos.security.vault import Vault
from agentos.storage.file import open_file_storage, safe_key
from agentos.storage.models import PROJECT_SETTINGS, ToolRecord, entity_key
from agentos.storage.ports import Storage

# Entities copied 1:1 between backends. Credentials are deliberately absent.
_COPIED = ("agents", "squads", "missions", "mcp_servers", "provider_configs")


@dataclass
class TransferReport:
    counts: Dict[str, int] = field(default_factory=dict)
    secrets_imported: List[str] = field(default_factory=list)  # vault entry names only
    skipped: List[str] = field(default_factory=list)

    def add(self, kind: str, n: int = 1) -> None:
        self.counts[kind] = self.counts.get(kind, 0) + n


def provider_key_envs() -> Dict[str, List[str]]:
    """API-key env var -> registry provider names that read it."""
    from agentos.llm.provider_registry import PROVIDER_REGISTRY

    envs: Dict[str, List[str]] = {}
    for p in PROVIDER_REGISTRY:
        if p.get("api_key_env"):
            envs.setdefault(p["api_key_env"], []).append(p["name"])
    return envs


def _write_project_tool(project_dir: str, tool: ToolRecord) -> None:
    tools_dir = Path(project_dir) / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    (tools_dir / f"{safe_key(tool.name)}.py").write_text(tool.code, encoding="utf-8")


# v1 folder -> how a file stem relates to the entity inside it
_V1_FOLDERS = {"agents": "agents", "crews": "squads", "missions": "missions"}


def scan_v1_file_names(project_dir: str) -> Dict[str, Dict[str, str]]:
    """Map entity slug -> file stem for v1 YAML files whose stem is not the slug of their name."""
    names: Dict[str, Dict[str, str]] = {}
    for folder in _V1_FOLDERS:
        for path in sorted((Path(project_dir) / folder).glob("*.yaml")):
            try:
                name = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("name")
            except yaml.YAMLError:
                continue
            if name and entity_key(name) != path.stem:
                names.setdefault(folder, {})[entity_key(name)] = path.stem
    return names


def restore_v1_file_names(project_dir: str, names: Dict[str, Dict[str, str]]) -> None:
    for folder, mapping in names.items():
        for key, stem in mapping.items():
            src = Path(project_dir) / folder / f"{key}.yaml"
            dst = Path(project_dir) / folder / f"{safe_key(stem)}.yaml"
            if src.exists() and not dst.exists():
                src.rename(dst)


async def copy_entities(source: Storage, target: Storage, report: TransferReport) -> None:
    file_names: Dict[str, Dict[str, str]] = {}
    if source.settings is not None and target.settings is not None:
        settings = await source.settings.get(PROJECT_SETTINGS)
        if settings is not None:
            file_names = scan_v1_file_names(source.location) if source.backend == "file" else settings.v1_file_names
            await target.settings.put(settings.model_copy(update={"v1_file_names": file_names}))
            report.add("settings")

    for kind in _COPIED:
        src_repo, dst_repo = getattr(source, kind), getattr(target, kind)
        for item in await src_repo.list():
            await dst_repo.put(item)
            report.add(kind)

    for tool in await source.tools.list():
        if tool.origin == "project" and target.backend == "file":
            # A v1 project tool goes back to tools/*.py, where the v1 runtime expects it.
            _write_project_tool(target.location, tool)
        else:
            await target.tools.put(tool)
        report.add(f"tools ({tool.origin})")

    if target.backend == "file" and file_names:
        restore_v1_file_names(target.location, file_names)
    report.skipped.append("run history, checkpoints and events are not migrated")


async def import_env_secrets(project_dir: str, vault: Optional[Vault], report: TransferReport) -> None:
    env_path = Path(project_dir) / ".env"
    if not env_path.exists():
        return
    from dotenv import dotenv_values

    key_envs = provider_key_envs()
    for name, value in dotenv_values(env_path).items():
        if not value:
            continue
        if name not in key_envs:
            report.skipped.append(f".env {name}: not a provider API key, not imported")
            continue
        if vault is None:
            report.skipped.append(f".env {name}: no vault configured, not imported")
            continue
        await vault.put(name, value, provider=",".join(key_envs[name]))
        report.secrets_imported.append(name)


async def import_project(
    project_dir: str, target: Storage, vault: Optional[Vault] = None, import_env: bool = True
) -> TransferReport:
    project_dir = os.path.abspath(project_dir)
    if not project_ops.is_valid_project(project_dir):
        raise ValueError(f"Not an AgentOS project (no agentos.config.yaml): {project_dir}")
    if target.backend == "file" and target.location and os.path.abspath(target.location) == project_dir:
        raise ValueError("Source and target are the same project directory")

    report = TransferReport()
    # The source's credentials repository is never read; point it at a path inside the project.
    source = open_file_storage(project_dir, vault_path=os.path.join(project_dir, ".agentos", "unused-vault.json"))
    await copy_entities(source, target, report)

    plugins_dir = Path(project_dir) / "mcp_plugins"
    if plugins_dir.exists():
        for plugin in sorted(p.name for p in plugins_dir.iterdir() if p.is_dir()):
            report.skipped.append(f"mcp_plugins/{plugin}: local plugin code is not imported; add it as an MCP server")

    if import_env:
        await import_env_secrets(project_dir, vault, report)
    return report


async def export_project(source: Storage, out_dir: str) -> TransferReport:
    out = Path(out_dir).resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"Export directory is not empty: {out}")
    if source.settings is None or await source.settings.get(PROJECT_SETTINGS) is None:
        raise ValueError("Source has no project settings to export (import a project first)")
    out.mkdir(parents=True, exist_ok=True)

    report = TransferReport()
    # Credentials are never exported: give the target a vault path it will not write.
    target = open_file_storage(str(out), vault_path=os.path.join(str(out), ".agentos", "never-written.json"))
    await copy_entities(source, target, report)
    names = [s.name for s in await source.credentials.list()]
    if names:
        report.skipped.append(f"credentials are never exported ({len(names)} in the vault: {', '.join(names)})")
    return report
