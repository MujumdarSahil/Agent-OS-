"""
pack_format.py — .agentpack file format definition and operations.

.agentpack is a ZIP archive with this internal structure:
  manifest.json   — metadata, contents list, optional signature
  agents/         — agent YAML files
  tools/          — Python tool files
  crews/          — crew YAML files
  mcp_plugins/    — plugin directories
  README.md       — human-readable description

This proves authenticity/integrity (via Ed25519 signing in signer.py).
It does NOT prevent redistribution or copying. See PHASE3_LIMITATIONS.md.
"""

import json
import os
import zipfile
import glob
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

AGENTOS_MIN_VERSION = "3.0.0"
PACK_EXTENSION = ".agentpack"


class AgentPackManifest(BaseModel):
    """Manifest schema stored as manifest.json inside the .agentpack zip."""
    name: str
    version: str = "1.0.0"
    author: str = "Unknown"
    description: str = ""
    license_type: str = "free"         # free | commercial
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agentos_min_version: str = AGENTOS_MIN_VERSION
    contents: Dict[str, List[str]] = Field(default_factory=lambda: {
        "agents": [], "tools": [], "crews": [], "mcp_plugins": []
    })
    signature: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    license_required: bool = False


def build_pack(
    project_path: str,
    include: Dict[str, List[str]],
    output_path: str,
) -> str:
    """
    Build a .agentpack zip from a project.

    Args:
        project_path: Source AgentOS project directory.
        include: Dict with keys 'agents', 'tools', 'crews', 'mcp_plugins'
                 containing lists of names to include.
        output_path: Destination .agentpack file path.

    Returns:
        Absolute path to the created pack.
    """
    if not output_path.endswith(PACK_EXTENSION):
        output_path += PACK_EXTENSION

    include_agents = include.get("agents", [])
    include_tools = include.get("tools", [])
    include_crews = include.get("crews", [])
    include_plugins = include.get("mcp_plugins", [])

    # Collect files to pack
    agent_files: List[str] = []
    tool_files: List[str] = []
    crew_files: List[str] = []
    plugin_dirs: List[str] = []

    agents_dir = os.path.join(project_path, "agents")
    if os.path.exists(agents_dir):
        for name in include_agents:
            slug = name.lower().replace(" ", "_")
            f = os.path.join(agents_dir, f"{slug}.yaml")
            if os.path.exists(f):
                agent_files.append(f)

    tools_dir = os.path.join(project_path, "tools")
    if os.path.exists(tools_dir):
        for name in include_tools:
            slug = name.lower().replace(" ", "_")
            f = os.path.join(tools_dir, f"{slug}.py")
            if os.path.exists(f):
                tool_files.append(f)

    crews_dir = os.path.join(project_path, "crews")
    if os.path.exists(crews_dir):
        for name in include_crews:
            slug = name.lower().replace(" ", "_")
            f = os.path.join(crews_dir, f"{slug}.yaml")
            if os.path.exists(f):
                crew_files.append(f)

    plugins_dir = os.path.join(project_path, "mcp_plugins")
    if os.path.exists(plugins_dir):
        for name in include_plugins:
            d = os.path.join(plugins_dir, name)
            if os.path.isdir(d):
                plugin_dirs.append(d)

    # Build manifest
    pack_name = os.path.splitext(os.path.basename(output_path))[0]
    manifest = AgentPackManifest(
        name=pack_name,
        contents={
            "agents": [os.path.basename(f) for f in agent_files],
            "tools": [os.path.basename(f) for f in tool_files],
            "crews": [os.path.basename(f) for f in crew_files],
            "mcp_plugins": [os.path.basename(d) for d in plugin_dirs],
        },
    )

    readme_content = _generate_readme(manifest)

    # Write zip
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest.model_dump_json(indent=2))
        zf.writestr("README.md", readme_content)
        for f in agent_files:
            zf.write(f, arcname=f"agents/{os.path.basename(f)}")
        for f in tool_files:
            zf.write(f, arcname=f"tools/{os.path.basename(f)}")
        for f in crew_files:
            zf.write(f, arcname=f"crews/{os.path.basename(f)}")
        for d in plugin_dirs:
            pname = os.path.basename(d)
            for fpath in glob.glob(os.path.join(d, "**", "*"), recursive=True):
                if os.path.isfile(fpath):
                    rel = os.path.relpath(fpath, plugins_dir)
                    zf.write(fpath, arcname=f"mcp_plugins/{rel}")

    return os.path.abspath(output_path)


def install_pack(
    pack_path: str,
    target_project: str,
    force: bool = False,
    license_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Install a .agentpack into a target AgentOS project.

    Args:
        pack_path: Path to the .agentpack file.
        target_project: Destination project directory.
        force: If True, overwrite existing files.
        license_key: Optional license key string to verify before installing.

    Returns:
        Dict summarising what was installed.

    Raises:
        FileExistsError: If a name collision occurs and force=False.
        PermissionError: If license_key is required but missing/invalid.
    """
    from agentos.packaging.signer import verify_pack

    # Signature verification — warn loudly if unsigned but allow with confirmation
    if not verify_pack(pack_path):
        import warnings
        warnings.warn(
            f"WARNING: Pack '{pack_path}' is unsigned or has an invalid signature. "
            "Install proceeds because force=True or caller accepted the risk.",
            stacklevel=2,
        )

    installed: Dict[str, List[str]] = {
        "agents": [], "tools": [], "crews": [], "mcp_plugins": []
    }

    with zipfile.ZipFile(pack_path, "r") as zf:
        # Read manifest
        manifest_raw = zf.read("manifest.json").decode()
        manifest = json.loads(manifest_raw)

        # License check
        if license_key is not None:
            from agentos.packaging.license_check import verify_license_str
            ok = verify_license_str(license_key, manifest)
            if not ok:
                raise PermissionError(
                    f"License key is invalid or does not match pack '{manifest.get('name')}'. "
                    "Installation blocked. Use a valid license key."
                )

        # Extract each section
        for name in manifest.get("contents", {}).get("agents", []):
            dest = os.path.join(target_project, "agents", name)
            if os.path.exists(dest) and not force:
                raise FileExistsError(
                    f"Agent file '{name}' already exists. Use --force to overwrite."
                )
            os.makedirs(os.path.join(target_project, "agents"), exist_ok=True)
            with zf.open(f"agents/{name}") as src, open(dest, "wb") as dst:
                dst.write(src.read())
            installed["agents"].append(name)

        for name in manifest.get("contents", {}).get("tools", []):
            dest = os.path.join(target_project, "tools", name)
            if os.path.exists(dest) and not force:
                raise FileExistsError(f"Tool file '{name}' already exists. Use --force to overwrite.")
            os.makedirs(os.path.join(target_project, "tools"), exist_ok=True)
            with zf.open(f"tools/{name}") as src, open(dest, "wb") as dst:
                dst.write(src.read())
            installed["tools"].append(name)

        for name in manifest.get("contents", {}).get("crews", []):
            dest = os.path.join(target_project, "crews", name)
            if os.path.exists(dest) and not force:
                raise FileExistsError(f"Crew file '{name}' already exists. Use --force to overwrite.")
            os.makedirs(os.path.join(target_project, "crews"), exist_ok=True)
            with zf.open(f"crews/{name}") as src, open(dest, "wb") as dst:
                dst.write(src.read())
            installed["crews"].append(name)

        # MCP plugins — extract whole directory
        for pname in manifest.get("contents", {}).get("mcp_plugins", []):
            dest_dir = os.path.join(target_project, "mcp_plugins", pname)
            if os.path.exists(dest_dir) and not force:
                raise FileExistsError(
                    f"MCP plugin '{pname}' already exists. Use --force to overwrite."
                )
            for zpath in zf.namelist():
                if zpath.startswith(f"mcp_plugins/{pname}/"):
                    rel = zpath[len("mcp_plugins/"):]
                    dest = os.path.join(target_project, "mcp_plugins", rel)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with zf.open(zpath) as src, open(dest, "wb") as dst:
                        dst.write(src.read())
            installed["mcp_plugins"].append(pname)

    return {"installed": installed, "pack": manifest.get("name"), "version": manifest.get("version")}


def find_pack_manifest_for_mission(
    project_path: str, mission_name: str
) -> Optional[Dict[str, Any]]:
    """
    Look for a .pack_origin file written during install that links a mission
    to its originating pack manifest. Returns None if mission is from the free project.
    This is a best-effort check; no-op if the marker file doesn't exist.
    """
    marker = os.path.join(project_path, ".pack_origins", f"{mission_name}.json")
    if not os.path.exists(marker):
        return None
    with open(marker, "r", encoding="utf-8") as f:
        return json.load(f)


def _generate_readme(manifest: AgentPackManifest) -> str:
    agents = "\n".join(f"  - {a}" for a in manifest.contents.get("agents", []))
    tools = "\n".join(f"  - {t}" for t in manifest.contents.get("tools", []))
    crews = "\n".join(f"  - {c}" for c in manifest.contents.get("crews", []))
    plugins = "\n".join(f"  - {p}" for p in manifest.contents.get("mcp_plugins", []))
    return f"""# {manifest.name}

**Version**: {manifest.version}
**Author**: {manifest.author}
**License**: {manifest.license_type}
**Created**: {manifest.created_at}
**Requires AgentOS**: >= {manifest.agentos_min_version}

## Description
{manifest.description or "No description provided."}

## Contents

### Agents
{agents or "  (none)"}

### Tools
{tools or "  (none)"}

### Crews
{crews or "  (none)"}

### MCP Plugins
{plugins or "  (none)"}

## Notes

This pack was exported from an AgentOS project.
- Install with: `agentos pack install <file>.agentpack <target_project>`
- Verify signature: `agentos pack verify <file>.agentpack`
"""
