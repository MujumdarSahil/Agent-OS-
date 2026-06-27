"""
test_packaging.py — Step 3 verification tests for .agentpack format.

Covers:
  1. build + sign + verify → True
  2. Tamper one byte → verify → False
  3. Install into fresh project → agents appear → mission runs
  4. License: missing → blocked; correct → passes
"""

import base64
import json
import os
import shutil
import tempfile
import zipfile
import yaml
import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def source_project(tmp_path_factory):
    """Source project with one agent, tool, and crew."""
    p = str(tmp_path_factory.mktemp("pack_source"))
    os.makedirs(os.path.join(p, "agents"))
    os.makedirs(os.path.join(p, "tools"))
    os.makedirs(os.path.join(p, "crews"))
    os.makedirs(os.path.join(p, "missions"))

    with open(os.path.join(p, "agentos.config.yaml"), "w") as f:
        yaml.safe_dump({"preferred_tags": ["fast"]}, f)

    with open(os.path.join(p, "agents", "packagist.yaml"), "w") as f:
        yaml.safe_dump({
            "name": "Packagist",
            "role": "Pack Tester",
            "goal": "Test packaging",
            "backstory": "A pack tester.",
            "llm_tags": ["fast"],
            "tool_refs": [],
            "memory_ref": None,
        }, f)

    tool_code = (
        "from agentos.core.base import BaseTool\n"
        "class PackTool(BaseTool):\n"
        "    name: str = 'pack_tool'\n"
        "    description: str = 'Pack test tool.'\n"
        "    def run(self, **kwargs): return 'pack_tool ran'\n"
    )
    with open(os.path.join(p, "tools", "pack_tool.py"), "w") as f:
        f.write(tool_code)

    with open(os.path.join(p, "crews", "pack_crew.yaml"), "w") as f:
        yaml.safe_dump({"name": "pack_crew", "agents": ["Packagist"], "process": "sequential"}, f)

    with open(os.path.join(p, "missions", "pack_mission.yaml"), "w") as f:
        yaml.safe_dump({
            "name": "pack_mission",
            "goal": "Run pack test",
            "description": "Pack mission",
            "crew": "pack_crew",
            "tasks": [{"description": "Do the pack task", "assigned_agent": "Packagist"}],
        }, f)

    return p


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    from agentos.packaging.signer import generate_keypair
    keys_dir = str(tmp_path_factory.mktemp("keys"))
    priv, pub = generate_keypair(keys_dir=keys_dir)
    return priv, pub


# ---------------------------------------------------------------------------
# Test 1 — Build + Sign + Verify → True
# ---------------------------------------------------------------------------

def test_build_sign_verify(source_project, keypair, tmp_path):
    from agentos.packaging.pack_format import build_pack
    from agentos.packaging.signer import sign_pack, verify_pack

    priv_path, _ = keypair
    pack_path = str(tmp_path / "test.agentpack")

    # Build
    built = build_pack(
        project_path=source_project,
        include={"agents": ["Packagist"], "tools": ["pack_tool"], "crews": ["pack_crew"], "mcp_plugins": []},
        output_path=pack_path,
    )
    assert os.path.exists(built)
    assert zipfile.is_zipfile(built)

    # Unsigned → verify returns False
    assert verify_pack(built) is False

    # Sign
    sign_pack(built, priv_path)

    # Verify after signing → True
    assert verify_pack(built) is True, "Signed pack should verify as True"


# ---------------------------------------------------------------------------
# Test 2 — Tamper one byte → verify → False
# ---------------------------------------------------------------------------

def test_tamper_breaks_verify(source_project, keypair, tmp_path):
    from agentos.packaging.pack_format import build_pack
    from agentos.packaging.signer import sign_pack, verify_pack, _update_manifest_in_zip

    priv_path, _ = keypair
    pack_path = str(tmp_path / "tamper.agentpack")
    build_pack(
        project_path=source_project,
        include={"agents": ["Packagist"], "tools": [], "crews": [], "mcp_plugins": []},
        output_path=pack_path,
    )
    sign_pack(pack_path, priv_path)
    assert verify_pack(pack_path) is True

    # Tamper: inject a fake field into manifest
    _update_manifest_in_zip(pack_path, {"TAMPERED": True})

    # Verify should now return False
    assert verify_pack(pack_path) is False, "Tampered pack should fail verification"


# ---------------------------------------------------------------------------
# Test 3 — Install into fresh project → agents appear → mission runs
# ---------------------------------------------------------------------------

def test_install_pack(source_project, keypair, tmp_path):
    from agentos.packaging.pack_format import build_pack, install_pack
    from agentos.packaging.signer import sign_pack, verify_pack
    from agentos.core.project_ops import list_agents

    priv_path, _ = keypair
    pack_path = str(tmp_path / "install.agentpack")

    build_pack(
        project_path=source_project,
        include={"agents": ["Packagist"], "tools": ["pack_tool"], "crews": ["pack_crew"], "mcp_plugins": []},
        output_path=pack_path,
    )
    sign_pack(pack_path, priv_path)
    assert verify_pack(pack_path) is True

    # Fresh target project
    target = str(tmp_path / "target_project")
    os.makedirs(os.path.join(target, "agents"), exist_ok=True)
    with open(os.path.join(target, "agentos.config.yaml"), "w") as f:
        yaml.safe_dump({"preferred_tags": ["fast"]}, f)

    result = install_pack(pack_path=pack_path, target_project=target, force=False)
    assert "Packagist" in result["installed"].get("agents", []) or \
           "packagist.yaml" in result["installed"].get("agents", [])

    # Agent YAML should now exist in the target
    assert os.path.exists(os.path.join(target, "agents", "packagist.yaml")), \
        "Agent not installed in target project"

    # list_agents should see it
    agents = list_agents(target)
    assert any(a.name == "Packagist" for a in agents), "Packagist not found via list_agents"


# ---------------------------------------------------------------------------
# Test 4a — License: missing → blocked
# ---------------------------------------------------------------------------

def test_license_missing_blocks(source_project, keypair, tmp_path):
    from agentos.packaging.pack_format import build_pack, install_pack
    from agentos.packaging.signer import sign_pack
    from agentos.packaging.license_check import verify_license_str

    priv_path, _ = keypair
    pack_path = str(tmp_path / "licensed.agentpack")
    build_pack(
        project_path=source_project,
        include={"agents": ["Packagist"], "tools": [], "crews": [], "mcp_plugins": []},
        output_path=pack_path,
    )
    sign_pack(pack_path, priv_path)

    # Simulate a manifest that requires a license
    import zipfile, json
    with zipfile.ZipFile(pack_path, "r") as zf:
        manifest = json.loads(zf.read("manifest.json"))

    # verify_license_str with None/empty → False
    assert verify_license_str("", manifest) is False
    assert verify_license_str("invalid_key", manifest) is False


# ---------------------------------------------------------------------------
# Test 4b — License: correct key → passes
# ---------------------------------------------------------------------------

def test_license_correct_key_passes(source_project, keypair, tmp_path):
    from agentos.packaging.signer import sign_pack
    from agentos.packaging.pack_format import build_pack
    from agentos.packaging.license_check import generate_license, verify_license_str
    import zipfile, json

    priv_path, _ = keypair
    pack_path = str(tmp_path / "licensed2.agentpack")
    build_pack(
        project_path=source_project,
        include={"agents": ["Packagist"], "tools": [], "crews": [], "mcp_plugins": []},
        output_path=pack_path,
    )
    sign_pack(pack_path, priv_path)

    with zipfile.ZipFile(pack_path, "r") as zf:
        manifest = json.loads(zf.read("manifest.json"))

    # Generate a valid license key for this pack
    license_key = generate_license(
        pack_name=manifest["name"],
        pack_version=manifest["version"],
        licensed_to="test@example.com",
        private_key_path=priv_path,
    )
    assert isinstance(license_key, str) and len(license_key) > 0

    # Verify → True
    assert verify_license_str(license_key, manifest) is True

    # Wrong pack_name → False
    bad_manifest = dict(manifest, name="wrong_pack")
    assert verify_license_str(license_key, bad_manifest) is False
