"""
test_transfer_1_3.py - v1 project importer / exporter (sub-milestone 1.3).

[MOCK] tests use File storage on temp dirs (no network).
[LIVE] tests (names end in _live) use MongoDB from AGENTOS_MONGO_URI and skip without it
(AGENTOS_REQUIRE_LIVE_MONGO=1 turns the skip into a failure, as in CI).

Round-trip equality is semantic: every config, agent, crew and mission file is parsed
through the v1 schema on both sides, tools/*.py are compared as text, and the set of
files must match.
"""

import hashlib
import os
import shutil
import uuid
from pathlib import Path

import pytest
import pytest_asyncio
import yaml
from typer.testing import CliRunner

from agentos.cli.main import app as cli_app
from agentos.core import project_ops
from agentos.core.config_models import AgentYAMLConfig, CrewYAMLConfig, MissionYAMLConfig, ProjectConfig
from agentos.security.vault import MasterKey, Vault
from agentos.storage import open_storage
from agentos.storage.transfer import export_project, import_project

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = sorted(p for p in (REPO_ROOT / "agentos" / "templates" / "source").iterdir() if p.is_dir())
FAKE_OPENAI = "sk-fake-openai-0000000000000000AAAA"
FAKE_ANTHROPIC = "sk-ant-fake-1111111111111111BBBB"
FAKE_OTHER = "not-a-provider-value-2222"

_SCHEMAS = {"agents": AgentYAMLConfig, "crews": CrewYAMLConfig, "missions": MissionYAMLConfig}


def _demo_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "demo"
    shutil.copytree(REPO_ROOT / "demo", dst, ignore=shutil.ignore_patterns(".env", "checkpoints", "memory"))
    return dst


def _sources(tmp_path: Path):
    return [(t.name, t) for t in TEMPLATES] + [("demo", _demo_copy(tmp_path))]


def project_view(root: Path) -> dict:
    """Semantic view of a v1 project: relpath -> parsed model (or text for tools)."""
    view = {}
    config = root / "agentos.config.yaml"
    if config.exists():
        view["agentos.config.yaml"] = ProjectConfig(**(yaml.safe_load(config.read_text(encoding="utf-8")) or {}))
    for folder, schema in _SCHEMAS.items():
        for f in sorted((root / folder).glob("*.yaml")):
            view[f"{folder}/{f.name}"] = schema(**yaml.safe_load(f.read_text(encoding="utf-8")))
    for f in sorted((root / "tools").glob("*.py")):
        view[f"tools/{f.name}"] = f.read_text(encoding="utf-8")
    return view


def _snapshot(root: Path) -> dict:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def _write_env(project: Path) -> None:
    (project / ".env").write_text(
        f"OPENAI_API_KEY={FAKE_OPENAI}\nANTHROPIC_API_KEY={FAKE_ANTHROPIC}\nUNRELATED_SETTING={FAKE_OTHER}\n",
        encoding="utf-8",
    )


def _assert_no_plaintext(root: Path) -> None:
    for p in root.rglob("*"):
        if p.is_file():
            data = p.read_bytes()
            for secret in (FAKE_OPENAI, FAKE_ANTHROPIC, FAKE_OTHER):
                assert secret.encode() not in data, f"plaintext secret found in {p}"
    assert not (root / ".env").exists()


async def _file_storage(path: Path, vault_path: Path):
    return await open_storage(str(path), backend="file", vault_path=str(vault_path))


@pytest_asyncio.fixture
async def mongo_storage():
    uri = os.environ.get("AGENTOS_MONGO_URI")
    if not uri:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_MONGO") == "1":
            pytest.fail("AGENTOS_MONGO_URI not set")
        pytest.skip("LIVE Mongo not available: set AGENTOS_MONGO_URI (see docker/compose.mongo.yml)")
    db_names = []

    async def make():
        db_name = f"agentos_test_{uuid.uuid4().hex[:12]}"
        db_names.append(db_name)
        return await open_storage(backend="mongo", mongo_uri=uri, db_name=db_name), db_name

    yield make
    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(uri)
    for name in db_names:
        await client.drop_database(name)
    await client.close()


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("template", TEMPLATES + [None], ids=[t.name for t in TEMPLATES] + ["demo"])
async def test_roundtrip_via_file_storage(template, tmp_path):
    source = template or _demo_copy(tmp_path)
    before = _snapshot(source)
    target = await _file_storage(tmp_path / "target", tmp_path / "vault.json")

    await import_project(str(source), target, vault=None)
    await export_project(target, str(tmp_path / "out"))

    assert project_view(tmp_path / "target") == project_view(source)
    assert project_view(tmp_path / "out") == project_view(source)
    assert _snapshot(source) == before  # importing never writes into the source


@pytest.mark.asyncio
async def test_exported_mission_still_found_by_v1_file_name(tmp_path):
    # task_planner's missions/plan_goal.yaml holds a mission whose slug differs from the file stem;
    # `agentos run --mission plan_goal` resolves by file name, so the export must keep it.
    source = REPO_ROOT / "agentos" / "templates" / "source" / "task_planner"
    mission_name = yaml.safe_load((source / "missions" / "plan_goal.yaml").read_text(encoding="utf-8"))["name"]
    target = await _file_storage(tmp_path / "target", tmp_path / "v.json")
    await import_project(str(source), target)
    await export_project(target, str(tmp_path / "out"))
    assert project_ops.read_mission(str(tmp_path / "out"), "plan_goal").name == mission_name


@pytest.mark.asyncio
async def test_roundtrip_all_projects_via_mongo_live(mongo_storage, tmp_path):
    for name, source in _sources(tmp_path):
        storage, _ = await mongo_storage()
        report = await import_project(str(source), storage, vault=None)
        assert report.counts.get("agents", 0) >= 1, name
        await export_project(storage, str(tmp_path / f"out-{name}"))
        await storage.close()
        assert project_view(tmp_path / f"out-{name}") == project_view(source), name


@pytest.mark.asyncio
async def test_squad_roles_and_2_0_entities_survive_export(tmp_path):
    from agentos.storage.models import MCPServerRecord, ProviderConfigRecord, SquadRecord, ToolRecord

    src = await _file_storage(tmp_path / "src", tmp_path / "v.json")
    await import_project(str(TEMPLATES[0]), src)
    await src.squads.put(SquadRecord(name="Ops", agents=["a"], roles={"a": "commander"}))
    await src.tools.put(ToolRecord(name="stored_tool", code="print('stored')"))
    await src.mcp_servers.put(MCPServerRecord(name="web", transport="http", url="http://127.0.0.1:9000/mcp"))
    await src.provider_configs.put(ProviderConfigRecord(name="groq", order=0))

    await export_project(src, str(tmp_path / "out"))
    out = await _file_storage(tmp_path / "out", tmp_path / "v2.json")
    assert (await out.squads.get("Ops")).roles == {"a": "commander"}
    assert (await out.tools.get("stored_tool")).origin == "stored"
    assert not (tmp_path / "out" / "tools" / "stored_tool.py").exists()  # stored code stays non-executable
    assert (await out.mcp_servers.get("web")).url == "http://127.0.0.1:9000/mcp"
    assert (await out.provider_configs.get("groq")).order == 0


@pytest.mark.asyncio
async def test_v1_project_tool_returns_to_tools_dir(tmp_path):
    source = tmp_path / "src"
    shutil.copytree(TEMPLATES[0], source)
    project_ops.scaffold_tool(str(source), "web_search")
    target = await _file_storage(tmp_path / "target", tmp_path / "v.json")

    report = await import_project(str(source), target)
    assert report.counts["tools (project)"] == 1
    await export_project(target, str(tmp_path / "out"))
    assert (tmp_path / "out" / "tools" / "web_search.py").read_text() == (source / "tools" / "web_search.py").read_text()


@pytest.mark.asyncio
async def test_mcp_plugins_and_history_are_reported_as_skipped(tmp_path):
    source = tmp_path / "src"
    shutil.copytree(TEMPLATES[0], source)
    (source / "mcp_plugins" / "my_plugin").mkdir(parents=True)
    report = await import_project(str(source), await _file_storage(tmp_path / "t", tmp_path / "v.json"))
    assert any("mcp_plugins/my_plugin" in s for s in report.skipped)
    assert any("not migrated" in s for s in report.skipped)


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_env_provider_keys_are_encrypted_and_never_exported(tmp_path):
    source = tmp_path / "src"
    shutil.copytree(TEMPLATES[0], source)
    _write_env(source)
    vault_file = tmp_path / "vault.json"
    target = await _file_storage(tmp_path / "target", vault_file)
    vault = Vault(target.credentials, MasterKey.generate())

    report = await import_project(str(source), target, vault=vault)
    assert sorted(report.secrets_imported) == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    assert await vault.reveal("OPENAI_API_KEY") == FAKE_OPENAI
    assert "openai_gpt4o" in (await vault.get_info("OPENAI_API_KEY")).provider.split(",")
    skipped_text = "\n".join(report.skipped)
    assert "UNRELATED_SETTING" in skipped_text and FAKE_OTHER not in skipped_text
    assert FAKE_OPENAI.encode() not in vault_file.read_bytes()

    export_report = await export_project(target, str(tmp_path / "out"))
    _assert_no_plaintext(tmp_path / "out")
    assert any("credentials are never exported" in s for s in export_report.skipped)


@pytest.mark.asyncio
async def test_env_keys_without_vault_are_reported_not_imported(tmp_path):
    source = tmp_path / "src"
    shutil.copytree(TEMPLATES[0], source)
    _write_env(source)
    target = await _file_storage(tmp_path / "target", tmp_path / "vault.json")
    report = await import_project(str(source), target, vault=None)
    assert report.secrets_imported == []
    assert any("OPENAI_API_KEY: no vault" in s for s in report.skipped)
    assert await target.credentials.list() == []


@pytest.mark.asyncio
async def test_env_keys_encrypted_into_mongo_and_not_exported_live(mongo_storage, tmp_path):
    source = tmp_path / "src"
    shutil.copytree(TEMPLATES[0], source)
    _write_env(source)
    storage, _ = await mongo_storage()
    vault = Vault(storage.credentials, MasterKey.generate())

    await import_project(str(source), storage, vault=vault)
    assert await vault.reveal("ANTHROPIC_API_KEY") == FAKE_ANTHROPIC
    raw = await storage.credentials.get("ANTHROPIC_API_KEY")
    assert FAKE_ANTHROPIC not in raw.model_dump_json()
    await export_project(storage, str(tmp_path / "out"))
    await storage.close()
    _assert_no_plaintext(tmp_path / "out")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transfer_guards(tmp_path):
    target = await _file_storage(tmp_path / "target", tmp_path / "v.json")
    with pytest.raises(ValueError, match="Not an AgentOS project"):
        await import_project(str(tmp_path / "nothing"), target)
    with pytest.raises(ValueError, match="no project settings"):
        await export_project(target, str(tmp_path / "out-empty"))

    await import_project(str(TEMPLATES[0]), target)
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy" / "file.txt").write_text("x")
    with pytest.raises(ValueError, match="not empty"):
        await export_project(target, str(tmp_path / "busy"))
    with pytest.raises(ValueError, match="same project"):
        await import_project(str(tmp_path / "target"), target)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_env(**extra):
    return {"AGENTOS_MASTER_KEY": MasterKey.generate().to_b64(), "AGENTOS_MOCK_LLM": "1", **extra}


def test_cli_import_export_file_backend(tmp_path):
    source = tmp_path / "src"
    shutil.copytree(TEMPLATES[0], source)
    _write_env(source)
    runner = CliRunner()
    env = _cli_env(AGENTOS_VAULT_PATH=str(tmp_path / "vault.json"))

    result = runner.invoke(cli_app, ["import", str(source), "--to", "file", "--dir", str(tmp_path / "t")], env=env)
    assert result.exit_code == 0, result.output
    assert "OPENAI_API_KEY" in result.output and FAKE_OPENAI not in result.output

    result = runner.invoke(cli_app, ["export", str(tmp_path / "out"), "--from", "file", "--dir", str(tmp_path / "t")], env=env)
    assert result.exit_code == 0, result.output
    assert project_view(tmp_path / "out") == project_view(source)
    _assert_no_plaintext(tmp_path / "out")


def test_cli_rejects_non_project(tmp_path):
    result = CliRunner().invoke(cli_app, ["import", str(tmp_path), "--to", "file", "--dir", str(tmp_path / "t")],
                                env=_cli_env(AGENTOS_VAULT_PATH=str(tmp_path / "v.json")))
    assert result.exit_code == 1 and "Not an AgentOS project" in result.output


def test_cli_import_demo_into_mongo_and_export_live(tmp_path):
    uri = os.environ.get("AGENTOS_MONGO_URI")
    if not uri:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_MONGO") == "1":
            pytest.fail("AGENTOS_MONGO_URI not set")
        pytest.skip("LIVE Mongo not available: set AGENTOS_MONGO_URI (see docker/compose.mongo.yml)")
    demo = _demo_copy(tmp_path)
    _write_env(demo)
    db_name = f"agentos_test_{uuid.uuid4().hex[:12]}"
    runner = CliRunner()
    env = _cli_env(AGENTOS_MONGO_URI=uri, AGENTOS_MONGO_DB=db_name)
    try:
        result = runner.invoke(cli_app, ["import", str(demo)], env=env)
        assert result.exit_code == 0, result.output
        assert uri not in result.output and FAKE_OPENAI not in result.output
        result = runner.invoke(cli_app, ["export", str(tmp_path / "out")], env=env)
        assert result.exit_code == 0, result.output
        assert project_view(tmp_path / "out") == project_view(demo)
        _assert_no_plaintext(tmp_path / "out")
    finally:
        import pymongo

        client = pymongo.MongoClient(uri)
        client.drop_database(db_name)
        client.close()
