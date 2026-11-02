"""
test_storage_contract_1_2.py - Repository contract suite (sub-milestone 1.2).

Every contract test runs against both backends:
  - file  [MOCK]  temp project dir + temp vault file, no external service
  - mongo [LIVE]  real MongoDB from AGENTOS_MONGO_URI (docker/compose.mongo.yml);
                  skipped with an explicit reason when the URI is unset or unreachable

File-only and Mongo-only tests at the bottom pin backend-specific guarantees
(v1 byte compatibility, read-only v1 tools, path safety, Mongo indexes).
"""

import ast
import asyncio
import os
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
import pytest_asyncio
import yaml
from pydantic import ValidationError

from agentos.core import project_ops
from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.core.config_models import AgentYAMLConfig, CrewYAMLConfig, TaskYAMLConfig
from agentos.storage import ReadOnlyEntityError, open_storage
from agentos.storage.models import (
    AgentRecord,
    EncryptedSecretRecord,
    MCPServerRecord,
    MissionRecord,
    ProviderConfigRecord,
    RunRecord,
    SquadRecord,
    ToolRecord,
    utcnow,
)

MONGO_URI = os.environ.get("AGENTOS_MONGO_URI")
MONGO_SKIP_REASON = (
    "LIVE Mongo not available: run `docker compose -f docker/compose.mongo.yml up -d --wait` "
    "and set AGENTOS_MONGO_URI (see docker/mongo-init.ps1)"
)
REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest_asyncio.fixture(params=["file", "mongo"])
async def storage(request, tmp_path):
    if request.param == "file":
        project = tmp_path / "project"
        project.mkdir()
        (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        s = await open_storage(str(project), backend="file", vault_path=str(tmp_path / "vault.json"))
        yield s
        await s.close()
        return

    async for s in _live_mongo_storage():
        yield s


async def _live_mongo_storage():
    """Yield Mongo storage on a throwaway database, or skip with the LIVE reason."""
    if not MONGO_URI:
        pytest.skip(MONGO_SKIP_REASON)
    db_name = f"agentos_test_{uuid.uuid4().hex[:12]}"
    try:
        s = await open_storage(backend="mongo", mongo_uri=MONGO_URI, db_name=db_name)
    except Exception as e:  # server selection timeout, auth failure, ...
        pytest.skip(f"{MONGO_SKIP_REASON} ({type(e).__name__}: {e})")
    yield s
    await s.close()
    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(MONGO_URI)
    await client.drop_database(db_name)
    await client.close()


@pytest_asyncio.fixture
async def mongo_storage():
    async for s in _live_mongo_storage():
        yield s


def _agent(name="Research Agent", **kw):
    return AgentRecord(name=name, role="Researcher", goal="Find facts", **kw)


def _secret(name="openai"):
    return EncryptedSecretRecord(
        name=name, provider="openai", key_id="kek-1",
        wrapped_dek="d3JhcHBlZA==", nonce="bm9uY2U=", ciphertext="Y2lwaGVy", hint="sk-...a1b2",
    )


# ---------------------------------------------------------------------------
# Named entities
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_agent_crud_roundtrip(storage):
    agent = _agent(tool_refs=["search"], llm_tags=["fast"], memory_ref="mem")
    assert await storage.agents.get(agent.name) is None
    await storage.agents.put(agent)

    assert await storage.agents.get("Research Agent") == agent
    assert await storage.agents.get("research agent") == agent  # v1 slug rules: case/space-insensitive
    assert [a.name for a in await storage.agents.list()] == ["Research Agent"]

    await storage.agents.put(agent.model_copy(update={"goal": "Updated"}))  # upsert, no duplicate
    assert len(await storage.agents.list()) == 1
    assert (await storage.agents.get(agent.name)).goal == "Updated"

    assert await storage.agents.delete(agent.name) is True
    assert await storage.agents.delete(agent.name) is False
    assert await storage.agents.list() == []


@pytest.mark.asyncio
async def test_squad_roles_and_mission_roundtrip(storage):
    squad = SquadRecord(name="Blue Team", agents=["lead", "analyst"], process="hierarchical",
                        roles={"lead": "commander", "analyst": "member"})
    plain = SquadRecord(name="Plain", agents=["solo"])
    mission = MissionRecord(name="Daily Brief", goal="Summarise", crew="Blue Team",
                            tasks=[TaskYAMLConfig(description="Collect", assigned_agent="analyst")])
    for item, repo in ((squad, storage.squads), (plain, storage.squads), (mission, storage.missions)):
        await repo.put(item)

    assert await storage.squads.get("blue team") == squad
    assert (await storage.squads.get("Plain")).roles == {}
    assert sorted(s.name for s in await storage.squads.list()) == ["Blue Team", "Plain"]
    assert await storage.missions.get("Daily Brief") == mission
    assert await storage.squads.delete("Plain") is True
    assert await storage.missions.delete("Daily Brief") is True
    assert await storage.missions.get("Daily Brief") is None


@pytest.mark.asyncio
async def test_tool_code_is_stored_not_executed(storage, tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"open({str(marker)!r}, 'w').write('ran')\nraise SystemExit('must never run')\n"
    tool = ToolRecord(name="dangerous_tool", description="should stay inert", code=code)

    await storage.tools.put(tool)
    assert await storage.tools.get("dangerous_tool") == tool
    assert tool in await storage.tools.list()
    assert not marker.exists()


@pytest.mark.asyncio
async def test_mcp_server_roundtrip_defaults_disabled(storage):
    server = MCPServerRecord(name="files", transport="stdio", command="npx",
                             args=["-y", "@modelcontextprotocol/server-filesystem"],
                             env={"LOG_LEVEL": "info"}, secret_env={"API_TOKEN": "files-token"})
    await storage.mcp_servers.put(server)
    got = await storage.mcp_servers.get("files")
    assert got == server and got.enabled is False


def test_mcp_server_requires_target():
    with pytest.raises(ValidationError):
        MCPServerRecord(name="x", transport="stdio")
    with pytest.raises(ValidationError):
        MCPServerRecord(name="y", transport="http")


@pytest.mark.asyncio
async def test_provider_configs_roundtrip(storage):
    configs = [ProviderConfigRecord(name="openai", order=1, enabled=False, timeout_s=12.5),
               ProviderConfigRecord(name="anthropic", order=0)]
    for c in configs:
        await storage.provider_configs.put(c)
    stored = sorted(await storage.provider_configs.list(), key=lambda c: c.order)
    assert [c.name for c in stored] == ["anthropic", "openai"]
    assert await storage.provider_configs.get("openai") == configs[0]


@pytest.mark.asyncio
async def test_credentials_store_ciphertext_fields_only(storage):
    secret = _secret()
    await storage.credentials.put(secret)
    got = await storage.credentials.get("openai")
    assert got == secret
    assert got.created_at.tzinfo is not None
    assert await storage.credentials.delete("openai") is True
    assert await storage.credentials.list() == []


# ---------------------------------------------------------------------------
# Runs and events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_runs_put_get_list_newest_first(storage):
    now = utcnow()
    runs = [RunRecord(run_id=f"run-{i}", mission_name="m", created_at=now + timedelta(seconds=i))
            for i in range(3)]
    for r in runs:
        await storage.runs.put(r)
    await storage.runs.put(runs[0].model_copy(update={"status": "completed", "outputs": {"t0": "ok"}}))

    assert (await storage.runs.get("run-0")).status == "completed"
    assert await storage.runs.get("missing") is None
    assert [r.run_id for r in await storage.runs.list()] == ["run-2", "run-1", "run-0"]
    assert [r.run_id for r in await storage.runs.list(limit=2)] == ["run-2", "run-1"]


@pytest.mark.asyncio
async def test_events_sequence_is_gap_free_and_replayable(storage):
    for i in range(3):
        await storage.events.append("run-a", "task_completed", {"i": i})
    await storage.events.append("run-b", "run_started")

    events = await storage.events.list("run-a")
    assert [e.seq for e in events] == [1, 2, 3]
    assert [e.data["i"] for e in events] == [0, 1, 2]
    assert [e.seq for e in await storage.events.list("run-a", after_seq=2)] == [3]
    assert [e.seq for e in await storage.events.list("run-b")] == [1]
    assert await storage.events.list("run-none") == []


@pytest.mark.asyncio
async def test_concurrent_event_appends_get_unique_sequence(storage):
    appended = await asyncio.gather(*(storage.events.append("run-c", "tick", {"n": n}) for n in range(20)))
    assert sorted(e.seq for e in appended) == list(range(1, 21))
    assert [e.seq for e in await storage.events.list("run-c")] == list(range(1, 21))


# ---------------------------------------------------------------------------
# Checkpoints: same semantics as SQLiteCheckpointStore
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_checkpoint_semantics_match_v1_store(storage):
    cp = storage.checkpoints
    state0 = {"status": "in_progress", "outputs": {"t0": "a"}}
    await cp.save_checkpoint("mission-1", 0, state0)
    await cp.save_checkpoint("mission-1", 1, {"status": "in_progress", "outputs": {"t1": "b"}, "provider": "groq"})
    await cp.save_checkpoint("mission-2", 0, {"status": "failed"})

    assert "timestamp" not in state0  # caller's dict is not mutated
    latest = await cp.load_latest_checkpoint("mission-1")
    assert latest["outputs"] == {"t1": "b"} and latest["provider"] == "groq" and latest["timestamp"]
    assert await cp.load_latest_checkpoint("nope") is None

    rows = await cp.list_runs("mission-1")
    assert {(r["task_index"], r["status"]) for r in rows} == {(0, "in_progress"), (1, "in_progress")}
    assert all(r["provider"] for r in rows)
    assert len(await cp.list_runs()) == 3

    await cp.mark_complete("mission-1")
    assert {r["status"] for r in await cp.list_runs("mission-1")} == {"completed"}
    assert {r["status"] for r in await cp.list_runs("mission-2")} == {"failed"}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_factory_rejects_unknown_backend_and_missing_uri(monkeypatch):
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    with pytest.raises(ValueError, match="Unknown storage backend"):
        await open_storage(backend="redis")
    with pytest.raises(ValueError, match="AGENTOS_MONGO_URI"):
        await open_storage(backend="mongo")


@pytest.mark.asyncio
async def test_factory_defaults_to_file(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENTOS_STORAGE", raising=False)
    s = await open_storage(str(tmp_path), vault_path=str(tmp_path / "v.json"))
    assert s.backend == "file"


# ---------------------------------------------------------------------------
# File backend only [MOCK]
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def file_storage(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    s = await open_storage(str(project), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield s, project


@pytest.mark.asyncio
async def test_file_yaml_is_byte_identical_to_v1_writer(file_storage, tmp_path):
    s, project = file_storage
    v1 = tmp_path / "v1"
    agent = AgentYAMLConfig(name="Writer", role="r", goal="g", tool_refs=["a"])
    crew = CrewYAMLConfig(name="Crew One", agents=["Writer"])

    await s.agents.put(agent)
    await s.squads.put(SquadRecord(**crew.model_dump()))
    project_ops.write_agent(str(v1), agent)
    project_ops.write_crew(str(v1), crew)

    for rel in ("agents/writer.yaml", "crews/crew_one.yaml"):
        assert (project / rel).read_bytes() == (v1 / rel).read_bytes()


@pytest.mark.asyncio
async def test_file_squad_roles_stay_readable_by_v1(file_storage):
    s, project = file_storage
    await s.squads.put(SquadRecord(name="Ops", agents=["a", "b"], roles={"a": "commander"}))
    v1_view = project_ops.read_crew(str(project), "Ops")
    assert v1_view.agents == ["a", "b"]
    assert yaml.safe_load((project / "crews" / "ops.yaml").read_text())["roles"] == {"a": "commander"}


@pytest.mark.asyncio
async def test_file_stored_tools_never_land_in_v1_tools_dir(file_storage):
    s, project = file_storage
    await s.tools.put(ToolRecord(name="stored_one", code="print('x')"))
    assert not (project / "tools").exists()
    assert (project / ".agentos" / "tools" / "stored_one.json").exists()


@pytest.mark.asyncio
async def test_file_v1_project_tools_are_listed_read_only(file_storage):
    s, project = file_storage
    project_ops.scaffold_tool(str(project), "web_search")

    listed = {t.name: t for t in await s.tools.list()}
    assert listed["web_search"].origin == "project"
    assert "class WebSearch" in listed["web_search"].code
    with pytest.raises(ReadOnlyEntityError):
        await s.tools.put(ToolRecord(name="web_search", code="overwrite"))
    with pytest.raises(ReadOnlyEntityError):
        await s.tools.delete("web_search")
    assert (project / "tools" / "web_search.py").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["../escape", "a/b", "..", ".hidden", "x\\y"])
async def test_file_rejects_path_traversal_names(file_storage, bad):
    s, _ = file_storage
    with pytest.raises(ValueError):
        await s.mcp_servers.get(bad)
    with pytest.raises(ValueError):
        await s.agents.get(bad)
    with pytest.raises(ValueError):
        await s.runs.get(bad)


@pytest.mark.asyncio
async def test_file_checkpoints_share_the_v1_database(file_storage):
    s, project = file_storage
    await s.checkpoints.save_checkpoint("m", 0, {"status": "in_progress", "provider": "mock"})
    v1 = SQLiteCheckpointStore(str(project / "checkpoints" / "run_history.db"))
    assert v1.load_latest_checkpoint("m")["provider"] == "mock"


@pytest.mark.asyncio
async def test_file_vault_holds_no_plaintext_fields(file_storage, tmp_path):
    s, _ = file_storage
    await s.credentials.put(_secret())
    raw = (tmp_path / "vault.json").read_text(encoding="utf-8")
    assert "ciphertext" in raw and "plaintext" not in raw and "value" not in raw


# ---------------------------------------------------------------------------
# Mongo backend only [LIVE]
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mongo_event_index_enforces_unique_sequence(mongo_storage):
    events = mongo_storage.events._events
    info = await events.index_information()
    unique = [v for v in info.values() if v.get("unique") and v["key"] == [("run_id", 1), ("seq", 1)]]
    assert unique, info


# ---------------------------------------------------------------------------
# Boundary [MOCK]
# ---------------------------------------------------------------------------

def test_only_the_mongo_adapter_imports_pymongo():
    offenders = []
    for path in (REPO_ROOT / "agentos").rglob("*.py"):
        rel = path.relative_to(REPO_ROOT)
        if "tests" in rel.parts or "__pycache__" in rel.parts or rel.parts[:3] == ("agentos", "storage", "mongo"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module
                     else [])
            if any(n.split(".")[0] in {"pymongo", "motor", "bson"} for n in names):
                offenders.append(f"{rel}:{node.lineno}")
    assert offenders == []
