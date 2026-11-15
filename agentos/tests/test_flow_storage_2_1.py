"""Tests for Flow storage (File and Mongo), atomic publish, and deletion guard."""

import asyncio
import os
import uuid
import pytest
import pytest_asyncio

from agentos.storage import open_storage
from agentos.storage.models import FlowRecord

MONGO_URI = os.environ.get("AGENTOS_MONGO_URI", "mongodb://127.0.0.1:27017")


@pytest_asyncio.fixture(params=["file", "mongo"])
async def flow_storage(request, tmp_path):
    if request.param == "file":
        project = tmp_path / "test_proj"
        project.mkdir(parents=True, exist_ok=True)
        (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        s = await open_storage(str(project), backend="file", vault_path=str(tmp_path / "vault.json"))
        yield s
        await s.close()
    else:
        # Mongo backend: skip if unreachable
        from pymongo import AsyncMongoClient
        client = AsyncMongoClient(MONGO_URI, serverSelectionTimeoutMS=1000)
        try:
            await client.admin.command("ping")
        except Exception:
            await client.close()
            pytest.skip("MongoDB not running on localhost:27017")

        db_name = f"test_flow_store_{uuid.uuid4().hex[:10]}"
        s = await open_storage(backend="mongo", mongo_uri=MONGO_URI, db_name=db_name)
        try:
            yield s
        finally:
            await s.close()
            cleanup_client = AsyncMongoClient(MONGO_URI)
            await cleanup_client.drop_database(db_name)
            await cleanup_client.close()


def _valid_flow(flow_id: str = "flow_a") -> FlowRecord:
    return FlowRecord(
        id=flow_id,
        name="Test Flow",
        entrypoint="node_entry",
        nodes={
            "node_entry": {
                "id": "node_entry",
                "type": "webhook_trigger",
                "config": {"path": "/in"},
            },
            "node_send": {
                "id": "node_send",
                "type": "send_email",
                "config": {},
                "pinned_args": {"to": "admin@internal.local"},
            },
        },
        edges=[
            {
                "source": "node_entry",
                "target": "node_send",
                "arg_mapping": {"body": "payload"},
            }
        ],
    )


@pytest.mark.asyncio
async def test_flow_draft_crud_and_validation(flow_storage):
    """Drafts can be saved, fetched, and updated; invalid DAGs are rejected on save."""
    flow = _valid_flow("my_flow")
    await flow_storage.flows.put_draft(flow)

    draft = await flow_storage.flows.get_draft("my_flow")
    assert draft is not None
    assert draft.id == "my_flow"
    assert draft.name == "Test Flow"
    assert draft.status == "draft"
    assert draft.version is None

    # Invalid flow config: missing entrypoint in nodes
    bad_flow = FlowRecord(
        id="bad_flow",
        name="Bad",
        entrypoint="non_existent",
        nodes={},
    )
    with pytest.raises(Exception):
        await flow_storage.flows.put_draft(bad_flow)


@pytest.mark.asyncio
async def test_publish_creates_immutable_version_and_updates_draft(flow_storage):
    """Publish assigns version 1, records content_sha256, and preserves immutability."""
    flow = _valid_flow("flow_pub")
    await flow_storage.flows.put_draft(flow)

    pub_v1 = await flow_storage.flows.publish(
        flow_id="flow_pub",
        content_sha256="sha256_mock_1",
        policy_hash="policy_hash_1",
    )
    assert pub_v1.version == 1
    assert pub_v1.status == "published"
    assert pub_v1.content_sha256 == "sha256_mock_1"
    assert pub_v1.policy_hash == "policy_hash_1"

    # Fetch version directly
    fetched_v1 = await flow_storage.flows.get_version("flow_pub", 1)
    assert fetched_v1 is not None
    assert fetched_v1.version == 1
    assert fetched_v1.content_sha256 == "sha256_mock_1"

    # Versions list
    versions = await flow_storage.flows.list_versions("flow_pub")
    assert len(versions) == 1
    assert versions[0].version == 1


@pytest.mark.asyncio
async def test_publish_atomicity_concurrent_publishes(flow_storage):
    """
    Requirement 4: Publish atomicity:
    Two concurrent publishes assign versions 1 and 2, no duplicates, no lost version.
    """
    flow = _valid_flow("flow_concurrent")
    await flow_storage.flows.put_draft(flow)

    # Launch two concurrent publishes
    t1 = flow_storage.flows.publish("flow_concurrent", "sha_concurrent_1", "policy_1")
    t2 = flow_storage.flows.publish("flow_concurrent", "sha_concurrent_2", "policy_2")
    res1, res2 = await asyncio.gather(t1, t2)

    assigned_versions = sorted([res1.version, res2.version])
    assert assigned_versions == [1, 2], f"Expected versions [1, 2], got {assigned_versions}"

    versions = await flow_storage.flows.list_versions("flow_concurrent")
    assert len(versions) == 2
    assert [v.version for v in versions] == [1, 2]


@pytest.mark.asyncio
async def test_deletion_guard_and_archive(flow_storage):
    """
    Requirement 7: Deletion guard: a flow that has published versions CANNOT be deleted.
    Archive endpoint marks the flow status as 'archived'.
    """
    flow = _valid_flow("flow_guard")
    await flow_storage.flows.put_draft(flow)

    # Before publishing, draft can be deleted
    deleted = await flow_storage.flows.delete_flow("flow_guard")
    assert deleted is True
    assert (await flow_storage.flows.get_draft("flow_guard")) is None

    # Re-create and publish
    await flow_storage.flows.put_draft(flow)
    await flow_storage.flows.publish("flow_guard", "content_hash", "policy_hash")

    # Now deletion must be refused (Requirement 7)
    with pytest.raises(ValueError, match="published versions exist"):
        await flow_storage.flows.delete_flow("flow_guard")

    # Archive should succeed
    archived = await flow_storage.flows.archive_flow("flow_guard")
    assert archived.status == "archived"
    draft = await flow_storage.flows.get_draft("flow_guard")
    assert draft is not None
    assert draft.status == "archived"
