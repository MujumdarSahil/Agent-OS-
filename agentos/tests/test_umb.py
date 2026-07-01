"""
Tests for UMB adapter
"""

import pytest
from agentos.core.umb_adapter import UMBAdapter, MemoryPermission, MemoryEntry, SimpleVectorStore


@pytest.fixture
def umb():
    """Create UMB adapter"""
    return UMBAdapter(backend="simple")


@pytest.mark.asyncio
async def test_umb_upsert(umb):
    """Test memory upsert"""
    entry = {
        "text": "Test memory entry",
        "metadata": {
            "author_agent": "agent1",
            "permission_level": "agent_private",
        }
    }
    
    entry_id = await umb.upsert(entry)
    assert entry_id is not None


@pytest.mark.asyncio
async def test_umb_query(umb):
    """Test memory query"""
    # Add entries
    await umb.upsert({
        "text": "Python programming",
        "metadata": {
            "author_agent": "agent1",
            "permission_level": "squad_shared",
        }
    })
    
    await umb.upsert({
        "text": "JavaScript programming",
        "metadata": {
            "author_agent": "agent2",
            "permission_level": "squad_shared",
        }
    })
    
    # Query
    results = await umb.query("programming", scope=["squad"], top_k=5)
    
    assert len(results) > 0


@pytest.mark.asyncio
async def test_umb_scope_filtering(umb):
    """Test scope filtering"""
    # Add private entry
    await umb.upsert({
        "text": "Private note",
        "metadata": {
            "author_agent": "agent1",
            "permission_level": "agent_private",
        }
    })
    
    # Add squad shared entry
    await umb.upsert({
        "text": "Squad note",
        "metadata": {
            "author_agent": "agent1",
            "permission_level": "squad_shared",
        }
    })
    
    # Query with agent scope (should only get agent's private)
    results = await umb.query("note", scope=["agent"], agent_id="agent1")
    
    # Should find at least the private note
    assert len(results) >= 1


@pytest.mark.asyncio
async def test_umb_revoke(umb):
    """Test memory revocation"""
    entry_id = await umb.upsert({
        "text": "To be deleted",
        "metadata": {"author_agent": "agent1"},
    })
    
    # Revoke
    result = await umb.revoke(entry_id)
    assert result is True
    
    # Verify deleted
    entry = await umb.get(entry_id)
    assert entry is None


@pytest.mark.asyncio
async def test_umb_to_dict():
    """Test MemoryEntry.to_dict"""
    entry = MemoryEntry(id="e1", text="some text", vector=[0.1, 0.2])
    d = entry.to_dict()
    assert d["id"] == "e1"
    assert d["text"] == "some text"
    assert d["vector"] == [0.1, 0.2]


@pytest.mark.asyncio
async def test_simple_vector_store_edge_cases():
    """Test SimpleVectorStore search edge cases"""
    store = SimpleVectorStore()
    
    # Search with empty query vector
    assert store.search(query_vector=[]) == []
    
    # Cosine similarity edge cases
    assert store._cosine_similarity([], []) == 0.0
    assert store._cosine_similarity([0.1], [0.1, 0.2]) == 0.0
    assert store._cosine_similarity([0.0], [0.0]) == 0.0


@pytest.mark.asyncio
async def test_umb_backends():
    """Test initializing different backends"""
    umb_faiss = UMBAdapter(backend="faiss")
    assert umb_faiss.backend_type == "faiss"
    
    umb_chroma = UMBAdapter(backend="chroma")
    assert umb_chroma.backend_type == "chroma"
    
    umb_other = UMBAdapter(backend="other_unknown")
    assert umb_other.backend_type == "other_unknown"


@pytest.mark.asyncio
async def test_umb_advanced_filters(umb):
    """Test advanced query filtering options in UMBAdapter"""
    # 1. Setup multiple records with various permissions and metadata
    await umb.upsert({
        "id": "e_squad",
        "text": "squad shared text",
        "metadata": {"permission_level": "squad_shared", "author_agent": "agent1", "mission_id": "m1"}
    })
    await umb.upsert({
        "id": "e_mission",
        "text": "mission scoped text",
        "metadata": {"permission_level": "mission_scoped", "author_agent": "agent1", "mission_id": "m1"}
    })
    await umb.upsert({
        "id": "e_private",
        "text": "agent private text",
        "metadata": {"permission_level": "agent_private", "author_agent": "agent1", "mission_id": "m2"}
    })
    
    # 2. Query with specific permission_level filter
    res = await umb.query("text", permission_level=MemoryPermission.AGENT_PRIVATE)
    assert len(res) == 1
    assert res[0]["id"] == "e_private"
    
    # 3. Query with mission_id filter
    res = await umb.query("text", mission_id="m1")
    assert any(x["id"] == "e_squad" for x in res)
    assert any(x["id"] == "e_mission" for x in res)
    assert all(x["id"] != "e_private" for x in res)

    # 4. Query with scope mismatch tests (e.g. scope is ["squad"] but querying private)
    res = await umb.query("text", scope=["squad"])
    assert any(x["id"] == "e_squad" for x in res)
    assert all(x["id"] != "e_private" for x in res)
    assert all(x["id"] != "e_mission" for x in res)
    
    # 5. Query with scope=["mission"]
    res = await umb.query("text", scope=["mission"], mission_id="m1")
    assert any(x["id"] == "e_mission" for x in res)
    
    # 6. Query with agent_id where agent is not author of private entry
    res = await umb.query("text", agent_id="agent2")
    assert all(x["id"] != "e_private" for x in res) # e_private belongs to agent1


@pytest.mark.asyncio
async def test_umb_revoke_not_found(umb):
    """Test revoke returns False if entry not found"""
    assert await umb.revoke("non-existent-id") is False


@pytest.mark.asyncio
async def test_umb_clear(umb):
    """Test clearing memory"""
    await umb.upsert({"id": "e1", "text": "clear test 1", "metadata": {"permission_level": "mission_scoped"}})
    await umb.upsert({"id": "e2", "text": "clear test 2", "metadata": {"permission_level": "agent_private"}})
    
    # Clear mission scope
    umb.clear(scope="mission")
    assert await umb.get("e1") is None
    assert await umb.get("e2") is not None
    
    # Clear agent scope
    umb.clear(scope="agent")
    assert await umb.get("e2") is None
    
    # Clear all
    await umb.upsert({"id": "e3", "text": "clear test 3"})
    umb.clear()
    assert await umb.get("e3") is None


