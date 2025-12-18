"""
Tests for UMB adapter
"""

import pytest
from agentos.core.umb_adapter import UMBAdapter, MemoryPermission


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

