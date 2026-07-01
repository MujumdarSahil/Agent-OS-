"""
Tests for Agent class
"""

import pytest
from agentos.core.agent import Agent, AgentStatus, ResourceQuota
from agentos.core.umb_adapter import UMBAdapter


@pytest.fixture
def umb():
    """Create UMB adapter for testing"""
    return UMBAdapter(backend="simple")


@pytest.fixture
def agent(umb):
    """Create test agent"""
    return Agent(
        name="TestAgent",
        skills=["coding", "testing"],
        memory_ref=umb,
    )


def test_agent_creation(agent):
    """Test agent creation"""
    assert agent.name == "TestAgent"
    assert "coding" in agent.skills
    assert agent.status == AgentStatus.IDLE
    assert agent.id is not None


def test_agent_skill_vector(agent):
    """Test skill vector building"""
    assert "coding" in agent.skill_vector
    assert agent.skill_vector["coding"] == 1.0


@pytest.mark.asyncio
async def test_agent_plan(agent):
    """Test agent planning"""
    task = {"id": "task1", "description": "Test task"}
    plan = await agent.plan(task)
    
    assert plan["agent_id"] == agent.id
    assert plan["task_id"] == task["id"]
    assert "subtasks" in plan


@pytest.mark.asyncio
async def test_agent_execute(agent):
    """Test agent execution"""
    task_node = {
        "id": "task1",
        "description": "Test execution",
        "type": "generic",
    }
    
    result = await agent.execute(task_node)
    
    assert result["success"] is True
    assert result["task_id"] == task_node["id"]


@pytest.mark.asyncio
async def test_agent_memory_update(agent, umb):
    """Test agent memory update"""
    task_node = {
        "id": "task1",
        "description": "Test task with memory",
    }
    
    result = await agent.execute(task_node)
    
    # Check if memory was updated
    results = await umb.query("Test task", scope=["agent"], agent_id=agent.id)
    assert len(results) > 0


def test_agent_resource_quota(agent):
    """Test resource quota"""
    quota = ResourceQuota(token_limit=10000, api_call_limit=100)
    agent.resource_quota = quota
    
    assert agent.resource_quota.token_limit == 10000
    assert agent.resource_quota.api_call_limit == 100


def test_agent_to_dict(agent):
    """Test agent serialization"""
    data = agent.to_dict()
    
    assert data["id"] == agent.id
    assert data["name"] == agent.name
    assert data["status"] == agent.status.value

