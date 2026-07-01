"""
Tests for Squad class
"""

import pytest
from agentos.core.squad import Squad, SquadRole
from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter


@pytest.fixture
def umb():
    """Create UMB adapter"""
    return UMBAdapter(backend="simple")


@pytest.fixture
def squad(umb):
    """Create test squad"""
    return Squad(
        name="TestSquad",
        shared_memory_ref=umb,
    )


@pytest.fixture
def agents(umb):
    """Create test agents"""
    return [
        Agent(name="Agent1", skills=["coding"], memory_ref=umb),
        Agent(name="Agent2", skills=["testing"], memory_ref=umb),
        Agent(name="Agent3", skills=["design"], memory_ref=umb),
    ]


def test_squad_creation(squad):
    """Test squad creation"""
    assert squad.name == "TestSquad"
    assert len(squad.agents) == 0
    assert squad.id is not None


def test_squad_add_agent(squad, agents):
    """Test adding agents to squad"""
    agent = agents[0]
    result = squad.add_agent(agent, SquadRole.WORKER)
    
    assert result is True
    assert agent.id in squad.agents
    assert squad.agent_roles[agent.id] == SquadRole.WORKER


def test_squad_assign_commander(squad, agents):
    """Test assigning commander"""
    agent = agents[0]
    squad.add_agent(agent, SquadRole.COMMANDER)
    
    assert squad.commander_id == agent.id
    assert squad.get_commander() == agent


def test_squad_create_mission(squad):
    """Test creating mission"""
    mission = squad.create_mission(
        goal="Test mission",
        description="Test description"
    )
    
    assert mission.id in squad.missions
    assert mission.goal == "Test mission"
    assert mission.status == "pending"


@pytest.mark.asyncio
async def test_squad_start_mission(squad, agents):
    """Test starting mission"""
    # Add agents
    for agent in agents:
        squad.add_agent(agent, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(goal="Test mission")
    
    # Start mission
    result = await squad.start_mission(mission.id)
    
    assert result["success"] is True
    assert squad.active_mission_id == mission.id
    assert mission.status in ("active", "completed")


def test_squad_get_agents_by_role(squad, agents):
    """Test getting agents by role"""
    squad.add_agent(agents[0], SquadRole.COMMANDER)
    squad.add_agent(agents[1], SquadRole.WORKER)
    squad.add_agent(agents[2], SquadRole.WORKER)
    
    workers = squad.get_agents_by_role(SquadRole.WORKER)
    assert len(workers) == 2
    
    commanders = squad.get_agents_by_role(SquadRole.COMMANDER)
    assert len(commanders) == 1

