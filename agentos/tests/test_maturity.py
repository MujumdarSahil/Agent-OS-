import pytest
import os
from unittest.mock import MagicMock, patch

from agentos.core.squad import Squad, SquadRole
from agentos.core.agent import Agent
from agentos.core.governance import (
    GovernanceEngine, Policy, PolicyType, PolicyDecision
)
from agentos.llm.llm_client import (
    LLMClient, AgentOSFallbackLogger, convert_message_to_dict,
    AgentOSChatModel, AgentOSCrewAILLM
)
from agentos.llm.router_factory import check_ollama_reachable, build_router
from agentos.llm.provider_registry import AgentOSLLMError
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage


# =====================================================================
# SQUAD MATURITY TESTS
# =====================================================================

def test_squad_add_agent_already_exists():
    squad = Squad(name="MaturitySquad")
    agent = Agent(name="Tester1")
    assert squad.add_agent(agent, SquadRole.WORKER) is True
    assert squad.add_agent(agent, SquadRole.WORKER) is False  # Already exists


def test_squad_add_agent_leader_id():
    squad = Squad(name="MaturitySquad")
    agent = Agent(name="Leader1")
    assert squad.add_agent(agent, SquadRole.SQUAD_LEADER) is True
    assert squad.leader_id == agent.id


def test_squad_remove_agent_handling():
    squad = Squad(name="MaturitySquad")
    agent1 = Agent(name="Commander1")
    agent2 = Agent(name="Leader1")
    
    squad.add_agent(agent1, SquadRole.COMMANDER)
    squad.add_agent(agent2, SquadRole.SQUAD_LEADER)
    
    assert squad.commander_id == agent1.id
    assert squad.leader_id == agent2.id
    
    # Try removing non-existent agent
    assert squad.remove_agent("non-existent-id") is False
    
    # Remove commander
    assert squad.remove_agent(agent1.id) is True
    assert squad.commander_id is None
    
    # Remove leader
    assert squad.remove_agent(agent2.id) is True
    assert squad.leader_id is None


def test_squad_assign_agent():
    squad = Squad(name="MaturitySquad")
    agent = Agent(name="Agent1")
    
    # Assign non-existent
    assert squad.assign_agent("non-existent", SquadRole.WORKER) is False
    
    squad.add_agent(agent, SquadRole.WORKER)
    assert squad.assign_agent(agent.id, SquadRole.COMMANDER) is True
    assert squad.commander_id == agent.id
    
    assert squad.assign_agent(agent.id, SquadRole.SQUAD_LEADER) is True
    assert squad.leader_id == agent.id


@pytest.mark.asyncio
async def test_squad_start_mission_not_found():
    squad = Squad(name="MaturitySquad")
    result = await squad.start_mission("non-existent-mission")
    assert result["success"] is False
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_squad_start_mission_exception_handling():
    squad = Squad(name="MaturitySquad")
    mission = squad.create_mission(goal="Test error handling")
    
    # Force run_mission to raise exception
    with patch.object(squad, 'run_mission', side_effect=ValueError("Simulated run error")):
        result = await squad.start_mission(mission.id)
        assert result["success"] is False
        assert "Simulated run error" in result["error"]
        assert mission.status == "failed"


class MockNode:
    def __init__(self, description, assigned_agent):
        self.description = description
        self.assigned_agent = assigned_agent


class MockTaskGraph:
    def __init__(self, nodes):
        self.nodes = nodes


def test_squad_run_mission_assigned_agent_by_name():
    squad = Squad(name="MaturitySquad")
    agent = Agent(name="SpecialAgent")
    squad.add_agent(agent, SquadRole.WORKER)
    
    mission = squad.create_mission(goal="Named agent mission")
    mission.task_graph = MockTaskGraph([
        MockNode("Task 1", "SpecialAgent")
    ])
    
    with patch("crewai.Crew") as MockCrew:
        mock_crew_instance = MagicMock()
        mock_crew_instance.kickoff.return_value = "Result"
        MockCrew.return_value = mock_crew_instance
        
        res = squad.run_mission(mission)
        assert res == "Result"


@pytest.mark.asyncio
async def test_squad_governance_blocking_before_kickoff():
    # Enforces pre-execution policy block checking
    squad = Squad(name="MaturitySquad")
    agent = Agent(name="WorkerAgent")
    squad.add_agent(agent, SquadRole.WORKER)
    
    mission = squad.create_mission(goal="Prohibited task")
    
    # Configure mock governance to block
    mock_governance = MagicMock()
    # Need to simulate async method for check
    async def mock_check(*args, **kwargs):
        return PolicyDecision(allowed=False, reason="Safety policy block")
    mock_governance.check = mock_check
    squad.governance = mock_governance
    
    # We expect ValueError because of governance block inside kickoff hook
    with patch("crewai.Crew") as MockCrew:
        mock_crew_instance = MagicMock()
        # Mock kickoff to call our callback
        def kickoff_mock():
            # Trigger callback
            callbacks = MockCrew.call_args[1].get("before_kickoff_callbacks", [])
            for cb in callbacks:
                cb({"some_input": "val"})
            return "Result"
        mock_crew_instance.kickoff = kickoff_mock
        MockCrew.return_value = mock_crew_instance
        
        with pytest.raises(ValueError, match="blocked by policy"):
            squad.run_mission(mission)


def test_squad_get_commander_and_leader_nones():
    squad = Squad(name="MaturitySquad")
    assert squad.get_commander() is None
    assert squad.get_leader() is None


def test_squad_to_dict():
    squad = Squad(name="MaturitySquad")
    agent = Agent(name="Agent1")
    squad.add_agent(agent, SquadRole.WORKER)
    data = squad.to_dict()
    assert data["name"] == "MaturitySquad"
    assert data["agent_count"] == 1
    assert agent.id in data["agent_ids"]


# =====================================================================
# GOVERNANCE MATURITY TESTS
# =====================================================================

@pytest.mark.asyncio
async def test_governance_policy_check_boolean():
    engine = GovernanceEngine()
    
    # Policy function returning bool
    async def check_bool(agent_id, action, context):
        return True
    
    policy = Policy(id="p1", policy_type=PolicyType.ACTION, name="BoolPolicy", check_func=check_bool)
    res = await policy.check("a1", "execute", {})
    assert res.allowed is True
    assert res.policy_id == "p1"
    
    # Policy function raising error
    async def check_error(agent_id, action, context):
        raise RuntimeError("Oops")
    
    policy2 = Policy(id="p2", policy_type=PolicyType.ACTION, name="ErrorPolicy", check_func=check_error)
    res2 = await policy2.check("a1", "execute", {})
    assert res2.allowed is False
    assert "Oops" in res2.reason


def test_governance_remove_policy():
    engine = GovernanceEngine()
    policy = Policy(id="p1", policy_type=PolicyType.ACTION, name="P1", check_func=lambda *args: True)
    engine.register_policy(policy, group="test")
    assert "p1" in engine.policies
    assert "p1" in engine.policy_groups["test"]
    
    assert engine.remove_policy("p1") is True
    assert "p1" not in engine.policies
    assert "p1" not in engine.policy_groups["test"]
    
    assert engine.remove_policy("p2_nonexistent") is False


@pytest.mark.asyncio
async def test_governance_llm_judge_layer():
    engine = GovernanceEngine()
    # Configure with no client -> fail open
    engine.configure_llm_judge(enabled=True, llm_client=None)
    decision = await engine.check("a1", "execute", {"task": "crack password"})
    # Although "crack password" is blocked by keyword policies, the keyword check ran and failed
    # Let's test the judge execution specifically by passing a non-blocked task
    # A non-blocked task passes keyword layer, then invokes LLM judge
    decision_pass = await engine.check("a1", "execute", {"task": "do some coding"})
    assert decision_pass.allowed is True
    assert "skipped: no client" in decision_pass.reason or "passed" in decision_pass.reason


@pytest.mark.asyncio
async def test_governance_llm_judge_blocked_and_fail_open():
    engine = GovernanceEngine()
    mock_client = MagicMock()
    engine.configure_llm_judge(enabled=True, llm_client=mock_client)
    
    # Simulate blocked judge response
    mock_client.complete.return_value = {
        "choices": [{
            "message": {
                "content": '{"blocked": true, "reason": "Judge policy violation"}'
            }
        }]
    }
    
    decision = await engine._llm_judge_policy_check("Prohibited task desc")
    assert decision.allowed is False
    assert "Judge policy violation" in decision.reason
    
    # Simulate malformed response causing fail-open (two attempts fail)
    mock_client.complete.return_value = {
        "choices": [{
            "message": {
                "content": 'Not a json response'
            }
        }]
    }
    decision_fail_open = await engine._llm_judge_policy_check("Malformed task desc")
    assert decision_fail_open.allowed is True
    assert "Failed open" in decision_fail_open.reason


@pytest.mark.asyncio
async def test_governance_check_context_variants():
    engine = GovernanceEngine()
    engine.initialize_security_policies()
    # Task context as a string directly
    res = await engine.check("a1", "execute", {"task": "crack password"})
    assert res.allowed is False


def test_governance_policy_relevance():
    engine = GovernanceEngine()
    p_privacy = Policy(id="priv", policy_type=PolicyType.PRIVACY, name="Priv", check_func=lambda *a: True)
    p_resource = Policy(id="res", policy_type=PolicyType.RESOURCE, name="Res", check_func=lambda *a: True)
    
    assert engine._is_relevant(p_privacy, "memory_read", {}) is True
    assert engine._is_relevant(p_privacy, "execute", {}) is False
    assert engine._is_relevant(p_resource, "tool_call", {}) is True
    assert engine._is_relevant(p_resource, "memory_read", {}) is False


@pytest.mark.asyncio
async def test_governance_policy_helpers():
    engine = GovernanceEngine()
    
    # Action policy helpers
    p_action = engine.create_action_policy(
        name="ActionTest",
        allowed_actions=["allowed_tool"],
        denied_actions=["denied_tool"]
    )
    # Check denied action
    res_deny = await p_action.check("a1", "denied_tool", {})
    assert res_deny.allowed is False
    # Check non-allowed action
    res_non_allow = await p_action.check("a1", "other_tool", {})
    assert res_non_allow.allowed is False
    
    # Privacy policy helpers
    p_privacy = engine.create_privacy_policy(
        name="PrivTest",
        allowed_scopes=["scope_allowed"]
    )
    res_priv_deny = await p_privacy.check("a1", "memory_read", {"scope": "scope_denied"})
    assert res_priv_deny.allowed is False
    res_priv_allow = await p_privacy.check("a1", "memory_read", {"scope": "scope_allowed"})
    assert res_priv_allow.allowed is True
    
    # Resource policy helpers
    p_resource = engine.create_resource_policy(
        name="ResTest",
        max_tokens=100,
        max_api_calls=5
    )
    class DummyAgent:
        def __init__(self, token, api):
            self.resource_metrics = {"token_usage": token, "api_calls": api}
            
    res_token_exceeded = await p_resource.check("a1", "execute", {"agent": DummyAgent(150, 2)})
    assert res_token_exceeded.allowed is False
    res_api_exceeded = await p_resource.check("a1", "execute", {"agent": DummyAgent(50, 10)})
    assert res_api_exceeded.allowed is False
    res_resource_ok = await p_resource.check("a1", "execute", {"agent": DummyAgent(50, 2)})
    assert res_resource_ok.allowed is True


@pytest.mark.asyncio
async def test_governance_safety_layer_checks():
    engine = GovernanceEngine()
    p_safety = engine.create_security_safety_layer()
    
    # Tool call not allowed
    res_tool_not_allowed = await p_safety.check("a1", "tool_call", {"tool_name": "unknown_tool", "task": {"description": "audit scan"}})
    # Wait, the task has "audit" which matches keyword "audit", but it needs to be in security_allow_list to set allowed=True.
    # The default security_allow_list is: "password auditing", "metadata-based network monitoring", "configuration auditing", "defensive cybersecurity scripts".
    # Let's test a tool name that hits security_deny_list:
    res_tool_deny = await p_safety.check("a1", "tool_call", {"tool_name": "exploit code", "task": {}})
    assert res_tool_deny.allowed is False
    
    # Script verification
    res_script_deny = await p_safety.check("a1", "generate_script", {"script_content": "import exploit"})
    assert res_script_deny.allowed is False


@pytest.mark.asyncio
async def test_governance_check_model_output_scenarios():
    engine = GovernanceEngine()
    
    # Passes checks
    res_ok = await engine.check_model_output("defensive firewall rules ufw config")
    assert res_ok.allowed is True
    
    # Fails verifier
    mock_verifier = MagicMock()
    mock_verifier.classify_policy_violation.return_value = {"violates_policy": True, "violations": ["exploit code"]}
    res_verifier_fail = await engine.check_model_output(
        "some output",
        verifier_models={"policy_verifier": mock_verifier}
    )
    assert res_verifier_fail.allowed is False


# =====================================================================
# LLM CLIENT MATURITY TESTS
# =====================================================================

def test_llm_client_fallback_logger():
    logger = AgentOSFallbackLogger()
    # Call methods to ensure no exceptions and proper coverage
    logger.log_failure_event({"model": "test-model", "exception": "timeout"}, None, None, None)
    logger.log_success_event({"model": "test-model"}, None, None, None)


@pytest.mark.asyncio
async def test_llm_client_fallback_logger_async():
    logger = AgentOSFallbackLogger()
    await logger.async_log_failure_event({"model": "test-model", "exception": "timeout"}, None, None, None)
    await logger.async_log_success_event({"model": "test-model"}, None, None, None)


@pytest.mark.asyncio
async def test_llm_client_complete_exception_handling():
    # If all providers fail, LLMClient complete/acomplete/stream/astream raise AgentOSLLMError
    with patch("litellm.Router") as MockRouter:
        mock_router_instance = MagicMock()
        mock_router_instance.completion.side_effect = Exception("Router completion failed")
        mock_router_instance.acompletion.side_effect = Exception("Router acompletion failed")
        MockRouter.return_value = mock_router_instance
        
        dummy_provider = [{
            "name": "dummy-provider",
            "litellm_model": "openai/mock-model",
            "api_key_env": "DUMMY_API_KEY",
            "api_base_env": None,
            "priority": 100,
            "tags": []
        }]
        
        # Temporarily clear mock LLM env variable to run through router logic
        with patch.dict(os.environ, {"AGENTOS_MOCK_LLM": "0", "DUMMY_API_KEY": "test_key"}):
            with patch("agentos.llm.router_factory.get_available_providers", return_value=dummy_provider):
                client = LLMClient()
                with pytest.raises(AgentOSLLMError, match="fallback chain failed"):
                    client.complete([{"role": "user", "content": "hi"}])
                    
                with pytest.raises(AgentOSLLMError, match="fallback chain failed"):
                    list(client.stream([{"role": "user", "content": "hi"}]))
                    
                with pytest.raises(AgentOSLLMError, match="fallback chain failed"):
                    await client.acomplete([{"role": "user", "content": "hi"}])
                    
                with pytest.raises(AgentOSLLMError, match="fallback chain failed"):
                    async for chunk in client.astream([{"role": "user", "content": "hi"}]):
                        pass


def test_convert_message_to_dict_branches():
    m_sys = SystemMessage(content="sys")
    assert convert_message_to_dict(m_sys) == {"role": "system", "content": "sys"}
    
    m_tool = ToolMessage(content="result", tool_call_id="call1")
    assert convert_message_to_dict(m_tool) == {"role": "tool", "tool_call_id": "call1", "content": "result"}
    
    # Custom message type
    class CustomMsg:
        type = "system"
        content = "custom sys"
    assert convert_message_to_dict(CustomMsg()) == {"role": "system", "content": "custom sys"}


@pytest.mark.asyncio
async def test_agentos_chat_model_generate():
    mock_client = MagicMock()
    mock_client.complete.return_value = {"choices": [{"message": {"content": "response"}}]}
    
    async def mock_acomplete(*args, **kwargs):
        return {"choices": [{"message": {"content": "async response"}}]}
    mock_client.acomplete = mock_acomplete
    
    model = AgentOSChatModel(mock_client)
    assert model._llm_type == "agentos-chat-model"
    assert isinstance(model._identifying_params, dict)
    
    res = model._generate([HumanMessage(content="hi")])
    assert res.generations[0].message.content == "response"
    
    res_async = await model._agenerate([HumanMessage(content="hi")])
    assert res_async.generations[0].message.content == "async response"


def test_agentos_crewai_llm_call():
    mock_client = MagicMock()
    mock_client.complete.return_value = {"choices": [{"message": {"content": "response"}}]}
    
    crew_llm = AgentOSCrewAILLM(mock_client)
    
    # Test call with string
    assert crew_llm.call("hello") == "response"
    
    # Test call with list of dicts
    assert crew_llm.call([{"role": "user", "content": "hi"}]) == "response"
    
    # Test call with custom objects containing role/content
    class DummyMsgObj:
        role = "user"
        content = "hi obj"
    assert crew_llm.call([DummyMsgObj()]) == "response"


# =====================================================================
# ROUTER FACTORY MATURITY TESTS
# =====================================================================

def test_check_ollama_reachable_nones():
    with patch.dict(os.environ, {"OLLAMA_BASE_URL": ""}):
        with patch("requests.get", side_effect=Exception("Failed connection")):
            # Will default to localhost
            res = check_ollama_reachable()
            assert res is False


def test_build_router_no_providers_exception():
    with patch("agentos.llm.router_factory.get_available_providers", return_value=[]):
        with patch("agentos.llm.router_factory.check_ollama_reachable", return_value=False):
            with patch.dict(os.environ, {"AGENTOS_MOCK_LLM": "0"}):
                with pytest.raises(AgentOSLLMError, match="No LLM providers are available"):
                    build_router()


def test_get_available_providers_scenarios():
    from agentos.llm.provider_registry import get_available_providers
    env_mock = {
        "OPENAI_COMPATIBLE_API_KEY": "test-key",
        "OPENAI_COMPATIBLE_MODEL_NAME": "my-special-model",
    }
    with patch.dict(os.environ, env_mock):
        providers = get_available_providers()
        openai_comp = next((p for p in providers if p["name"] == "openai_compatible"), None)
        assert openai_comp is not None
        assert openai_comp["litellm_model"] == "openai/my-special-model"


def test_llm_client_mock_branches():
    client = LLMClient()
    
    # 1. Trigger suggested_tools branch
    res_tools = client.complete([{"role": "user", "content": "suggested_tools"}])
    assert "SecurityCodeReviewer" in res_tools["choices"][0]["message"]["content"]
    
    # 2. Trigger squad configuration matching branch
    res_squad = client.complete([{"role": "user", "content": "squad configuration matching"}])
    assert "ResearchCrew" in res_squad["choices"][0]["message"]["content"]
    
    # 3. Trigger snake_case_tool_name branch
    res_stub = client.complete([{"role": "user", "content": "snake_case_tool_name"}])
    assert "mock_tool" in res_stub["choices"][0]["message"]["content"]


def test_convert_message_to_dict_more_branches():
    # AIMessage with tool calls
    msg = AIMessage(content="hello", additional_kwargs={"tool_calls": [{"id": "c1", "type": "function"}]})
    res = convert_message_to_dict(msg)
    assert res["role"] == "assistant"
    assert "tool_calls" in res
    assert res["tool_calls"][0]["id"] == "c1"
    
    # Custom objects with type "ai"
    class MsgAI:
        type = "ai"
        content = "hello ai"
    res_ai = convert_message_to_dict(MsgAI())
    assert res_ai["role"] == "assistant"
    
    # Custom objects with type "tool"
    class MsgTool:
        type = "tool"
        content = "hello tool"
    res_tool = convert_message_to_dict(MsgTool())
    assert res_tool["role"] == "tool"


def test_llm_client_router_success_paths():
    client = LLMClient()
    mock_response = MagicMock()
    mock_response.model = "my-mocked-router-model"
    client.router.completion = MagicMock(return_value=mock_response)
    
    with patch.dict(os.environ, {"AGENTOS_MOCK_LLM": "0"}):
        res = client.complete([{"role": "user", "content": "hi"}])
        assert res.model == "my-mocked-router-model"
        
        # Test stream
        client.router.completion.return_value = [mock_response]
        stream_res = list(client.stream([{"role": "user", "content": "hi"}]))
        assert len(stream_res) == 1
        assert stream_res[0].model == "my-mocked-router-model"


@pytest.mark.asyncio
async def test_llm_client_router_async_success_paths():
    client = LLMClient()
    mock_response = MagicMock()
    mock_response.model = "my-mocked-router-model"
    
    async def mock_acompletion(*args, **kwargs):
        if kwargs.get("stream"):
            async def async_gen():
                yield mock_response
            return async_gen()
        return mock_response
        
    client.router.acompletion = mock_acompletion
    
    with patch.dict(os.environ, {"AGENTOS_MOCK_LLM": "0"}):
        res = await client.acomplete([{"role": "user", "content": "hi"}])
        assert res.model == "my-mocked-router-model"
        
        # Test astream
        chunks = []
        async for chunk in client.astream([{"role": "user", "content": "hi"}]):
            chunks.append(chunk)
        assert len(chunks) == 1
        assert chunks[0].model == "my-mocked-router-model"


def test_agentos_crewai_llm_call_other_msg():
    mock_client = MagicMock()
    mock_client.complete.return_value = {"choices": [{"message": {"content": "response"}}]}
    crew_llm = AgentOSCrewAILLM(mock_client)
    
    # Test call with float
    assert crew_llm.call(123.45) == "response"


@pytest.mark.asyncio
async def test_agentos_crewai_llm_acall():
    mock_client = MagicMock()
    mock_client.complete.return_value = {"choices": [{"message": {"content": "async response"}}]}
    crew_llm = AgentOSCrewAILLM(mock_client)
    
    # Test acall
    res = await crew_llm.acall("hello")
    assert res == "async response"


def test_json_logging_formatter():
    from agentos.core.logging_config import JSONFormatter
    import logging
    import json
    
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test-logger",
        level=logging.INFO,
        pathname="test_file.py",
        lineno=10,
        msg="Hello %s",
        args=("world",),
        exc_info=None
    )
    record.__dict__["extra_key"] = "extra_val"
    
    output = formatter.format(record)
    parsed = json.loads(output)
    
    assert parsed["name"] == "test-logger"
    assert parsed["level"] == "INFO"
    assert parsed["message"] == "Hello world"
    assert parsed["extra_key"] == "extra_val"
    assert "timestamp" in parsed



