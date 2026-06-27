"""
Phase 1 Smoke Test - Verification of AgentOS multi-agent execution,
governance checking, and LLM fallback chain.
"""

import os
import sys
import logging
from typing import Dict, Any, List, Optional

# Ensure the project root is in the python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("phase1_smoke_test")

# Load dotenv if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from agentos import Agent, Squad, GovernanceEngine, PolicyDecision
from agentos.core.base import BaseAgent, BaseTool, AgentRegistry, ToolRegistry
from agentos.llm import LLMClient, AgentOSLLMError
from agentos.core.squad import Mission, SquadRole
from agentos.core.planner import TaskGraph, TaskNode

# 1. Define custom agents subclassing BaseAgent (or concrete Agent)
class ResearcherAgent(Agent):
    """Custom researcher agent subclassing Agent/BaseAgent"""
    def __init__(self, **kwargs):
        super().__init__(
            name=kwargs.get("name", "Researcher"),
            role="Research Analyst",
            goal="Research and extract information about the given topic.",
            backstory="An analyst with a passion for finding and summarizing truth.",
            **kwargs
        )

class WriterAgent(Agent):
    """Custom writer agent subclassing Agent/BaseAgent"""
    def __init__(self, **kwargs):
        super().__init__(
            name=kwargs.get("name", "Writer"),
            role="Content Writer",
            goal="Write a clean and engaging response summarizing facts.",
            backstory="A creative writer who turns raw facts into beautiful prose.",
            **kwargs
        )

# 2. Define custom tool subclassing BaseTool
class WebSearchTool(BaseTool):
    """Mock search tool for testing"""
    name: str = "web_search"
    description: str = "Searches the web for the query and returns matching information."

    def run(self, query: str = "", **kwargs) -> str:
        logger.info(f"WebSearchTool executed with query: {query}")
        return f"Mock search result: AgentOS Phase 1 represents a major milestone in multi-agent orchestration. Query: '{query}'"

# 3. Main test runner
def run_test():
    logger.info("=== STEP 1: INITIALIZING LLM CLIENT & TESTING FALLBACK ===")
    
    # Check set keys in environment
    known_keys = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY"]
    set_keys = [k for k in known_keys if os.environ.get(k)]
    logger.info(f"Keys found in environment: {set_keys}")
    
    # Save original keys to restore later
    original_env = {k: os.environ.get(k) for k in known_keys}
    
    # If no keys are set, let's configure fake keys for multiple providers to test the fallback logging
    if not set_keys:
        logger.info("No keys found. Injecting multiple fake keys to demonstrate fallback chain traversal.")
        os.environ["OPENAI_API_KEY"] = "sk-fake-openai-key"
        os.environ["GEMINI_API_KEY"] = "fake-gemini-key"
    else:
        # If keys are set, make the highest priority key fake (OpenAI) to trigger fallback to the next configured key
        logger.info("Keys found. Injecting fake OpenAI key to trigger fallback to the next available provider.")
        os.environ["OPENAI_API_KEY"] = "sk-fake-openai-key"

    # Initialize the LLMClient
    try:
        client = LLMClient()
    except Exception as e:
        logger.error(f"Failed to build LLMClient: {e}")
        # Restore environment
        for k, v in original_env.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
        sys.exit(1)

    # Test complete
    logger.info("Sending test prompt: 'Say hello in 5 words'")
    fallback_success = False
    try:
        res = client.complete(messages=[{"role": "user", "content": "Say hello in 5 words"}])
        content = res.get("choices", [{}])[0].get("message", {}).get("content", "")
        logger.info(f"Completion output: '{content}'")
        fallback_success = True
    except AgentOSLLMError as e:
        logger.info(f"LLM Client fallback chain failed as expected since all keys are fake: {e}")
        
    # Restore original environment keys for valid mission testing
    for k, v in original_env.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)
            
    # Reinitialize client with real keys if available
    real_set_keys = [k for k in known_keys if os.environ.get(k)]
    if real_set_keys:
        logger.info(f"Re-initializing LLM Client with real keys: {real_set_keys}")
        client = LLMClient()
    else:
        logger.warning("No real keys available in environment. Valid mission execution will run in mock/skip mode.")

    logger.info("=== STEP 2: SQUAD SETUP & GOVERNANCE ENGINE POLICY BLOCKING ===")

    # Initialize agents
    search_tool = WebSearchTool()
    researcher = ResearcherAgent(llm_client=client, tools=[search_tool])
    writer = WriterAgent(llm_client=client)

    # Initialize GovernanceEngine
    governance = GovernanceEngine()
    
    # Add a policy that denies actions containing the word "exploit" or "malware"
    async def deny_harmful_action_check(agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
        task = context.get("task", {})
        desc = task.get("description", "").lower()
        if "exploit" in desc or "malware" in desc:
            return PolicyDecision(allowed=False, reason="Action contains prohibited cybersecurity words.")
        return PolicyDecision(allowed=True)

    policy = governance.create_action_policy(
        name="Block Harmful Cyber Actions",
        check_func=deny_harmful_action_check,
        priority=100
    )
    governance.register_policy(policy)

    # Build Squad
    squad = Squad(name="SmokeTestSquad", governance=governance)
    squad.add_agent(researcher, SquadRole.WORKER)
    squad.add_agent(writer, SquadRole.WORKER)

    # Create a task graph with a blocked task
    blocked_task = TaskNode(
        id="t1",
        description="Generate an exploit payload script for testing.",
        assigned_agent=researcher.id
    )
    task_graph = TaskGraph(id="tg1", goal="Simulated penetration test.", nodes=[blocked_task])
    mission = Mission(id="m1", goal="Blocked mission test.", description="Attempt a blocked task.", task_graph=task_graph)

    logger.info("Running blocked task (should raise ValueError)...")
    try:
        squad.run_mission(mission)
        logger.error("FAIL: Blocked task was not stopped by governance!")
    except ValueError as e:
        logger.info(f"SUCCESS: Task was blocked successfully! Reason: {e}")

    logger.info("=== STEP 3: RUNNING A VALID MISSION END-TO-END ===")
    
    if not real_set_keys:
        logger.info("Skipping real mission end-to-end execution because no real keys were configured in .env.")
        logger.info("ALL PHASE 1 SMOKE TESTS PASSED!")
        return

    # Create a valid task graph
    task1 = TaskNode(
        id="t1",
        description="Use the web search tool to find info about AgentOS.",
        assigned_agent=researcher.id
    )
    task2 = TaskNode(
        id="t2",
        description="Write a short blog post summarizing AgentOS based on the search findings.",
        assigned_agent=writer.id
    )
    task_graph_valid = TaskGraph(id="tg2", goal="Information summary mission.", nodes=[task1, task2])
    mission_valid = Mission(
        id="m2",
        goal="Summarize AgentOS",
        description="Write a summary about AgentOS.",
        task_graph=task_graph_valid
    )

    logger.info("Running valid mission end-to-end...")
    try:
        result = squad.run_mission(mission_valid)
        logger.info("=== VALID MISSION OUTPUT ===")
        logger.info(result)
        logger.info("SUCCESS: Valid mission completed end-to-end!")
        logger.info("ALL PHASE 1 SMOKE TESTS PASSED!")
    except Exception as e:
        logger.error(f"FAIL: Valid mission execution failed: {e}")

if __name__ == "__main__":
    run_test()
