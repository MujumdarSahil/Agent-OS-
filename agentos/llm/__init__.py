"""
AgentOS LLM module initialization
"""

from agentos.llm.provider_registry import PROVIDER_REGISTRY, get_available_providers
from agentos.llm.router_factory import build_router, check_ollama_reachable
from agentos.llm.llm_client import LLMClient, AgentOSLLMError, AgentOSChatModel, AgentOSCrewAILLM

__all__ = [
    "PROVIDER_REGISTRY",
    "get_available_providers",
    "build_router",
    "check_ollama_reachable",
    "LLMClient",
    "AgentOSLLMError",
    "AgentOSChatModel",
    "AgentOSCrewAILLM",
]
