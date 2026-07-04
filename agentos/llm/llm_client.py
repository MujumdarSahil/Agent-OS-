"""
LLM Client - Provider-agnostic interface with fallback logic and LangChain ChatModel adapter
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional, Generator, AsyncGenerator
import litellm
from litellm.integrations.custom_logger import CustomLogger

# Drop top-level parameters unsupported by some providers.
# Defense-in-depth alongside _sanitize_messages() below.
litellm.drop_params = True

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.callbacks import CallbackManagerForLLMRun, AsyncCallbackManagerForLLMRun
from crewai.llms.base_llm import BaseLLM as CrewAIBaseLLM

from agentos.llm.router_factory import build_router
from agentos.llm.provider_registry import AgentOSLLMError

logger = logging.getLogger(__name__)


import threading

_local_storage = threading.local()
_fallback_events_count = 0

def set_last_used_provider(provider: str) -> None:
    _local_storage.last_used_provider = provider

def get_last_used_provider() -> Optional[str]:
    return getattr(_local_storage, "last_used_provider", None)

def increment_fallback_events() -> None:
    global _fallback_events_count
    _fallback_events_count += 1

def get_fallback_events_count() -> int:
    global _fallback_events_count
    return _fallback_events_count

class AgentOSFallbackLogger(CustomLogger):
    """
    LiteLLM custom logger callback to log provider successes, failures,
    and fallback events.
    """
    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        model = kwargs.get("model", "unknown")
        exception = kwargs.get("exception", "unknown error")
        logger.info(f"Provider {model} failed ({exception}), trying next fallback...")
        increment_fallback_events()

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        model = kwargs.get("model", "unknown")
        exception = kwargs.get("exception", "unknown error")
        logger.info(f"Provider {model} failed ({exception}), trying next fallback...")
        increment_fallback_events()

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        model = kwargs.get("model", "unknown")
        logger.info(f"Successfully served request using provider/model: {model}")
        set_last_used_provider(model)

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        model = kwargs.get("model", "unknown")
        logger.info(f"Successfully served request using provider/model: {model}")
        set_last_used_provider(model)

# Register custom fallback logger callback globally in litellm
litellm.callbacks = [AgentOSFallbackLogger()]

# ─────────────────────────────────────────────────────────────────────────────
# Message sanitizer
# ─────────────────────────────────────────────────────────────────────────────
_CACHE_FIELDS = frozenset({"cache_breakpoint", "cache_control"})

def _sanitize_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Strip Anthropic/OpenAI prompt-caching metadata fields from message dicts.

    LiteLLM ≥ 1.86 mutates message objects in-place when the first provider
    (e.g. OpenAI) uses prompt caching, inserting 'cache_breakpoint' or
    'cache_control' into individual message dicts.  Those fields are then
    forwarded verbatim to the next fallback provider (e.g. Groq), which
    rejects them with a 400 Bad Request.  This helper strips the fields before
    every router call so every provider in the chain receives a clean payload.
    """
    cleaned = []
    for msg in messages:
        if not isinstance(msg, dict):
            cleaned.append(msg)
            continue
        filtered = {k: v for k, v in msg.items() if k not in _CACHE_FIELDS}
        cleaned.append(filtered)
    return cleaned


class LLMClient:
    """
    The main client class used to talk to LLM providers.
    It builds and maintains the LiteLLM Router for fallback execution.
    """
    def __init__(self, preferred_tags: Optional[List[str]] = None):
        self.router = build_router(preferred_tags=preferred_tags)

    def complete(self, messages: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """
        Runs synchronous completion request across the fallback chain.
        """
        if os.environ.get("AGENTOS_MOCK_LLM") == "1":
            prompt = ""
            for m in messages:
                prompt += m.get("content", "") + "\n"
            
            content = "Mock LLM Response"
            if "suggested_tools" in prompt.lower():
                content = json.dumps({
                    "name": "SecurityCodeReviewer",
                    "role": "Security Code Reviewer",
                    "goal": "Review python code for security vulnerabilities",
                    "backstory": "An experienced security analyst specializing in python AST checks.",
                    "suggested_tools": ["data_fetcher"]
                })
            elif "snake_case_tool_name" in prompt.lower() or "class_name" in prompt.lower():
                content = json.dumps({
                    "name": "mock_tool",
                    "class_name": "MockTool",
                    "description": "Mock description",
                    "run_code_stub": "        return 'Mock Tool Executed'"
                })
            elif "squad configuration matching" in prompt.lower():
                content = json.dumps({
                    "name": "ResearchCrew",
                    "process": "sequential",
                    "agents": [
                        {
                            "name": "Researcher",
                            "role": "Web Fact Finder",
                            "goal": "Find raw facts",
                            "backstory": "Fact finder.",
                            "suggested_tools": ["data_fetcher"]
                        }
                    ],
                    "tasks": [
                        {
                            "description": "Fetch initial facts about AgentOS Phase 2.",
                            "assigned_agent": "Researcher"
                        }
                    ]
                })
                
            return {
                "model": "mock-model",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": content
                        }
                    }
                ]
            }

        try:
            response = self.router.completion(
                model="agentos-default",
                messages=_sanitize_messages(messages),
                **kwargs
            )
            # Log which provider actually served the request
            model_served = "unknown"
            if hasattr(response, "model"):
                model_served = response.model
            elif isinstance(response, dict) and "model" in response:
                model_served = response["model"]
            logger.info(f"Request served by: {model_served}")
            set_last_used_provider(model_served)
            return response
        except Exception as e:
            logger.error(f"All providers in fallback chain failed: {e}")
            raise AgentOSLLMError(f"All providers in the fallback chain failed: {e}") from e

    def stream(self, messages: List[Dict[str, Any]], **kwargs) -> Generator[Dict[str, Any], None, None]:
        """
        Runs synchronous streaming completion across the fallback chain.
        """
        try:
            response = self.router.completion(
                model="agentos-default",
                messages=_sanitize_messages(messages),
                stream=True,
                **kwargs
            )
            for chunk in response:
                yield chunk
        except Exception as e:
            logger.error(f"All providers in fallback chain failed during streaming: {e}")
            raise AgentOSLLMError(f"All providers in the fallback chain failed during streaming: {e}") from e

    async def acomplete(self, messages: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """
        Runs asynchronous completion request across the fallback chain.
        """
        if os.environ.get("AGENTOS_MOCK_LLM") == "1":
            return self.complete(messages, **kwargs)
            
        try:
            response = await self.router.acompletion(
                model="agentos-default",
                messages=_sanitize_messages(messages),
                **kwargs
            )
            model_served = "unknown"
            if hasattr(response, "model"):
                model_served = response.model
            elif isinstance(response, dict) and "model" in response:
                model_served = response["model"]
            logger.info(f"Request served by: {model_served}")
            set_last_used_provider(model_served)
            return response
        except Exception as e:
            logger.error(f"All providers in fallback chain failed in acomplete: {e}")
            raise AgentOSLLMError(f"All providers in the fallback chain failed: {e}") from e

    async def astream(self, messages: List[Dict[str, Any]], **kwargs) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Runs asynchronous streaming completion across the fallback chain.
        """
        try:
            response = await self.router.acompletion(
                model="agentos-default",
                messages=_sanitize_messages(messages),
                stream=True,
                **kwargs
            )
            async for chunk in response:
                yield chunk
        except Exception as e:
            logger.error(f"All providers in fallback chain failed during astream: {e}")
            raise AgentOSLLMError(f"All providers in the fallback chain failed during streaming: {e}") from e


def convert_message_to_dict(message: BaseMessage) -> Dict[str, Any]:
    """Helper to convert LangChain BaseMessage to LiteLLM message dictionary"""
    if isinstance(message, SystemMessage):
        return {"role": "system", "content": message.content}
    elif isinstance(message, HumanMessage):
        return {"role": "user", "content": message.content}
    elif isinstance(message, AIMessage):
        res = {"role": "assistant", "content": message.content}
        if message.additional_kwargs.get("tool_calls"):
            res["tool_calls"] = message.additional_kwargs["tool_calls"]
        return res
    elif isinstance(message, ToolMessage):
        return {"role": "tool", "tool_call_id": message.tool_call_id, "content": message.content}
    else:
        role = "user"
        if hasattr(message, "type"):
            if message.type == "system":
                role = "system"
            elif message.type == "ai":
                role = "assistant"
            elif message.type == "tool":
                role = "tool"
        return {"role": role, "content": message.content}


class AgentOSChatModel(BaseChatModel):
    """
    Custom LangChain ChatModel adapter that delegates generating calls to
    an AgentOS LLMClient, enabling full fallback-chain support inside CrewAI/LangChain.
    """
    
    def __init__(self, llm_client: LLMClient, **kwargs):
        super().__init__(**kwargs)
        self._llm_client = llm_client

    @property
    def _llm_type(self) -> str:
        return "agentos-chat-model"

    @property
    def _identifying_params(self) -> Dict[str, Any]:
        return {"llm_client": id(self._llm_client)}

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        dict_messages = [convert_message_to_dict(m) for m in messages]
        res = self._llm_client.complete(messages=dict_messages, **kwargs)
        content = res.get("choices", [{}])[0].get("message", {}).get("content", "")
        message = AIMessage(content=content)
        generation = ChatGeneration(message=message)
        return ChatResult(generations=[generation])

    async def _agenerate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        dict_messages = [convert_message_to_dict(m) for m in messages]
        res = await self._llm_client.acomplete(messages=dict_messages, **kwargs)
        content = res.get("choices", [{}])[0].get("message", {}).get("content", "")
        message = AIMessage(content=content)
        generation = ChatGeneration(message=message)
        return ChatResult(generations=[generation])


class AgentOSCrewAILLM(CrewAIBaseLLM):
    """
    CrewAI-compatible LLM adapter that inherits from CrewAI's BaseLLM
    and delegates to our fallback-aware LLMClient.
    """
    
    def __init__(self, llm_client: LLMClient, **kwargs):
        kwargs.setdefault("model", "agentos-default")
        super().__init__(**kwargs)
        self._llm_client = llm_client

    def call(
        self,
        messages: Any,
        tools: Any = None,
        callbacks: Any = None,
        available_functions: Any = None,
        from_task: Any = None,
        from_agent: Any = None,
        response_model: Any = None,
    ) -> str:
        dict_messages = []
        if isinstance(messages, str):
            dict_messages = [{"role": "user", "content": messages}]
        elif isinstance(messages, list):
            for msg in messages:
                if isinstance(msg, dict):
                    dict_messages.append(msg)
                elif hasattr(msg, "role") and hasattr(msg, "content"):
                    dict_messages.append({"role": msg.role, "content": msg.content})
                else:
                    dict_messages.append({"role": "user", "content": str(msg)})
        else:
            dict_messages = [{"role": "user", "content": str(messages)}]

        res = self._llm_client.complete(messages=dict_messages)
        content = res.get("choices", [{}])[0].get("message", {}).get("content", "")
        return content

    async def acall(
        self,
        messages: Any,
        tools: Any = None,
        callbacks: Any = None,
        available_functions: Any = None,
        from_task: Any = None,
        from_agent: Any = None,
        response_model: Any = None,
    ) -> str:
        return self.call(
            messages=messages,
            tools=tools,
            callbacks=callbacks,
            available_functions=available_functions,
            from_task=from_task,
            from_agent=from_agent,
            response_model=response_model,
        )
