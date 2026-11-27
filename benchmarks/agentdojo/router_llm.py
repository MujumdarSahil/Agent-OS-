"""4.1b D6: an AgentDojo agent whose model is the AgentOS router (fallback chain, cooldowns, 3.2 run limits/budgets).

The router runs the tool loop itself (``AgentOSRouterLLM.call(messages, tools, available_functions)``); every tool
call goes to the executor (AgentOS proxy or plain), and the calls are written back as AgentDojo messages so
AgentDojo's trace-based checks see them. Keys come only from environment variables (the router's default chain).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import (ChatAssistantMessage, ChatMessage, ChatToolResultMessage, get_text_content_as_str,
                             text_content_block_from_string)

from benchmarks.agentdojo.defense import AgentOSExecutor, PlainExecutor


def _openai_messages(messages: Sequence[ChatMessage]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        content = m.get("content")
        text = get_text_content_as_str(content) if isinstance(content, list) else (content or "")
        if m["role"] in ("system", "user"):
            out.append({"role": m["role"], "content": text})
        elif m["role"] == "assistant":
            out.append({"role": "assistant", "content": text})
    return out


def tool_schemas(runtime: FunctionsRuntime) -> list[dict[str, Any]]:
    return [{"type": "function", "function": {"name": f.name, "description": f.description,
                                              "parameters": f.parameters.model_json_schema()}}
            for f in runtime.functions.values()]


class RouterAgent(BasePipelineElement):
    """``llm_factory()`` returns a fresh ``AgentOSRouterLLM`` (with its own RunGuard) for each task."""

    def __init__(self, llm_factory: Callable[[], Any], executor: PlainExecutor | AgentOSExecutor) -> None:
        self.llm_factory, self.executor = llm_factory, executor

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}
              ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        trace: list[tuple[FunctionCall, str, str | None]] = []

        def make(name: str) -> Callable[..., str]:
            def fn(**kwargs: Any) -> str:
                tc = FunctionCall(function=name, args=dict(kwargs), id=f"call_{len(trace)}")
                text, error = self.executor.call(name, dict(kwargs))
                trace.append((tc, text, error))
                return text if error is None else f"Error: {error}"
            return fn

        llm = self.llm_factory()
        answer = llm.call(_openai_messages(messages), tools=tool_schemas(runtime),
                          available_functions={n: make(n) for n in runtime.functions})
        new: list[ChatMessage] = []
        for tc, text, error in trace:
            new.append(ChatAssistantMessage(role="assistant", tool_calls=[tc],
                                            content=[text_content_block_from_string("")]))
            new.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                             tool_call_id=tc.id, tool_call=tc, error=error))
        new.append(ChatAssistantMessage(role="assistant", tool_calls=None,
                                        content=[text_content_block_from_string(str(answer or ""))]))
        return query, runtime, env, [*messages, *new], extra_args
