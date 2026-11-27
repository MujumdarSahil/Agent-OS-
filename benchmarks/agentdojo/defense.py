"""4.1b D2/D3/D5: AgentDojo tool calls through the REAL AgentOS tool proxy.

- ``AgentDojoCatalog``: every AgentDojo function becomes an external ``ToolEntry`` (server ``agentdojo``) with the
  NodeSpec from ``specs.py``; unknown tools fail closed.
- ``_DojoManager``: what the proxy calls to execute an external tool; it runs AgentDojo's own runtime on the task's
  environment (so AgentDojo's utility / security checks see the real effects).
- ``AgentOSExecutor``: one ``AgentOSToolProxy`` per task. The user task is the trusted input label; each tool output
  joins the context label as untrusted (the proxy's own rule); sink rules decide. A refusal goes back to the model as
  a tool error (D5).
- ``PlainExecutor``: no defense (AgentDojo's plain tool execution).
- ``ExecutorElement`` / ``DefendedPipeline`` / ``ReplayAgent``: AgentDojo pipeline glue (``ReplayAgent`` replays the
  tasks' ground truth: no model; used by the CI smoke test).
"""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, ChatToolResultMessage, text_content_block_from_string

from agentos.flows.labels import Label
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import AgentOSToolProxy
from agentos.flows.rules import PinnedArgumentOverrideError, SinkRuleViolationError
from agentos.flows.tool_catalog import ToolCatalog, ToolEntry, ToolLookupError
from benchmarks.agentdojo.specs import node_spec

SERVER = "agentdojo"


class AgentDojoCatalog(ToolCatalog):
    def __init__(self, runtime: FunctionsRuntime) -> None:
        super().__init__()
        self._dojo: dict[str, ToolEntry] = {}
        for name, fn in runtime.functions.items():
            schema = fn.parameters.model_json_schema()
            self._dojo[name] = ToolEntry(
                name=name, spec=node_spec(name, schema), is_mcp=True, server=SERVER, tool=name,
                server_tool_name=name, sha256="", admin_description=fn.description,
                server_description=fn.description, input_schema=schema)

    def resolve(self, name: str) -> ToolEntry:
        entry = self._dojo.get(name)
        if entry is None:
            raise ToolLookupError(name, "unknown")
        return entry

    def try_resolve(self, name: str) -> ToolEntry | None:
        return self._dojo.get(name)

    def server(self, name: str) -> Any:
        return {"name": SERVER} if name == SERVER else None


@dataclass
class _Result:
    status: str
    text: str
    duration_ms: float = 0.0
    output_bytes: int = 0
    truncated: bool = False


class _DojoManager:
    def __init__(self) -> None:
        self.env: Env | None = None
        self.runtime: FunctionsRuntime | None = None

    async def call_tool(self, record: Any, name: str, sha256: str, args: dict[str, Any]) -> _Result:
        assert self.runtime is not None
        result, error = self.runtime.run_function(self.env, name, dict(args))
        text = tool_result_to_str(result) if error is None else str(error)
        return _Result("ok" if error is None else "error", text, output_bytes=len(text))


class PlainExecutor:
    """No defense: AgentDojo's plain tool execution."""

    name = "none"

    def __init__(self) -> None:
        self.blocked = 0
        self.calls = 0
        self.env: Env | None = None
        self.runtime: FunctionsRuntime | None = None

    def reset(self, env: Env, runtime: FunctionsRuntime) -> None:
        self.env, self.runtime = env, runtime

    def call(self, name: str, args: dict[str, Any]) -> tuple[str, str | None]:
        assert self.runtime is not None
        self.calls += 1
        if name not in self.runtime.functions:
            return "", f"Invalid tool {name} provided."
        result, error = self.runtime.run_function(self.env, name, dict(args))
        return tool_result_to_str(result), error

    def close(self) -> None:
        pass


class AgentOSExecutor:
    """AgentDojo tools behind the AgentOS tool proxy (labels + sink rules), one proxy (= one label context) per task."""

    name = "agentos"

    def __init__(self, policy: SecurityPolicy | None = None) -> None:
        from agentos.storage import open_storage

        self.policy = policy or SecurityPolicy()
        self.loop = asyncio.new_event_loop()
        self._tmp = tempfile.TemporaryDirectory(prefix="agentos-agentdojo-", ignore_cleanup_errors=True)
        proj = Path(self._tmp.name) / "p"
        proj.mkdir()
        (proj / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        self.storage = self.loop.run_until_complete(
            open_storage(str(proj), backend="file", vault_path=str(Path(self._tmp.name) / "vault.json")))
        self.manager = _DojoManager()
        self.proxy: AgentOSToolProxy | None = None
        self.blocked = 0
        self.calls = 0
        self.blocked_tools: dict[str, int] = {}
        self._task = 0

    def reset(self, env: Env, runtime: FunctionsRuntime) -> None:
        self._task += 1
        self.manager.env, self.manager.runtime = env, runtime
        self.proxy = AgentOSToolProxy(
            f"agentdojo-{self._task}", "agent", self.storage, self.policy,
            agent_input_label=Label.trusted(sources={"user_task"}), loop=self.loop,
            tool_catalog=AgentDojoCatalog(runtime), mcp_manager=self.manager)

    def call(self, name: str, args: dict[str, Any]) -> tuple[str, str | None]:
        assert self.proxy is not None, "reset() first"
        self.calls += 1
        try:
            text = self.loop.run_until_complete(self.proxy.invoke("agent", name, dict(args)))
        except (SinkRuleViolationError, PinnedArgumentOverrideError) as err:
            self.blocked += 1
            self.blocked_tools[name] = self.blocked_tools.get(name, 0) + 1
            return "", f"Blocked by AgentOS: {err}"
        except ValueError as err:  # unknown tool and other fail-closed refusals
            return "", f"AgentOS refused the call: {err}"
        if text.startswith("Tool error: "):
            return "", text[len("Tool error: "):]
        return text, None

    def close(self) -> None:
        try:
            self.loop.run_until_complete(self.storage.close())
        finally:
            self.loop.close()
            self._tmp.cleanup()


class ExecutorElement(BasePipelineElement):
    """Drop-in for AgentDojo's ToolsExecutor: runs the last assistant message's tool calls through ``executor``."""

    def __init__(self, executor: PlainExecutor | AgentOSExecutor) -> None:
        self.executor = executor

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}
              ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1].get("tool_calls"):
            return query, runtime, env, messages, extra_args
        results: list[ChatMessage] = []
        for tc in messages[-1]["tool_calls"]:
            text, error = self.executor.call(tc.function, dict(tc.args))
            results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                                 tool_call_id=tc.id, tool_call=tc, error=error))
        return query, runtime, env, [*messages, *results], extra_args


class DefendedPipeline(BasePipelineElement):
    """Resets the executor (fresh AgentOS label context) at the start of every task, then runs ``inner``."""

    def __init__(self, inner: BasePipelineElement, executor: PlainExecutor | AgentOSExecutor, name: str) -> None:
        self.inner, self.executor, self.name = inner, executor, name

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}
              ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        self.executor.reset(env, runtime)
        return self.inner.query(query, runtime, env, messages, extra_args)


class ReplayAgent(BasePipelineElement):
    """No model: an agent that obeys everything. It replays the user task's ground truth, then the injection task's
    ground truth (as a fully injected agent would), each call through ``element`` (with or without AgentOS)."""

    def __init__(self, user_task: Any, injection_task: Any | None, element: ExecutorElement) -> None:
        self.user_task, self.injection_task, self.element = user_task, injection_task, element

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}
              ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        msgs = list(messages)
        for task in [t for t in (self.user_task, self.injection_task) if t is not None]:
            for tc in task.ground_truth(env):
                msgs.append(ChatAssistantMessage(role="assistant", tool_calls=[tc],
                                                 content=[text_content_block_from_string("")]))
                _, _, _, msgs, _ = self.element.query(query, runtime, env, msgs, extra_args)
                msgs = list(msgs)
        msgs.append(ChatAssistantMessage(role="assistant", tool_calls=None, content=[
            text_content_block_from_string(self.user_task.GROUND_TRUTH_OUTPUT)]))
        return query, runtime, env, msgs, extra_args
