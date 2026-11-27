"""Proof: ScriptedLLM for CrewAI 1.15.41 native function calling."""
import os
os.environ["CREWAI_TELEMETRY_OPT_OUT"] = "true"
os.environ["OTEL_SDK_DISABLED"] = "true"

from crewai.agent.core import Agent
from crewai.llm import BaseLLM
from crewai.task import Task
from crewai.tools import tool

class NativeScriptedLLM(BaseLLM):
    model: str = "mock/native-scripted"
    responses: list = []
    _idx: int = 0

    def supports_function_calling(self) -> bool:
        return True

    def call(self, messages, **kwargs):
        idx = getattr(self, "_idx", 0)
        resp = self.responses[idx] if idx < len(self.responses) else "Finished"
        object.__setattr__(self, "_idx", idx + 1)
        return resp

tool_calls_recorded = []

@tool("mock_sink")
def mock_sink(recipient: str, message: str) -> str:
    """Send a message to a recipient."""
    tool_calls_recorded.append((recipient, message))
    return f"Sent to {recipient}"

llm = NativeScriptedLLM(
    model="mock",
    responses=[
        [{"id": "call_1", "name": "mock_sink", "arguments": {"recipient": "alice@corp.local", "message": "hello"}}],
        "Email dispatched via native function call"
    ]
)

agent = Agent(role="Worker", goal="Send native", backstory="Tester", llm=llm, tools=[mock_sink], verbose=False)
task = Task(description="Send email to alice", expected_output="Confirmation", agent=agent)
result = agent.execute_task(task)

print("RESULT:", result)
print("TOOL CALLS RECORDED:", tool_calls_recorded)
assert tool_calls_recorded == [("alice@corp.local", "hello")], f"Expected call not found: {tool_calls_recorded}"
assert "Email dispatched via native function call" in str(result)
print("NATIVE FUNCTION CALLING PROOF SUCCESSFUL!")
