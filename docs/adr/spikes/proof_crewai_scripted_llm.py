"""Proof: ScriptedLLM for CrewAI 1.15.41 deterministically driving tool execution."""
import os
os.environ["CREWAI_TELEMETRY_OPT_OUT"] = "true"
os.environ["OTEL_SDK_DISABLED"] = "true"

from crewai.llm import BaseLLM
from crewai.agent.core import Agent
from crewai.task import Task
from crewai.tools import tool

class ScriptedLLM(BaseLLM):
    model: str = "mock/scripted"
    responses: list[str] = []
    _idx: int = 0

    def call(self, messages, **kwargs) -> str:
        idx = getattr(self, "_idx", 0)
        resp = self.responses[idx] if idx < len(self.responses) else "Final Answer: completed"
        object.__setattr__(self, "_idx", idx + 1)
        return resp

tool_calls_received = []

@tool("mock_sink")
def mock_sink(recipient: str, message: str) -> str:
    """Send a message to a recipient."""
    tool_calls_received.append((recipient, message))
    return f"Sent to {recipient}"

llm = ScriptedLLM(model="mock", responses=[
    'Thought: Calling tool\nAction: mock_sink\nAction Input: {"recipient": "alice@corp.local", "message": "hello"}',
    'Thought: Got observation\nFinal Answer: Email dispatched successfully'
])

agent = Agent(role="Worker", goal="Send test", backstory="Tester", llm=llm, tools=[mock_sink], verbose=False)
task = Task(description="Send an email to alice", expected_output="Confirmation", agent=agent)
result = agent.execute_task(task)

print("RESULT:", result)
print("TOOL CALLS RECORDED:", tool_calls_received)
assert tool_calls_received == [("alice@corp.local", "hello")], f"Unexpected: {tool_calls_received}"
assert "Email dispatched successfully" in str(result), f"Unexpected result: {result}"
print("PROOF SUCCESSFUL!")
