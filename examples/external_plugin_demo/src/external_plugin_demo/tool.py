from agentos.core.base import BaseTool
from typing import Any

class DemoCustomTool(BaseTool):
    name: str = "demo_custom_tool"
    description: str = "A custom tool that demonstrates external package capabilities."

    def run(self, **kwargs: Any) -> str:
        param = kwargs.get("param", "default")
        return f"DemoCustomTool executed with parameter: {param}"
