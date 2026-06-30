from agentos.core.base import BaseMCPPlugin, BaseTool
from typing import List, Any

class DemoMCPTool(BaseTool):
    name: str = "demo_mcp_tool"
    description: str = "A tool provided by DemoMCPPlugin."

    def run(self, **kwargs: Any) -> str:
        return "DemoMCPTool response"

class DemoMCPPlugin(BaseMCPPlugin):
    name = "demo_mcp_plugin"
    manifest = {
        "name": "demo_mcp_plugin",
        "version": "0.1.0",
        "author": "Demo Author",
        "permissions": [],
        "entrypoint": "external_plugin_demo.plugin:DemoMCPPlugin"
    }

    def register_tools(self) -> List[BaseTool]:
        return [DemoMCPTool()]
