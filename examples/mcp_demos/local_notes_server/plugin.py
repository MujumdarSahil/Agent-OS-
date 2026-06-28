import os
import asyncio
from typing import Any, List
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from agentos.core.base import BaseMCPPlugin, BaseTool

class NotesTool(BaseTool):
    """A wrapper tool that invokes the local Notes MCP server via stdio transport on-demand."""
    
    def __init__(self, name: str, description: str, tool_name: str):
        super().__init__(name=name, description=description)
        self.tool_name = tool_name
        self.server_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.py")

    def run(self, **kwargs: Any) -> str:
        async def _run_async():
            server_params = StdioServerParameters(
                command="python",
                args=[self.server_py],
            )
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool(self.tool_name, arguments=kwargs)
                    text = ""
                    for content in result.content:
                        if hasattr(content, "text"):
                            text += content.text
                    return text
        try:
            return asyncio.run(_run_async())
        except Exception as e:
            return f"Error executing notes tool: {e}"

class LocalNotesPlugin(BaseMCPPlugin):
    """BaseMCPPlugin implementation for the custom local notes server."""
    
    def register_tools(self) -> List[BaseTool]:
        return [
            NotesTool(
                name="add_note",
                description="Add a new text note to the persistent local notes store. Requires 'text' parameter.",
                tool_name="add_note"
            ),
            NotesTool(
                name="list_notes",
                description="Retrieve all notes currently in the persistent local notes store.",
                tool_name="list_notes"
            ),
            NotesTool(
                name="clear_notes",
                description="Clear all notes from the persistent local notes store.",
                tool_name="clear_notes"
            ),
        ]
