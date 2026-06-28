import logging
from typing import List
from agentos.core.base import BaseMCPPlugin, BaseTool
from agentos.mcp.plugin_loader import MCPNativeToolWrapper
from crewai.mcp import MCPServerHTTP
from crewai.mcp.tool_resolver import MCPToolResolver

logger = logging.getLogger(__name__)

class Context7DocsPlugin(BaseMCPPlugin):
    """BaseMCPPlugin implementation wrapping the remote Context7 docs search MCP server."""
    
    def register_tools(self) -> List[BaseTool]:
        url = self.manifest.get("mcp_server_url") or "https://mcp.context7.com/mcp"
        server_config = MCPServerHTTP(url=url)
        resolver = MCPToolResolver(agent=None, logger=logger)
        
        # Synchronously resolve remote HTTP/SSE MCP tools
        native_tools = resolver.resolve([server_config])
        
        wrapped_tools = []
        for tool in native_tools:
            # Map tool names to clean names (removing the crewai domain prefix)
            clean_name = tool.name
            if "query_docs" in tool.name:
                clean_name = "query_docs"
            elif "resolve_library_id" in tool.name:
                clean_name = "resolve_context7_library_id"
                
            wrapped = MCPNativeToolWrapper(
                native_tool=tool,
                name=clean_name,
                description=tool.description
            )
            wrapped_tools.append(wrapped)
            
        return wrapped_tools
