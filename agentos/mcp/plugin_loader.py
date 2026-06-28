"""
MCP Plugin Loader - Dynamic discovery and loading of Model Context Protocol plugins
"""

import os
import sys
import yaml
import importlib
import logging
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field
import asyncio

from agentos.core.base import BaseTool, ToolRegistry, BaseMCPPlugin
from crewai.mcp import MCPServerHTTP
from crewai.mcp.tool_resolver import MCPToolResolver

logger = logging.getLogger(__name__)

class MCPPluginManifest(BaseModel):
    """Pydantic model for plugin manifest verification"""
    name: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    author: str = Field(..., min_length=1)
    permissions: List[str] = Field(default_factory=list)
    entrypoint: Optional[str] = None
    mcp_server_url: Optional[str] = None


class MCPNativeToolWrapper(BaseTool):
    """
    Adapter wrapping a native CrewAI tool resolved from an external MCP server,
    conforming to the AgentOS BaseTool interface.
    """
    
    def __init__(self, native_tool: Any, name: str, description: str):
        super().__init__(name=name, description=description)
        self._native_tool = native_tool

    def run(self, **kwargs: Any) -> Any:
        # Run using native tool execution mechanism
        if hasattr(self._native_tool, "run"):
            return self._native_tool.run(**kwargs)
        elif hasattr(self._native_tool, "_run"):
            return self._native_tool._run(**kwargs)
        elif callable(self._native_tool):
            return self._native_tool(**kwargs)
        raise ValueError(f"Wrapped tool {self.name} is not runnable.")

    def to_crewai_tool(self) -> Any:
        return self._native_tool


def discover_plugins(project_path: str) -> List[Tuple[MCPPluginManifest, str]]:
    """
    Scans <project>/mcp_plugins/*/manifest.yaml (or manifest.yml),
    validates the manifest against the schema, and returns a list of (manifest, path) tuples.
    """
    plugins_dir = os.path.join(project_path, "mcp_plugins")
    discovered = []
    
    if not os.path.exists(plugins_dir):
        logger.debug(f"No mcp_plugins directory found at {plugins_dir}")
        return discovered

    for item in os.listdir(plugins_dir):
        item_path = os.path.join(plugins_dir, item)
        if not os.path.isdir(item_path):
            continue
            
        manifest_path = None
        for name in ["manifest.yaml", "manifest.yml"]:
            test_path = os.path.join(item_path, name)
            if os.path.exists(test_path):
                manifest_path = test_path
                break
                
        if not manifest_path:
            continue
            
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            manifest = MCPPluginManifest(**data)
            discovered.append((manifest, manifest_path))
            logger.debug(f"Discovered plugin {manifest.name} at {manifest_path}")
        except Exception as e:
            logger.error(f"Failed to load plugin manifest at {manifest_path}: {e}")
            
    return discovered


def load_plugin(manifest: MCPPluginManifest, manifest_path: str, tool_registry: ToolRegistry) -> List[str]:
    """
    Dynamically loads tools from a plugin manifest and registers them under namespaced keys.
    """
    registered_keys = []
    
    # 1. Load tools from external MCP server if URL is provided
    if manifest.mcp_server_url:
        logger.info(f"Connecting to remote MCP server for plugin '{manifest.name}' at {manifest.mcp_server_url}")
        
        # Security check: if connecting to remote server, manifest MUST declare 'network' permission
        if "network" not in manifest.permissions:
            raise ValueError(f"Plugin '{manifest.name}' attempts remote MCP connection but does not declare 'network' permission.")
            
        logger.warning(
            f"WARNING: Plugin '{manifest.name}' requires 'network' permission. "
            "Note that AgentOS permissions are declarative-only and do not enforce "
            "network-level or system-level sandboxing at runtime."
        )
            
        try:
            resolver = MCPToolResolver()
            server_config = MCPServerHTTP(url=manifest.mcp_server_url)
            # Resolve tools synchronously using resolver
            native_tools = resolver.resolve([server_config])
            
            for tool in native_tools:
                namespaced_name = f"{manifest.name}.{tool.name}"
                wrapped = MCPNativeToolWrapper(
                    native_tool=tool,
                    name=namespaced_name,
                    description=tool.description
                )
                tool_registry.register_instance(namespaced_name, wrapped)
                registered_keys.append(namespaced_name)
                logger.info(f"Registered external MCP tool: {namespaced_name}")
                
        except Exception as e:
            logger.error(f"Failed to resolve external MCP tools for '{manifest.name}': {e}")
            
    # 2. Load custom python-defined tools if entrypoint is provided
    if manifest.entrypoint:
        plugin_dir = os.path.dirname(os.path.abspath(manifest_path))
        if plugin_dir not in sys.path:
            sys.path.insert(0, plugin_dir)
            
        try:
            module_name, class_name = manifest.entrypoint.rsplit(".", 1)
            module = importlib.import_module(module_name)
            plugin_class = getattr(module, class_name)
            
            if not issubclass(plugin_class, BaseMCPPlugin):
                raise TypeError(f"Plugin entrypoint '{manifest.entrypoint}' must subclass BaseMCPPlugin.")
                
            plugin_instance = plugin_class(name=manifest.name, manifest=manifest.model_dump())
            tools = plugin_instance.register_tools()
            
            for tool in tools:
                # Update tool name to namespaced key
                original_name = tool.name
                namespaced_name = f"{manifest.name}.{original_name}"
                tool.name = namespaced_name
                
                tool_registry.register_instance(namespaced_name, tool)
                registered_keys.append(namespaced_name)
                logger.info(f"Registered custom plugin tool: {namespaced_name}")
                
        except Exception as e:
            logger.error(f"Failed to load custom plugin entrypoint '{manifest.entrypoint}': {e}")
            
    return registered_keys
