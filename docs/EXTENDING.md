# Extending AgentOS

AgentOS is built to be modular and extensible. You can register custom **Agents**, **Tools**, and **MCP Plugins** either directly in a project or from a completely separate, third-party Python package using Python entry points.

---

## 1. Project-Local Extension (Existing Way)

To define a custom component inside your AgentOS project without creating a separate package:

### Custom Tools
Place a Python file in your project's `tools/` directory (e.g. `tools/my_tool.py`):
```python
from agentos.core.base import BaseTool

class MyTool(BaseTool):
    name: str = "my_tool"
    description: str = "A simple local tool."

    def run(self, **kwargs) -> str:
        query = kwargs.get("query", "")
        return f"Local tool ran with query: {query}"
```

### Custom MCP Plugins
Place a plugin folder in your project's `mcp_plugins/` directory containing:
1. `manifest.yaml` specifying `name`, `version`, `author`, `permissions`, and `entrypoint`.
2. `plugin.py` implementing a subclass of `BaseMCPPlugin` and overriding `register_tools()`.

---

## 2. Third-Party Package Extension (New Entry Points Way)

To define custom components in a completely separate Python package and distribute them, use AgentOS entry point groups.

### Step 1: Define Entry Points in `pyproject.toml`
In your custom package's `pyproject.toml`, register your classes under these entry point groups:

```toml
[project.entry-points."agentos.agents"]
MyCustomAgent = "my_package.agent:MyCustomAgent"

[project.entry-points."agentos.tools"]
MyCustomTool = "my_package.tool:MyCustomTool"

[project.entry-points."agentos.mcp_plugins"]
MyMCPPlugin = "my_package.plugin:MyMCPPlugin"
```

### Step 2: Implement Component Subclasses

#### Custom Agent Class
```python
from typing import Any, Optional, List
from agentos.core.agent import Agent
from agentos.llm.llm_client import LLMClient
from agentos.core.base import BaseTool, BaseMemory

class MyCustomAgent(Agent):
    def __init__(
        self,
        name: str = "CustomAgent",
        role: str = "Custom Specialist",
        goal: str = "Perform custom actions",
        backstory: str = "",
        llm_client: Optional[LLMClient] = None,
        tools: Optional[List[BaseTool]] = None,
        memory: Optional[BaseMemory] = None,
        **kwargs: Any
    ):
        if not backstory:
            backstory = "A dynamically registered agent type."
        super().__init__(
            name=name,
            role=role,
            goal=goal,
            backstory=backstory,
            llm_client=llm_client,
            tools=tools,
            memory=memory,
            **kwargs
        )
```

#### Custom Tool Class
```python
from agentos.core.base import BaseTool
from typing import Any

class MyCustomTool(BaseTool):
    name: str = "my_custom_tool"
    description: str = "A custom tool defined in an external package."

    def run(self, **kwargs: Any) -> str:
        return "Custom external tool executed successfully."
```

#### Custom MCP Plugin Class
```python
from agentos.core.base import BaseMCPPlugin, BaseTool
from typing import List

class MyMCPPlugin(BaseMCPPlugin):
    name = "my_mcp_plugin"
    manifest = {
        "name": "my_mcp_plugin",
        "version": "1.0.0",
        "author": "Developer",
        "permissions": [],
        "entrypoint": "my_package.plugin:MyMCPPlugin"
    }

    def register_tools(self) -> List[BaseTool]:
        return [MyCustomTool()]
```

### Step 3: Install & Discover
Install the external package in editable mode:
```powershell
pip install -e /path/to/my_package
```

Verify that AgentOS registers the custom types:
```powershell
agentos list-agent-types
agentos list-tool-types
```

Use the custom type inside any project `agents/*.yaml`:
```yaml
name: "MyCustomAgentInstance"
role: "Custom Specialist"
goal: "Perform actions"
type: "MyCustomAgent"
```
