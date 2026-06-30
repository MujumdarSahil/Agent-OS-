# AgentOS External Plugin Demo

This standalone Python package demonstrates how to extend AgentOS with custom Agent, Tool, and MCPPlugin types from third-party packages using Python entry points.

## Installation

Install this package in editable mode within the AgentOS virtual environment:

```powershell
.\venv\Scripts\pip install -e .\examples\external_plugin_demo
```

## Verification

Once installed, check that the new components are recognized by AgentOS:

```powershell
# Show registered agent types (DemoCustomAgent should appear)
.\venv\Scripts\agentos list-agent-types

# Show registered tool types (DemoCustomTool should appear)
.\venv\Scripts\agentos list-tool-types
```
