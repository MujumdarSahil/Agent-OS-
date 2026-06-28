# AgentOS MCP Demos (Teaching Examples)

This directory contains two minimal, self-contained examples designed to show how an Agent, a Tool, and an MCP server connect in AgentOS.

> [!IMPORTANT]
> These are deliberately minimal teaching examples meant to be read in a few minutes. They are **not** meant for production use.
> For production-ready templates, please refer to [agentos/templates/](file:///c:/Users/mujum/OneDrive/Desktop/Agent%20OS/agentos/templates/).

---

## The Demos

1. **[Demo 1: Custom Local Notes Server](file:///c:/Users/mujum/OneDrive/Desktop/Agent%20OS/examples/mcp_demos/local_notes_server/)**
   - Connects to a custom, local MCP server running via **stdio transport**. Exposes notes storage and editing tools (`add_note`, `list_notes`, `clear_notes`) reading and writing a local `notes.json` file.
   - Works fully offline with zero API keys when Ollama is running locally.

2. **[Demo 2: External Context7 Docs Lookup Server](file:///c:/Users/mujum/OneDrive/Desktop/Agent%20OS/examples/mcp_demos/context7_docs_lookup/)**
   - Connects to Context7 (`https://mcp.context7.com/mcp`), a public remote MCP server for technical documentation lookup, exposing search capabilities as a namespaced tool.
   - Requires internet connectivity.

---

## Security Considerations

> [!WARNING]
> - **Local MCP Servers**: Running local stdio MCP servers executes arbitrary code as a subprocess under your user account on your machine. Ensure you inspect and trust the server codebase before running.
> - **Remote MCP Servers**: Connecting to remote MCP servers over HTTP/SSE sends agent prompts/parameters over the network to a third-party host. Only configure remote URLs that you trust.
