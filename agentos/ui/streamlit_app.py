"""
AgentOS Streamlit UI

Python-only dashboard to:
- Create and inspect agents
- Register logical tools
- Create and execute simple tasks
- Inspect available MCP servers
"""

import asyncio
import os
import sys
from typing import Dict, Any

import streamlit as st

# Ensure project root is on PYTHONPATH so `agentos` can be imported
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter
from agentos.dmsg.registry import MCPRegistry


def get_state():
    """Initialize and return Streamlit session state containers."""
    if "umb" not in st.session_state:
        st.session_state.umb = UMBAdapter(backend="simple")
    if "agents" not in st.session_state:
        st.session_state.agents: Dict[str, Agent] = {}
    if "tasks" not in st.session_state:
        st.session_state.tasks: Dict[str, Dict[str, Any]] = {}
    if "tools" not in st.session_state:
        st.session_state.tools: Dict[str, Dict[str, Any]] = {}
    return st.session_state


def create_agent_form(state):
    st.subheader("Create Agent")
    with st.form("create_agent"):
        name = st.text_input("Name", value="Agent")
        roles = st.text_input("Roles (comma-separated)", value="")
        skills = st.text_input("Skills (comma-separated)", value="")
        submitted = st.form_submit_button("Create Agent")
    if submitted:
        role_list = [r.strip() for r in roles.split(",") if r.strip()]
        skill_list = [s.strip() for s in skills.split(",") if s.strip()]
        agent = Agent(
            name=name,
            roles=role_list,
            skills=skill_list,
            memory_ref=state.umb,
        )
        state.agents[agent.id] = agent
        st.success(f"Created agent {agent.name} (id={agent.id})")


def register_tool_form(state):
    st.subheader("Register Logical Tool")
    with st.form("register_tool"):
        name = st.text_input("Tool name", value="")
        description = st.text_area("Description", value="")
        submitted = st.form_submit_button("Register Tool")
    if submitted:
        if not name.strip():
            st.error("Tool name is required.")
        else:
            state.tools[name] = {"name": name, "description": description}
            st.success(f"Registered tool '{name}'.")

    st.caption(
        "Bind these logical tool names to real callables in Python using "
        "`Agent.register_tool(name, func)`."
    )


def create_task_form(state):
    st.subheader("Create & Execute Task")
    with st.form("create_task"):
        description = st.text_area("Task description", value="", height=100)
        agent_options = {"<none>": None}
        for aid, agent in state.agents.items():
            agent_options[f"{agent.name} ({aid[:8]})"] = aid
        agent_label = st.selectbox("Assign to agent (optional)", list(agent_options.keys()))
        submitted = st.form_submit_button("Create Task")

    if submitted:
        if not description.strip():
            st.error("Description is required.")
            return

        task_id = f"task-{len(state.tasks) + 1}"
        agent_id = agent_options[agent_label]
        task: Dict[str, Any] = {
            "id": task_id,
            "description": description,
            "agent_id": agent_id,
            "status": "created",
            "result": None,
        }

        if agent_id and agent_id in state.agents:
            agent = state.agents[agent_id]

            async def _run():
                return await agent.execute(
                    {
                        "id": task_id,
                        "description": description,
                        "type": "generic",
                    }
                )

            result = asyncio.run(_run())
            task["status"] = "executed" if result.get("success") else "error"
            task["result"] = result

            if result.get("success"):
                st.success("Task executed successfully.")
                st.json(result)
            else:
                st.error(f"Task execution failed: {result.get('error')}")
        else:
            st.info("Task created but not executed (no agent selected).")

        state.tasks[task_id] = task


def list_agents(state):
    st.subheader("Agents")
    if not state.agents:
        st.caption("No agents created yet.")
        return
    for aid, agent in state.agents.items():
        with st.expander(f"{agent.name} ({aid})", expanded=False):
            st.write("Roles:", ", ".join(agent.roles) or "-")
            st.write("Skills:", ", ".join(agent.skills) or "-")
            st.json(agent.to_dict())


def list_tasks(state):
    st.subheader("Tasks")
    if not state.tasks:
        st.caption("No tasks created yet.")
        return
    for tid, task in state.tasks.items():
        with st.expander(f"{tid} – {task['status']}", expanded=False):
            st.write("Description:", task["description"])
            st.write("Agent ID:", task.get("agent_id") or "<none>")
            st.json(task.get("result") or {})


def list_tools(state):
    st.subheader("Registered Tools (logical)")
    if not state.tools:
        st.caption("No tools registered yet.")
        return
    for name, tool in state.tools.items():
        with st.expander(name, expanded=False):
            st.write(tool.get("description") or "(no description)")


def list_mcps():
    st.subheader("MCP Servers (from registry)")
    registry = MCPRegistry()
    if not registry.mcp_nodes:
        st.caption("No MCPs registered (or MCP registry not initialized).")
        return
    for mcp_id, mcp_node in registry.mcp_nodes.items():
        with st.expander(f"{mcp_id}", expanded=False):
            st.write("Name:", getattr(mcp_node, "name", mcp_id))
            st.write("Domain:", getattr(mcp_node, "domain", "unknown"))
            skills = getattr(mcp_node, "skills", [])
            st.write("Skills:", len(skills))
            for skill in skills:
                st.markdown(f"- **{skill.name}** – {skill.description}")


def main():
    st.set_page_config(page_title="AgentOS Streamlit UI", layout="wide")
    st.title("AgentOS – Streamlit UI (Python only)")
    st.caption(
        "Create agents, register tools, create/execute tasks, and inspect MCP servers "
        "without any Node/React stack."
    )

    state = get_state()

    tab_create, tab_lists = st.tabs(["Create / Execute", "Inspect State"])

    with tab_create:
        col1, col2 = st.columns(2)
        with col1:
            create_agent_form(state)
            register_tool_form(state)
        with col2:
            create_task_form(state)

    with tab_lists:
        col_a, col_b = st.columns(2)
        with col_a:
            list_agents(state)
            list_tools(state)
        with col_b:
            list_tasks(state)
            list_mcps()


if __name__ == "__main__":
    main()


