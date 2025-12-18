#!/usr/bin/env python3
"""
Agent with Tools Demo - AgentOS

This example shows how to:
- Create agents that use simple tools (web search + file write)
- Run a small two-step workflow: research then write a markdown report
"""

import asyncio
from pathlib import Path
from typing import Dict, Any

from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter
from agentos.modelhub.llm_connector import LLMConnector


async def web_search_tool(task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Very simple 'web search' tool.
    In a real system you would call an actual search API here.
    """
    query = task.get("query") or task.get("description", "")

    # Simulated search results
    fake_results = [
        {
            "title": "AI Trends in 2025: Multi-Agent Systems",
            "content": "Multi-agent systems coordinate specialized agents to solve complex tasks.",
        },
        {
            "title": "Edge AI and On-Device Models",
            "content": "On-device inference reduces latency and improves privacy for AI workloads.",
        },
        {
            "title": "AI Safety and Governance",
            "content": "Governance frameworks and guardrails are critical for responsible AI.",
        },
    ]

    # Optionally augment with an LLM summary if connector is provided
    llm: LLMConnector | None = task.get("llm")
    if llm is not None:
        prompt = (
            "You are an expert journalist.\n"
            "Summarize the following AI news items for 2025 in markdown with headings:\n\n"
            f"{fake_results}"
        )
        llm_resp = await llm.call(prompt, agent_id=task.get("agent_id", "news_researcher"))
        if llm_resp.get("success"):
            summary = llm_resp.get("response", "")
        else:
            summary = "Failed to get LLM summary; using raw results instead."
    else:
        summary_lines = []
        for item in fake_results:
            summary_lines.append(f"## {item['title']}\n\n{item['content']}\n")
        summary = "\n".join(summary_lines)

    return {
        "success": True,
        "outputs": {
            "results": fake_results,
            "markdown": summary,
        },
        "cost": {"tokens": 500, "api_calls": 1, "cpu_time": 0.1, "wall_time": 1.0},
    }


async def file_write_tool(task: Dict[str, Any]) -> Dict[str, Any]:
    """Tool that writes markdown content to a local file."""
    file_path = task.get("file_path", "news_report.md")
    content = task.get("content", "")

    path = Path(file_path)
    path.write_text(content, encoding="utf-8")

    return {
        "success": True,
        "outputs": {
            "file_path": str(path),
            "bytes_written": len(content.encode("utf-8")),
        },
        "cost": {"tokens": 0, "api_calls": 0, "cpu_time": 0.01, "wall_time": 0.01},
    }


async def main():
    # Shared memory bus
    umb = UMBAdapter(backend="simple")

    # LLM connector (local/placeholder – can be wired to real backend)
    llm = LLMConnector(provider="local", model="ollama/llama3.2:latest")

    # News research agent
    news_agent = Agent(
        name="NewsResearcher",
        roles=["researcher"],
        skills=["web_search", "analysis"],
        memory_ref=umb,
    )
    news_agent.register_tool("web_search", web_search_tool)

    # File writer agent
    writer_agent = Agent(
        name="FileWriter",
        roles=["writer"],
        skills=["file_write"],
        memory_ref=umb,
    )
    writer_agent.register_tool("file_write", file_write_tool)

    # Step 1: research AI trends
    search_task = {
        "id": "search-ai-trends-2025",
        "type": "web_search",
        "description": "Search for AI trends in 2025 and summarize as markdown.",
        "query": "AI trends in 2025",
        "llm": llm,
        "agent_id": news_agent.id,
    }

    print("\n=== Running news research task ===")
    search_result = await news_agent.execute(search_task)
    if not search_result.get("success"):
        print("Search task failed:", search_result)
        return

    markdown_content = search_result["outputs"]["markdown"]

    # Step 2: write report file
    printing_task = {
        "id": "write-news-report",
        "type": "file_write",
        "description": "Write the researched news to 'news_report.md' in markdown.",
        "file_path": "news_report.md",
        "content": markdown_content,
    }

    print("\n=== Writing news_report.md ===")
    write_result = await writer_agent.execute(printing_task)
    if not write_result.get("success"):
        print("File write task failed:", write_result)
        return

    outputs = write_result["outputs"]
    print(f"\nReport written to: {outputs['file_path']} "
          f"({outputs['bytes_written']} bytes)")


if __name__ == "__main__":
    asyncio.run(main())


