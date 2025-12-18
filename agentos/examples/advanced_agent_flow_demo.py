#!/usr/bin/env python3
"""
Advanced Agent Flow Demo - AgentOS

Demonstrates an advanced flow where:
- One agent analyzes data and makes a YES/NO decision
- Another agent conditionally writes a detailed report based on that decision
"""

import asyncio
from typing import Dict, Any

from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter
from agentos.modelhub.llm_connector import LLMConnector


async def analysis_tool(task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tool used by the analyzer agent.
    Calls an LLM to analyze AI market trends and decide if a detailed report is needed.
    """
    llm: LLMConnector = task["llm"]
    prompt = (
        "You are a senior AI market analyst.\n\n"
        "Task: Analyze current AI market trends and clearly state whether a detailed report "
        "is needed. Respond in this format:\n\n"
        "ANALYSIS:\n"
        "<a few paragraphs>\n\n"
        "RECOMMENDATION: <YES or NO> for detailed report."
    )

    resp = await llm.call(prompt, agent_id="advanced_flow_analyzer", max_tokens=600, temperature=0.3)
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error", "LLM error")}

    text = resp.get("response", "")
    recommendation = "YES" if "RECOMMENDATION: YES" in text.upper() else "NO"

    return {
        "success": True,
        "outputs": {
            "analysis": text,
            "recommendation": recommendation,
        },
        "cost": {"tokens": 600, "api_calls": 1, "cpu_time": 0.1, "wall_time": 1.0},
    }


async def report_tool(task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tool used by the writer agent.
    If the recommendation is YES, it writes a detailed report; otherwise it skips.
    """
    llm: LLMConnector = task["llm"]
    analysis: str = task["analysis"]
    recommendation: str = task["recommendation"]

    if recommendation.upper() != "YES":
        return {
            "success": True,
            "outputs": {
                "generated": False,
                "reason": "Recommendation was NO, skipping detailed report.",
            },
            "cost": {"tokens": 0, "api_calls": 0, "cpu_time": 0.0, "wall_time": 0.0},
        }

    prompt = (
        "You are an expert report writer.\n\n"
        "Based on the following market analysis, write a comprehensive report about AI market trends.\n\n"
        f"{analysis}\n\n"
        "The report should include an executive summary, key trends, risks, and opportunities."
    )

    resp = await llm.call(prompt, agent_id="advanced_flow_writer", max_tokens=1200, temperature=0.4)
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error", "LLM error")}

    return {
        "success": True,
        "outputs": {
            "generated": True,
            "report": resp.get("response", ""),
        },
        "cost": {"tokens": 1200, "api_calls": 1, "cpu_time": 0.2, "wall_time": 2.0},
    }


async def main():
    # Shared memory (optional, for future extension)
    umb = UMBAdapter(backend="simple")

    # LLM connector (configured for local/simulated model)
    llm = LLMConnector(provider="local", model="ollama/llama3.2:latest")

    # Analyzer agent
    analyzer = Agent(
        name="DataAnalyzer",
        roles=["analyzer"],
        skills=["market_analysis"],
        memory_ref=umb,
    )
    analyzer.register_tool("market_analysis", analysis_tool)

    # Writer agent
    writer = Agent(
        name="ReportWriter",
        roles=["writer"],
        skills=["report_writing"],
        memory_ref=umb,
    )
    writer.register_tool("report_writing", report_tool)

    # Step 1: run analysis
    analysis_task = {
        "id": "analysis-task",
        "type": "market_analysis",
        "description": "Analyze the current AI market trends and decide if a detailed report is needed.",
        "llm": llm,
    }

    print("\n=== Advanced Agent Flow Demo ===")
    print("\n[1] Running analysis task with DataAnalyzer...")
    analysis_result = await analyzer.execute(analysis_task)
    if not analysis_result.get("success"):
        print("Analysis failed:", analysis_result.get("error"))
        return

    recommendation = analysis_result["outputs"]["recommendation"]
    print(f"\nAnalysis recommendation: {recommendation}")

    # Step 2: conditionally run report writing
    print("\n[2] Running conditional report generation with ReportWriter...")
    report_task = {
        "id": "report-task",
        "type": "report_writing",
        "description": "Write a detailed report about AI market trends based on the prior analysis.",
        "llm": llm,
        "analysis": analysis_result["outputs"]["analysis"],
        "recommendation": recommendation,
    }

    report_result = await writer.execute(report_task)
    if not report_result.get("success"):
        print("Report generation failed:", report_result.get("error"))
        return

    outputs = report_result["outputs"]
    if not outputs.get("generated"):
        print("\nDetailed report was skipped:", outputs.get("reason"))
    else:
        print("\n=== Generated Detailed Report (truncated) ===\n")
        print(outputs["report"][:1500])


if __name__ == "__main__":
    asyncio.run(main())


