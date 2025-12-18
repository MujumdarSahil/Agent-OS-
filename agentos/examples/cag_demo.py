#!/usr/bin/env python3
"""
CAG Demo - AgentOS

Demonstrates Context-Augmented Generation (CAG) by:
- Creating a small set of contextual documents
- Using CAG to build an augmented prompt
- Calling LLMConnector with that augmented prompt
"""

import asyncio
from typing import Dict, Any, List

from agentos.core.cag import CAG
from agentos.modelhub.llm_connector import LLMConnector


def build_ai_development_context() -> List[Dict[str, Any]]:
    """Create a small in-memory context corpus about AI development."""
    docs: List[Dict[str, Any]] = [
        {
            "text": "AI development has accelerated rapidly since 2020 with transformer-based architectures.",
            "metadata": {"context_type": "historical", "topic": "AI_development"},
        },
        {
            "text": "Large language models like GPT and Claude have revolutionized natural language processing.",
            "metadata": {"context_type": "technical", "topic": "AI_development"},
        },
        {
            "text": "Recent advances include multi-agent systems, tool-use, and retrieval-augmented generation (RAG).",
            "metadata": {"context_type": "recent", "topic": "AI_development"},
        },
    ]
    return docs


async def main():
    # Build context docs in memory
    context_docs = build_ai_development_context()

    # User prompt that should be answered using the above context
    prompt = (
        "Write a summary of AI development trends, considering historical context and recent advances."
    )

    print("\n=== Building CAG augmented prompt ===")
    augmented = CAG.augment_prompt_with_context(
        prompt=prompt,
        context_docs=context_docs,
        max_context_length=2000,
    )

    augmented_prompt = augmented["augmented_prompt"]
    print(f"Context documents used: {augmented['context_docs_count']}")

    # LLM connector (local/simulated backend)
    llm = LLMConnector(provider="local", model="ollama/llama3.2:latest")

    print("\n=== Calling LLM with context-augmented prompt ===")
    llm_resp = await llm.call(
        augmented_prompt,
        agent_id="cag_demo_agent",
        max_tokens=600,
        temperature=0.3,
    )

    if not llm_resp.get("success"):
        print("LLM call failed:", llm_resp.get("error"))
        return

    print("\n=== Final CAG Answer ===")
    print(llm_resp.get("response", ""))


if __name__ == "__main__":
    asyncio.run(main())


