#!/usr/bin/env python3
"""
RAG Demo - AgentOS

Demonstrates Retrieval-Augmented Generation using:
- UMB as a simple document store
- RAGManager to build a retrieval context and augmented prompt
"""

import asyncio
from typing import Dict, Any

from agentos.core.umb_adapter import UMBAdapter
from agentos.core.rag_manager import RAGManager
from agentos.modelhub.llm_connector import LLMConnector


async def seed_knowledge(umb: UMBAdapter) -> None:
    """Seed the UMB with some renewable-energy knowledge documents."""
    docs = [
        "Renewable energy sources include solar, wind, hydroelectric, and geothermal power.",
        "Solar energy is the most abundant energy source on Earth.",
        "Wind energy is one of the fastest-growing renewable energy technologies.",
        "Hydroelectric power generates electricity using flowing water.",
        "Geothermal energy harnesses heat from the Earth's core.",
        "Nuclear energy provides clean, reliable power with zero direct carbon emissions.",
    ]

    for i, text in enumerate(docs):
        entry: Dict[str, Any] = {
            "id": f"doc-{i+1}",
            "text": text,
            "vector": [],  # let UMB compute if backed by a vector DB
            "metadata": {
                "topic": "energy",
                "subtype": "renewable" if "renewable" in text.lower() else "general",
                "source": "rag_demo_seed",
            },
        }
        await umb.upsert(entry)


async def main():
    # Initialize memory and RAG manager
    umb = UMBAdapter(backend="simple")
    rag_manager = RAGManager(umb_adapter=umb)

    # Seed knowledge into UMB
    await seed_knowledge(umb)

    # Question to answer via RAG
    query = "Explain the main types of renewable energy sources and their benefits."

    print("\n=== Running RAG workflow ===")
    rag_result = await rag_manager.run_rag(
        query=query,
        top_k=5,
        scope="squad_shared",
        flow_type="retrieval_first",
    )

    context_docs = rag_result["retrieval_context"].get("context_docs", [])
    print(f"Retrieved {len(context_docs)} documents from UMB.")
    for i, doc in enumerate(context_docs, start=1):
        print(f"\nDocument {i} (score={doc.get('score', 0.0)}):")
        print(doc.get("text", ""))

    # Use LLMConnector to generate an answer from the augmented prompt
    llm = LLMConnector(provider="local", model="ollama/llama3.2:latest")
    augmented_prompt = rag_result["augmented_prompt"]

    print("\n=== Calling LLM with augmented prompt ===")
    llm_resp = await llm.call(
        augmented_prompt,
        agent_id="rag_demo_agent",
        max_tokens=800,
        temperature=0.2,
    )

    if not llm_resp.get("success"):
        print("LLM call failed:", llm_resp.get("error"))
        return

    print("\n=== Final RAG Answer ===")
    print(llm_resp.get("response", ""))


if __name__ == "__main__":
    asyncio.run(main())


