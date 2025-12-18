#!/usr/bin/env python3
"""
Agentic Chunking Demo - AgentOS

This demo showcases:
- Semantic / layout / fixed chunking using the built-in Chunker
- How different content types and chunk sizes affect chunk statistics
- A simple retrieval-style query over chunked content
"""

import asyncio
from typing import List, Dict, Any

from agentos.core.chunkers import Chunker


# Reuse the same sample documents from your original demo (shortened slightly for brevity)
TECHNICAL_PAPER = \"\"\"Introduction

Artificial intelligence has undergone remarkable transformations in recent years...
Deep Learning Fundamentals

Neural networks, particularly deep learning architectures, have demonstrated unprecedented capabilities...

Transformer Architecture Revolution

The transformer architecture introduced the attention mechanism as a fundamental building block...

Large Language Models

GPT models demonstrate the power of unsupervised pre-training on vast text corpora...
\"\"\"

BUSINESS_REPORT = \"\"\"Executive Summary

Q3 2024 Financial Performance Review

Our company achieved exceptional results in Q3 2024, demonstrating strong growth across all key performance indicators...

Revenue Analysis

Product sales comprised 65% of total revenue, generating significant year-over-year growth...
\"\"\"

USER_MANUAL = \"\"\"Chapter 1: Getting Started

Welcome to the Advanced Document Management System (ADMS) 3.0...

Installation Process

Step 1: Download the installation package from our official website...

Chapter 2: Basic Operations

ADMS 3.0 supports multiple file formats including PDF, Word, and image formats...
\"\"\"


def summarize_chunks(chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
    lengths = [c["length"] for c in chunks] or [0]
    return {
        "count": len(chunks),
        "avg_length": sum(lengths) // max(len(lengths), 1),
        "min_length": min(lengths),
        "max_length": max(lengths),
    }


def print_sample_chunks(chunks: List[Dict[str, Any]], label: str, limit: int = 3) -> None:
    print(f"\n🔍 Sample chunks from {label}:")
    for i, chunk in enumerate(chunks[:limit]):
        text = chunk["text"]
        print(f"\n  Chunk {i+1} ({len(text)} chars, strategy={chunk['strategy']}):")
        print("  " + text[:150].replace("\n", " ") + "...")


def simple_keyword_search(chunks: List[Dict[str, Any]], query: str, limit: int = 2) -> List[Dict[str, Any]]:
    """Very basic keyword search over chunk texts."""
    q = query.lower()
    results = []
    for c in chunks:
        if q in c["text"].lower():
            results.append(c)
            if len(results) >= limit:
                break
    return results


async def main():
    print("🤖 Agentic-Style Chunking Demo - AgentOS")
    print("=" * 60)

    # 1) Technical paper with semantic chunking
    print("\n1️⃣  Technical Paper → Semantic Chunking")
    tech_chunks = Chunker.chunk_text(
        text=TECHNICAL_PAPER,
        chunk_size=800,
        chunk_overlap=200,
        strategy="semantic",
    )
    stats = summarize_chunks(tech_chunks)
    print(f"📊 Chunks: {stats['count']}, avg length: {stats['avg_length']} chars")
    print_sample_chunks(tech_chunks, "technical paper (semantic)")

    # 2) Business report with layout-aware chunking
    print("\n2️⃣  Business Report → Layout-Aware Chunking")
    biz_chunks = Chunker.chunk_text(
        text=BUSINESS_REPORT,
        chunk_size=600,
        chunk_overlap=0,
        strategy="layout",
    )
    stats = summarize_chunks(biz_chunks)
    print(f"📊 Chunks: {stats['count']}, avg length: {stats['avg_length']} chars")
    print_sample_chunks(biz_chunks, "business report (layout)")

    # 3) User manual with fixed chunking
    print("\n3️⃣  User Manual → Fixed-Size Chunking")
    manual_chunks = Chunker.chunk_text(
        text=USER_MANUAL,
        chunk_size=500,
        chunk_overlap=100,
        strategy="fixed",
    )
    stats = summarize_chunks(manual_chunks)
    print(f"📊 Chunks: {stats['count']}, avg length: {stats['avg_length']} chars")
    print_sample_chunks(manual_chunks, "user manual (fixed)")

    # 4) Simple retrieval-style queries over chunks
    print("\n4️⃣  Simple Retrieval over Chunked Content")
    queries = [
        "transformer architecture",
        "Q3 2024 revenue",
        "automatic backups",
    ]
    corpora = [
        ("Technical paper", tech_chunks),
        ("Business report", biz_chunks),
        ("User manual", manual_chunks),
    ]

    for query in queries:
        print(f"\n🔎 Query: {query}")
        for label, chunks in corpora:
            hits = simple_keyword_search(chunks, query, limit=1)
            if hits:
                print(f"  ✅ Found match in {label}: {hits[0]['text'][:100].replace('\n', ' ')}...")
            else:
                print(f"  ❌ No direct match in {label}")

    print("\n✅ Agentic-style chunking demo complete (using AgentOS Chunker).")


if __name__ == "__main__":
    asyncio.run(main())


