"""
Unit tests for RAG/CAG modules
"""

import pytest
from agentos.core.rag_manager import RAGManager
from agentos.core.cag import CAG


@pytest.mark.asyncio
async def test_rag_manager():
    """Test RAG manager"""
    rag_manager = RAGManager()
    
    context = await rag_manager.create_retrieval_context("test query", top_k=5)
    assert "context_docs" in context
    assert "query" in context


def test_cag():
    """Test CAG"""
    context_docs = [
        {"text": "Document 1", "metadata": {}},
        {"text": "Document 2", "metadata": {}},
    ]
    
    result = CAG.augment_prompt_with_context("test query", context_docs)
    assert "augmented_prompt" in result
    assert result["context_used"] is True

