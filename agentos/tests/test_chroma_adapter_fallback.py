"""Tests for ChromaAdapter and UMBAdapter fallback when chromadb is unavailable."""

import logging
import sys
import pytest

from agentos.core.retrieval_adapters.chroma_adapter import ChromaAdapter
from agentos.core.umb_adapter import SimpleVectorStore, UMBAdapter


def test_chroma_adapter_fallback_when_missing(monkeypatch, caplog):
    """When chromadb is not importable, ChromaAdapter logs a warning and returns stub responses."""
    # Simulate missing chromadb module
    monkeypatch.setitem(sys.modules, "chromadb", None)

    adapter = ChromaAdapter(collection_name="test_collection")

    with caplog.at_level(logging.WARNING):
        # 1. index_documents returns structured error
        idx_res = adapter.index_documents([{"id": "doc1", "text": "sample text", "vector": [0.1, 0.2]}])
        assert idx_res["success"] is False
        assert idx_res["error"] == "ChromaDB not available"

        # 2. search returns empty list
        search_res = adapter.search([0.1, 0.2, 0.3], top_k=3)
        assert search_res == []

        # 3. delete returns False
        del_res = adapter.delete("doc1")
        assert del_res is False

        # 4. Fallback warning was logged
        assert any(
            "ChromaDB not available, using stub implementation" in record.message
            for record in caplog.records
        )


def test_umb_adapter_chroma_backend_fallback():
    """UMBAdapter requested with backend='chroma' warns and falls back to SimpleVectorStore."""
    with pytest.warns(UserWarning, match="Requested UMB backend 'chroma' is not implemented"):
        umb = UMBAdapter(backend="chroma")
    assert umb.backend_type == "chroma"
    assert isinstance(umb.store, SimpleVectorStore)
