"""
Targeted tests for GraphifyAdapter.
"""

import os
import tempfile
import pytest
from agentos_swe.graph.graphify_adapter import GraphifyAdapter
from agentos_swe.exceptions import GraphBuildError, GraphProviderError
from agentos_swe.models import NodeType, RelationType


def test_graphify_adapter_unbuilt_error():
    adapter = GraphifyAdapter()
    with pytest.raises(GraphProviderError):
        adapter.get_node("nonexistent")


def test_graphify_adapter_invalid_path():
    adapter = GraphifyAdapter()
    with pytest.raises(GraphBuildError):
        adapter.build("/path/does/not/exist/98765")


def test_graphify_adapter_build_and_queries(tmp_path):
    # Create sample repository structure
    repo_dir = tmp_path / "sample_repo"
    repo_dir.mkdir()

    mod_a = repo_dir / "module_a.py"
    mod_a.write_text(
        "import module_b\n"
        "class ComponentA:\n"
        "    def run(self):\n"
        "        pass\n"
    )

    mod_b = repo_dir / "module_b.py"
    mod_b.write_text(
        "def helper():\n"
        "    pass\n"
    )

    adapter = GraphifyAdapter()
    meta = adapter.build(str(repo_dir))

    assert meta["provider"] == "graphify"
    assert meta["node_count"] > 0

    # Query nodes
    results = adapter.query("module_a")
    assert len(results) >= 1
    node_a = results[0]
    assert node_a.source == "graphify"

    # Check dependencies
    node_id = f"file::module_a.py"
    node = adapter.get_node(node_id)
    assert node is not None
    assert node.source == "graphify"

    deps = adapter.get_dependencies(node_id)
    assert any(d.id == "file::module_b.py" for d in deps)

    dependents = adapter.get_dependents("file::module_b.py")
    assert any(d.id == node_id for d in dependents)


def test_graphify_adapter_provider_failure_handling(tmp_path):
    adapter = GraphifyAdapter(use_ast_fallback=False)
    # Without fallback and without graphify CLI installed, building should raise GraphBuildError
    with pytest.raises(GraphBuildError):
        adapter.build(str(tmp_path))

