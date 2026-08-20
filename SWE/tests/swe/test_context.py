"""
Targeted tests for RepositoryContext and build_repository_context.
"""

import os
import pytest
from agentos_swe.context import RepositoryContext, build_repository_context
from agentos_swe.exceptions import RepositoryContextError


def test_repository_context_uninitialized_error():
    ctx = RepositoryContext(
        name="test",
        repository_path="/path/test",
    )
    with pytest.raises(RepositoryContextError):
        ctx.query_graph("test")


def test_build_repository_context_end_to_end(tmp_path):
    repo_dir = tmp_path / "my_project"
    repo_dir.mkdir()

    (repo_dir / "app.py").write_text("import utils\n\ndef main():\n    utils.run()\n")
    (repo_dir / "utils.py").write_text("def run():\n    pass\n")

    context = build_repository_context(str(repo_dir))

    assert context.name == "my_project"
    assert context.repository_path == str(repo_dir)
    assert "Python" in context.languages
    assert context.graph_metadata["provider"] == "graphify"
    assert context.graph_metadata["node_count"] > 0

    # Query graph via context
    nodes = context.query_graph("app")
    assert len(nodes) >= 1

    app_node = context.get_node("file::app.py")
    assert app_node is not None
    assert app_node.source == "graphify"

    deps = context.get_dependencies("file::app.py")
    assert any(d.id == "file::utils.py" for d in deps)

    # Test serialization
    d = context.to_dict()
    assert d["name"] == "my_project"
    assert d["graph_metadata"]["provider"] == "graphify"
