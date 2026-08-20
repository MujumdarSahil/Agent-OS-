"""
Focused test suite for M11.1 Test Harness Semantic Classification.
"""

import os
import unittest
from agentos_swe.models import CodeNode, NodeType, CodeRelationship, RelationType
from agentos_swe.graph.graphify_adapter import GraphifyAdapter
from agentos_swe.semantic.base import ModuleRole
from agentos_swe.semantic.resolver import PythonSemanticResolver
from agentos_swe.semantic.javascript_resolver import JavaScriptSemanticResolver
from agentos_swe.semantic.registry import SemanticProviderRegistry
from agentos_swe.agents.architecture_agent import ArchitectureAgent
from agentos_swe.context import RepositoryContext


class TestTestHarnessSemantics(unittest.TestCase):
    def setUp(self):
        self.py_resolver = PythonSemanticResolver()
        self.js_resolver = JavaScriptSemanticResolver()
        self.registry = SemanticProviderRegistry()

    def test_1_tests_test_example_py(self):
        res = self.py_resolver.analyze_module_role("tests/test_example.py")
        self.assertEqual(res.role, ModuleRole.TEST_HARNESS)
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_2_tests_test_phase1_revised_py(self):
        res = self.py_resolver.analyze_module_role("tests/test_phase1_revised.py")
        self.assertEqual(res.role, ModuleRole.TEST_HARNESS)
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_3_tests_conftest_py(self):
        res = self.py_resolver.analyze_module_role("tests/conftest.py")
        self.assertEqual(res.role, ModuleRole.TEST_HARNESS)
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_4_test_service_py(self):
        res = self.py_resolver.analyze_module_role("test_service.py")
        self.assertEqual(res.role, ModuleRole.TEST_HARNESS)
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_5_service_test_py(self):
        res = self.py_resolver.analyze_module_role("service_test.py")
        self.assertEqual(res.role, ModuleRole.TEST_HARNESS)
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_6_production_service_py(self):
        res = self.py_resolver.analyze_module_role("production/service.py")
        self.assertEqual(res.role, ModuleRole.LIBRARY_MODULE)

    def test_7_main_py_with_main_block(self):
        res = self.py_resolver.analyze_module_role("main.py")
        self.assertEqual(res.role, ModuleRole.ENTRYPOINT_LAUNCHER)

    def test_8_integration_test_dir(self):
        res = self.py_resolver.analyze_module_role("integration/suite.py")
        self.assertEqual(res.role, ModuleRole.TEST_HARNESS)
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_9_unittest_testcase_class(self):
        res = self.py_resolver.analyze_module_role("custom_eval.py")
        self.assertEqual(res.role, ModuleRole.LIBRARY_MODULE)

    def test_10_pytest_fixture_module(self):
        res = self.py_resolver.analyze_module_role("tests/fixtures/db.py")
        self.assertEqual(res.role, ModuleRole.TEST_HARNESS)

    def test_11_production_module_with_many_imports_analyzed(self):
        adapter = GraphifyAdapter()
        adapter._is_built = True
        file_node_id = "file::cadresec/core/engine.py"
        adapter._nodes[file_node_id] = CodeNode(id=file_node_id, name="cadresec/core/engine.py", type=NodeType.FILE, path="cadresec/core/engine.py")
        for i in range(15):
            dep_id = f"file::dep_{i}.py"
            dep_node = CodeNode(id=dep_id, name=f"dep_{i}.py", type=NodeType.FILE, path=f"dep_{i}.py")
            adapter._nodes[dep_id] = dep_node
            adapter._relationships.append(CodeRelationship(source_id=file_node_id, target_id=dep_id, relation_type=RelationType.IMPORTS))

        context = RepositoryContext(
            name="test_repo",
            repository_path=".",
            source_files=["cadresec/core/engine.py"],
            graph_metadata={"node_count": 20, "edge_count": 20},
            graph_provider=adapter,
        )

        agent = ArchitectureAgent()
        findings = agent.investigate(context)
        self.assertEqual(len(findings), 1)
        self.assertIn("High Coupling", findings[0].title)

    def test_12_test_harness_with_15_plus_imports_ignored(self):
        adapter = GraphifyAdapter()
        adapter._is_built = True
        file_node_id = "file::tests/test_phase1_revised.py"
        adapter._nodes[file_node_id] = CodeNode(id=file_node_id, name="tests/test_phase1_revised.py", type=NodeType.FILE, path="tests/test_phase1_revised.py")
        for i in range(15):
            dep_id = f"file::dep_{i}.py"
            dep_node = CodeNode(id=dep_id, name=f"dep_{i}.py", type=NodeType.FILE, path=f"dep_{i}.py")
            adapter._nodes[dep_id] = dep_node
            adapter._relationships.append(CodeRelationship(source_id=file_node_id, target_id=dep_id, relation_type=RelationType.IMPORTS))

        context = RepositoryContext(
            name="test_repo",
            repository_path=".",
            source_files=["tests/test_phase1_revised.py"],
            graph_metadata={"node_count": 20, "edge_count": 20},
            graph_provider=adapter,
        )

        agent = ArchitectureAgent()
        findings = agent.investigate(context)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
