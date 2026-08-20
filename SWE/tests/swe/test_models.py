"""
Targeted tests for M0 Domain Models.
"""

import pytest
from agentos_swe.models import (
    NodeType,
    RelationType,
    FindingStatus,
    EvidenceSource,
    EvidenceKind,
    CodeNode,
    CodeRelationship,
    Evidence,
    Finding,
)


def test_code_node_serialization():
    node = CodeNode(
        id="file::agentos/core/agent.py",
        name="agent",
        type=NodeType.MODULE,
        path="agentos/core/agent.py",
        line_range=(1, 225),
        symbol="agent",
        source="graphify",
    )
    d = node.to_dict()
    assert d["id"] == "file::agentos/core/agent.py"
    assert d["type"] == "module"
    assert d["source"] == "graphify"
    assert d["line_range"] == (1, 225)

    reconstructed = CodeNode.from_dict(d)
    assert reconstructed.id == node.id
    assert reconstructed.type == NodeType.MODULE
    assert reconstructed.line_range == (1, 225)


def test_code_relationship_serialization():
    rel = CodeRelationship(
        source_id="file::agentos/core/agent.py",
        target_id="file::agentos/llm/llm_client.py",
        relation_type=RelationType.IMPORTS,
        source="graphify",
    )
    d = rel.to_dict()
    assert d["relation_type"] == "imports"
    assert d["source"] == "graphify"

    reconstructed = CodeRelationship.from_dict(d)
    assert reconstructed.relation_type == RelationType.IMPORTS
    assert reconstructed.source_id == rel.source_id


def test_evidence_model():
    ev = Evidence(
        source=EvidenceSource.CODE_GRAPH,
        kind=EvidenceKind.OBSERVED,
        description="Module imports llm_client",
        confidence=0.95,
    )
    d = ev.to_dict()
    assert d["source"] == "CODE_GRAPH"
    assert d["kind"] == "OBSERVED"

    reconstructed = Evidence.from_dict(d)
    assert reconstructed.source == EvidenceSource.CODE_GRAPH
    assert reconstructed.kind == EvidenceKind.OBSERVED
    assert reconstructed.confidence == 0.95


def test_finding_lifecycle_model():
    ev = Evidence(
        source=EvidenceSource.STATIC_ANALYSIS,
        kind=EvidenceKind.OBSERVED,
        description="Unused variable detected",
    )
    finding = Finding(
        category="security",
        severity="high",
        title="SQL Injection Risk",
        description="Raw string formatting in query",
        repository="Agent-OS",
        file="agentos/core/checkpoint.py",
        line_range=(50, 55),
        evidence=[ev],
        status=FindingStatus.DISCOVERED,
    )
    assert finding.status == FindingStatus.DISCOVERED
    assert len(finding.evidence) == 1

    d = finding.to_dict()
    assert d["status"] == "DISCOVERED"
    assert d["evidence"][0]["source"] == "STATIC_ANALYSIS"

    reconstructed = Finding.from_dict(d)
    assert reconstructed.status == FindingStatus.DISCOVERED
    assert len(reconstructed.evidence) == 1
    assert reconstructed.evidence[0].source == EvidenceSource.STATIC_ANALYSIS
