"""
Targeted tests for FindingAggregator.
"""

from agentos_swe.core.aggregator import FindingAggregator
from agentos_swe.core.models import Finding, Evidence, EvidenceSource, EvidenceKind


def test_aggregator_deduplication():
    aggregator = FindingAggregator()

    ev1 = Evidence(source=EvidenceSource.STATIC_ANALYSIS, description="AST bare except")
    f1 = Finding(
        category="bug",
        severity="low",
        title="Swallowed Exception",
        description="Bare except on line 10",
        file="app.py",
        line_range=(10, 10),
        evidence=[ev1],
        confidence=0.8,
    )

    ev2 = Evidence(source=EvidenceSource.LLM_REASONING, description="LLM verified bare except")
    f2 = Finding(
        category="bug",
        severity="medium",
        title="Swallowed Exception",
        description="Bare except on line 10",
        file="app.py",
        line_range=(10, 10),
        evidence=[ev2],
        confidence=0.9,
    )

    results = aggregator.aggregate([f1, f2])

    assert len(results) == 1
    merged = results[0]
    assert merged.confidence == 0.9
    assert merged.severity == "medium"
    assert len(merged.evidence) == 2
    sources = {e.source for e in merged.evidence}
    assert EvidenceSource.STATIC_ANALYSIS in sources
    assert EvidenceSource.LLM_REASONING in sources


def test_aggregator_distinct_findings():
    aggregator = FindingAggregator()

    f1 = Finding(category="bug", title="Bug 1", file="a.py", line_range=(1, 1))
    f2 = Finding(category="security", title="Sec 1", file="b.py", line_range=(5, 5))

    results = aggregator.aggregate([f1, f2])
    assert len(results) == 2
