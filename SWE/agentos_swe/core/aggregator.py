"""
FindingAggregator - Minimal finding deduplication and normalization engine for AgentOS-SWE (M2).
Preserves evidence provenance and merges multi-agent findings cleanly.
"""

import logging
from typing import List, Dict, Any, Set

from agentos_swe.core.models import Finding, Evidence

logger = logging.getLogger(__name__)


class FindingAggregator:
    """
    Deduplicates and normalizes findings collected across specialized investigation agents.
    """

    def aggregate(self, findings: List[Finding]) -> List[Finding]:
        """
        Aggregate and deduplicate raw agent findings into a clean Finding set.
        """
        if not findings:
            return []

        grouped: Dict[str, Finding] = {}

        for finding in findings:
            key = self._generate_dedup_key(finding)

            if key in grouped:
                # Merge duplicate finding into existing finding
                existing = grouped[key]
                self._merge_findings(existing, finding)
            else:
                grouped[key] = finding

        return list(grouped.values())

    def _generate_dedup_key(self, finding: Finding) -> str:
        """Construct deterministic deduplication key."""
        category = (finding.category or "general").lower()
        file_path = (finding.file or "").lower()
        line_start = finding.line_range[0] if finding.line_range else 0
        title_words = "".join(e for e in (finding.title or "").lower() if e.isalnum())
        return f"{category}::{file_path}::{line_start}::{title_words[:30]}"

    def _merge_findings(self, target: Finding, incoming: Finding) -> None:
        """Merge incoming finding details, evidence, and graph context into target."""
        # 1. Merge Evidence (avoiding duplicate evidence descriptions)
        existing_descs = {e.description for e in target.evidence}
        for ev in incoming.evidence:
            if ev.description not in existing_descs:
                target.evidence.append(ev)
                existing_descs.add(ev.description)

        # 2. Update confidence to max
        target.confidence = max(target.confidence, incoming.confidence)

        # 3. Merge Graph Context
        if incoming.graph_context:
            for k, v in incoming.graph_context.items():
                if k not in target.graph_context:
                    target.graph_context[k] = v

        # 4. Severity escalation if higher
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity_order.get(incoming.severity, 0) > severity_order.get(target.severity, 0):
            target.severity = incoming.severity
