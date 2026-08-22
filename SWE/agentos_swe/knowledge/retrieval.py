"""
M21 Deterministic Security Knowledge Retriever.

Performs explainable similarity lookups for security findings, attack paths,
and historical remediation outcomes without mandatory LLM or vector DB dependencies.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.knowledge.models import SecurityKnowledgeRecord
from agentos_swe.knowledge.store import SecurityKnowledgeStore
from agentos_swe.knowledge.fingerprint import SecurityPatternFingerprinter


class SecurityKnowledgeRetriever:
    """
    Retrieves similar historical security knowledge records.
    """

    def __init__(self, store: Optional[SecurityKnowledgeStore] = None):
        self.store = store or SecurityKnowledgeStore()
        self.fingerprinter = SecurityPatternFingerprinter()

    def retrieve_similar_records(
        self,
        finding: Dict[str, Any],
        limit: int = 5,
    ) -> List[SecurityKnowledgeRecord]:
        """
        Retrieves top similar historical knowledge records for a finding.
        """
        rc = str(finding.get("root_cause") or finding.get("category") or "").upper()
        if not rc:
            return []

        candidates = self.store.get_by_root_cause(rc)
        if not candidates:
            # Fallback search by broader family
            fam = str(finding.get("vulnerability_family") or "").upper()
            candidates = self.store.search(fam or rc)

        # Rank candidates by relevance score
        ranked: List[tuple[float, SecurityKnowledgeRecord]] = []
        for rec in candidates:
            score = 0.0
            if rec.root_cause.upper() == rc:
                score += 50.0
            if rec.source_pattern.upper() == str(finding.get("source_type", "")).upper():
                score += 20.0
            if rec.sink_pattern.upper() == str(finding.get("sink_type", "")).upper():
                score += 20.0
            if rec.confidence > 0:
                score += rec.confidence * 10.0
            ranked.append((score, rec))

        ranked.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in ranked[:limit]]
