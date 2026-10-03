"""
M16 Attack Path Correlator & Deduplicator.

Correlates findings sharing entrypoints or propagation chains into single attack paths and deduplicates using SHA-256 fingerprints.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.intelligence.attackpath.models import AttackPath
from agentos_swe.intelligence.attackpath.path_builder import AttackPathBuilder
from agentos_swe.intelligence.attackpath.attack_scorer import AttackPathScorer


class AttackPathCorrelator:
    """
    Attack Path Correlator grouping and deduplicating findings into unified attack paths.
    """

    def __init__(self):
        self.path_builder = AttackPathBuilder()
        self.scorer = AttackPathScorer()

    def correlate_attack_paths(
        self,
        findings: List[Dict[str, Any]],
        taint_findings: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Any] = None,
    ) -> List[AttackPath]:
        """
        Builds, scores, and deduplicates attack paths across findings.
        """
        taint_findings = taint_findings or []
        seen_fingerprints = set()
        deduped_paths: List[AttackPath] = []

        for f in findings:
            fid = f.get("finding_id") or f.get("id")
            matching_taint = next((t for t in taint_findings if t.get("finding_id") == fid), None)

            path = self.path_builder.build_attack_path(finding=f, taint_finding=matching_taint, context=context)
            self.scorer.score_attack_path(path)

            if path.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(path.fingerprint)
                deduped_paths.append(path)

        # Sort by risk_score descending
        deduped_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return deduped_paths
