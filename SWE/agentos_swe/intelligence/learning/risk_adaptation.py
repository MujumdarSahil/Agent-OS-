"""
M25 Adaptive Risk Engine.

Adapts finding risk scores and priority dynamically based on historical recurrence,
reopen history, attack-path involvement, and remediation efficacy.
"""

from typing import List, Dict, Any, Optional

from agentos_swe.intelligence.learning.models import (
    AdaptiveRiskSignal,
    FindingRecurrence,
    RecurrenceClassification,
    SecurityPattern,
    SecurityPatternType,
)


class AdaptiveRiskEngine:
    """
    Computes deterministic adaptive risk multipliers and signals per finding.
    """

    def compute_adaptive_signals(
        self,
        current_findings: List[Dict[str, Any]],
        recurrence_insights: List[FindingRecurrence],
        patterns: List[SecurityPattern],
    ) -> List[AdaptiveRiskSignal]:
        """
        Computes AdaptiveRiskSignal entries for all current findings based on learned history.
        """
        signals: List[AdaptiveRiskSignal] = []

        rec_map: Dict[str, FindingRecurrence] = {r.fingerprint: r for r in recurrence_insights}
        pattern_types = {p.pattern_type for p in patterns}

        for idx, f in enumerate(current_findings):
            fid = str(f.get("finding_id") or f.get("id") or f"f_{idx+1}")
            fp = (
                f.get("fingerprint")
                or f.get("finding_id")
                or f.get("id")
                or f"{f.get('root_cause', 'RC')}::{f.get('file', '')}::{f.get('line', 0)}"
            )
            rc = f.get("root_cause") or f.get("category") or "UNKNOWN"
            raw_score = f.get("risk_score") or f.get("exploitability") or 5.0
            try:
                base_score = float(raw_score)
            except (ValueError, TypeError):
                sev_map = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
                base_score = sev_map.get(str(raw_score).upper(), 5.0)

            multiplier = 1.0
            reasons: List[str] = []

            # 1. Recurrence classification multiplier
            rec = rec_map.get(fp)
            if rec:
                if rec.classification == RecurrenceClassification.CHRONIC:
                    multiplier += 0.50
                    reasons.append("Chronic recurrence pattern (+0.50x risk)")
                elif rec.classification == RecurrenceClassification.PERSISTENT:
                    multiplier += 0.35
                    reasons.append("Persistent un-remediated finding (+0.35x risk)")
                elif rec.classification == RecurrenceClassification.RECURRING:
                    multiplier += 0.25
                    reasons.append("Recurring vulnerability across scans (+0.25x risk)")
                elif rec.classification == RecurrenceClassification.OCCASIONAL:
                    multiplier += 0.10
                    reasons.append("Occasional vulnerability recurrence (+0.10x risk)")

                if rec.reopen_count > 0:
                    multiplier += 0.30
                    reasons.append(f"Reopened {rec.reopen_count} time(s) after prior fix (+0.30x risk)")

            # 2. Failed remediation multiplier
            if SecurityPatternType.FAILED_REMEDIATION in pattern_types:
                if any(p.pattern_type == SecurityPatternType.FAILED_REMEDIATION and fp in p.metadata.get("failed_fingerprints", []) for p in patterns):
                    multiplier += 0.20
                    reasons.append("Prior remediation attempt failed validation (+0.20x risk)")

            # 3. Repeated attack path multiplier
            if SecurityPatternType.REPEATED_ATTACK_PATH in pattern_types or f.get("in_attack_path") or f.get("attack_path"):
                multiplier += 0.25
                reasons.append("Involved in repeated exploitability attack path (+0.25x risk)")

            # Cap maximum risk multiplier to 2.5x for safety and sanity
            multiplier = min(round(multiplier, 2), 2.5)

            adapted_score = round(base_score * multiplier, 2)
            priority_boost = multiplier >= 1.30 or (rec and rec.classification in [RecurrenceClassification.CHRONIC, RecurrenceClassification.PERSISTENT])

            if not reasons:
                reasons.append("Baseline risk score unchanged (no historical escalation factors)")

            signals.append(
                AdaptiveRiskSignal(
                    finding_id=fid,
                    fingerprint=fp,
                    root_cause=rc,
                    base_risk_score=base_score,
                    adapted_risk_score=adapted_score,
                    risk_multiplier=multiplier,
                    adaptation_reasons=reasons,
                    priority_boost=priority_boost,
                )
            )

        return signals
