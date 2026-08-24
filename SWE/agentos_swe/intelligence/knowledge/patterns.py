"""
M21 Security Pattern Learner.

Extracts recurring security patterns, attack path patterns, and cross-repository patterns
from historical scan telemetry and execution outcomes.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.intelligence.knowledge.models import (
    SecurityPattern,
    AttackPathPattern,
    CrossRepositorySecurityPattern,
)
from agentos_swe.intelligence.knowledge.fingerprint import SecurityPatternFingerprinter


class SecurityPatternLearner:
    """
    Learns recurring vulnerability structures and cross-repository patterns.
    """

    def __init__(self):
        self.fingerprinter = SecurityPatternFingerprinter()

    def extract_pattern(
        self,
        finding: Dict[str, Any],
        repository_name: str,
    ) -> SecurityPattern:
        """
        Extracts a SecurityPattern instance from a finding.
        """
        rc = str(finding.get("root_cause") or finding.get("category") or "UNKNOWN").upper()
        fam = finding.get("vulnerability_family") or rc
        src = str(finding.get("source_type") or finding.get("source") or "INPUT").upper()
        snk = str(finding.get("sink_type") or finding.get("sink") or "EXECUTION").upper()
        fw = str(finding.get("framework") or "PYTHON").upper()

        pid = self.fingerprinter.compute_pattern_fingerprint(fam, rc, src, snk, fw)

        return SecurityPattern(
            pattern_id=f"pat_{pid}",
            vulnerability_family=fam,
            root_cause=rc,
            source_type=src,
            sink_type=snk,
            framework=fw,
            confidence="HIGH",
            recurrence_count=1,
            repositories_seen=[repository_name],
        )

    def extract_attack_path_pattern(
        self,
        attack_path: Dict[str, Any],
        repository_name: str,
    ) -> AttackPathPattern:
        """
        Extracts an AttackPathPattern instance from an AttackPath model.
        """
        ep_type = str(attack_path.get("entrypoint_type") or "INTERNET").upper()
        auth_state = str(attack_path.get("auth_status") or "UNAUTHENTICATED").upper()
        src_type = str(attack_path.get("source_type") or "HTTP").upper()
        snk_type = str(attack_path.get("sink_type") or "SUBPROCESS_SHELL").upper()
        rc = str(attack_path.get("root_cause") or "COMMAND_INJECTION").upper()

        pid = self.fingerprinter.compute_attack_path_fingerprint(ep_type, src_type, snk_type, rc)

        return AttackPathPattern(
            pattern_id=f"app_{pid}",
            entrypoint_type=ep_type,
            authentication_state=auth_state,
            source_type=src_type,
            sink_type=snk_type,
            severity=str(attack_path.get("severity") or "CRITICAL").upper(),
            historical_frequency=1,
            repositories_seen=[repository_name],
        )

    def learn_cross_repository_patterns(
        self,
        records: List[Dict[str, Any]],
    ) -> List[CrossRepositorySecurityPattern]:
        """
        Aggregates recurring patterns across multiple repositories.
        """
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in records:
            rc = str(r.get("root_cause", "UNKNOWN")).upper()
            groups.setdefault(rc, []).append(r)

        cross_patterns: List[CrossRepositorySecurityPattern] = []
        for rc, group in groups.items():
            repos = list(set(r.get("repository", "Repo") for r in group))
            if len(repos) >= 1:
                tot = len(group)
                succ = sum(1 for r in group if r.get("validation_result") == "SUCCESSFUL_REPAIR")
                regs = sum(1 for r in group if r.get("regression_result") == "INTRODUCED_REGRESSION")
                cross_patterns.append(
                    CrossRepositorySecurityPattern(
                        pattern_id=f"cross_{rc.lower()}",
                        vulnerability_family=rc,
                        root_cause=rc,
                        frequency=tot,
                        repositories=repos,
                        common_source=group[0].get("source_pattern", "HTTP_INPUT"),
                        common_sink=group[0].get("sink_pattern", "SUBPROCESS_SHELL"),
                        common_remediation=group[0].get("remediation_strategy", "Defensive sanitization"),
                        successful_remediation_rate=round(succ / tot, 2) if tot > 0 else 1.0,
                        regression_rate=round(regs / tot, 2) if tot > 0 else 0.0,
                    )
                )
        return cross_patterns
