"""
M27 Repository Operational State Manager.

Maintains in-memory repository security operational state aggregated across M14-M26.
"""

from typing import Dict, Any, Optional, List

from agentos_swe.operations.controlplane.models import (
    RepositoryOperationalState,
    OperationalStatus,
    OperationalMode,
    SecurityPostureSnapshot,
    ActiveSecurityIssue,
)


def _safe_float(val: Any, default: float = 0.5) -> float:
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        v = val.upper()
        if v == "CRITICAL":
            return 9.0
        if v == "HIGH":
            return 7.5
        if v == "MEDIUM":
            return 5.0
        if v == "LOW":
            return 2.5
        try:
            return float(val)
        except ValueError:
            return default
    return default


class RepositoryOperationalStateManager:
    """
    Manages operational repository security states per repository.
    """

    _registry: Dict[str, RepositoryOperationalState] = {}

    @classmethod
    def get_or_create_state(
        cls, repository_name: str, commit_sha: str = "HEAD"
    ) -> RepositoryOperationalState:
        """Retrieves active operational state or instantiates a clean state."""
        if repository_name not in cls._registry:
            cls._registry[repository_name] = RepositoryOperationalState(
                repository_name=repository_name,
                commit_sha=commit_sha,
                operational_status=OperationalStatus.UNKNOWN,
                operational_mode=OperationalMode.IDLE,
            )
        else:
            cls._registry[repository_name].commit_sha = commit_sha
        return cls._registry[repository_name]

    @classmethod
    def update_state_from_pipeline(
        cls,
        repository_name: str,
        commit_sha: str,
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        decision_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        drift_result: Optional[Any] = None,
    ) -> RepositoryOperationalState:
        """
        Updates in-memory operational state with intelligence from M14-M26.
        """
        state = cls.get_or_create_state(repository_name, commit_sha)

        findings = prioritized_findings or verified_findings or []
        findings_dict = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

        SAFE_RC = {"DICT_LOOKUP", "INTENTIONAL_FALLBACK", "TEST_HARNESS_DIAGNOSTIC", "FORMATTING_ONLY", "COMMENT_ONLY"}
        active_f_dict = [
            f for f in findings_dict
            if not f.get("sanitized") and not f.get("is_safe") and f.get("root_cause") not in SAFE_RC
        ]

        crit_count = sum(1 for f in active_f_dict if str(f.get("severity")).upper() == "CRITICAL")
        high_count = sum(1 for f in active_f_dict if str(f.get("severity")).upper() == "HIGH")
        med_count = sum(1 for f in active_f_dict if str(f.get("severity")).upper() == "MEDIUM")
        low_count = sum(1 for f in active_f_dict if str(f.get("severity")).upper() == "LOW")

        p0_count = sum(1 for f in active_f_dict if str(f.get("priority")).upper() == "P0")
        p1_count = sum(1 for f in active_f_dict if str(f.get("priority")).upper() == "P1")
        p2_count = sum(1 for f in active_f_dict if str(f.get("priority")).upper() == "P2")

        paths_dict = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]
        active_paths = len(paths_dict)
        exposed_paths = sum(
            1 for ap in paths_dict
            if ap.get("is_internet_exposed") or "INTERNET" in str(ap.get("entrypoint_type", "")).upper()
        )

        state.snapshot = SecurityPostureSnapshot(
            security_score=decision_result.get("remediation_plan", {}).get("current_security_score", 100) if hasattr(decision_result, "get") else 100,
            risk_score=round((crit_count * 25.0) + (high_count * 10.0), 2),
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            p0_count=p0_count,
            p1_count=p1_count,
            p2_count=p2_count,
            active_attack_paths_count=active_paths,
            internet_exposed_paths_count=exposed_paths,
        )

        # Build active security issues list
        active_issues: List[ActiveSecurityIssue] = []
        for idx, f in enumerate(findings_dict):
            if f.get("root_cause") in SAFE_RC or f.get("sanitized"):
                continue

            active_issues.append(
                ActiveSecurityIssue(
                    issue_id=f.get("finding_id") or f.get("id") or f"iss_{idx+1}",
                    root_cause=f.get("root_cause") or "UNKNOWN",
                    severity=(f.get("severity") or "MEDIUM").upper(),
                    priority=(f.get("priority") or "P2").upper(),
                    file=f.get("file") or "N/A",
                    exploitability=_safe_float(f.get("exploitability"), 0.5),
                    exposure=f.get("exposure", "INTERNAL"),
                    recurrence_classification=f.get("recurrence_classification", "FIRST_SEEN"),
                    risk_multiplier=_safe_float(f.get("risk_multiplier"), 1.0),
                    governance_decision=f.get("recommended_action", "MONITOR"),
                )
            )
        state.active_issues = active_issues
        return state
