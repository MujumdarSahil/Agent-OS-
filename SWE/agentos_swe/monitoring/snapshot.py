"""
M23 Security Snapshot Engine.

Constructs serializable SecuritySnapshot objects capturing repository posture,
findings count, security score, risk score, and attack path metrics.
"""

import uuid
from typing import Dict, Any, List, Optional
from agentos_swe.monitoring.models import SecuritySnapshot


class SecuritySnapshotEngine:
    """
    Creates and manages SecuritySnapshot objects.
    """

    def create_snapshot(
        self,
        repository_name: str,
        commit_sha: str,
        findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        simulation_results: Optional[Any] = None,
        remediation_plan: Optional[Any] = None,
        security_score: float = 100.0,
        branch: str = "main",
    ) -> SecuritySnapshot:
        """
        Builds a serializable SecuritySnapshot instance.
        """
        findings_list = [f.to_dict() if hasattr(f, "to_dict") else f for f in (findings or [])]
        paths_list = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]

        crit = sum(1 for f in findings_list if str(f.get("severity", "")).upper() == "CRITICAL")
        high = sum(1 for f in findings_list if str(f.get("severity", "")).upper() == "HIGH")
        med = sum(1 for f in findings_list if str(f.get("severity", "")).upper() == "MEDIUM")
        low = sum(1 for f in findings_list if str(f.get("severity", "")).upper() in ("LOW", "INFO"))

        exploitable = [ap for ap in paths_list if ap.get("classification") in ("EXPLOITABLE", "PARTIALLY_MITIGATED")]

        sim_dict = simulation_results.to_dict() if hasattr(simulation_results, "to_dict") else (simulation_results or {})

        return SecuritySnapshot(
            snapshot_id=f"snap_{uuid.uuid4().hex[:8]}",
            repository=repository_name,
            commit_sha=commit_sha,
            branch=branch,
            findings=findings_list,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            security_score=float(security_score),
            risk_score=round(float(100.0 - security_score), 2),
            attack_paths=paths_list,
            exploitable_paths=exploitable,
            simulation_results=sim_dict,
        )
