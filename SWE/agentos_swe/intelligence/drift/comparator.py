"""
M26 Security Postural Comparator.

Performs deterministic before/after differential analysis comparing repository baseline
and current scan snapshots across findings, fingerprints, severity, exposure, attack paths,
trust boundaries, and security scores.
"""

from typing import List, Dict, Any, Optional, Set
from agentos_swe.intelligence.drift.models import DriftComparisonResult


class SecurityPosturalComparator:
    """
    Compares baseline security posture with current scan state.
    """

    def compare_postures(
        self,
        current_findings: List[Dict[str, Any]],
        baseline_findings: Optional[List[Dict[str, Any]]] = None,
        current_attack_paths: Optional[List[Dict[str, Any]]] = None,
        baseline_attack_paths: Optional[List[Dict[str, Any]]] = None,
        current_score: int = 100,
        baseline_score: int = 100,
        current_scan_id: str = "current_scan",
        baseline_scan_id: Optional[str] = "baseline_scan",
        current_commit: str = "HEAD",
        baseline_commit: Optional[str] = "HEAD~1",
    ) -> DriftComparisonResult:
        """
        Executes fine-grained differential analysis between baseline and current security posture.
        """
        base_f = baseline_findings or []
        curr_f = current_findings or []

        # Index findings by fingerprint
        base_map: Dict[str, Dict[str, Any]] = {self._fp(f): f for f in base_f}
        curr_map: Dict[str, Dict[str, Any]] = {self._fp(f): f for f in curr_f}

        base_fps = set(base_map.keys())
        curr_fps = set(curr_map.keys())

        # Categorize finding deltas
        new_fps = curr_fps - base_fps
        fixed_fps = base_fps - curr_fps
        persisted_fps = curr_fps & base_fps

        new_findings = [curr_map[fp] for fp in new_fps]
        fixed_findings = [base_map[fp] for fp in fixed_fps]

        # Reopened findings check
        reopened_findings = [
            curr_map[fp] for fp in curr_fps
            if curr_map[fp].get("reopened") or curr_map[fp].get("reopened_count", 0) > 0
        ]

        # Attack path deltas
        curr_paths = current_attack_paths or []
        base_paths = baseline_attack_paths or []

        curr_path_keys = {self._path_key(ap) for ap in curr_paths}
        base_path_keys = {self._path_key(ap) for ap in base_paths}

        new_path_keys = curr_path_keys - base_path_keys
        removed_path_keys = base_path_keys - curr_path_keys

        new_attack_paths = [ap for ap in curr_paths if self._path_key(ap) in new_path_keys]
        removed_attack_paths = [ap for ap in base_paths if self._path_key(ap) in removed_path_keys]

        # Exposure & Trust boundary changes
        exposure_changes: List[Dict[str, Any]] = []
        trust_boundary_changes: List[Dict[str, Any]] = []

        for fp in persisted_fps:
            b_f = base_map[fp]
            c_f = curr_map[fp]

            b_exp = str(b_f.get("exposure") or b_f.get("exposure_level") or "INTERNAL").upper()
            c_exp = str(c_f.get("exposure") or c_f.get("exposure_level") or "INTERNAL").upper()

            if b_exp != c_exp:
                exposure_changes.append({
                    "fingerprint": fp,
                    "finding_id": c_f.get("finding_id") or c_f.get("id"),
                    "file": c_f.get("file"),
                    "previous_exposure": b_exp,
                    "current_exposure": c_exp,
                })

            b_tb = bool(b_f.get("trust_boundary") or b_f.get("intersects_trust_boundary"))
            c_tb = bool(c_f.get("trust_boundary") or c_f.get("intersects_trust_boundary"))

            if b_tb != c_tb:
                trust_boundary_changes.append({
                    "fingerprint": fp,
                    "finding_id": c_f.get("finding_id") or c_f.get("id"),
                    "file": c_f.get("file"),
                    "previous_trust_boundary": b_tb,
                    "current_trust_boundary": c_tb,
                })

        score_delta = current_score - baseline_score

        return DriftComparisonResult(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            baseline_commit=baseline_commit,
            current_commit=current_commit,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            reopened_findings=reopened_findings,
            new_attack_paths=new_attack_paths,
            removed_attack_paths=removed_attack_paths,
            exposure_changes=exposure_changes,
            trust_boundary_changes=trust_boundary_changes,
            score_before=baseline_score,
            score_after=current_security_score if 'current_security_score' in locals() else current_score,
            score_delta=score_delta,
        )

    def _fp(self, finding: Dict[str, Any]) -> str:
        """Deterministically extracts or constructs a finding fingerprint."""
        return (
            finding.get("fingerprint")
            or finding.get("finding_id")
            or finding.get("id")
            or f"{finding.get('root_cause', 'RC')}::{finding.get('file', '')}::{finding.get('line', 0)}"
        )

    def _path_key(self, attack_path: Dict[str, Any]) -> str:
        """Constructs a key for attack paths."""
        return (
            attack_path.get("path_id")
            or f"{attack_path.get('entrypoint')}->{attack_path.get('target')}"
        )
