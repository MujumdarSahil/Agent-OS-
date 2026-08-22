"""
M23 Security Change Impact Correlator.

Correlates modified files and security-sensitive changes with findings and attack paths.
"""

from typing import Dict, Any, List, Optional
from agentos_swe.monitoring.models import SecurityChangeImpact


class SecurityChangeImpactCorrelator:
    """
    Correlates code changes to findings, taint flows, and attack paths.
    """

    def correlate_impact(
        self,
        change_analysis: Dict[str, Any],
        findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
    ) -> SecurityChangeImpact:
        """
        Determines change impact on findings and attack paths.
        """
        mod_files = change_analysis.get("modified_files", [])
        sec_files = change_analysis.get("security_sensitive_files", [])
        add_lines = change_analysis.get("added_lines", 0)
        rem_lines = change_analysis.get("removed_lines", 0)

        findings_list = [f.to_dict() if hasattr(f, "to_dict") else f for f in (findings or [])]
        paths_list = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]

        aff_findings: List[Dict[str, Any]] = []
        aff_paths: List[Dict[str, Any]] = []

        for f in findings_list:
            aff_file = f.get("affected_file") or f.get("file") or ""
            if aff_file in mod_files or any(m in aff_file for m in mod_files):
                aff_findings.append(f)

        for ap in paths_list:
            src_file = ap.get("source_file", "")
            snk_file = ap.get("sink_file", "")
            if src_file in mod_files or snk_file in mod_files:
                aff_paths.append(ap)

        rationale = f"Analyzed {len(mod_files)} modified files ({len(sec_files)} security-sensitive). Correlated {len(aff_findings)} findings and {len(aff_paths)} attack paths."

        return SecurityChangeImpact(
            modified_files=mod_files,
            security_sensitive_files=sec_files,
            added_lines=add_lines,
            removed_lines=rem_lines,
            affected_findings=aff_findings,
            affected_attack_paths=aff_paths,
            rationale=rationale,
        )
