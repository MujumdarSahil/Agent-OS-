"""
M14 Changed-Code Impact Analyzer.

Performs read-only git diff analysis to identify modified files, functions, and lines,
and intersects changed code with discovered security findings.
"""

import subprocess
import logging
import os
import re
from typing import List, Dict, Any, Optional
from agentos_swe.intelligence.history.models import ChangedCodeImpact

logger = logging.getLogger(__name__)


class ChangedCodeImpactAnalyzer:
    """
    Read-only Git Diff & Changed-Code Impact Analyzer.
    Correlates security findings with recently modified functions/files between commits.
    """

    def analyze_git_diff(
        self,
        repository_path: str,
        commit_a: Optional[str] = None,
        commit_b: str = "HEAD",
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[ChangedCodeImpact]:
        """
        Executes read-only git diff and intersects modified files/functions with findings.
        """
        findings = findings or []
        impacts = []

        if not os.path.exists(repository_path):
            return impacts

        try:
            cmd = ["git", "diff", "--numstat"]
            if commit_a:
                cmd.extend([commit_a, commit_b])

            res = subprocess.run(
                cmd,
                cwd=repository_path,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if res.returncode != 0 or not res.stdout.strip():
                return impacts

            for line in res.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    added_str, removed_str, rel_path = parts[0], parts[1], parts[2]
                    added = int(added_str) if added_str.isdigit() else 0
                    removed = int(removed_str) if removed_str.isdigit() else 0
                    norm_path = rel_path.replace("\\", "/").lower()

                    # Find intersecting findings
                    matching_f = [
                        f for f in findings
                        if (f.get("affected_file") or f.get("file") or "").replace("\\", "/").lower() == norm_path
                    ]

                    if matching_f:
                        for mf in matching_f:
                            fid = mf.get("finding_id") or mf.get("id") or "N/A"
                            fp = mf.get("fingerprint")
                            rc = mf.get("root_cause") or mf.get("category") or "UNKNOWN"
                            sev = (mf.get("severity") or "MEDIUM").upper()

                            impacts.append(
                                ChangedCodeImpact(
                                    file=rel_path,
                                    function_name=mf.get("affected_function"),
                                    lines_added=added,
                                    lines_removed=removed,
                                    intersects_finding_id=fid,
                                    finding_fingerprint=fp,
                                    root_cause=rc,
                                    severity=sev,
                                    impact_level="HIGH" if sev in ("CRITICAL", "HIGH") else "MEDIUM",
                                    description=f"Changed code in '{rel_path}' intersects with {sev} {rc} finding.",
                                )
                            )
                    else:
                        impacts.append(
                            ChangedCodeImpact(
                                file=rel_path,
                                function_name=None,
                                lines_added=added,
                                lines_removed=removed,
                                intersects_finding_id=None,
                                impact_level="LOW",
                                description=f"Modified file '{rel_path}' (+{added}/-{removed} lines)",
                            )
                        )
        except Exception as ex:
            logger.debug(f"[ChangedCodeImpactAnalyzer] Read-only git diff error: {ex}")

        return impacts
