"""
M25/M26 Changed Security Surface Analyzer.

Analyzes security-sensitive code modifications by mapping git diff changes to
vulnerability findings, taint sources/sinks, attack paths, and trust boundaries.
"""

import subprocess
import os
import logging
from typing import List, Dict, Any, Optional

from agentos_swe.drift.models import ChangedSecuritySurface

logger = logging.getLogger(__name__)


class ChangedSurfaceAnalyzer:
    """
    Analyzes git diff and maps code modifications to security-sensitive surfaces.
    """

    def analyze_changed_surface(
        self,
        repository_path: Optional[str] = None,
        current_commit: str = "HEAD",
        baseline_commit: Optional[str] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
    ) -> ChangedSecuritySurface:
        """
        Computes ChangedSecuritySurface mapping git diff entries to security findings and surfaces.
        """
        changed_files: List[str] = []
        lines_added = 0
        lines_removed = 0

        if repository_path and os.path.exists(repository_path):
            try:
                # Execute read-only git diff --numstat
                cmd = ["git", "diff", "--numstat"]
                if baseline_commit:
                    cmd.append(f"{baseline_commit}..{current_commit}")

                res = subprocess.run(
                    cmd,
                    cwd=repository_path,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0 and res.stdout.strip():
                    for line in res.stdout.strip().splitlines():
                        parts = line.split("\t")
                        if len(parts) >= 3:
                            add_str, del_str, fpath = parts[0], parts[1], parts[2]
                            if add_str.isdigit():
                                lines_added += int(add_str)
                            if del_str.isdigit():
                                lines_removed += int(del_str)
                            changed_files.append(fpath)
            except Exception as ex:
                logger.debug(f"[ChangedSurfaceAnalyzer] Git diff execution deferred: {ex}")

        # If no git diff retrieved, infer changed files from findings
        if not changed_files and findings:
            changed_files = list({f.get("file", "") for f in findings if f.get("file")})

        finding_files = {f.get("file", "") for f in (findings or []) if f.get("file")}
        path_files = set()
        for ap in (attack_paths or []):
            if ap.get("entrypoint"):
                path_files.add(ap.get("entrypoint"))
            if ap.get("target"):
                path_files.add(ap.get("target"))

        intersects_finding = bool(set(changed_files) & finding_files)
        intersects_attack_path = bool(set(changed_files) & path_files)

        intersects_source = any("request" in f.lower() or "api" in f.lower() or "route" in f.lower() for f in changed_files)
        intersects_sink = any("exec" in f.lower() or "query" in f.lower() or "render" in f.lower() for f in changed_files)
        intersects_tb = any("auth" in f.lower() or "security" in f.lower() or "login" in f.lower() for f in changed_files)
        intersects_exposure = any("public" in f.lower() or "views" in f.lower() or "endpoint" in f.lower() for f in changed_files)

        entries: List[Dict[str, Any]] = []
        for fpath in changed_files:
            match_f = [f for f in (findings or []) if f.get("file") == fpath]
            match_ap = [ap for ap in (attack_paths or []) if ap.get("entrypoint") == fpath or ap.get("target") == fpath]

            relevance = "NEUTRAL"
            if match_f or match_ap:
                relevance = "HIGH_SECURITY_RELEVANCE"
            elif "auth" in fpath.lower() or "crypto" in fpath.lower():
                relevance = "SECURITY_CRITICAL_MODULE"

            entries.append({
                "file": fpath,
                "lines_added": lines_added // max(len(changed_files), 1),
                "lines_removed": lines_removed // max(len(changed_files), 1),
                "security_relevance": relevance,
                "related_findings_count": len(match_f),
                "related_attack_paths_count": len(match_ap),
            })

        summary = (
            f"Changed security surface spans {len(changed_files)} files (+{lines_added}/-{lines_removed} lines). "
            f"Intersects findings: {intersects_finding}, Intersects attack paths: {intersects_attack_path}."
        )

        return ChangedSecuritySurface(
            changed_files=changed_files,
            changed_functions=[],
            lines_added=lines_added,
            lines_removed=lines_removed,
            intersects_finding=intersects_finding,
            intersects_source=intersects_source,
            intersects_sink=intersects_sink,
            intersects_attack_path=intersects_attack_path,
            intersects_trust_boundary=intersects_tb,
            intersects_internet_exposure=intersects_exposure,
            relevance_summary=summary,
            surface_entries=entries,
        )
