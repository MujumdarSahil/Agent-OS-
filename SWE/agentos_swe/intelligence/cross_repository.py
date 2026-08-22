"""
M15 Cross-Repository Intelligence Engine.

Aggregates vulnerability patterns across multiple repository scan histories stored in local SQLite.
Identifies recurring cross-repository vulnerability families (COMMAND_INJECTION, SQL_INJECTION, etc.).
"""

from typing import List, Dict, Any, Optional
from agentos_swe.history.store import HistoricalScanStore
from agentos_swe.intelligence.models import CrossRepositoryPattern


class CrossRepositoryIntelligenceEngine:
    """
    Cross-Repository Risk Intelligence Engine analyzing multi-repository security trends.
    """

    def analyze_cross_repository_patterns(
        self,
        store: Optional[HistoricalScanStore] = None,
        current_repository: str = "",
        current_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[CrossRepositoryPattern]:
        """
        Groups security findings across stored repository scans into vulnerability families.
        """
        store = store or HistoricalScanStore()
        all_scans = store.list_scans()
        current_findings = current_findings or []

        # Family Aggregator Map: family_name -> {repos: set(), count: int, sevs: list(), sinks: list()}
        families: Dict[str, Dict[str, Any]] = {}

        def record_finding(family: str, repo: str, sev: str, sink: str):
            fam_key = family.upper()
            if fam_key not in families:
                families[fam_key] = {
                    "repos": set(),
                    "count": 0,
                    "sevs": [],
                    "sinks": [],
                }
            families[fam_key]["repos"].add(repo)
            families[fam_key]["count"] += 1
            families[fam_key]["sevs"].append(sev.upper())
            if sink:
                families[fam_key]["sinks"].append(sink)

        # 1. Process stored historical scans
        for scan in all_scans:
            repo_name = scan.repository or "Unknown Repo"
            for f in (scan.correlated_findings or scan.findings or []):
                fam = f.get("root_cause") or f.get("vulnerability_category") or f.get("category") or "UNKNOWN"
                sev = f.get("severity") or "MEDIUM"
                sink = f.get("sink_kind") or ""
                record_finding(fam, repo_name, sev, sink)

        # 2. Process current scan findings
        if current_repository:
            for f in current_findings:
                fam = f.get("root_cause") or f.get("vulnerability_category") or f.get("category") or "UNKNOWN"
                sev = f.get("severity") or "MEDIUM"
                sink = f.get("sink_kind") or ""
                record_finding(fam, current_repository, sev, sink)

        # 3. Build CrossRepositoryPattern objects
        patterns = []
        for fam_name, f_data in families.items():
            repos_list = list(f_data["repos"])
            cnt = f_data["count"]
            sevs = f_data["sevs"]
            highest_sev = "CRITICAL" if "CRITICAL" in sevs else ("HIGH" if "HIGH" in sevs else ("MEDIUM" if "MEDIUM" in sevs else "LOW"))

            # Determine most common sink
            sinks = f_data["sinks"]
            most_common_sink = max(set(sinks), key=sinks.count) if sinks else "N/A"

            patterns.append(
                CrossRepositoryPattern(
                    vulnerability_family=fam_name,
                    affected_repositories_count=len(repos_list),
                    total_occurrences=cnt,
                    repositories=repos_list,
                    highest_severity=highest_sev,
                    most_common_sink=most_common_sink,
                    trend="RECURRING" if len(repos_list) > 1 else "LOCAL",
                )
            )

        # Sort patterns by total occurrences descending
        patterns.sort(key=lambda p: p.total_occurrences, reverse=True)
        return patterns
