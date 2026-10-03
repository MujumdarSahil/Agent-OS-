"""
M25 Security Pattern Detector.

Analyzes historical scan snapshots and memory records to detect recurring,
reopened, structural, and emerging security patterns.
"""

from typing import List, Dict, Any, Set, Optional
from collections import defaultdict

from agentos_swe.intelligence.learning.models import SecurityPattern, SecurityPatternType
from agentos_swe.intelligence.history.models import ScanRecord


class SecurityPatternDetector:
    """
    Deterministic detector for 10 core historical security pattern types.
    """

    def detect_patterns(
        self,
        finding_memories: List[Dict[str, Any]],
        historical_scans: List[ScanRecord],
        current_findings: List[Dict[str, Any]],
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        drift_result: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityPattern]:
        """
        Detects recurring security patterns across repository scan history and current state.
        """
        patterns: List[SecurityPattern] = []

        if not finding_memories and not historical_scans and not current_findings:
            return patterns

        # 1. RECURRING_VULNERABILITY
        recurring_fps = [mem for mem in finding_memories if mem.get("recurrence_count", 1) >= 2]
        if recurring_fps:
            files = list({mem.get("file", "") for mem in recurring_fps if mem.get("file")})
            rcs = list({mem.get("root_cause", "") for mem in recurring_fps if mem.get("root_cause")})
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.RECURRING_VULNERABILITY,
                    title="Recurring Vulnerabilities Detected",
                    description=f"Found {len(recurring_fps)} vulnerability fingerprints recurring across multiple scans.",
                    confidence=0.95,
                    occurrences=len(recurring_fps),
                    affected_files=files,
                    affected_root_causes=rcs,
                    metadata={"fingerprints": [mem.get("fingerprint") for mem in recurring_fps]},
                )
            )

        # 2. REOPENED_VULNERABILITY
        reopened_fps = [mem for mem in finding_memories if mem.get("reopened_count", 0) >= 1]
        if reopened_fps:
            files = list({mem.get("file", "") for mem in reopened_fps if mem.get("file")})
            rcs = list({mem.get("root_cause", "") for mem in reopened_fps if mem.get("root_cause")})
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.REOPENED_VULNERABILITY,
                    title="Reopened Vulnerabilities Detected",
                    description=f"{len(reopened_fps)} previously remediated vulnerabilities have been reopened in subsequent scans.",
                    confidence=1.0,
                    occurrences=len(reopened_fps),
                    affected_files=files,
                    affected_root_causes=rcs,
                    metadata={"reopened_fingerprints": [mem.get("fingerprint") for mem in reopened_fps]},
                )
            )

        # 3. REPEATED_ROOT_CAUSE
        rc_counts: Dict[str, int] = defaultdict(int)
        rc_files: Dict[str, Set[str]] = defaultdict(set)
        for mem in finding_memories:
            rc = mem.get("root_cause") or "UNKNOWN"
            rc_counts[rc] += mem.get("recurrence_count", 1)
            if mem.get("file"):
                rc_files[rc].add(mem.get("file"))

        repeated_rcs = [rc for rc, count in rc_counts.items() if count >= 3]
        if repeated_rcs:
            all_files = list({f for rc in repeated_rcs for f in rc_files[rc]})
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.REPEATED_ROOT_CAUSE,
                    title="Repeated Root Cause Pattern",
                    description=f"Root causes {repeated_rcs} occurred repeatedly (>= 3 times) in repository history.",
                    confidence=0.90,
                    occurrences=sum(rc_counts[rc] for rc in repeated_rcs),
                    affected_files=all_files,
                    affected_root_causes=repeated_rcs,
                    metadata={"root_cause_counts": {rc: rc_counts[rc] for rc in repeated_rcs}},
                )
            )

        # 4. REPEATED_FILE_PATTERN
        file_counts: Dict[str, int] = defaultdict(int)
        file_rcs: Dict[str, Set[str]] = defaultdict(set)
        for mem in finding_memories:
            fpath = mem.get("file")
            if fpath:
                file_counts[fpath] += mem.get("recurrence_count", 1)
                if mem.get("root_cause"):
                    file_rcs[fpath].add(mem.get("root_cause"))

        repeated_files = [f for f, count in file_counts.items() if count >= 3]
        if repeated_files:
            all_rcs = list({rc for f in repeated_files for rc in file_rcs[f]})
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.REPEATED_FILE_PATTERN,
                    title="High-Risk Hotspot Files Detected",
                    description=f"Files {repeated_files[:3]} have accumulated 3 or more security findings.",
                    confidence=0.92,
                    occurrences=sum(file_counts[f] for f in repeated_files),
                    affected_files=repeated_files,
                    affected_root_causes=all_rcs,
                    metadata={"file_counts": {f: file_counts[f] for f in repeated_files}},
                )
            )

        # 5. REPEATED_ATTACK_PATH
        path_counts: Dict[str, int] = defaultdict(int)
        if attack_paths:
            for ap in attack_paths:
                key = ap.get("path_id") or f"{ap.get('entrypoint')}->{ap.get('target')}"
                path_counts[key] += 1

        for mem in finding_memories:
            if mem.get("attack_path_presence") and mem.get("recurrence_count", 1) >= 2:
                path_counts[mem.get("fingerprint")] += 1

        repeated_paths = [p for p, c in path_counts.items() if c >= 2]
        if repeated_paths:
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.REPEATED_ATTACK_PATH,
                    title="Repeated Attack Paths Present",
                    description=f"{len(repeated_paths)} attack paths recurred across multiple security scans.",
                    confidence=0.88,
                    occurrences=len(repeated_paths),
                    affected_files=[],
                    affected_root_causes=[],
                    metadata={"repeated_paths": repeated_paths},
                )
            )

        # 6. REPEATED_SECURITY_DRIFT
        if len(historical_scans) >= 2:
            scores = [s.security_score for s in historical_scans if hasattr(s, "security_score")]
            negative_drifts = 0
            for i in range(len(scores) - 1):
                if scores[i] < scores[i + 1]:  # Chronological order from store is desc, so scores[i] is newer
                    negative_drifts += 1

            if negative_drifts >= 2 or (drift_result and drift_result.get("drift", {}).get("category") in ["NEGATIVE_DRIFT", "SEVERE_DRIFT"]):
                patterns.append(
                    SecurityPattern(
                        pattern_type=SecurityPatternType.REPEATED_SECURITY_DRIFT,
                        title="Repeated Negative Security Drift",
                        description="Repository has experienced repeated security score degradation across consecutive commits.",
                        confidence=0.90,
                        occurrences=max(negative_drifts, 1),
                        metadata={"score_history": scores[:5]},
                    )
                )

        # 7. FAILED_REMEDIATION
        failed_mems = [
            mem for mem in finding_memories
            if mem.get("repair_validation_result") in ["FAIL", "FAILED", "REGRESSION"]
            or mem.get("security_regression_result") in ["REGRESSION", "REGRESSION_DETECTED"]
        ]
        if failed_mems:
            files = list({mem.get("file", "") for mem in failed_mems if mem.get("file")})
            rcs = list({mem.get("root_cause", "") for mem in failed_mems if mem.get("root_cause")})
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.FAILED_REMEDIATION,
                    title="Failed Remediation Attempts Detected",
                    description=f"Attempted repairs for {len(failed_mems)} findings failed validation or caused security regressions.",
                    confidence=0.95,
                    occurrences=len(failed_mems),
                    affected_files=files,
                    affected_root_causes=rcs,
                    metadata={"failed_fingerprints": [mem.get("fingerprint") for mem in failed_mems]},
                )
            )

        # 8. SUCCESSFUL_REMEDIATION
        successful_mems = [
            mem for mem in finding_memories
            if mem.get("repair_validation_result") in ["PASS", "SUCCESS", "PASSED"]
            and not mem.get("active")
        ]
        if successful_mems:
            files = list({mem.get("file", "") for mem in successful_mems if mem.get("file")})
            rcs = list({mem.get("root_cause", "") for mem in successful_mems if mem.get("root_cause")})
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.SUCCESSFUL_REMEDIATION,
                    title="Verified Successful Remediations",
                    description=f"{len(successful_mems)} security vulnerabilities were successfully remediated and verified clean.",
                    confidence=1.0,
                    occurrences=len(successful_mems),
                    affected_files=files,
                    affected_root_causes=rcs,
                    metadata={"successful_fingerprints": [mem.get("fingerprint") for mem in successful_mems]},
                )
            )

        # 9. PERSISTENT_VULNERABILITY
        persistent_mems = [
            mem for mem in finding_memories
            if mem.get("active") and mem.get("recurrence_count", 1) >= 3
        ]
        if persistent_mems:
            files = list({mem.get("file", "") for mem in persistent_mems if mem.get("file")})
            rcs = list({mem.get("root_cause", "") for mem in persistent_mems if mem.get("root_cause")})
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.PERSISTENT_VULNERABILITY,
                    title="Persistent Vulnerabilities Unresolved",
                    description=f"{len(persistent_mems)} findings have remained active and un-remediated across 3 or more scans.",
                    confidence=0.95,
                    occurrences=len(persistent_mems),
                    affected_files=files,
                    affected_root_causes=rcs,
                    metadata={"persistent_fingerprints": [mem.get("fingerprint") for mem in persistent_mems]},
                )
            )

        # 10. NEW_EMERGING_PATTERN
        known_rcs = {mem.get("root_cause") for mem in finding_memories if mem.get("scan_occurrences") and len(mem.get("scan_occurrences", [])) > 1}
        current_rcs = {f.get("root_cause") for f in current_findings if f.get("root_cause")}
        new_rcs = list(current_rcs - known_rcs) if known_rcs else []

        if new_rcs:
            new_files = [f.get("file", "") for f in current_findings if f.get("root_cause") in new_rcs]
            patterns.append(
                SecurityPattern(
                    pattern_type=SecurityPatternType.NEW_EMERGING_PATTERN,
                    title="New Emerging Vulnerability Types",
                    description=f"New root cause categories {new_rcs} were observed for the first time in recent scans.",
                    confidence=0.85,
                    occurrences=len(new_rcs),
                    affected_files=new_files,
                    affected_root_causes=new_rcs,
                    metadata={"new_root_causes": new_rcs},
                )
            )

        return patterns
