"""
M25 Security Memory Store.

Manages derived historical security memory and intelligence records using the
existing M14 SQLite persistent database infrastructure (HistoricalScanStore).
Ensures zero secondary database engines, full multi-repo isolation, and secret protection.
"""

import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.intelligence.history.store import HistoricalScanStore
from agentos_swe.intelligence.history.models import ScanRecord
from agentos_swe.security.secret_protection import SecretProtection

logger = logging.getLogger(__name__)


class SecurityMemory:
    """
    Persistent memory store for historical vulnerability findings, remediation outcomes,
    decision history, and drift impact using M14 SQLite storage.
    """

    def __init__(self, store: Optional[HistoricalScanStore] = None):
        self.store = store or HistoricalScanStore()

    def record_scan_snapshot(self, scan_record: ScanRecord) -> bool:
        """
        Saves a scan snapshot into persistent SQLite storage.
        """
        return self.store.save_scan(scan_record)

    def get_repository_scans(self, repository: str) -> List[ScanRecord]:
        """
        Retrieves all historical scan records for a repository in descending chronological order.
        """
        return self.store.list_scans(repository)

    def get_latest_scan(self, repository: str) -> Optional[ScanRecord]:
        """
        Retrieves the most recent scan snapshot for a repository.
        """
        return self.store.get_latest_scan(repository)

    def extract_finding_memories(self, repository: str) -> List[Dict[str, Any]]:
        """
        Extracts aggregated finding lifecycle memories across all historical scans for a repository.

        Tracks:
        - fingerprint, root_cause, severity, priority, exploitability, exposure, attack_path_presence
        - first_seen, last_seen, fixed_time, reopened_count, recurrence_count
        - previous_decision, previous_remediation, repair_validation_result, security_regression_result, drift_impact
        """
        scans = self.get_repository_scans(repository)
        if not scans:
            return []

        # Chronological order (oldest to newest)
        chronological_scans = list(reversed(scans))

        memories: Dict[str, Dict[str, Any]] = {}

        for scan_idx, scan in enumerate(chronological_scans):
            scan_id = scan.scan_id
            timestamp = scan.timestamp or datetime.now().isoformat()
            commit_sha = scan.commit_sha or "HEAD"

            # Index repair validations and results from this scan
            validations_by_fp: Dict[str, Dict[str, Any]] = {}
            for rv in getattr(scan, "repair_validations", []) or []:
                fp = rv.get("fingerprint") or rv.get("finding_id")
                if fp:
                    validations_by_fp[fp] = rv

            repairs_by_rc: Dict[str, Dict[str, Any]] = {}
            for rp in getattr(scan, "repair_results", []) or []:
                rc = rp.get("root_cause")
                if rc:
                    repairs_by_rc[rc] = rp

            # Combine all findings from scan record
            scan_findings = (
                getattr(scan, "prioritized_findings", None)
                or getattr(scan, "correlated_findings", None)
                or getattr(scan, "findings", None)
                or []
            )

            current_scan_fingerprints = set()

            for f in scan_findings:
                fp = (
                    f.get("fingerprint")
                    or f.get("finding_id")
                    or f.get("id")
                    or f"{f.get('root_cause', 'RC')}::{f.get('file', '')}::{f.get('line', 0)}"
                )
                current_scan_fingerprints.add(fp)

                root_cause = f.get("root_cause") or f.get("category") or "UNKNOWN"
                severity = f.get("severity") or "MEDIUM"
                priority = f.get("priority") or "P2"
                file_path = f.get("file") or f.get("path") or ""

                raw_exploit = f.get("exploitability") or f.get("exploitability_score") or 0.5
                try:
                    exploitability = float(raw_exploit)
                except (ValueError, TypeError):
                    severity_map = {"CRITICAL": 0.9, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}
                    exploitability = severity_map.get(str(raw_exploit).upper(), 0.5)

                exposure = f.get("exposure") or f.get("exposure_level") or "INTERNAL"
                has_attack_path = bool(f.get("attack_path") or f.get("has_attack_path") or f.get("in_attack_path"))

                val_result = validations_by_fp.get(fp, {}).get("verdict") or validations_by_fp.get(fp, {}).get("status") or "NOT_TESTED"
                repair_info = repairs_by_rc.get(root_cause, {})
                strategy = repair_info.get("strategy") or repair_info.get("patch_type") or "NONE"

                if fp not in memories:
                    memories[fp] = {
                        "fingerprint": fp,
                        "root_cause": root_cause,
                        "severity": severity,
                        "priority": priority,
                        "file": file_path,
                        "exploitability": exploitability,
                        "exposure": exposure,
                        "attack_path_presence": has_attack_path,
                        "first_seen": timestamp,
                        "first_seen_commit": commit_sha,
                        "last_seen": timestamp,
                        "last_seen_commit": commit_sha,
                        "fixed_time": None,
                        "reopened_count": 0,
                        "recurrence_count": 1,
                        "active": True,
                        "scan_occurrences": [scan_id],
                        "previous_decision": f.get("decision") or scan.final_verdict,
                        "previous_remediation": strategy,
                        "repair_validation_result": val_result,
                        "security_regression_result": f.get("regression_status") or "NO_REGRESSION",
                        "drift_impact": f.get("drift_impact") or "NONE",
                    }
                else:
                    mem = memories[fp]
                    mem["last_seen"] = timestamp
                    mem["last_seen_commit"] = commit_sha
                    mem["scan_occurrences"].append(scan_id)
                    mem["exploitability"] = max(mem["exploitability"], exploitability)
                    mem["attack_path_presence"] = mem["attack_path_presence"] or has_attack_path

                    # Check if finding was previously fixed and is now reopened
                    if not mem["active"]:
                        mem["reopened_count"] += 1
                        mem["recurrence_count"] += 1
                        mem["active"] = True
                        mem["fixed_time"] = None
                    else:
                        mem["recurrence_count"] += 1

                    mem["previous_decision"] = f.get("decision") or scan.final_verdict
                    mem["previous_remediation"] = strategy or mem["previous_remediation"]
                    mem["repair_validation_result"] = val_result if val_result != "NOT_TESTED" else mem["repair_validation_result"]

            # Mark findings not present in current scan as inactive / fixed
            for fp, mem in memories.items():
                if fp not in current_scan_fingerprints:
                    if mem["active"]:
                        mem["active"] = False
                        mem["fixed_time"] = timestamp
                    if fp in validations_by_fp:
                        val_res = validations_by_fp[fp].get("verdict") or validations_by_fp[fp].get("status")
                        if val_res:
                            mem["repair_validation_result"] = val_res

        # Ensure all fields sanitized
        sanitized_memories = []
        for mem in memories.values():
            blob = SecretProtection.sanitize_text(json.dumps(mem))
            sanitized_memories.append(json.loads(blob))

        return sanitized_memories
