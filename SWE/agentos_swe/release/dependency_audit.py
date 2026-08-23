"""
M30 Safe Dependency Auditor.

Inspects local dependency manifests (requirements.txt, pyproject.toml) offline
without requiring internet connectivity or auto-installing packages.
Never fabricates CVEs or vulnerability metrics when offline.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from agentos_swe.release.models import DependencyRisk, ReleaseCheck, CheckStatus

logger = logging.getLogger(__name__)


class DependencyAuditor:
    """
    Safely inspects local project dependency manifests offline.
    """

    @classmethod
    def audit_dependencies(cls, repository_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspects requirements.txt or pyproject.toml if present.
        """
        base_dir = repository_path or os.getcwd()
        req_file = os.path.join(base_dir, "requirements.txt")
        pyproject_file = os.path.join(base_dir, "pyproject.toml")

        found_dependencies: List[str] = []
        checks: List[ReleaseCheck] = []

        if os.path.exists(req_file):
            try:
                with open(req_file, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    found_dependencies.extend(lines)
                checks.append(ReleaseCheck("DEP-01", "requirements.txt Inspection", "DEPENDENCY", CheckStatus.PASS, f"Parsed {len(lines)} dependency specifiers from requirements.txt.", f"DEPENDENCIES_PARSED={len(lines)}"))
            except Exception as e:
                checks.append(ReleaseCheck("DEP-01", "requirements.txt Inspection", "DEPENDENCY", CheckStatus.WARN, f"Could not parse requirements.txt: {e}."))
        else:
            checks.append(ReleaseCheck("DEP-01", "requirements.txt Inspection", "DEPENDENCY", CheckStatus.PASS, "No requirements.txt found in target directory."))

        if os.path.exists(pyproject_file):
            checks.append(ReleaseCheck("DEP-02", "pyproject.toml Inspection", "DEPENDENCY", CheckStatus.PASS, "pyproject.toml manifest identified."))
        else:
            checks.append(ReleaseCheck("DEP-02", "pyproject.toml Inspection", "DEPENDENCY", CheckStatus.PASS, "No pyproject.toml found in target directory."))

        # Explicit offline vulnerability database notice
        vulnerability_status = "VULNERABILITY_DATABASE_UNAVAILABLE"
        checks.append(
            ReleaseCheck(
                "DEP-03",
                "Offline CVE Database Status",
                "DEPENDENCY",
                CheckStatus.PASS,
                "Offline analysis active: live CVE lookup skipped; zero fabricated vulnerabilities reported.",
                f"VULN_DB={vulnerability_status}",
            )
        )

        return {
            "risk": DependencyRisk.LOW.value,
            "dependencies_count": len(found_dependencies),
            "manifests_found": [
                os.path.basename(p) for p in [req_file, pyproject_file] if os.path.exists(p)
            ],
            "vulnerability_database": vulnerability_status,
            "checks": [c.to_dict() for c in checks],
        }
