"""
M21 Deterministic Security Pattern Fingerprinter.

Computes stable, canonical hashes for vulnerability patterns, root causes, sources, sinks,
and attack path structures. Insensitive to line shifts, formatting, and comments.
"""

import hashlib
import re
from typing import Dict, Any, Optional


class SecurityPatternFingerprinter:
    """
    Computes deterministic hashes for vulnerability patterns.
    """

    def compute_pattern_fingerprint(
        self,
        vulnerability_family: str,
        root_cause: str,
        source_type: str,
        sink_type: str,
        framework: str = "PYTHON",
    ) -> str:
        """
        Calculates a canonical 16-character hex fingerprint hash.
        """
        raw = f"{vulnerability_family.upper()}:{root_cause.upper()}:{source_type.upper()}:{sink_type.upper()}:{framework.upper()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def compute_attack_path_fingerprint(
        self,
        entrypoint_type: str,
        source_type: str,
        sink_type: str,
        root_cause: str,
    ) -> str:
        """
        Calculates a canonical attack path structural fingerprint.
        """
        raw = f"{entrypoint_type.upper()}->{source_type.upper()}->{sink_type.upper()}:{root_cause.upper()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def normalize_code_snippet(self, code: str) -> str:
        """
        Normalizes code snippet by removing comments, blank lines, and whitespace shifts.
        """
        if not code:
            return ""
        # Remove single line comments
        code_no_comments = re.sub(r"#.*", "", code)
        # Collapse whitespace
        lines = [line.strip() for line in code_no_comments.splitlines() if line.strip()]
        return " ".join(lines)
