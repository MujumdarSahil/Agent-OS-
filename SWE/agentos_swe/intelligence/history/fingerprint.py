"""
M14 Finding Fingerprinting Engine.

Computes line-number-invariant SHA-256 fingerprints for security findings:
The same vulnerability retains its fingerprint across commits even if line numbers shift,
whitespace changes, or unrelated code comments are added.
"""

import hashlib
import re
from typing import Dict, Any, Optional
from agentos_swe.core.models import Finding
from agentos_swe.remediation.correlation.models import CorrelatedFinding, RootCauseCategory
from agentos_swe.security.taint.models import TaintFinding


class FindingFingerprinter:
    """
    Deterministic Fingerprinting Engine producing stable SHA-256 identifiers
    invariant to line movement, whitespace, and comment edits.
    """

    def compute_fingerprint(
        self,
        finding: Any,
        code_context: str = "",
        affected_function: Optional[str] = None,
    ) -> str:
        """
        Computes SHA-256 fingerprint from stable finding characteristics.
        """
        file_path = ""
        root_cause = "UNKNOWN"
        category = "general"
        sink_name = ""
        source_name = ""
        title = ""

        if isinstance(finding, CorrelatedFinding):
            file_path = finding.affected_file or ""
            root_cause = finding.root_cause.value if hasattr(finding.root_cause, "value") else str(finding.root_cause)
            category = finding.vulnerability_category or "general"
            affected_function = affected_function or finding.affected_function
            if finding.evidence_chain:
                if finding.evidence_chain.sink_evidence:
                    sink_name = str(finding.evidence_chain.sink_evidence[0].get("sink_kind", ""))
                if finding.evidence_chain.source_evidence:
                    source_name = str(finding.evidence_chain.source_evidence[0].get("source_kind", ""))

        elif isinstance(finding, Finding):
            file_path = finding.file or ""
            category = finding.category or "general"
            title = finding.title or ""
            root_cause = category.upper()

        elif isinstance(finding, TaintFinding):
            file_path = finding.path.file if finding.path else ""
            if finding.path and finding.path.sink:
                sink_name = finding.path.sink.sink_kind.value if hasattr(finding.path.sink.sink_kind, "value") else str(finding.path.sink.sink_kind)
            if finding.path and finding.path.source:
                source_name = finding.path.source.source_kind.value if hasattr(finding.path.source.source_kind, "value") else str(finding.path.source.source_kind)
            root_cause = "TAINT_FLOW"

        elif isinstance(finding, dict):
            file_path = finding.get("affected_file") or finding.get("file") or ""
            root_cause = finding.get("root_cause") or finding.get("category") or "UNKNOWN"
            category = finding.get("vulnerability_category") or finding.get("category") or "general"
            title = finding.get("title") or ""
            affected_function = affected_function or finding.get("affected_function")

        # Normalize file path (basename + relative directory)
        norm_file = os_norm_path(file_path)

        # Normalize code context: strip whitespace, comments, line numbers
        norm_context = self.normalize_text(code_context)
        norm_fn = (affected_function or "").strip().lower()

        # Construct raw canonical string
        canonical_str = f"{norm_file}|{root_cause.lower()}|{category.lower()}|{norm_fn}|{sink_name.lower()}|{source_name.lower()}|{norm_context}"

        # Hash with SHA-256
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def normalize_text(text: str) -> str:
        """Strips whitespace, comments, and line numbers to form line-invariant representation."""
        if not text:
            return ""
        # Remove single-line comments (#...)
        cleaned = re.sub(r"#.*$", "", text, flags=re.MULTILINE)
        # Remove multi-line string comments ("""...""" or '''...''')
        cleaned = re.sub(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'', "", cleaned)
        # Remove all whitespace
        cleaned = re.sub(r"\s+", "", cleaned)
        return cleaned.lower()[:200]


def os_norm_path(path: str) -> str:
    """Normalizes path representation for cross-platform stability."""
    if not path:
        return ""
    p = path.replace("\\", "/").strip().lower()
    parts = p.split("/")
    return "/".join(parts[-2:]) if len(parts) >= 2 else p
