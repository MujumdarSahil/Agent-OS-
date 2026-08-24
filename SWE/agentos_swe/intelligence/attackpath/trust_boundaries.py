"""
M16 Trust Boundary Analyzer.

Detects trust boundary transitions along propagation paths (INTERNET -> APPLICATION -> OS/DATABASE).
"""

from typing import List, Dict, Any, Tuple, Optional

from agentos_swe.intelligence.attackpath.models import TrustBoundary, EntrypointType


class TrustBoundaryAnalyzer:
    """
    Deterministic Trust Boundary Analyzer identifying cross-boundary transitions.
    """

    def analyze_trust_boundaries(
        self,
        entrypoint_type: EntrypointType,
        source_kind: str = "",
        sink_kind: str = "",
        propagation_steps: Optional[List[Any]] = None,
    ) -> Tuple[List[TrustBoundary], int]:
        """
        Determines the list of trust boundaries crossed and total boundary count.
        """
        boundaries = [TrustBoundary.APPLICATION]

        # 1. Entry Boundary
        if entrypoint_type == EntrypointType.INTERNET or source_kind in ("HTTP", "FLASK_REQUEST", "FASTAPI_REQUEST"):
            boundaries.insert(0, TrustBoundary.INTERNET)
        elif entrypoint_type == EntrypointType.AUTHENTICATED_HTTP:
            boundaries.insert(0, TrustBoundary.AUTHENTICATED_USER)
        elif entrypoint_type == EntrypointType.USER_CLI or source_kind == "CLI_ARG":
            boundaries.insert(0, TrustBoundary.USER)

        # 2. Sink Boundary
        snk_upper = (sink_kind or "").upper()
        if snk_upper in ("SUBPROCESS_SHELL", "EVAL", "EXEC", "COMMAND_INJECTION"):
            boundaries.append(TrustBoundary.OPERATING_SYSTEM)
        elif snk_upper in ("SQL_EXECUTE", "SQL_INJECTION"):
            boundaries.append(TrustBoundary.DATABASE)
        elif snk_upper in ("FILE_WRITE", "FILE_READ", "PATH_TRAVERSAL"):
            boundaries.append(TrustBoundary.FILESYSTEM)
        elif snk_upper in ("SSRF", "EXTERNAL_API"):
            boundaries.append(TrustBoundary.EXTERNAL_API)
        elif snk_upper in ("LLM_PROMPT", "PROMPT_INJECTION"):
            boundaries.append(TrustBoundary.LLM)

        # Deduplicate while preserving sequence
        unique_boundaries = []
        for b in boundaries:
            if b not in unique_boundaries:
                unique_boundaries.append(b)

        return unique_boundaries, len(unique_boundaries)
