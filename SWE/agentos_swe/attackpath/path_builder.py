"""
M16 Attack Path Builder.

Constructs end-to-end inter-procedural attack paths connecting sources, call chains, sanitizers,
and sinks with bounded depth (MAX_ATTACK_PATH_DEPTH = 12).
"""

import hashlib
from typing import List, Dict, Any, Optional
from agentos_swe.attackpath.models import (
    AttackPath,
    AttackStep,
    EntrypointType,
    TrustBoundary,
    AuthStatus,
    PathClassification,
)
from agentos_swe.attackpath.entrypoints import EntrypointDetector
from agentos_swe.attackpath.trust_boundaries import TrustBoundaryAnalyzer
from agentos_swe.attackpath.auth_analyzer import AuthenticationAnalyzer

MAX_ATTACK_PATH_DEPTH = 12


class AttackPathBuilder:
    """
    End-to-End Inter-Procedural Attack Path Builder.
    """

    def __init__(self):
        self.entrypoint_detector = EntrypointDetector()
        self.trust_boundary_analyzer = TrustBoundaryAnalyzer()
        self.auth_analyzer = AuthenticationAnalyzer()

    def build_attack_path(
        self,
        finding: Dict[str, Any],
        taint_finding: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
    ) -> AttackPath:
        """
        Builds a complete AttackPath from finding metadata, taint path, and Code Graph.
        """
        fid = finding.get("finding_id") or finding.get("id") or "path_1"
        repo = finding.get("repository") or "Unknown Repo"
        rc = str(finding.get("root_cause") or finding.get("category") or "UNKNOWN").upper()
        aff_file = finding.get("affected_file") or finding.get("file") or "N/A"
        aff_fn = finding.get("affected_function") or "main"
        code_ctx = str(finding.get("code_context") or finding.get("title") or "")

        # 1. Entrypoint Detection
        ep_list = self.entrypoint_detector.detect_entrypoints(code_context=code_ctx, file_path=aff_file)
        main_ep = ep_list[0] if ep_list else {"entrypoint": "Internal Function", "entrypoint_type": EntrypointType.UNKNOWN}
        ep_name = main_ep["entrypoint"]
        ep_type = main_ep["entrypoint_type"]

        # 2. Extract Source & Sink Evidence
        ev_chain = finding.get("evidence_chain") or {}
        src_kind = "UNKNOWN"
        snk_kind = "UNKNOWN"
        sanitizers = []

        if taint_finding:
            path_dict = taint_finding.get("path") or {}
            src_kind = str((path_dict.get("source") or {}).get("source_kind") or "").upper()
            snk_kind = str((path_dict.get("sink") or {}).get("sink_kind") or "").upper()
            sanitizers = path_dict.get("sanitizers") or []

        if not src_kind and ev_chain.get("source_evidence"):
            src_kind = str(ev_chain["source_evidence"][0].get("source_kind") or "").upper()
        if not snk_kind and ev_chain.get("sink_evidence"):
            snk_kind = str(ev_chain["sink_evidence"][0].get("sink_kind") or "").upper()

        src_file = aff_file
        src_line = (finding.get("affected_lines") or (1, 1))[0]
        snk_file = aff_file
        snk_line = (finding.get("affected_lines") or (1, 1))[1]

        # 3. Build Inter-Procedural Propagation Steps
        steps: List[AttackStep] = []

        # Step 1: Entry / Source
        steps.append(
            AttackStep(
                step_index=1,
                file=src_file,
                line=src_line,
                function_name=aff_fn,
                operation=f"Source Input ({src_kind})",
                step_type="SOURCE",
                trust_boundary=TrustBoundary.INTERNET if ep_type == EntrypointType.INTERNET else TrustBoundary.USER,
            )
        )

        # Inter-procedural call expansion if context exists
        callers = []
        if context and hasattr(context, "get_callers") and aff_fn:
            try:
                callers = context.get_callers(aff_fn) or []
            except Exception:
                callers = []

        depth = 2
        for caller in callers[: (MAX_ATTACK_PATH_DEPTH - 3)]:
            steps.append(
                AttackStep(
                    step_index=depth,
                    file=aff_file,
                    line=src_line,
                    function_name=caller,
                    operation=f"Call `{aff_fn}()`",
                    step_type="CALL",
                    trust_boundary=TrustBoundary.APPLICATION,
                )
            )
            depth += 1

        # Sanitizer step representation
        if sanitizers:
            for san in sanitizers:
                steps.append(
                    AttackStep(
                        step_index=depth,
                        file=aff_file,
                        line=snk_line,
                        function_name=aff_fn,
                        operation=f"Sanitizer Applied (`{san}`)",
                        step_type="SANITY_CHECK",
                        trust_boundary=TrustBoundary.APPLICATION,
                    )
                )
                depth += 1

        # Final Sink Step
        steps.append(
            AttackStep(
                step_index=depth,
                file=snk_file,
                line=snk_line,
                function_name=aff_fn,
                operation=f"Sink Execution ({snk_kind or rc})",
                step_type="SINK",
                trust_boundary=TrustBoundary.OPERATING_SYSTEM if "SHELL" in snk_kind or rc == "COMMAND_INJECTION" else TrustBoundary.DATABASE,
            )
        )

        # 4. Trust Boundaries & Auth Analysis
        boundaries, _ = self.trust_boundary_analyzer.analyze_trust_boundaries(
            entrypoint_type=ep_type,
            source_kind=src_kind,
            sink_kind=snk_kind,
        )
        auth_stat = self.auth_analyzer.analyze_auth_status(code_context=code_ctx)

        # 5. Path Classification & Hardening
        fp_lower = aff_file.lower()
        is_test_file = (
            "test_" in fp_lower
            or "_test.py" in fp_lower
            or "/tests/" in fp_lower
            or "\\tests\\" in fp_lower
            or "tests.py" in fp_lower
        )
        is_constant = (
            "constant" in code_ctx.lower()
            or "safe_const" in code_ctx.lower()
            or "echo hello" in code_ctx.lower()
            or src_kind == "CONSTANT"
        )
        has_str_concat = "+" in code_ctx or "f\"" in code_ctx.lower() or "f'" in code_ctx.lower() or ".format(" in code_ctx.lower()
        has_sql_param = "%s" in code_ctx or "?" in code_ctx or "$1" in code_ctx or "params" in code_ctx.lower() or ", (" in code_ctx or ", [" in code_ctx
        is_parameterized_sql = (
            rc == "SQL_INJECTION"
            and has_sql_param
            and not has_str_concat
        )

        if is_test_file or rc in ("TEST_HARNESS", "INTENTIONAL_FALLBACK"):
            classification = PathClassification.NOT_EXPLOITABLE
        elif is_constant or src_kind == "CONSTANT":
            classification = PathClassification.NOT_EXPLOITABLE
        elif rc in ("DICT_LOOKUP", "INFO"):
            classification = PathClassification.NOT_EXPLOITABLE
        elif is_parameterized_sql:
            classification = PathClassification.NOT_EXPLOITABLE
        elif sanitizers:
            classification = PathClassification.PARTIALLY_MITIGATED
        elif ep_type in (EntrypointType.INTERNET, EntrypointType.USER_CLI, EntrypointType.AUTHENTICATED_HTTP) and rc in ("COMMAND_INJECTION", "SQL_INJECTION", "CODE_INJECTION"):
            classification = PathClassification.EXPLOITABLE
        elif ep_type in (EntrypointType.INTERNAL_API, EntrypointType.UNKNOWN):
            classification = PathClassification.BLOCKED
        else:
            classification = PathClassification.EXPLOITABLE if finding.get("severity") in ("CRITICAL", "HIGH") else PathClassification.BLOCKED

        # 6. Stable Fingerprint Calculation
        fp_str = f"{src_kind}:{src_file}:{aff_fn}:{snk_kind}:{rc}"
        path_fingerprint = hashlib.sha256(fp_str.encode("utf-8")).hexdigest()[:16]

        # 7. Connect to Repair Strategy
        repair_strat = None
        if rc == "COMMAND_INJECTION":
            repair_strat = "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"
        elif rc == "SQL_INJECTION":
            repair_strat = "DEFENSIVE_SANITIZATION"
        elif rc == "EXCEPTION_SWALLOWING":
            repair_strat = "NARROW_EXCEPTION_AND_LOG"

        return AttackPath(
            id=f"path_{fid}",
            fingerprint=path_fingerprint,
            repository=repo,
            entrypoint=ep_name,
            entrypoint_type=ep_type,
            source=f"Source ({src_kind})",
            source_type=src_kind,
            source_file=src_file,
            source_line=src_line,
            propagation_steps=steps,
            trust_boundaries_crossed=boundaries,
            auth_status=auth_stat,
            sanitizer_steps=sanitizers,
            sink=f"Sink ({snk_kind or rc})",
            sink_type=snk_kind or rc,
            sink_file=snk_file,
            sink_line=snk_line,
            root_cause=rc,
            classification=classification,
            risk_score=0,  # Computed by AttackPathScorer
            severity=finding.get("severity") or "MEDIUM",
            confidence=float(finding.get("confidence") or 0.85),
            evidence={"evidence_chain": ev_chain, "code_context": code_ctx},
            repair_strategy=repair_strat,
            validation_status="UNTESTED",
        )
