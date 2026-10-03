"""
M13 Deterministic Root-Cause Analysis.

Identifies root vulnerability categories using deterministic AST, taint, graph,
and semantic signals without requiring mandatory LLM execution.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.core.models import Finding
from agentos_swe.security.taint.models import TaintFinding, TaintSinkKind
from agentos_swe.remediation.correlation.models import RootCauseCategory


class RootCauseAnalyzer:
    """
    Deterministic Root Cause Analyzer mapping findings, taint paths,
    and semantic context into unified RootCauseCategory values.
    """

    def determine_root_cause(
        self,
        finding: Finding,
        taint_finding: Optional[TaintFinding] = None,
        semantic_info: Optional[Dict[str, Any]] = None,
    ) -> RootCauseCategory:
        """
        Determines the primary root cause category based on available evidence.
        """
        category_str = (finding.category or "").lower()
        title_str = (finding.title or "").lower()
        desc_str = (finding.description or "").lower()

        # Check Taint Finding Sink if present
        if taint_finding and taint_finding.path and taint_finding.path.sink:
            sink_kind = taint_finding.path.sink.sink_kind
            if sink_kind in (TaintSinkKind.SHELL_EXECUTION, TaintSinkKind.COMMAND_EXECUTION):
                return RootCauseCategory.COMMAND_INJECTION
            elif sink_kind in (TaintSinkKind.EVAL_EXECUTION, TaintSinkKind.DYNAMIC_CODE_EXECUTION):
                return RootCauseCategory.CODE_INJECTION
            elif sink_kind == TaintSinkKind.SQL_QUERY:
                return RootCauseCategory.SQL_INJECTION
            elif sink_kind in (TaintSinkKind.HTML_OUTPUT, TaintSinkKind.TEMPLATE_RENDERING):
                return RootCauseCategory.XSS
            elif sink_kind == TaintSinkKind.HTTP_REQUEST:
                return RootCauseCategory.SSRF
            elif sink_kind in (TaintSinkKind.FILE_PATH_OPERATION, TaintSinkKind.FILE_WRITE):
                return RootCauseCategory.PATH_TRAVERSAL
            elif sink_kind == TaintSinkKind.DESERIALIZATION:
                return RootCauseCategory.UNSAFE_DESERIALIZATION

        # Semantic info checks taking precedence over raw title keyword matching
        if semantic_info:
            intent = semantic_info.get("exception_intent", "")
            if intent == "INTENTIONAL_FALLBACK":
                return RootCauseCategory.UNKNOWN
            elif intent == "POSSIBLE_ERROR_SWALLOW":
                return RootCauseCategory.EXCEPTION_SWALLOWING

        # Pattern check on title, category, description
        combined_text = f"{category_str} {title_str} {desc_str}"

        if "command" in combined_text or "shell" in combined_text or "os.system" in combined_text or "subprocess" in combined_text:
            return RootCauseCategory.COMMAND_INJECTION
        if "eval" in combined_text or "exec" in combined_text or "code injection" in combined_text:
            return RootCauseCategory.CODE_INJECTION
        if "sql" in combined_text or "query injection" in combined_text:
            return RootCauseCategory.SQL_INJECTION
        if "xss" in combined_text or "cross site scripting" in combined_text or "html escape" in combined_text:
            return RootCauseCategory.XSS
        if "ssrf" in combined_text or "request forgery" in combined_text:
            return RootCauseCategory.SSRF
        if "path traversal" in combined_text or "directory traversal" in combined_text or "filepath" in combined_text:
            return RootCauseCategory.PATH_TRAVERSAL
        if "deserialize" in combined_text or "pickle" in combined_text or "yaml.load" in combined_text:
            return RootCauseCategory.UNSAFE_DESERIALIZATION
        if "secret" in combined_text or "password" in combined_text or "token" in combined_text or "sensitive" in combined_text:
            return RootCauseCategory.SENSITIVE_DATA_EXPOSURE
        if "exception" in combined_text or "swallow" in combined_text or "bare except" in combined_text:
            return RootCauseCategory.EXCEPTION_SWALLOWING
        if "performance" in combined_text or "n+1" in combined_text or "loop" in combined_text:
            return RootCauseCategory.PERFORMANCE_ANTI_PATTERN
        if "architecture" in combined_text or "coupling" in combined_text or "circular" in combined_text:
            return RootCauseCategory.ARCHITECTURE_COUPLING

        return RootCauseCategory.UNKNOWN
