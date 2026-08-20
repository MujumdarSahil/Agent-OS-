"""
JavaScript / JSX Semantic Resolver for AgentOS-SWE M11.
"""

import os
import re
from typing import Dict, Any, Optional, List, Tuple
from agentos_swe.semantic.base import (
    SemanticCodeProvider,
    SemanticCallResult,
    ExceptionAnalysisResult,
    ModuleRoleResult,
    SemanticCategory,
    ExceptionIntent,
    ModuleRole,
)


class JavaScriptSemanticResolver(SemanticCodeProvider):
    """
    Deterministic static semantic resolver for JavaScript (.js, .jsx) files.
    Distinguishes network I/O (fetch, axios) from object method lookups (obj.get, map.get),
    analyzes exception intent, detects launcher entrypoints, and audits JS security patterns.
    """

    def __init__(self):
        self.language = "javascript"
        self.provider = "JavaScriptSemanticResolver"

    def resolve_call(
        self,
        file_path: str,
        call_node: Any,
        context_tree: Optional[Any] = None
    ) -> SemanticCallResult:
        """Resolve a JS/JSX call expression or string statement to a semantic category."""
        text = ""
        if isinstance(call_node, str):
            text = call_node
        elif hasattr(call_node, "text"):
            text = getattr(call_node, "text")

        text_clean = text.strip()

        # 1. Direct fetch API
        if re.search(r"\bfetch\s*\(", text_clean):
            return SemanticCallResult(
                category=SemanticCategory.HTTP_NETWORK_CALL,
                confidence=0.95,
                resolved_symbol="globalThis.fetch",
                resolved_receiver_type="window/global",
                reason="Global fetch API call detected.",
                language=self.language,
                provider=self.provider,
                rule="fetch_global_call",
            )

        # 2. Axios / HTTP client calls: axios.get, axios.post, http.get, client.get (with alias tracking)
        axios_match = re.search(r"(\w+)\.(get|post|put|delete|patch|request)\s*\(", text_clean)
        if axios_match:
            receiver, method = axios_match.group(1), axios_match.group(2)
            if receiver in ("axios", "http", "https", "client", "api", "request", "httpClient"):
                return SemanticCallResult(
                    category=SemanticCategory.HTTP_NETWORK_CALL,
                    confidence=0.95,
                    resolved_symbol=f"{receiver}.{method}",
                    resolved_receiver_type=f"{receiver}_http_client",
                    reason=f"HTTP network call '{receiver}.{method}' detected.",
                    language=self.language,
                    provider=self.provider,
                    rule="http_client_method",
                )

        # 3. Disambiguate object .get() lookups (map.get, config.get, job.get)
        get_match = re.search(r"(\w+)\.get\s*\(", text_clean)
        if get_match:
            receiver = get_match.group(1)
            # Heuristic variable type resolution
            if receiver in ("job", "data", "map", "config", "params", "state", "props", "dict", "opts"):
                return SemanticCallResult(
                    category=SemanticCategory.DICT_LOOKUP,
                    confidence=0.85,
                    resolved_symbol=f"{receiver}.get",
                    resolved_receiver_type="Object/Map",
                    reason=f"Object key lookup '{receiver}.get()' detected.",
                    language=self.language,
                    provider=self.provider,
                    rule="js_object_get",
                )

        return SemanticCallResult(
            category=SemanticCategory.UNKNOWN,
            confidence=0.30,
            resolved_symbol=text_clean[:40],
            resolved_receiver_type="unknown",
            reason="Unrecognized JavaScript call pattern.",
            language=self.language,
            provider=self.provider,
            rule="unknown_call",
        )

    def analyze_exception_block(
        self,
        file_path: str,
        handler_node: Any,
        context_tree: Optional[Any] = None
    ) -> ExceptionAnalysisResult:
        """Analyze JavaScript try { ... } catch (e) { ... } blocks for intentional fallback vs swallowed bug."""
        text = ""
        if isinstance(handler_node, str):
            text = handler_node
        elif hasattr(handler_node, "text"):
            text = getattr(handler_node, "text")

        # Check for fallback return or fallback assignment inside catch
        if re.search(r"catch\s*\([^)]*\)\s*\{\s*(return|assign|console\.(log|warn|error)|fallback)\b", text):
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.INTENTIONAL_FALLBACK,
                confidence=0.92,
                reason="Catch block contains explicit fallback return, assignment, or logging.",
                caught_exceptions=["Error"],
                has_fallback_value=True,
                language=self.language,
                provider=self.provider,
                rule="js_catch_fallback",
            )

        # Check for empty catch block
        if re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", text):
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.POSSIBLE_ERROR_SWALLOW,
                confidence=0.85,
                reason="Empty JavaScript catch block swallows exception without fallback.",
                caught_exceptions=["Error"],
                has_fallback_value=False,
                language=self.language,
                provider=self.provider,
                rule="js_empty_catch",
            )

        return ExceptionAnalysisResult(
            intent=ExceptionIntent.UNKNOWN,
            confidence=0.40,
            reason="Ambiguous JavaScript catch block.",
            language=self.language,
            provider=self.provider,
            rule="js_catch_unknown",
        )

    def analyze_module_role(
        self,
        file_path: str,
        context: Optional[Any] = None
    ) -> ModuleRoleResult:
        """Classify JS module as ENTRYPOINT_LAUNCHER, TEST_HARNESS, or LIBRARY_MODULE."""
        filename = os.path.basename(file_path).lower()
        rel_path = file_path.lower().replace("\\", "/")

        is_test_dir = rel_path.startswith("tests/") or "/tests/" in rel_path or rel_path.startswith("test/") or "/test/" in rel_path or rel_path.startswith("spec/") or "/spec/" in rel_path or rel_path.startswith("e2e/") or "/e2e/" in rel_path
        is_test_file = filename.startswith("test_") or filename.endswith(".test.js") or filename.endswith(".test.jsx") or filename.endswith(".spec.js") or filename.endswith(".spec.jsx") or filename.endswith("_test.js")

        if is_test_dir or is_test_file:
            return ModuleRoleResult(
                role=ModuleRole.TEST_HARNESS,
                confidence=0.95,
                reason=f"JavaScript test harness module '{filename}'.",
                language=self.language,
                provider=self.provider,
                rule="js_test_harness",
            )

        if filename in ("index.js", "main.js", "app.js", "server.js", "index.jsx", "app.jsx", "vite.config.js"):
            return ModuleRoleResult(
                role=ModuleRole.ENTRYPOINT_LAUNCHER,
                confidence=0.95,
                reason=f"JavaScript composition root / launcher file '{filename}'.",
                language=self.language,
                provider=self.provider,
                rule="js_launcher_filename",
            )

        return ModuleRoleResult(
            role=ModuleRole.LIBRARY_MODULE,
            confidence=0.80,
            reason=f"JavaScript module '{filename}'.",
            language=self.language,
            provider=self.provider,
            rule="js_library_module",
        )

    def analyze_security_patterns(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Audit JavaScript security risks (dangerouslySetInnerHTML, eval, new Function, child_process.exec)."""
        findings = []

        if "dangerouslySetInnerHTML" in content:
            findings.append({
                "title": "Unsafe React/JSX dangerouslySetInnerHTML Usage",
                "severity": "high",
                "category": "security",
                "reason": "Direct assignment to dangerouslySetInnerHTML introduces XSS vulnerability risks.",
                "rule": "js_xss_dangerously_set_inner_html",
            })

        if re.search(r"\beval\s*\(", content):
            findings.append({
                "title": "Dangerous Function 'eval' in JavaScript",
                "severity": "high",
                "category": "security",
                "reason": "eval() executes dynamic string input with full privilege.",
                "rule": "js_eval_execution",
            })

        if re.search(r"\bnew\s+Function\s*\(", content):
            findings.append({
                "title": "Dynamic Function Constructor 'new Function'",
                "severity": "high",
                "category": "security",
                "reason": "new Function() creates dynamic code execution paths.",
                "rule": "js_new_function_execution",
            })

        if re.search(r"\bchild_process\b|\bexec\s*\(", content):
            findings.append({
                "title": "Subprocess Command Execution in Node.js",
                "severity": "high",
                "category": "security",
                "reason": "Node.js child_process.exec can allow command injection.",
                "rule": "js_child_process_exec",
            })

        return findings
