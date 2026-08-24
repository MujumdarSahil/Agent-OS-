"""
React Component Semantic Resolver for AgentOS-SWE M11.
"""

import os
import re
from typing import Dict, Any, Optional, List
from agentos_swe.analysis.semantic.javascript_resolver import JavaScriptSemanticResolver
from agentos_swe.analysis.semantic.base import (
    SemanticCallResult,
    ExceptionAnalysisResult,
    ModuleRoleResult,
    SemanticCategory,
    ExceptionIntent,
    ModuleRole,
)


class ReactSemanticResolver(JavaScriptSemanticResolver):
    """
    Semantic resolver for React Functional/Class Components (.jsx, .tsx).
    Audits hooks (useState, useEffect), event handlers, and API calls.
    """

    def __init__(self):
        super().__init__()
        self.language = "react"
        self.provider = "ReactSemanticResolver"

    def resolve_call(
        self,
        file_path: str,
        call_node: Any,
        context_tree: Optional[Any] = None
    ) -> SemanticCallResult:
        """Resolve React component call expressions."""
        res = super().resolve_call(file_path, call_node, context_tree)
        res.language = self.language
        res.provider = self.provider

        text = call_node if isinstance(call_node, str) else getattr(call_node, "text", "")

        # Detect useEffect API calls: useEffect(() => { fetch(...) }, [])
        if "useEffect" in text and ("fetch(" in text or "axios." in text):
            return SemanticCallResult(
                category=SemanticCategory.HTTP_NETWORK_CALL,
                confidence=0.96,
                resolved_symbol="React.useEffect.fetch",
                resolved_receiver_type="React.Hook",
                reason="Network I/O request executed inside React useEffect lifecycle hook.",
                language=self.language,
                provider=self.provider,
                rule="react_use_effect_network_io",
            )

        return res

    def analyze_component(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze React Component structure for hooks, imports, and API calls."""
        # Detect React hooks
        hooks = re.findall(r"\b(useState|useEffect|useContext|useReducer|useCallback|useMemo|useRef)\b", content)

        # Detect component imports
        component_imports = re.findall(r"import\s+([A-Z]\w+)\s+from\s+['\"]([^'\"]+)['\"]", content)

        # Detect API calls inside components
        has_fetch = "fetch(" in content
        has_axios = "axios." in content or "http." in content

        # Extract referenced API endpoints
        endpoints = re.findall(r"['\"](/(?:api|v1|v2)/[^'\"]+)['\"]", content)

        return {
            "file": file_path,
            "hooks": list(set(hooks)),
            "component_imports": component_imports,
            "has_network_io": has_fetch or has_axios,
            "api_endpoints": list(set(endpoints)),
            "is_functional_component": bool(re.search(r"function\s+[A-Z]\w+|const\s+[A-Z]\w+\s*=\s*\(", content)),
        }
