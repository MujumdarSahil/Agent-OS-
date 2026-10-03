"""
Vue Component Semantic Resolver for AgentOS-SWE M11.
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


class VueSemanticResolver(JavaScriptSemanticResolver):
    """
    Semantic resolver for Vue Single File Components (.vue).
    Extracts <script> and <script setup> sections to audit component imports,
    lifecycle hooks (onMounted), and network I/O calls (axios/fetch).
    """

    def __init__(self):
        super().__init__()
        self.language = "vue"
        self.provider = "VueSemanticResolver"

    def extract_script_content(self, vue_content: str) -> str:
        """Extract code from <script> and <script setup> tags in a .vue SFC."""
        scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", vue_content, re.IGNORECASE)
        return "\n".join(scripts) if scripts else vue_content

    def resolve_call(
        self,
        file_path: str,
        call_node: Any,
        context_tree: Optional[Any] = None
    ) -> SemanticCallResult:
        """Resolve Vue component call expressions."""
        res = super().resolve_call(file_path, call_node, context_tree)
        res.language = self.language
        res.provider = self.provider
        return res

    def analyze_component(self, file_path: str, vue_content: str) -> Dict[str, Any]:
        """Analyze Vue SFC structure for imports, API calls, and lifecycle hooks."""
        script_code = self.extract_script_content(vue_content)

        # Detect component imports
        imports = re.findall(r"import\s+(\w+)\s+from\s+['\"]([^'\"]+\.vue)['\"]", script_code)

        # Detect lifecycle hooks
        hooks = re.findall(r"\b(onMounted|onBeforeMount|onUpdated|onUnmounted|watch|computed)\b", script_code)

        # Detect API calls inside setup/methods
        has_fetch = "fetch(" in script_code
        has_axios = "axios." in script_code or "http." in script_code

        # Extract referenced API endpoints
        endpoints = re.findall(r"['\"](/(?:api|v1|v2)/[^'\"]+)['\"]", script_code)

        return {
            "file": file_path,
            "component_imports": imports,
            "lifecycle_hooks": list(set(hooks)),
            "has_network_io": has_fetch or has_axios,
            "api_endpoints": list(set(endpoints)),
            "is_script_setup": "<script setup" in vue_content.lower(),
        }
