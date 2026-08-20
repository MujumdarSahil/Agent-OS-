"""
TypeScript / TSX Semantic Resolver for AgentOS-SWE M11.
"""

import os
import re
from typing import Dict, Any, Optional, List
from agentos_swe.semantic.javascript_resolver import JavaScriptSemanticResolver
from agentos_swe.semantic.base import (
    SemanticCallResult,
    ExceptionAnalysisResult,
    ModuleRoleResult,
    SemanticCategory,
    ExceptionIntent,
    ModuleRole,
)


class TypeScriptSemanticResolver(JavaScriptSemanticResolver):
    """
    Static semantic resolver for TypeScript (.ts, .tsx) files.
    Extends JavaScriptSemanticResolver with type annotation aware API client resolution.
    """

    def __init__(self):
        super().__init__()
        self.language = "typescript"
        self.provider = "TypeScriptSemanticResolver"

    def resolve_call(
        self,
        file_path: str,
        call_node: Any,
        context_tree: Optional[Any] = None
    ) -> SemanticCallResult:
        """Resolve TS/TSX call expression to semantic category."""
        res = super().resolve_call(file_path, call_node, context_tree)
        res.language = self.language
        res.provider = self.provider

        text = call_node if isinstance(call_node, str) else getattr(call_node, "text", "")

        # Typed API Client patterns: apiClient.get<T>("/url")
        if re.search(r"(\w+)\.(get|post|put|delete)<[^>]+>\s*\(", text):
            match = re.search(r"(\w+)\.(get|post|put|delete)<", text)
            receiver, method = match.group(1), match.group(2)
            return SemanticCallResult(
                category=SemanticCategory.HTTP_NETWORK_CALL,
                confidence=0.98,
                resolved_symbol=f"{receiver}.{method}",
                resolved_receiver_type=f"TypedApiClient<{receiver}>",
                reason=f"Typed TypeScript API client network request '{receiver}.{method}<T>()' detected.",
                language=self.language,
                provider=self.provider,
                rule="ts_typed_api_client",
            )

        return res

    def analyze_module_role(
        self,
        file_path: str,
        context: Optional[Any] = None
    ) -> ModuleRoleResult:
        """Classify TS module role."""
        filename = os.path.basename(file_path).lower()
        if filename in ("index.ts", "main.ts", "app.ts", "server.ts", "index.tsx", "app.tsx", "vite.config.ts"):
            return ModuleRoleResult(
                role=ModuleRole.ENTRYPOINT_LAUNCHER,
                confidence=0.95,
                reason=f"TypeScript composition root / launcher file '{filename}'.",
                language=self.language,
                provider=self.provider,
                rule="ts_launcher_filename",
            )

        return ModuleRoleResult(
            role=ModuleRole.LIBRARY_MODULE,
            confidence=0.80,
            reason=f"TypeScript module '{filename}'.",
            language=self.language,
            provider=self.provider,
            rule="ts_library_module",
        )
