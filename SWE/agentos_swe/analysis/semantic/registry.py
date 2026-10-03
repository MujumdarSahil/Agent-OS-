"""
Polyglot Semantic Provider Registry for AgentOS-SWE M11.
"""

import os
from typing import Dict, Any, Optional, List, Type
from agentos_swe.analysis.semantic.base import (
    SemanticCodeProvider,
    SemanticCallResult,
    ExceptionAnalysisResult,
    ModuleRoleResult,
    SemanticCategory,
    ExceptionIntent,
    ModuleRole,
)
from agentos_swe.analysis.semantic.resolver import PythonSemanticResolver
from agentos_swe.analysis.semantic.javascript_resolver import JavaScriptSemanticResolver
from agentos_swe.analysis.semantic.typescript_resolver import TypeScriptSemanticResolver
from agentos_swe.analysis.semantic.vue_resolver import VueSemanticResolver
from agentos_swe.analysis.semantic.react_resolver import ReactSemanticResolver


class DefaultUnknownSemanticResolver(SemanticCodeProvider):
    """Fallback resolver for unsupported file types."""

    def resolve_call(self, file_path: str, call_node: Any, context_tree: Optional[Any] = None) -> SemanticCallResult:
        return SemanticCallResult(
            category=SemanticCategory.UNKNOWN,
            confidence=0.10,
            resolved_symbol="unknown",
            reason=f"Unsupported file type '{os.path.splitext(file_path)[1]}'.",
            language="unknown",
            provider="DefaultUnknownSemanticResolver",
            rule="unsupported_extension",
        )

    def analyze_exception_block(self, file_path: str, handler_node: Any, context_tree: Optional[Any] = None) -> ExceptionAnalysisResult:
        return ExceptionAnalysisResult(
            intent=ExceptionIntent.UNKNOWN,
            confidence=0.10,
            reason=f"Unsupported file type '{os.path.splitext(file_path)[1]}'.",
            language="unknown",
            provider="DefaultUnknownSemanticResolver",
            rule="unsupported_extension",
        )

    def analyze_module_role(self, file_path: str, context: Optional[Any] = None) -> ModuleRoleResult:
        return ModuleRoleResult(
            role=ModuleRole.LIBRARY_MODULE,
            confidence=0.50,
            reason=f"Default library module role for unsupported file type '{os.path.splitext(file_path)[1]}'.",
            language="unknown",
            provider="DefaultUnknownSemanticResolver",
            rule="unsupported_extension",
        )


class SemanticProviderRegistry:
    """
    Central registry for polyglot language semantic resolvers.
    Resolves providers by file extension (.py, .js, .jsx, .ts, .tsx, .vue) and delegates semantic analysis queries.
    """

    def __init__(self):
        self._providers: Dict[str, SemanticCodeProvider] = {}
        self._default_provider = DefaultUnknownSemanticResolver()
        self._register_defaults()

    def _register_defaults(self):
        py_resolver = PythonSemanticResolver()
        js_resolver = JavaScriptSemanticResolver()
        ts_resolver = TypeScriptSemanticResolver()
        vue_resolver = VueSemanticResolver()
        react_resolver = ReactSemanticResolver()

        self.register_provider(".py", py_resolver)
        self.register_provider(".js", js_resolver)
        self.register_provider(".jsx", react_resolver)
        self.register_provider(".ts", ts_resolver)
        self.register_provider(".tsx", react_resolver)
        self.register_provider(".vue", vue_resolver)

    def register_provider(self, extension: str, provider: SemanticCodeProvider):
        """Register a semantic code provider for a file extension (e.g., '.py', '.js')."""
        ext = extension.lower()
        if not ext.startswith("."):
            ext = f".{ext}"
        self._providers[ext] = provider

    def get_provider_for_file(self, file_path: str) -> SemanticCodeProvider:
        """Resolve registered SemanticCodeProvider for a file based on extension."""
        ext = os.path.splitext(file_path)[1].lower()
        return self._providers.get(ext, self._default_provider)

    def resolve_call(
        self,
        file_path: str,
        call_node: Any,
        context_tree: Optional[Any] = None
    ) -> SemanticCallResult:
        """Delegate call resolution to the language-specific provider."""
        try:
            provider = self.get_provider_for_file(file_path)
            return provider.resolve_call(file_path, call_node, context_tree)
        except Exception as e:
            return SemanticCallResult(
                category=SemanticCategory.UNKNOWN,
                confidence=0.10,
                resolved_symbol="error",
                reason=f"Graceful fallback: exception during semantic call resolution ({e}).",
                provider="SemanticProviderRegistry",
                rule="exception_fallback",
            )

    def analyze_exception_block(
        self,
        file_path: str,
        handler_node: Any,
        context_tree: Optional[Any] = None
    ) -> ExceptionAnalysisResult:
        """Delegate exception analysis to the language-specific provider."""
        try:
            provider = self.get_provider_for_file(file_path)
            return provider.analyze_exception_block(file_path, handler_node, context_tree)
        except Exception as e:
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.UNKNOWN,
                confidence=0.10,
                reason=f"Graceful fallback: exception during exception analysis ({e}).",
                provider="SemanticProviderRegistry",
                rule="exception_fallback",
            )

    def analyze_module_role(
        self,
        file_path: str,
        context: Optional[Any] = None
    ) -> ModuleRoleResult:
        """Delegate module role analysis to the language-specific provider."""
        try:
            provider = self.get_provider_for_file(file_path)
            return provider.analyze_module_role(file_path, context)
        except Exception as e:
            return ModuleRoleResult(
                role=ModuleRole.LIBRARY_MODULE,
                confidence=0.50,
                reason=f"Graceful fallback: exception during module role analysis ({e}).",
                provider="SemanticProviderRegistry",
                rule="exception_fallback",
            )

    def analyze_security_patterns(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Audit file content for language-specific security flaws."""
        try:
            provider = self.get_provider_for_file(file_path)
            if hasattr(provider, "analyze_security_patterns"):
                return getattr(provider, "analyze_security_patterns")(file_path, content)
        except Exception as ex:
            logger.warning(f"[SemanticProviderRegistry] Security pattern analysis failed for '{file_path}': {ex}")
        return []
