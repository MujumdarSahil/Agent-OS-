"""
M15 Internet Exposure Analyzer.

Determines reachability of vulnerable code paths from external internet boundaries
or user-controlled inputs by analyzing structural AST and decorator indicators.
"""

import re
from typing import Dict, Any, Optional
from agentos_swe.intelligence.models import ExposureLevel


class ExposureAnalyzer:
    """
    Structural Exposure Analyzer identifying internet-exposed web routes and CLI entrypoints.
    """

    def analyze_exposure(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
    ) -> ExposureLevel:
        """
        Calculates ExposureLevel from finding metadata and code context.
        """
        ctx_lower = code_context.lower() if code_context else ""
        file_path = (finding.get("affected_file") or finding.get("file") or "").lower()
        fn_name = (finding.get("affected_function") or "").lower()

        # Check for web framework route decorators
        if (
            "@app.get" in ctx_lower
            or "@app.post" in ctx_lower
            or "@app.route" in ctx_lower
            or "@router.get" in ctx_lower
            or "@router.post" in ctx_lower
            or "@blueprint.route" in ctx_lower
        ):
            return ExposureLevel.INTERNET_EXPOSED

        # Check for HTTP request parameters
        if (
            "request.args" in ctx_lower
            or "request.form" in ctx_lower
            or "request.json" in ctx_lower
            or "request.get_json" in ctx_lower
            or "request.headers" in ctx_lower
        ):
            return ExposureLevel.INTERNET_EXPOSED

        # Check for CLI argument entrypoints
        if "sys.argv" in ctx_lower or "argparse" in ctx_lower or "click.command" in ctx_lower or fn_name == "main":
            return ExposureLevel.USER_CONTROLLED

        # Check for API or controller file naming patterns
        if "api/" in file_path or "routes/" in file_path or "controllers/" in file_path or "views.py" in file_path:
            return ExposureLevel.INTERNET_EXPOSED

        # Check for internal test or fixture files
        if "test" in file_path or "conftest.py" in file_path or "fixtures" in file_path:
            return ExposureLevel.INTERNAL

        return ExposureLevel.INTERNAL
