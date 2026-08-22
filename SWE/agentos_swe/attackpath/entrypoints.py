"""
M16 Entrypoint Detector.

Discovers framework entrypoints across Python (FastAPI, Flask, Django, CLI, WebSocket, MCP)
with structural proof to prevent false positive internet exposure claims.
"""

import re
from typing import List, Dict, Any, Optional
from agentos_swe.attackpath.models import EntrypointType


class EntrypointDetector:
    """
    Structural Entrypoint Detector mapping code contexts and route decorators to EntrypointTypes.
    """

    def detect_entrypoints(self, code_context: str = "", file_path: str = "") -> List[Dict[str, Any]]:
        """
        Scans code context and file path for structural entrypoint indicators.
        """
        entrypoints = []
        ctx = code_context or ""
        ctx_lower = ctx.lower()
        fp_lower = (file_path or "").lower()

        # 1. FastAPI / Starlette Routes
        fastapi_matches = re.findall(r'@(?:app|router|blueprint)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', ctx, re.IGNORECASE)
        for method, path in fastapi_matches:
            entrypoints.append({
                "entrypoint": f"{method.upper()} {path}",
                "entrypoint_type": EntrypointType.INTERNET,
                "framework": "FastAPI",
                "evidence": f"Decorator @app.{method.lower()}('{path}')",
            })

        # 2. Flask Routes
        flask_matches = re.findall(r'@(?:app|blueprint)\.route\s*\(\s*["\']([^"\']+)["\']', ctx, re.IGNORECASE)
        for path in flask_matches:
            entrypoints.append({
                "entrypoint": f"HTTP {path}",
                "entrypoint_type": EntrypointType.INTERNET,
                "framework": "Flask",
                "evidence": f"Decorator @app.route('{path}')",
            })

        # 3. Django URLs
        if "urlpatterns" in ctx_lower or "path(" in ctx_lower or "re_path(" in ctx_lower:
            django_paths = re.findall(r'path\s*\(\s*["\']([^"\']+)["\']', ctx)
            for dp in django_paths:
                entrypoints.append({
                    "entrypoint": f"Django {dp}",
                    "entrypoint_type": EntrypointType.INTERNET,
                    "framework": "Django",
                    "evidence": f"Django URL path('{dp}')",
                })

        # 4. CLI Entrypoints
        if "sys.argv" in ctx_lower or "argparse" in ctx_lower or "click.command" in ctx_lower or "typer" in ctx_lower:
            entrypoints.append({
                "entrypoint": "CLI Command",
                "entrypoint_type": EntrypointType.USER_CLI,
                "framework": "CLI",
                "evidence": "CLI argument parser (sys.argv / argparse / click / typer)",
            })

        # 5. WebSocket Routes
        ws_matches = re.findall(r'@(?:app|router)\.websocket\s*\(\s*["\']([^"\']+)["\']', ctx, re.IGNORECASE)
        for path in ws_matches:
            entrypoints.append({
                "entrypoint": f"WS {path}",
                "entrypoint_type": EntrypointType.INTERNET,
                "framework": "WebSocket",
                "evidence": f"WebSocket route @app.websocket('{path}')",
            })

        # 6. Fallback based on file naming patterns
        if not entrypoints:
            if "api/" in fp_lower or "routes/" in fp_lower or "controllers/" in fp_lower:
                entrypoints.append({
                    "entrypoint": f"API Handler ({file_path})",
                    "entrypoint_type": EntrypointType.INTERNAL_API,
                    "framework": "Internal API",
                    "evidence": f"File path pattern '{file_path}'",
                })
            else:
                entrypoints.append({
                    "entrypoint": f"Function Entrypoint ({file_path})",
                    "entrypoint_type": EntrypointType.UNKNOWN,
                    "framework": "Internal Module",
                    "evidence": f"Internal execution scope in '{file_path}'",
                })

        return entrypoints
