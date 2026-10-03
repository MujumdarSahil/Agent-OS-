"""
Cross-Language API Contract Analyzer for AgentOS-SWE M11.
Audits frontend (JS/TS/Vue/React) requests against backend (Python/FastAPI/Flask) routes.
"""

import os
import re
from typing import Dict, Any, List, Optional, Set, Tuple


class APIContractAnalyzer:
    """
    Analyzes API endpoints across frontend request calls and backend route definitions
    to detect contract mismatches (path mismatch, HTTP method mismatch, missing backend route).
    """

    def extract_frontend_endpoints(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Extract API call endpoints and HTTP methods from JS/TS/Vue/React content."""
        results = []

        # 1. fetch('/api/...')
        fetch_matches = re.findall(r"fetch\s*\(\s*['\"](/(?:api|v1|v2)/[^'\"]+)['\"](?:\s*,\s*\{\s*method:\s*['\"](\w+)['\"])?", content, re.IGNORECASE)
        for url, method in fetch_matches:
            results.append({
                "file": file_path,
                "endpoint": url.split("?")[0],
                "method": method.upper() if method else "GET",
                "source": "fetch",
            })

        # 2. axios.get('/api/...') / axios.post('/api/...')
        axios_matches = re.findall(r"axios\.(get|post|put|delete|patch)\s*\(\s*['\"](/(?:api|v1|v2)/[^'\"]+)['\"]", content, re.IGNORECASE)
        for method, url in axios_matches:
            results.append({
                "file": file_path,
                "endpoint": url.split("?")[0],
                "method": method.upper(),
                "source": "axios",
            })

        return results

    def extract_backend_routes(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Extract backend API route definitions and HTTP methods from Python content."""
        results = []

        # @app.get('/api/...') / @router.post('/api/...')
        route_matches = re.findall(r"@(?:app|router)\.(get|post|put|delete|patch|route)\s*\(\s*['\"](/(?:api|v1|v2)/[^'\"]+)['\"]", content, re.IGNORECASE)
        for method, url in route_matches:
            results.append({
                "file": file_path,
                "endpoint": url.split("?")[0],
                "method": method.upper() if method != "route" else "GET",
                "source": "fastapi_flask",
            })

        return results

    def analyze_contracts(
        self,
        frontend_calls: List[Dict[str, Any]],
        backend_routes: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Compare frontend API calls against backend route definitions to identify contract mismatches."""
        mismatches = []

        backend_endpoint_map: Dict[str, Set[str]] = {}
        for r in backend_routes:
            ep = r["endpoint"]
            backend_endpoint_map.setdefault(ep, set()).add(r["method"])

        for call in frontend_calls:
            url = call["endpoint"]
            method = call["method"]

            # Exact match
            if url in backend_endpoint_map:
                allowed_methods = backend_endpoint_map[url]
                if method not in allowed_methods and "ROUTE" not in allowed_methods:
                    mismatches.append({
                        "title": f"API Contract HTTP Method Mismatch for '{url}'",
                        "type": "METHOD_MISMATCH",
                        "frontend_file": call["file"],
                        "endpoint": url,
                        "frontend_method": method,
                        "backend_methods": list(allowed_methods),
                        "confidence": 0.80,
                        "reason": f"Frontend calls '{url}' via {method}, but backend route only permits {list(allowed_methods)}.",
                    })
            else:
                # Check singular/plural or trailing slash path mismatch
                possible_match = None
                for b_url in backend_endpoint_map:
                    if b_url.rstrip("s") == url.rstrip("s") or b_url.strip("/") == url.strip("/"):
                        possible_match = b_url
                        break

                if possible_match:
                    mismatches.append({
                        "title": f"API Contract Endpoint Path Mismatch '{url}' vs '{possible_match}'",
                        "type": "PATH_MISMATCH",
                        "frontend_file": call["file"],
                        "frontend_endpoint": url,
                        "suggested_backend_route": possible_match,
                        "confidence": 0.75,
                        "reason": f"Frontend references '{url}', but backend defines route as '{possible_match}'.",
                    })
                else:
                    mismatches.append({
                        "title": f"Missing Backend API Route for Frontend Request '{url}'",
                        "type": "MISSING_BACKEND_ROUTE",
                        "frontend_file": call["file"],
                        "endpoint": url,
                        "confidence": 0.70,
                        "reason": f"Frontend calls endpoint '{url}', but no matching backend route definition was found in repository.",
                    })

        return mismatches
