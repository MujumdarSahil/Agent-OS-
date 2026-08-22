"""
M16 Authentication & Authorization Analyzer.

Determines structural authentication/authorization controls on entrypoints and attack paths.
"""

from typing import Dict, Any, Optional
from agentos_swe.attackpath.models import AuthStatus


class AuthenticationAnalyzer:
    """
    Authentication & Authorization Analyzer checking structural decorators and dependencies.
    """

    def analyze_auth_status(
        self,
        code_context: str = "",
        entrypoint_meta: Optional[Dict[str, Any]] = None,
    ) -> AuthStatus:
        """
        Calculates AuthStatus using structural evidence (Depends(get_current_user), @login_required).
        """
        ctx_lower = (code_context or "").lower()

        # 1. Structural FastAPI / Starlette authentication / dependency injection
        auth_deps = (
            "depends(get_current_user)",
            "depends(require_auth)",
            "depends(verify_token)",
            "depends(get_auth_user)",
            "depends(get_user)",
            "depends(auth)",
            "security(",
            "httpbearer",
            "oauth2passwordbearer",
        )
        if any(dep in ctx_lower for dep in auth_deps):
            return AuthStatus.AUTHENTICATED

        # 2. Structural Flask / Django / Framework authentication decorators
        auth_decorators = (
            "@login_required",
            "@requires_auth",
            "@authenticated",
            "@jwt_required",
            "@token_required",
            "@auth_required",
            "permission_classes",
            "isauthenticated",
        )
        if any(dec in ctx_lower for dec in auth_decorators):
            return AuthStatus.AUTHENTICATED

        # 3. Explicit permission / role check functions
        perm_checks = (
            "has_permission(",
            "check_authorization(",
            "verify_permissions(",
            "require_permission(",
            "check_perm(",
        )
        if any(chk in ctx_lower for chk in perm_checks):
            return AuthStatus.AUTHORIZATION_REQUIRED

        # 4. Explicit HTTP Route entrypoints with no auth decorators
        if any(route in ctx_lower for route in ("@app.get", "@app.post", "@app.put", "@app.delete", "@app.route", "@router.")):
            return AuthStatus.UNAUTHENTICATED

        return AuthStatus.UNKNOWN
