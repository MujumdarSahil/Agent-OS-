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

        # 1. Structural FastAPI authentication / dependency injection
        if (
            "depends(get_current_user)" in ctx_lower
            or "depends(require_auth)" in ctx_lower
            or "depends(verify_token)" in ctx_lower
            or "depends(get_auth_user)" in ctx_lower
        ):
            return AuthStatus.AUTHENTICATED

        # 2. Structural Flask / Django authentication decorators
        if "@login_required" in ctx_lower or "@requires_auth" in ctx_lower or "@authenticated" in ctx_lower:
            return AuthStatus.AUTHENTICATED

        # 3. Explicit permission / role check functions
        if "has_permission(" in ctx_lower or "check_authorization(" in ctx_lower or "verify_permissions(" in ctx_lower:
            return AuthStatus.AUTHORIZATION_REQUIRED

        # 4. Explicit unauthenticated indicators (public routes)
        if "@app.get" in ctx_lower or "@app.post" in ctx_lower or "@app.route" in ctx_lower:
            return AuthStatus.UNAUTHENTICATED

        return AuthStatus.UNKNOWN
