"""
M15 Security Recommendation Engine.

Produces deterministic, explainable remediation recommendations for prioritized findings:
why_this_matters, what_to_fix, why_it_is_prioritized, recommended_action, expected_risk_reduction.
Connects directly to M13/M13.1 intelligent repair strategies.
"""

from typing import Dict, Any, Optional
from agentos_swe.intelligence.models import (
    PriorityTier,
    ExploitabilityLevel,
    ExposureLevel,
    BlastRadiusLevel,
)


class SecurityRecommendationEngine:
    """
    Deterministic Recommendation Engine generating explainable fix advice.
    """

    def generate_recommendation(
        self,
        finding: Dict[str, Any],
        priority_tier: PriorityTier,
        priority_score: int,
        exploitability: ExploitabilityLevel,
        exposure: ExposureLevel,
        blast_radius: BlastRadiusLevel,
    ) -> Dict[str, str]:
        """
        Builds explainable recommendation details for a prioritized finding.
        """
        rc = str(finding.get("root_cause") or finding.get("category") or "UNKNOWN").upper()
        affected_file = finding.get("affected_file") or finding.get("file") or "N/A"
        affected_fn = finding.get("affected_function") or "main"

        why_matters = ""
        what_fix = f"Target `{affected_file}` (Function `{affected_fn}`)"
        why_pri = f"Assigned {priority_tier.value} priority (Score: {priority_score}/100) due to {exploitability.value} exploitability and {exposure.value} exposure."
        action = ""
        risk_red = ""
        strategy = None

        if rc == "COMMAND_INJECTION":
            why_matters = "Untrusted input reaches shell command execution, allowing arbitrary operating system command execution."
            action = "Replace `shell=True` or string concatenation in `subprocess.run()` with a fixed list/array of string arguments."
            risk_red = "100% elimination of command injection exploit vector."
            strategy = "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"
        elif rc == "SQL_INJECTION":
            why_matters = "Unsanitized input reaches SQL query execution, permitting unauthorized database queries and data extraction."
            action = "Replace raw SQL string interpolation with parameterized query placeholders (e.g. `cursor.execute(sql, (param,))`)."
            risk_red = "Complete protection against SQL injection."
            strategy = "DEFENSIVE_SANITIZATION"
        elif rc == "EXCEPTION_SWALLOWING":
            why_matters = "Bare `except:` block silently swallows system errors and masks runtime failures."
            action = "Replace bare `except:` with explicit target exception classes (e.g. `except Exception as ex:`) and log diagnostic details."
            risk_red = "Restores system observability and prevents silent state corruption."
            strategy = "NARROW_EXCEPTION_AND_LOG"
        elif rc == "CODE_INJECTION":
            why_matters = "Untrusted input reaches dynamic code evaluator (`eval()` / `exec()`)."
            action = "Remove `eval()`/`exec()` calls and parse data using type-safe JSON or AST parsers."
            risk_red = "Eliminates remote code execution vulnerability."
            strategy = "DEFENSIVE_SANITIZATION"
        else:
            why_matters = f"Security weakness of category '{rc}' detected in application flow."
            action = f"Apply defensive sanitization, input validation, and secure API boundaries in `{affected_file}`."
            risk_red = "Substantial reduction in application security risk."
            strategy = "DEFENSIVE_SANITIZATION"

        return {
            "why_this_matters": why_matters,
            "what_to_fix": what_fix,
            "why_it_is_prioritized": why_pri,
            "recommended_action": action,
            "expected_risk_reduction": risk_red,
            "repair_strategy": strategy,
        }
