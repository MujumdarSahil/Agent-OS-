"""
M22 Security Scenario Generator.

Generates safe synthetic reproduction scenarios for supported vulnerability classes:
- COMMAND_INJECTION: Uses harmless local marker command ('echo M22_TEST_MARKER').
- SQL_INJECTION: Uses isolated in-memory or temporary SQLite database.
- PATH_TRAVERSAL: Uses synthetic sandbox file ('sandbox_test.txt').
- SSRF: Uses localhost-only loopback endpoint ('http://127.0.0.1:8080/health').
- XSS: Uses inert string marker ('<script>/*M22_MARKER*/</script>').
- CODE_INJECTION: Uses harmless arithmetic marker ('1 + 1').
"""

from typing import Dict, Any, List, Optional
from agentos_swe.remediation.simulation.models import SimulationScenario


class SecurityScenarioGenerator:
    """
    Generates safe synthetic reproduction scenarios for vulnerability findings.
    """

    SAFE_SYNTHETIC_MARKERS = {
        "COMMAND_INJECTION": "echo M22_TEST_MARKER",
        "SQL_INJECTION": "' UNION SELECT 'M22_TEST_MARKER' --",
        "PATH_TRAVERSAL": "../sandbox_test.txt",
        "SSRF": "http://127.0.0.1:8080/health",
        "XSS": "<script>/*M22_MARKER*/</script>",
        "CODE_INJECTION": "1 + 1",
    }

    def generate_scenario(
        self,
        finding: Dict[str, Any],
        attack_path: Optional[Dict[str, Any]] = None,
    ) -> SimulationScenario:
        """
        Constructs a safe SimulationScenario instance.
        """
        fid = str(finding.get("finding_id") or finding.get("id") or "f_1")
        rc = str(finding.get("root_cause") or finding.get("category") or "UNKNOWN").upper()
        src = str(finding.get("source_type") or finding.get("source") or "HTTP").upper()
        snk = str(finding.get("sink_type") or finding.get("sink") or "SINK").upper()

        marker = self.SAFE_SYNTHETIC_MARKERS.get(rc, "M22_SAFE_MARKER")

        return SimulationScenario(
            scenario_id=f"scen_{fid}",
            vulnerability_id=fid,
            root_cause=rc,
            source=src,
            sink=snk,
            attack_path=attack_path,
            preconditions=["IsolatedSandbox active", "Safe synthetic marker injected"],
            expected_behavior=f"Safe execution of synthetic marker '{marker}'",
            safety_constraints=["Localhost target only", "No external egress", "10s execution timeout"],
            severity=str(finding.get("severity") or "HIGH").upper(),
        )
