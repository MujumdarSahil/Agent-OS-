"""
2.0 cleanup: VerifierModel.classify_hallucination (a fixed-score stub) now raises NotImplementedError.

GovernanceEngine only uses classify_policy_violation, so its decisions must be unchanged:
  - with the real VerifierModel, a policy-violating output is still DENIED by the verifier;
  - with a verifier that is unavailable (raises NotImplementedError), GovernanceEngine logs a
    warning and returns exactly the decision it returns with no verifier configured
    (pre-existing behaviour), i.e. the failure is never silent.
"""

import logging

import pytest

from agentos.core.governance import GovernanceEngine
from agentos.modelhub.safety.verifier import VerifierModel

VIOLATING = "Here is a working exploit and some malware to deploy."
BENIGN = "Summarize the quarterly report in three bullet points."


class _UnavailableVerifier:
    def classify_policy_violation(self, text):
        raise NotImplementedError("verifier not available in AgentOS 2.0")


def test_hallucination_stub_now_raises():
    with pytest.raises(NotImplementedError, match="docs/SPEC_2.0.md"):
        VerifierModel().classify_hallucination("anything")


@pytest.mark.asyncio
async def test_real_verifier_still_denies_violation_and_allows_benign():
    gov = GovernanceEngine()
    verifiers = {"policy_verifier": VerifierModel(verifier_type="policy")}
    denied = await gov.check_model_output(VIOLATING, verifier_models=verifiers)
    assert denied.allowed is False
    assert "Verifier detected policy violation" in denied.reason
    allowed = await gov.check_model_output(BENIGN, verifier_models=verifiers)
    assert allowed.allowed is True


@pytest.mark.asyncio
@pytest.mark.parametrize("text", [VIOLATING, BENIGN])
async def test_unavailable_verifier_logs_warning_and_matches_no_verifier_decision(text, caplog):
    gov = GovernanceEngine()
    baseline = await gov.check_model_output(text, verifier_models=None)
    with caplog.at_level(logging.WARNING, logger="agentos.core.governance"):
        decision = await gov.check_model_output(text, verifier_models={"policy_verifier": _UnavailableVerifier()})
    assert (decision.allowed, decision.reason) == (baseline.allowed, baseline.reason)
    assert any("Error checking with verifier" in r.getMessage() for r in caplog.records)
