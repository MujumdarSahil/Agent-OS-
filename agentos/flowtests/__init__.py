"""4.2 flow test cases: save real runs as tests, write expectations, run them against a flow version and against
different models with fake transports only, compare models, see regressions, optional publish gate.
Design: docs/evidence/4.2.md."""

from agentos.flowtests.models import CaseResult, GateSettings, SuiteRun, TestCase
from agentos.flowtests.runner import TestEnv, run_case
from agentos.flowtests.service import FlowTestError, compare_models, execute_suite, gate_check, resolve_flow
from agentos.flowtests.store import FlowTestStore, flowtests_store_for

__all__ = ["CaseResult", "FlowTestError", "FlowTestStore", "GateSettings", "SuiteRun", "TestCase", "TestEnv",
           "compare_models", "execute_suite", "flowtests_store_for", "gate_check", "resolve_flow", "run_case"]
