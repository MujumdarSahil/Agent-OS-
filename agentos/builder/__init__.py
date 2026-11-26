"""4.0 natural-language flow builder ("Describe it"). Design: docs/evidence/4.0.md.

The model is never trusted for safety: everything it produces is a DRAFT that must pass the same FlowDefinition
validation and StaticFlowAnalyzer check as the Publish gate. The builder never saves and never publishes.
No FastAPI or Mongo imports here (ports and adapters); the HTTP layer is agentos_server/routes_v2/builder.py.
"""

from agentos.builder.service import BuilderInputError, BuilderRequest, NLFlowBuilder, check_report

__all__ = ["BuilderInputError", "BuilderRequest", "NLFlowBuilder", "check_report"]
