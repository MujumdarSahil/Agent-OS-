"""
Governance & Policy Engine - Enforces policies for actions, privacy, and resources.

Phase 4 additions:
  - _keyword_policy_check: the original fast substring-matching safety check (renamed for clarity)
  - _llm_judge_policy_check: optional second layer that sends task+policies to an LLM for
    semantic evaluation. Fails OPEN (judge layer only) if LLM is unavailable or returns
    malformed JSON — the keyword layer still applies normally.
  - Both layers run in sequence in check(); either can block.
  - The LLM judge layer is OPT-IN via project config: governance.llm_judge_enabled=true.
    Default is false — zero latency/cost impact for existing projects.
"""

from typing import Dict, Any, Optional, List, Callable, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum
import json
import logging
import uuid

if TYPE_CHECKING:
    from agentos.llm.llm_client import LLMClient

logger = logging.getLogger(__name__)


class PolicyType(Enum):
    """Types of policies"""
    ACTION = "action"  # Allow/deny tool usage
    PRIVACY = "privacy"  # Memory sharing policies
    RESOURCE = "resource"  # Resource limits
    SAFETY = "safety"  # Safety constraints


@dataclass
class PolicyDecision:
    """Policy decision result"""
    allowed: bool
    reason: str = ""
    policy_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class Policy:
    """Base policy class"""

    def __init__(
        self,
        id: str,
        policy_type: PolicyType,
        name: str,
        check_func: Callable,
        priority: int = 0
    ):
        self.id = id
        self.policy_type = policy_type
        self.name = name
        self.check_func = check_func
        self.priority = priority

    async def check(self, agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
        """Check policy"""
        try:
            result = await self.check_func(agent_id, action, context)
            if isinstance(result, bool):
                return PolicyDecision(
                    allowed=result,
                    policy_id=self.id,
                    reason=f"Policy {self.name} check",
                )
            elif isinstance(result, PolicyDecision):
                result.policy_id = self.id
                return result
            else:
                return PolicyDecision(
                    allowed=False,
                    policy_id=self.id,
                    reason="Invalid policy check result",
                )
        except Exception as e:
            return PolicyDecision(
                allowed=False,
                policy_id=self.id,
                reason=f"Policy check error: {str(e)}",
            )


class GovernanceEngine:
    """
    Governance engine that enforces policies for agent actions.

    Phase 4: Two-layer safety system.
      Layer 1 (keyword): Fast substring matching. Free, instant, always runs.
                         Trivially bypassable by rephrasing — see GOVERNANCE.md.
      Layer 2 (LLM judge): Optional semantic evaluation via LLMClient.
                            Opt-in via governance.llm_judge_enabled=true in config.
                            Fails open (judge layer only) on malformed response or LLM unavailability.
                            Adds ~1 LLM call per task check when enabled.
    """

    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self.policy_groups: Dict[str, List[str]] = {}  # group_name -> policy_ids
        # Security Safety Layer - explicit allow/deny lists
        self.security_allow_list: List[str] = [
            "password auditing",
            "metadata-based network monitoring",
            "configuration auditing",
            "defensive cybersecurity scripts",
        ]
        self.security_deny_list: List[str] = [
            "exploit code",
            "malware or payload generation",
            "password cracking or brute-force attempts",
            "intrusive/active scanning",
            "privilege escalation automation",
        ]
        # Phase 4: LLM judge config (set by caller; None = disabled)
        self._llm_judge_enabled: bool = False
        self._llm_client: Optional["LLMClient"] = None

    def configure_llm_judge(self, enabled: bool, llm_client: Optional["LLMClient"] = None) -> None:
        """
        Configure the optional LLM judge layer.

        Args:
            enabled: If True, the LLM judge runs after the keyword layer when
                     the keyword layer does NOT block. Requires llm_client.
            llm_client: LLMClient instance to use for judge calls.
                        If None and enabled=True, judge is skipped with a warning.
        """
        self._llm_judge_enabled = enabled
        self._llm_client = llm_client
        if enabled and llm_client is None:
            logger.warning(
                "GovernanceEngine: llm_judge_enabled=True but no llm_client provided. "
                "Judge layer will be skipped (fail-open). Provide an LLMClient to enable it."
            )

    # -------------------------------------------------------------------------
    # Policy registration
    # -------------------------------------------------------------------------

    def register_policy(
        self,
        policy: Policy,
        group: Optional[str] = None
    ) -> str:
        """Register a policy."""
        self.policies[policy.id] = policy
        if group:
            if group not in self.policy_groups:
                self.policy_groups[group] = []
            self.policy_groups[group].append(policy.id)
        return policy.id

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy"""
        if policy_id in self.policies:
            del self.policies[policy_id]
            for group_policies in self.policy_groups.values():
                if policy_id in group_policies:
                    group_policies.remove(policy_id)
            return True
        return False

    # -------------------------------------------------------------------------
    # Phase 4: LLM Judge Layer (private)
    # -------------------------------------------------------------------------

    def _build_judge_prompt(self, task_description: str) -> str:
        """
        Build the structured prompt for the LLM judge.
        Includes active keyword-based deny lists for context.
        """
        # Collect deny keywords from active policies for context
        deny_keywords = []
        for p in self.policies.values():
            if hasattr(p, '_denied_keywords'):
                deny_keywords.extend(p._denied_keywords)
        # Also include the built-in security deny list
        deny_keywords.extend([
            "crack password", "brute force", "exploit vulnerability",
            "create malware", "unauthorized access",
            "exploit code", "malware or payload generation",
            "password cracking or brute-force attempts",
            "intrusive/active scanning", "privilege escalation automation",
        ])
        deny_list_text = "\n".join(f"  - {k}" for k in sorted(set(deny_keywords)))

        return (
            "You are a security and safety policy enforcement judge for an AI agent framework.\n"
            "Your job is to evaluate whether the following task description violates any safety policies.\n\n"
            "PROHIBITED CATEGORIES (examples — not exhaustive; use semantic judgment):\n"
            f"{deny_list_text}\n\n"
            "TASK DESCRIPTION TO EVALUATE:\n"
            f"{task_description}\n\n"
            "Respond with ONLY valid JSON in this exact format, no other text:\n"
            '{"blocked": true/false, "reason": "one sentence explanation"}\n\n'
            "Be conservative: block if the task is clearly or likely attempting something harmful.\n"
            "Do NOT block legitimate defensive security, research, analysis, or ordinary tasks.\n"
            "Do NOT add markdown code fences or extra text — JSON only."
        )

    def _parse_judge_response(self, response_text: str) -> Optional[Dict[str, Any]]:
        """
        Parse LLM judge response. Returns None if response is not valid JSON
        with the expected schema.
        """
        # Strip markdown fences if present
        text = response_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]) if len(lines) > 2 else text
        text = text.strip()

        try:
            data = json.loads(text)
            if isinstance(data, dict) and "blocked" in data and "reason" in data:
                return data
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    async def _llm_judge_policy_check(
        self,
        task_description: str,
    ) -> PolicyDecision:
        """
        Phase 4: Optional LLM semantic judge layer.

        Sends task_description to the LLMClient with a structured prompt.
        Parses JSON response {"blocked": bool, "reason": str}.
        Retries once with a correction prompt if JSON is malformed.
        Fails OPEN (allows) if both attempts fail — logs a clear warning.

        Returns:
            PolicyDecision with allowed=True/False based on judge verdict.
            On failure: allowed=True (fail open) with warning logged.
        """
        if self._llm_client is None:
            logger.warning(
                "GovernanceEngine LLM judge: no llm_client configured, skipping judge (fail-open)"
            )
            return PolicyDecision(allowed=True, reason="LLM judge skipped: no client configured")

        prompt = self._build_judge_prompt(task_description)
        messages = [{"role": "user", "content": prompt}]

        # Attempt 1
        try:
            response = self._llm_client.complete(messages=messages)
            content = (
                response.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            parsed = self._parse_judge_response(content)
            if parsed is not None:
                blocked = bool(parsed.get("blocked", False))
                reason = str(parsed.get("reason", "LLM judge verdict"))
                if blocked:
                    logger.warning(f"[LLM Judge] Blocked task: {reason}")
                else:
                    logger.info(f"[LLM Judge] Task allowed: {reason}")
                return PolicyDecision(
                    allowed=not blocked,
                    reason=f"[LLM Judge] {reason}",
                )
        except Exception as e:
            logger.warning(f"GovernanceEngine LLM judge attempt 1 failed: {e}")
            # Fall through to retry

        # Attempt 2: correction prompt
        correction_prompt = (
            "Your previous response was not valid JSON. You MUST respond with ONLY this JSON format:\n"
            '{"blocked": true, "reason": "explanation"}\n'
            "or\n"
            '{"blocked": false, "reason": "explanation"}\n\n'
            f"Re-evaluate this task: {task_description}"
        )
        messages2 = [{"role": "user", "content": correction_prompt}]
        try:
            response2 = self._llm_client.complete(messages=messages2)
            content2 = (
                response2.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            parsed2 = self._parse_judge_response(content2)
            if parsed2 is not None:
                blocked = bool(parsed2.get("blocked", False))
                reason = str(parsed2.get("reason", "LLM judge verdict (retry)"))
                if blocked:
                    logger.warning(f"[LLM Judge retry] Blocked task: {reason}")
                else:
                    logger.info(f"[LLM Judge retry] Task allowed: {reason}")
                return PolicyDecision(
                    allowed=not blocked,
                    reason=f"[LLM Judge retry] {reason}",
                )
        except Exception as e:
            logger.warning(f"GovernanceEngine LLM judge attempt 2 failed: {e}")

        # Both attempts failed — FAIL OPEN on judge layer only
        logger.warning(
            "GovernanceEngine LLM judge: both attempts failed (malformed JSON or LLM error). "
            "FAILING OPEN on judge layer — keyword layer still applies. "
            "Check LLM provider availability or disable governance.llm_judge_enabled."
        )
        return PolicyDecision(
            allowed=True,
            reason="[LLM Judge] Failed open — judge layer unavailable (both attempts failed)"
        )

    # -------------------------------------------------------------------------
    # Phase 4: Keyword check layer (renamed for clarity, behavior unchanged)
    # -------------------------------------------------------------------------

    async def _keyword_policy_check(
        self,
        agent_id: str,
        action: str,
        context: Dict[str, Any]
    ) -> PolicyDecision:
        """
        Layer 1: Keyword-based substring policy check.

        Runs all registered policies (sorted by priority).
        This is the original behavior from Phase 1-3, renamed for clarity.
        Fast, free, zero-latency. Trivially bypassable by rephrasing — see GOVERNANCE.md.
        """
        relevant_policies = [
            p for p in self.policies.values()
            if self._is_relevant(p, action, context)
        ]
        relevant_policies.sort(key=lambda p: p.priority, reverse=True)

        for policy in relevant_policies:
            decision = await policy.check(agent_id, action, context)
            if not decision.allowed:
                logger.warning(
                    f"[Keyword Layer] Blocked by policy '{policy.name}': {decision.reason}"
                )
                return decision

        return PolicyDecision(allowed=True, reason="Keyword layer: all policy checks passed")

    # -------------------------------------------------------------------------
    # Main entry point — both layers
    # -------------------------------------------------------------------------

    async def check(
        self,
        agent_id: str,
        action: str,
        context: Dict[str, Any]
    ) -> PolicyDecision:
        """
        Check if an action is allowed by policies.

        Phase 4: Runs TWO layers in sequence:
          1. Keyword layer (always runs — fast, free)
          2. LLM judge layer (only if llm_judge_enabled=True AND keyword layer didn't block)

        Either layer can block. If the keyword layer blocks, the LLM judge is NOT called.
        The LLM judge fails open (allows) on errors — the keyword layer still applies normally.

        Args:
            agent_id: Agent ID
            action: Action name (e.g., "execute", "memory_read", "tool_call")
            context: Context dictionary with agent, task, etc.

        Returns:
            PolicyDecision
        """
        # --- Layer 1: Keyword check (always) ---
        keyword_decision = await self._keyword_policy_check(agent_id, action, context)
        if not keyword_decision.allowed:
            return keyword_decision  # Keyword layer blocked — done, no LLM call

        # --- Layer 2: LLM judge (opt-in, only if keyword layer passed) ---
        if self._llm_judge_enabled and self._llm_client is not None:
            # Extract task description from context for the judge
            task = context.get("task", {})
            task_desc = ""
            if isinstance(task, dict):
                task_desc = task.get("description", "")
            elif isinstance(task, str):
                task_desc = task

            if task_desc and action in ["execute", "tool_call", "request_tool", "generate_script"]:
                judge_decision = await self._llm_judge_policy_check(task_desc)
                if not judge_decision.allowed:
                    return judge_decision  # LLM judge blocked

        return PolicyDecision(allowed=True, reason="All policy checks passed")

    def _is_relevant(self, policy: Policy, action: str, context: Dict[str, Any]) -> bool:
        """Check if a policy is relevant to the action"""
        if policy.policy_type == PolicyType.ACTION:
            return action in ["execute", "tool_call", "request_tool"]
        elif policy.policy_type == PolicyType.PRIVACY:
            return action in ["memory_read", "memory_write", "memory_share"]
        elif policy.policy_type == PolicyType.RESOURCE:
            return action in ["execute", "tool_call"]
        elif policy.policy_type == PolicyType.SAFETY:
            # Safety policies are always relevant
            return action in ["execute", "tool_call", "request_tool", "generate_script"] or True
        return False

    # -------------------------------------------------------------------------
    # Policy factory methods (unchanged from Phase 1-3)
    # -------------------------------------------------------------------------

    def create_action_policy(
        self,
        name: str,
        allowed_actions: List[str] = None,
        denied_actions: List[str] = None,
        check_func: Optional[Callable] = None,
        priority: int = 0
    ) -> Policy:
        """Create an action policy (allow/deny tool usage)."""
        policy_id = str(uuid.uuid4())

        if check_func:
            check = check_func
        else:
            async def check(agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
                if denied_actions and action in denied_actions:
                    return PolicyDecision(
                        allowed=False,
                        reason=f"Action '{action}' is denied by policy",
                    )
                if allowed_actions and action not in allowed_actions:
                    return PolicyDecision(
                        allowed=False,
                        reason=f"Action '{action}' is not in allowed list",
                    )
                return PolicyDecision(allowed=True)

            check = check

        return Policy(
            id=policy_id,
            policy_type=PolicyType.ACTION,
            name=name,
            check_func=check,
            priority=priority,
        )

    def create_privacy_policy(
        self,
        name: str,
        allowed_scopes: List[str] = None,
        check_func: Optional[Callable] = None,
        priority: int = 0
    ) -> Policy:
        """Create a privacy policy (memory sharing)."""
        policy_id = str(uuid.uuid4())

        if check_func:
            check = check_func
        else:
            async def check(agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
                if action == "memory_read" or action == "memory_write":
                    scope = context.get("scope", "agent_private")
                    if allowed_scopes and scope not in allowed_scopes:
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Scope '{scope}' not allowed by privacy policy",
                        )
                return PolicyDecision(allowed=True)

            check = check

        return Policy(
            id=policy_id,
            policy_type=PolicyType.PRIVACY,
            name=name,
            check_func=check,
            priority=priority,
        )

    def create_resource_policy(
        self,
        name: str,
        max_tokens: Optional[int] = None,
        max_api_calls: Optional[int] = None,
        check_func: Optional[Callable] = None,
        priority: int = 0
    ) -> Policy:
        """Create a resource policy (resource limits)."""
        policy_id = str(uuid.uuid4())

        if check_func:
            check = check_func
        else:
            async def check(agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
                agent = context.get("agent")
                if agent:
                    metrics = agent.resource_metrics
                    if max_tokens and metrics.get("token_usage", 0) >= max_tokens:
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Token limit ({max_tokens}) exceeded",
                        )
                    if max_api_calls and metrics.get("api_calls", 0) >= max_api_calls:
                        return PolicyDecision(
                            allowed=False,
                            reason=f"API call limit ({max_api_calls}) exceeded",
                        )
                return PolicyDecision(allowed=True)

            check = check

        return Policy(
            id=policy_id,
            policy_type=PolicyType.RESOURCE,
            name=name,
            check_func=check,
            priority=priority,
        )

    def create_security_safety_layer(self, priority: int = 100) -> Policy:
        """
        Create Security Safety Layer policy with explicit allow/deny lists.
        Behavior unchanged from Phase 1-3 — this is Layer 1 (keyword layer) content.
        """
        import re

        policy_id = str(uuid.uuid4())

        async def security_safety_check(agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
            task = context.get("task", {})
            tool_name = context.get("tool_name", "")
            script_content = context.get("script_content", "")
            script_preview = context.get("script_preview", "")
            mcp_name = context.get("mcp_name", "")

            logger.info(f"Security Safety Layer check: agent={agent_id}, action={action}")

            if action in ["tool_call", "request_tool", "execute", "mcp_call"]:
                operation_desc = (
                    tool_name.lower() + " " +
                    (task.get("description", "") or "").lower() + " " +
                    (mcp_name or "").lower()
                )

                allowed = False
                for allowed_op in self.security_allow_list:
                    if allowed_op.lower() in operation_desc:
                        allowed = True
                        logger.info(f"Operation allowed: {allowed_op}")
                        break

                for denied_op in self.security_deny_list:
                    if denied_op.lower() in operation_desc:
                        denied = True
                        logger.warning(f"Operation denied: {denied_op}")
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Security Safety Layer: Operation '{denied_op}' is in deny_list",
                            metadata={"denied_operation": denied_op}
                        )

                if any(keyword in operation_desc for keyword in ["password", "network", "audit", "security", "firewall", "log"]):
                    if not allowed:
                        return PolicyDecision(
                            allowed=False,
                            reason="Security Safety Layer: Security operation not in allow_list",
                        )

            if action == "generate_script" or "script" in action.lower():
                script_text = script_content or script_preview or ""
                script_lower = script_text.lower()

                deny_patterns = [
                    (r"exploit", "exploit code"),
                    (r"malware|trojan|virus|payload", "malware or payload generation"),
                    (r"password.*crack|brute.*force", "password cracking or brute-force attempts"),
                    (r"active.*scan|intrusive.*scan|port.*scan.*active", "intrusive/active scanning"),
                    (r"privilege.*escalation|sudo.*exploit|root.*exploit", "privilege escalation automation"),
                ]

                for pattern, deny_reason in deny_patterns:
                    if re.search(pattern, script_lower):
                        logger.warning(f"Script pattern denied: {deny_reason}")
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Security Safety Layer: Script contains prohibited pattern - {deny_reason}",
                            metadata={"prohibited_pattern": deny_reason}
                        )

                allowed_patterns = [
                    r"firewall.*config|ufw|iptables",
                    r"log.*analysis|log.*parse",
                    r"siem.*ingestion",
                    r"permission.*audit|user.*audit",
                    r"network.*metadata|metadata.*inventory",
                    r"config.*audit|configuration.*audit",
                ]

                script_allowed = any(re.search(pattern, script_lower) for pattern in allowed_patterns)
                if script_text and not script_allowed:
                    logger.warning("Script does not match allowed defensive patterns")

            return PolicyDecision(allowed=True, reason="Security Safety Layer check passed")

        return Policy(
            id=policy_id,
            policy_type=PolicyType.SAFETY,
            name="Security Safety Layer",
            check_func=security_safety_check,
            priority=priority,
        )

    def create_security_policy(
        self,
        name: str = "Security Policy",
        priority: int = 100
    ) -> Policy:
        """
        Create a security policy that prohibits harmful cybersecurity operations.
        Behavior unchanged from Phase 1-3 — this is Layer 1 (keyword layer) content.
        """
        import re

        policy_id = str(uuid.uuid4())

        async def security_check(agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
            task = context.get("task", {})
            tool_name = context.get("tool_name", "")
            script_content = context.get("script_content", "")
            script_preview = context.get("script_preview", "")

            if action in ["tool_call", "request_tool", "execute"]:
                prohibited_tools = [
                    "crack_password",
                    "brute_force",
                    "exploit",
                    "malware",
                    "trojan",
                    "backdoor",
                    "unauthorized_access",
                ]

                tool_lower = tool_name.lower() if tool_name else ""
                task_desc = task.get("description", "").lower() if task else ""

                for prohibited in prohibited_tools:
                    if prohibited in tool_lower or prohibited in task_desc:
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Security policy violation: Prohibited tool/action '{prohibited}' detected",
                        )

            if action == "generate_script":
                script_text = script_content or script_preview or ""
                script_lower = script_text.lower()

                prohibited_patterns = [
                    (r"password.*crack", "Password cracking scripts are prohibited"),
                    (r"brute.*force", "Brute force attacks are prohibited"),
                    (r"exploit", "Exploit code generation is prohibited"),
                    (r"malware|trojan|virus", "Malware creation is prohibited"),
                    (r"backdoor", "Backdoor creation is prohibited"),
                    (r"unauthorized.*access", "Unauthorized access attempts are prohibited"),
                    (r"privilege.*escalation", "Privilege escalation exploits are prohibited"),
                ]

                for pattern, reason in prohibited_patterns:
                    if re.search(pattern, script_lower):
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Security policy violation: {reason}",
                        )

            if task:
                task_desc = task.get("description", "").lower()
                task_type = task.get("type", "").lower()

                prohibited_actions = [
                    "crack password",
                    "brute force",
                    "exploit vulnerability",
                    "create malware",
                    "unauthorized access",
                ]

                for prohibited in prohibited_actions:
                    if prohibited in task_desc or prohibited in task_type:
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Security policy violation: Prohibited action '{prohibited}' in task",
                        )

            return PolicyDecision(allowed=True, reason="Security policy check passed")

        return Policy(
            id=policy_id,
            policy_type=PolicyType.SAFETY,
            name=name,
            check_func=security_check,
            priority=priority,
        )

    def initialize_security_policies(self):
        """
        Initialize default security policies including Security Safety Layer.
        Behavior unchanged from Phase 1-3.
        """
        safety_layer = self.create_security_safety_layer(priority=100)
        self.register_policy(safety_layer, group="security")

        security_policy = self.create_security_policy(
            name="Default Security Policy",
            priority=90
        )
        self.register_policy(security_policy, group="security")

        script_policy = self.create_action_policy(
            name="Script Generation Security",
            denied_actions=["generate_exploit", "generate_malware", "generate_cracker"],
            priority=80
        )
        self.register_policy(script_policy, group="security")

        return [safety_layer.id, security_policy.id, script_policy.id]

    async def check_model_output(
        self,
        model_output: str,
        verifier_models: Optional[Dict[str, Any]] = None
    ) -> PolicyDecision:
        """
        Check model output using verifier models and constitutional rules.
        Behavior unchanged from Phase 1-3.
        """
        decision = await self.check(
            agent_id="model_output_checker",
            action="generate_script",
            context={
                "script_content": model_output,
                "script_preview": model_output[:500],
            }
        )

        if not decision.allowed:
            return decision

        if verifier_models:
            try:
                from agentos.modelhub.safety.verifier import VerifierModel

                verifier = verifier_models.get("policy_verifier")
                if verifier:
                    violation_result = verifier.classify_policy_violation(model_output)
                    if violation_result.get("violates_policy"):
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Verifier detected policy violation: {violation_result.get('violations', [])}",
                        )
            except Exception as e:
                logger.warning(f"Error checking with verifier: {e}")

        try:
            from agentos.modelhub.safety.constitutional_ai import ConstitutionalAI

            constitutional_ai = ConstitutionalAI()
            constitutional_check = await constitutional_ai.check_output(model_output)

            if not constitutional_check.get("allowed"):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Constitutional AI check failed: {constitutional_check.get('remediation', 'Output violates constitutional rules')}",
                )
        except Exception as e:
            logger.warning(f"Error checking with Constitutional AI: {e}")

        return PolicyDecision(allowed=True, reason="Model output passed all safety checks")
