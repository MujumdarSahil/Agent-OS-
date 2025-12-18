"""
Governance & Policy Engine - Enforces policies for actions, privacy, and resources
"""

from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from enum import Enum
import uuid


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
    
    def register_policy(
        self,
        policy: Policy,
        group: Optional[str] = None
    ) -> str:
        """
        Register a policy.
        
        Args:
            policy: Policy instance
            group: Optional policy group name
            
        Returns:
            Policy ID
        """
        self.policies[policy.id] = policy
        
        if group:
            if group not in self.policy_groups:
                self.policy_groups[group] = []
            self.policy_groups[group].append(policy.id)
        
        return policy.id
    
    def create_action_policy(
        self,
        name: str,
        allowed_actions: List[str] = None,
        denied_actions: List[str] = None,
        check_func: Optional[Callable] = None,
        priority: int = 0
    ) -> Policy:
        """
        Create an action policy (allow/deny tool usage).
        
        Args:
            name: Policy name
            allowed_actions: List of allowed action names
            denied_actions: List of denied action names
            check_func: Custom check function
            priority: Policy priority (higher = checked first)
            
        Returns:
            Policy instance
        """
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
        """
        Create a privacy policy (memory sharing).
        
        Args:
            name: Policy name
            allowed_scopes: Allowed memory scopes
            check_func: Custom check function
            priority: Policy priority
            
        Returns:
            Policy instance
        """
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
        """
        Create a resource policy (resource limits).
        
        Args:
            name: Policy name
            max_tokens: Maximum tokens allowed
            max_api_calls: Maximum API calls allowed
            check_func: Custom check function
            priority: Policy priority
            
        Returns:
            Policy instance
        """
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
    
    async def check(
        self,
        agent_id: str,
        action: str,
        context: Dict[str, Any]
    ) -> PolicyDecision:
        """
        Check if an action is allowed by policies.
        
        Args:
            agent_id: Agent ID
            action: Action name (e.g., "execute", "memory_read", "tool_call")
            context: Context dictionary with agent, task, etc.
            
        Returns:
            PolicyDecision
        """
        # Get relevant policies (sorted by priority)
        relevant_policies = [
            p for p in self.policies.values()
            if self._is_relevant(p, action, context)
        ]
        relevant_policies.sort(key=lambda p: p.priority, reverse=True)
        
        # Check each policy
        for policy in relevant_policies:
            decision = await policy.check(agent_id, action, context)
            if not decision.allowed:
                return decision
        
        # All policies passed
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
            # Safety policies are always relevant, but also check for script generation
            return action in ["execute", "tool_call", "request_tool", "generate_script"] or True
        return False
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy"""
        if policy_id in self.policies:
            del self.policies[policy_id]
            # Remove from groups
            for group_policies in self.policy_groups.values():
                if policy_id in group_policies:
                    group_policies.remove(policy_id)
            return True
        return False
    
    def create_security_safety_layer(self, priority: int = 100) -> Policy:
        """
        Create Security Safety Layer policy with explicit allow/deny lists.
        
        This layer ensures all security tools route through governance checks
        and enforces pattern-scanning for ScriptAuthorAgent output.
        
        Args:
            priority: Policy priority (default: 100, high priority)
            
        Returns:
            Policy instance
        """
        import re
        import logging
        
        logger = logging.getLogger(__name__)
        policy_id = str(uuid.uuid4())
        
        async def security_safety_check(agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
            """
            Security Safety Layer check function.
            Routes all security tools through this layer.
            """
            task = context.get("task", {})
            tool_name = context.get("tool_name", "")
            script_content = context.get("script_content", "")
            script_preview = context.get("script_preview", "")
            mcp_name = context.get("mcp_name", "")
            
            # Log security operation
            logger.info(f"Security Safety Layer check: agent={agent_id}, action={action}")
            
            # Check allow_list for security operations
            if action in ["tool_call", "request_tool", "execute", "mcp_call"]:
                operation_desc = (
                    tool_name.lower() + " " + 
                    (task.get("description", "") or "").lower() + " " +
                    (mcp_name or "").lower()
                )
                
                # Check if operation matches allow_list
                allowed = False
                for allowed_op in self.security_allow_list:
                    if allowed_op.lower() in operation_desc:
                        allowed = True
                        logger.info(f"Operation allowed: {allowed_op}")
                        break
                
                # Check deny_list
                denied = False
                for denied_op in self.security_deny_list:
                    if denied_op.lower() in operation_desc:
                        denied = True
                        logger.warning(f"Operation denied: {denied_op}")
                        return PolicyDecision(
                            allowed=False,
                            reason=f"Security Safety Layer: Operation '{denied_op}' is in deny_list",
                            metadata={"denied_operation": denied_op}
                        )
                
                # If security-related operation, must be in allow_list
                if any(keyword in operation_desc for keyword in ["password", "network", "audit", "security", "firewall", "log"]):
                    if not allowed:
                        return PolicyDecision(
                            allowed=False,
                            reason="Security Safety Layer: Security operation not in allow_list",
                        )
            
            # Pattern-scanning for ScriptAuthorAgent output
            if action == "generate_script" or "script" in action.lower():
                script_text = script_content or script_preview or ""
                script_lower = script_text.lower()
                
                # Check deny_list patterns in script
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
                
                # Check allow_list patterns in script
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
                    # If script has content but doesn't match allowed patterns, warn
                    logger.warning("Script does not match allowed defensive patterns")
            
            # All checks passed
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
        priority: int = 100  # High priority for security
    ) -> Policy:
        """
        Create a security policy that prohibits harmful cybersecurity operations.
        
        Prohibits:
        - Exploit code generation
        - Malware creation
        - Password cracking (actual cracking, not auditing)
        - Unauthorized access attempts
        
        Allows:
        - Password auditing (policy evaluation, hash identification)
        - Monitoring tools (log analysis, anomaly detection)
        - System hardening automation (configuration checks, firewall validation)
        - Defensive security scripts
        
        Args:
            name: Policy name
            priority: Policy priority (default: 100, high priority)
            
        Returns:
            Policy instance
        """
        import re
        
        policy_id = str(uuid.uuid4())
        
        async def security_check(agent_id: str, action: str, context: Dict[str, Any]) -> PolicyDecision:
            """Security policy check function"""
            task = context.get("task", {})
            tool_name = context.get("tool_name", "")
            script_content = context.get("script_content", "")
            script_preview = context.get("script_preview", "")
            
            # Check for prohibited patterns in tool calls
            if action in ["tool_call", "request_tool", "execute"]:
                # Prohibited tool patterns
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
            
            # Check for prohibited patterns in script generation
            if action == "generate_script":
                script_text = script_content or script_preview or ""
                script_lower = script_text.lower()
                
                # Prohibited script patterns
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
            
            # Check task description for prohibited actions
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
            
            # All checks passed
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
        
        This method sets up the standard security policy framework:
        - Security Safety Layer with explicit allow/deny lists
        - Prohibits exploit code, malware, password cracking
        - Allows password auditing, monitoring, system hardening
        - Ensures all security tools route through governance
        """
        # Create Security Safety Layer (highest priority)
        safety_layer = self.create_security_safety_layer(priority=100)
        self.register_policy(safety_layer, group="security")
        
        # Create main security policy
        security_policy = self.create_security_policy(
            name="Default Security Policy",
            priority=90
        )
        self.register_policy(security_policy, group="security")
        
        # Create script generation policy
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
        
        Args:
            model_output: Model output to check
            verifier_models: Verifier model instances
            
        Returns:
            PolicyDecision
        """
        # Check against security safety layer
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
        
        # Check with verifier models if available
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
        
        # Check with Constitutional AI if available
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

