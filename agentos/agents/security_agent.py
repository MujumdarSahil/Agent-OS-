"""
Security Agent - Specialized agent for cybersecurity operations

Inherits from BaseAgent (core.agent.Agent) and provides:
- Built-in roles: auditor, monitor, analyst, policy-advisor
- Auto-bind security MCP servers
- Auto-store mission results into UMB
- Support squad collaboration
"""

import logging
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime
from agentos.core.agent import Agent
from agentos.core.base import BaseTool, ToolRegistry
from agentos.mcp_connectors.base_mcp import BaseMCPConnector

logger = logging.getLogger(__name__)


class SecurityWrapperTool(BaseTool):
    """
    A helper tool wrapper that bridges older callable-style tools to BaseTool.
    """
    def __init__(self, name: str, description: str, func: Any):
        super().__init__(name=name, description=description)
        self.func = func

    def run(self, **kwargs: Any) -> Any:
        return self.func(kwargs)


class SecurityAgent(Agent):
    """
    Security Agent - Specialized agent for cybersecurity operations.
    
    Built-in roles:
    - auditor: Performs security audits and compliance checks
    - monitor: Monitors network and system activity
    - analyst: Analyzes security events and incidents
    - policy-advisor: Provides security policy recommendations
    
    Features:
    - Auto-binds security MCP servers (PAT-MCP, Network Monitor MCP, System Audit MCP)
    - Auto-stores mission results into UMB
    - Supports squad collaboration
    """
    
    VALID_ROLES = ["auditor", "monitor", "analyst", "policy-advisor"]
    
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "SecurityAgent",
        role: str = "analyst",
        security_mcps: Optional[Dict[str, BaseMCPConnector]] = None,
        memory_ref: Optional[Any] = None,
        **kwargs
    ):
        # Validate role
        if role not in self.VALID_ROLES:
            raise ValueError(f"Invalid role '{role}'. Must be one of: {self.VALID_ROLES}")
        
        # Initialize base agent with security skills
        security_skills = [
            "security_audit",
            "incident_analysis",
            "network_monitoring",
            "policy_evaluation",
            "vulnerability_assessment",
        ]
        
        super().__init__(
            id=id,
            name=name,
            roles=[role],
            skills=security_skills,
            memory_ref=memory_ref,
            **kwargs
        )
        
        self.security_role = role
        self.security_mcps = security_mcps or {}
        
        # Auto-bind security MCP servers
        if security_mcps:
            self._auto_bind_security_mcps()
        
        # Import and register cybersecurity tools
        self._register_cybersecurity_tools()
        
        logger.info(f"SecurityAgent created: {name} (role: {role})")
    
    def _register_cybersecurity_tools(self):
        """Register cybersecurity tools from ToolRegistry"""
        try:
            tool_registry = ToolRegistry()
            tool_names = [
                "LogAnalyzer",
                "FirewallAudit",
                "PermissionAudit",
                "SystemHardening",
                "NetworkMetadataInspector",
                "SIEMScriptBuilder"
            ]
            for name in tool_names:
                try:
                    tool_instance = tool_registry.create(name)
                    self.register_tool(tool_instance)
                except Exception as e:
                    logger.warning(f"Could not load tool '{name}' from registry: {e}")
        except Exception as e:
            logger.warning(f"Error registering cybersecurity tools: {e}")
    
    async def run_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a security tool with governance checks.
        
        Args:
            tool_name: Name of the tool to run
            params: Tool parameters
            
        Returns:
            Tool execution result
        """
        tool = next((t for t in self.tools if t.name == tool_name), None)
        if tool:
            if hasattr(tool, "run"):
                res = tool.run(**params)
                if asyncio.iscoroutine(res):
                    return await res
                return res
            elif callable(tool):
                res = tool(params)
                if asyncio.iscoroutine(res):
                    return await res
                return res
        return {
            "success": False,
            "error": f"Tool '{tool_name}' not available",
        }
    
    def create_mission_from_template(
        self,
        template_name: str,
        parameters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create a mission from a predefined template.
        
        Args:
            template_name: Name of the mission template
            parameters: Template parameters
            
        Returns:
            Mission configuration dictionary
        """
        parameters = parameters or {}
        
        templates = {
            "password_audit": {
                "goal": "Perform enterprise password policy audit",
                "description": "Audit password policies and detect weak patterns",
                "steps": [
                    {"action": "evaluate_policy", "tool": "password_policy_eval"},
                    {"action": "detect_patterns", "tool": "ai_pattern_detector"},
                ]
            },
            "firewall_audit": {
                "goal": "Audit firewall configuration",
                "description": "Review firewall rules for security issues",
                "steps": [
                    {"action": "audit_firewall", "tool": "audit_firewall"},
                ]
            },
            "permission_audit": {
                "goal": "Audit user permissions",
                "description": "Review user permissions and access controls",
                "steps": [
                    {"action": "audit_permissions", "tool": "audit_permissions"},
                ]
            },
            "system_hardening": {
                "goal": "Generate system hardening recommendations",
                "description": "Analyze system and generate hardening recommendations",
                "steps": [
                    {"action": "audit_config", "tool": "audit_config"},
                    {"action": "generate_hardening", "tool": "generate_hardening"},
                ]
            },
        }
        
        if template_name not in templates:
            return {
                "success": False,
                "error": f"Template '{template_name}' not found",
            }
        
        template = templates[template_name]
        return {
            "success": True,
            "mission_config": {
                **template,
                "parameters": parameters,
            }
        }
    
    def _auto_bind_security_mcps(self):
        """Auto-bind security MCP servers based on role"""
        # PAT-MCP for password auditing
        if "pat_mcp" in self.security_mcps:
            pat_mcp = self.security_mcps["pat_mcp"]
            self._register_pat_tools(pat_mcp)
        
        # Network Monitor MCP for network monitoring
        if "network_monitor_mcp" in self.security_mcps:
            network_mcp = self.security_mcps["network_monitor_mcp"]
            self._register_network_tools(network_mcp)
        
        # System Audit MCP for system auditing
        if "audit_mcp" in self.security_mcps:
            audit_mcp = self.security_mcps["audit_mcp"]
            self._register_audit_tools(audit_mcp)
    
    def _register_pat_tools(self, pat_mcp: BaseMCPConnector):
        """Register PAT-MCP tools"""
        async def identify_hash(params: Dict[str, Any]) -> Dict[str, Any]:
            return await pat_mcp.call_skill("hash_type", params)
        
        async def hash_strength(params: Dict[str, Any]) -> Dict[str, Any]:
            return await pat_mcp.call_skill("hash_strength", params)
        
        async def password_policy_eval(params: Dict[str, Any]) -> Dict[str, Any]:
            return await pat_mcp.call_skill("password_policy_eval", params)
        
        self.register_tool(SecurityWrapperTool("identify_hash", "Identify password hash type", identify_hash))
        self.register_tool(SecurityWrapperTool("hash_strength", "Benchmark password hash strength", hash_strength))
        self.register_tool(SecurityWrapperTool("password_policy_eval", "Evaluate password policy", password_policy_eval))
    
    def _register_network_tools(self, network_mcp: BaseMCPConnector):
        """Register Network Monitor MCP tools"""
        async def detect_port_scans(params: Dict[str, Any]) -> Dict[str, Any]:
            return await network_mcp.call_skill("detect_port_scans_behavior", params)
        
        async def detect_anomalies(params: Dict[str, Any]) -> Dict[str, Any]:
            return await network_mcp.call_skill("detect_network_anomalies", params)
        
        async def classify_incident(params: Dict[str, Any]) -> Dict[str, Any]:
            return await network_mcp.call_skill("classify_incident", params)
        
        self.register_tool(SecurityWrapperTool("detect_port_scans", "Detect network port scans", detect_port_scans))
        self.register_tool(SecurityWrapperTool("detect_anomalies", "Detect network anomalies", detect_anomalies))
        self.register_tool(SecurityWrapperTool("classify_incident", "Classify network security incident", classify_incident))
    
    def _register_audit_tools(self, audit_mcp: BaseMCPConnector):
        """Register System Audit MCP tools"""
        async def audit_firewall(params: Dict[str, Any]) -> Dict[str, Any]:
            return await audit_mcp.call_skill("audit_firewall_status", params)
        
        async def audit_config(params: Dict[str, Any]) -> Dict[str, Any]:
            return await audit_mcp.call_skill("audit_config_security", params)
        
        async def generate_hardening(params: Dict[str, Any]) -> Dict[str, Any]:
            return await audit_mcp.call_skill("generate_hardening_recommendations", params)
        
        self.register_tool(SecurityWrapperTool("audit_firewall", "Audit system firewall status", audit_firewall))
        self.register_tool(SecurityWrapperTool("audit_config", "Audit system configuration security", audit_config))
        self.register_tool(SecurityWrapperTool("generate_hardening", "Generate system hardening recommendations", generate_hardening))
    
    async def execute(self, task_node: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute a task node and auto-store results in UMB.
        
        Overrides base execute to automatically store mission results.
        """
        # Call parent execute
        result = await super().execute(task_node, context)
        
        # Auto-store mission results into UMB
        if self.memory_ref and result.get("success"):
            await self._store_mission_result(task_node, result, context)
        
        return result
    
    async def _store_mission_result(self, task_node: Dict[str, Any], result: Dict[str, Any], context: Dict[str, Any] = None):
        """Auto-store mission results into UMB"""
        if not self.memory_ref:
            return
        
        mission_result = {
            "id": f"mission_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "text": f"Mission: {task_node.get('description', 'Unknown')}\nResult: {result.get('outputs', {})}",
            "vector": [],  # Will be computed by UMB
            "metadata": {
                "agent_id": self.id,
                "agent_role": self.security_role,
                "task_id": task_node.get("id"),
                "timestamp": datetime.now().isoformat(),
                "permission_level": "squad_shared",  # Share with squad
                "mission_id": context.get("mission_id") if context else None,
            }
        }
        
        try:
            await self.memory_ref.upsert(mission_result)
            logger.info(f"Mission result stored in UMB: {mission_result['id']}")
        except Exception as e:
            logger.error(f"Failed to store mission result in UMB: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize agent to dictionary"""
        base_dict = super().to_dict()
        base_dict["security_role"] = self.security_role
        base_dict["security_mcps"] = list(self.security_mcps.keys())
        return base_dict

