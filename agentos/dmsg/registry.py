"""
MCP Registry - Registry for MCP servers and their skills
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import uuid
from enum import Enum


class SkillType(Enum):
    """Types of skills"""
    TOOL = "tool"
    API = "api"
    TRANSFORM = "transform"
    ANALYSIS = "analysis"


@dataclass
class Skill:
    """Skill definition"""
    id: str
    name: str
    description: str
    skill_type: SkillType
    inputs: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    latency_estimate: float = 1.0  # seconds
    accuracy_estimate: float = 1.0  # 0-1
    data_sensitivity: str = "public"  # "public", "private", "confidential"
    cost_estimate: Dict[str, float] = field(default_factory=dict)


@dataclass
class MCPNode:
    """MCP server node in skill graph"""
    id: str
    name: str
    domain: str  # e.g., "file_operations", "web_scraping"
    endpoint: str  # MCP server endpoint
    skills: List[Skill] = field(default_factory=list)
    cost_model: Dict[str, Any] = field(default_factory=dict)
    trust_score: float = 1.0  # 0-1
    status: str = "active"  # "active", "inactive", "error"
    metadata: Dict[str, Any] = field(default_factory=dict)


class MCPRegistry:
    """
    Registry for MCP servers and their skills.
    Maintains a graph of MCP nodes and skills.
    """
    
    def __init__(self):
        self.mcp_nodes: Dict[str, MCPNode] = {}
        self.skill_index: Dict[str, List[str]] = {}  # skill_name -> [mcp_node_ids]
        self.domain_index: Dict[str, List[str]] = {}  # domain -> [mcp_node_ids]
        # Auto-register security MCPs on initialization
        self._auto_register_security_mcps()
    
    def register(
        self,
        mcp_metadata: Dict[str, Any]
    ) -> str:
        """
        Register an MCP server.
        
        Args:
            mcp_metadata: MCP metadata with id, name, domain, endpoint, skills, etc.
            
        Returns:
            MCP node ID
        """
        mcp_id = mcp_metadata.get("id") or str(uuid.uuid4())
        
        # Parse skills
        skills = []
        for skill_data in mcp_metadata.get("skills", []):
            skill = Skill(
                id=skill_data.get("id") or str(uuid.uuid4()),
                name=skill_data.get("name", ""),
                description=skill_data.get("description", ""),
                skill_type=SkillType(skill_data.get("type", "tool")),
                inputs=skill_data.get("inputs", {}),
                outputs=skill_data.get("outputs", {}),
                latency_estimate=skill_data.get("latency_estimate", 1.0),
                accuracy_estimate=skill_data.get("accuracy_estimate", 1.0),
                data_sensitivity=skill_data.get("data_sensitivity", "public"),
                cost_estimate=skill_data.get("cost_estimate", {}),
            )
            skills.append(skill)
        
        # Create MCP node
        node = MCPNode(
            id=mcp_id,
            name=mcp_metadata.get("name", "Unnamed MCP"),
            domain=mcp_metadata.get("domain", "generic"),
            endpoint=mcp_metadata.get("endpoint", ""),
            skills=skills,
            cost_model=mcp_metadata.get("cost_model", {}),
            trust_score=mcp_metadata.get("trust_score", 1.0),
            status=mcp_metadata.get("status", "active"),
            metadata=mcp_metadata.get("metadata", {}),
        )
        
        # Register
        self.mcp_nodes[mcp_id] = node
        
        # Update indices
        for skill in skills:
            if skill.name not in self.skill_index:
                self.skill_index[skill.name] = []
            if mcp_id not in self.skill_index[skill.name]:
                self.skill_index[skill.name].append(mcp_id)
        
        domain = node.domain
        if domain not in self.domain_index:
            self.domain_index[domain] = []
        if mcp_id not in self.domain_index[domain]:
            self.domain_index[domain].append(mcp_id)
        
        return mcp_id
    
    def get_mcp(self, mcp_id: str) -> Optional[MCPNode]:
        """Get MCP node by ID"""
        return self.mcp_nodes.get(mcp_id)
    
    def find_mcps_by_skill(self, skill_name: str) -> List[MCPNode]:
        """Find MCPs that provide a skill"""
        mcp_ids = self.skill_index.get(skill_name, [])
        return [self.mcp_nodes[mid] for mid in mcp_ids if mid in self.mcp_nodes]
    
    def find_mcps_by_domain(self, domain: str) -> List[MCPNode]:
        """Find MCPs in a domain"""
        mcp_ids = self.domain_index.get(domain, [])
        return [self.mcp_nodes[mid] for mid in mcp_ids if mid in self.mcp_nodes]
    
    def list_all_skills(self) -> List[str]:
        """List all available skills"""
        return list(self.skill_index.keys())
    
    def unregister(self, mcp_id: str) -> bool:
        """Unregister an MCP server"""
        if mcp_id not in self.mcp_nodes:
            return False
        
        node = self.mcp_nodes[mcp_id]
        
        # Remove from indices
        for skill in node.skills:
            if skill.name in self.skill_index:
                if mcp_id in self.skill_index[skill.name]:
                    self.skill_index[skill.name].remove(mcp_id)
                if not self.skill_index[skill.name]:
                    del self.skill_index[skill.name]
        
        domain = node.domain
        if domain in self.domain_index:
            if mcp_id in self.domain_index[domain]:
                self.domain_index[domain].remove(mcp_id)
            if not self.domain_index[domain]:
                del self.domain_index[domain]
        
        del self.mcp_nodes[mcp_id]
        return True
    
    def _auto_register_security_mcps(self):
        """
        Auto-register security MCP servers with domain="cybersecurity".
        This method is called during initialization to ensure security MCPs
        are available in the registry.
        """
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Import security MCPs (lazy import to avoid circular dependencies)
            from agentos.mcp.security.pat_mcp import PasswordAuditToolMCP
            from agentos.mcp.security.network_monitor_mcp import NetworkMonitorMCP
            from agentos.mcp.security.system_audit_mcp import SystemAuditMCP
            
            # Register PAT-MCP
            try:
                pat_mcp = PasswordAuditToolMCP()
                pat_metadata = pat_mcp.to_mcp_metadata()
                pat_metadata["domain"] = "cybersecurity"
                self.register(pat_metadata)
                logger.info("PAT-MCP auto-registered in DMSG registry")
            except Exception as e:
                logger.debug(f"Could not auto-register PAT-MCP: {e}")
            
            # Register Network Monitor MCP
            try:
                network_mcp = NetworkMonitorMCP()
                network_metadata = network_mcp.to_mcp_metadata()
                network_metadata["domain"] = "cybersecurity"
                self.register(network_metadata)
                logger.info("Network Monitor MCP auto-registered in DMSG registry")
            except Exception as e:
                logger.debug(f"Could not auto-register Network Monitor MCP: {e}")
            
            # Register System Audit MCP
            try:
                audit_mcp = SystemAuditMCP()
                audit_metadata = audit_mcp.to_mcp_metadata()
                audit_metadata["domain"] = "cybersecurity"
                self.register(audit_metadata)
                logger.info("System Audit MCP auto-registered in DMSG registry")
            except Exception as e:
                logger.debug(f"Could not auto-register System Audit MCP: {e}")
        except ImportError as e:
            # Security MCPs not available, skip registration
            logger.debug(f"Security MCPs not available for auto-registration: {e}")

