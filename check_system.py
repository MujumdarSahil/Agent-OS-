"""
Comprehensive System Check for AgentOS
Tests all components, tools, and MCP servers
"""

import asyncio
import sys
from typing import Dict, List, Any

# Color codes for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text:^60}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")

def print_success(text: str):
    """Print success message"""
    print(f"{GREEN}✓ {text}{RESET}")

def print_error(text: str):
    """Print error message"""
    print(f"{RED}✗ {text}{RESET}")

def print_warning(text: str):
    """Print warning message"""
    print(f"{YELLOW}⚠ {text}{RESET}")

def print_info(text: str):
    """Print info message"""
    print(f"  {text}")


async def check_core_components():
    """Check core AgentOS components"""
    print_header("Checking Core Components")
    
    results = {}
    
    # Check Agent
    try:
        from agentos.core.agent import Agent
        from agentos.core.umb_adapter import UMBAdapter
        umb = UMBAdapter(backend="simple")
        agent = Agent(name="TestAgent", skills=["test"], memory_ref=umb)
        results["Agent"] = True
        print_success("Agent class imported and instantiated")
        print_info(f"  Agent ID: {agent.id}")
        print_info(f"  Skills: {agent.skills}")
    except Exception as e:
        results["Agent"] = False
        print_error(f"Agent: {str(e)}")
    
    # Check Squad
    try:
        from agentos.core.squad import Squad, SquadRole
        squad = Squad(name="TestSquad", shared_memory_ref=umb)
        results["Squad"] = True
        print_success("Squad class imported and instantiated")
        print_info(f"  Squad ID: {squad.id}")
    except Exception as e:
        results["Squad"] = False
        print_error(f"Squad: {str(e)}")
    
    # Check Planner
    try:
        from agentos.core.planner import Planner
        planner = Planner()
        graph = planner.create_graph("Test goal")
        results["Planner"] = True
        print_success("Planner class imported and working")
        print_info(f"  Created graph with {len(graph.nodes)} nodes")
    except Exception as e:
        results["Planner"] = False
        print_error(f"Planner: {str(e)}")
    
    # Check Router
    try:
        from agentos.core.router import TaskRouter, AssignmentStrategy
        router = TaskRouter(strategy=AssignmentStrategy.HYBRID)
        results["Router"] = True
        print_success("TaskRouter class imported and instantiated")
    except Exception as e:
        results["Router"] = False
        print_error(f"Router: {str(e)}")
    
    # Check Governance
    try:
        from agentos.core.governance import GovernanceEngine
        governance = GovernanceEngine()
        results["Governance"] = True
        print_success("GovernanceEngine class imported and instantiated")
    except Exception as e:
        results["Governance"] = False
        print_error(f"Governance: {str(e)}")
    
    # Check UMB
    try:
        from agentos.core.umb_adapter import UMBAdapter
        umb_test = UMBAdapter(backend="simple")
        results["UMB"] = True
        print_success("UMBAdapter class imported and instantiated")
    except Exception as e:
        results["UMB"] = False
        print_error(f"UMB: {str(e)}")
    
    return results


async def check_mcp_registry():
    """Check MCP Registry and list all tools"""
    print_header("Checking MCP Registry and Tools")
    
    try:
        from agentos.dmsg.registry import MCPRegistry
        
        registry = MCPRegistry()
        print_success("MCPRegistry imported and instantiated")
        
        # List all registered MCPs
        mcp_count = len(registry.mcp_nodes)
        print_info(f"Registered MCPs: {mcp_count}")
        
        if mcp_count > 0:
            print("\n  MCP Servers:")
            for mcp_id, mcp_node in registry.mcp_nodes.items():
                print(f"    - {mcp_node.name} (ID: {mcp_id})")
                print(f"      Domain: {mcp_node.domain}")
                print(f"      Skills: {len(mcp_node.skills)}")
                for skill in mcp_node.skills:
                    print(f"        • {skill.name}: {skill.description}")
        else:
            print_warning("No MCPs registered yet")
        
        # List all skills
        all_skills = registry.list_all_skills()
        print(f"\n  Total available skills: {len(all_skills)}")
        if all_skills:
            print("  Skills:")
            for skill in sorted(all_skills):
                print(f"    • {skill}")
        
        return {
            "registry": True,
            "mcp_count": mcp_count,
            "skill_count": len(all_skills),
            "mcps": list(registry.mcp_nodes.keys()),
            "skills": all_skills
        }
    except Exception as e:
        print_error(f"MCP Registry: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"registry": False, "error": str(e)}


async def check_security_tools():
    """Check security tools and MCPs"""
    print_header("Checking Security Tools")
    
    results = {}
    
    # Check security MCPs
    security_mcps = [
        ("PAT-MCP", "agentos.mcp.security.pat_mcp", "PasswordAuditToolMCP"),
        ("Network Monitor MCP", "agentos.mcp.security.network_monitor_mcp", "NetworkMonitorMCP"),
        ("System Audit MCP", "agentos.mcp.security.system_audit_mcp", "SystemAuditMCP"),
    ]
    
    for name, module_path, class_name in security_mcps:
        try:
            module = __import__(module_path, fromlist=[class_name])
            mcp_class = getattr(module, class_name)
            mcp = mcp_class()
            results[name] = True
            print_success(f"{name} imported and instantiated")
        except Exception as e:
            results[name] = False
            print_error(f"{name}: {str(e)}")
    
    # Check security tools
    security_tools = [
        ("LogAnalyzer", "agentos.mcp.security.tools.log_analyzer"),
        ("FirewallAudit", "agentos.mcp.security.tools.firewall_audit"),
        ("PermissionAudit", "agentos.mcp.security.tools.permission_audit"),
        ("SystemHardening", "agentos.mcp.security.tools.system_hardening"),
        ("NetworkMetadataInspector", "agentos.mcp.security.tools.network_metadata_inspector"),
        ("SIEMScriptBuilder", "agentos.mcp.security.tools.siem_script_builder"),
    ]
    
    for name, module_path in security_tools:
        try:
            module = __import__(module_path, fromlist=[name])
            tool_class = getattr(module, name)
            results[f"Tool: {name}"] = True
            print_success(f"{name} tool imported")
        except Exception as e:
            results[f"Tool: {name}"] = False
            print_error(f"{name}: {str(e)}")
    
    return results


async def check_cybercore():
    """Check CyberCore components"""
    print_header("Checking CyberCore Components")
    
    results = {}
    
    # Check CyberCore MCPs
    cybercore_mcps = [
        ("PasswordAuditMCP", "agentos.cybercore.mcp.password_audit_mcp"),
        ("ThreatIntelMCP", "agentos.cybercore.mcp.threat_intel_mcp"),
        ("LogAnalysisMCP", "agentos.cybercore.mcp.log_analysis_mcp"),
        ("SandboxMCP", "agentos.cybercore.mcp.sandbox_mcp"),
    ]
    
    for name, module_path in cybercore_mcps:
        try:
            module = __import__(module_path, fromlist=[name])
            mcp_class = getattr(module, name)
            results[f"CyberCore MCP: {name}"] = True
            print_success(f"{name} imported")
        except Exception as e:
            results[f"CyberCore MCP: {name}"] = False
            print_error(f"{name}: {str(e)}")
    
    # Check CyberCore Agents
    cybercore_agents = [
        ("TriageAgent", "agentos.cybercore.agents.triage_agent"),
        ("InvestigatorAgent", "agentos.cybercore.agents.investigator_agent"),
        ("SandboxAnalysisAgent", "agentos.cybercore.agents.sandbox_analysis_agent"),
        ("ComplianceAgent", "agentos.cybercore.agents.compliance_agent"),
        ("ThreatHuntAgent", "agentos.cybercore.agents.threat_hunt_agent"),
        ("RedTeamSimAgent", "agentos.cybercore.agents.redteam_sim_agent"),
    ]
    
    for name, module_path in cybercore_agents:
        try:
            module = __import__(module_path, fromlist=[name])
            agent_class = getattr(module, name)
            results[f"CyberCore Agent: {name}"] = True
            print_success(f"{name} imported")
        except Exception as e:
            results[f"CyberCore Agent: {name}"] = False
            print_error(f"{name}: {str(e)}")
    
    return results


async def check_modelhub():
    """Check ModelHub components"""
    print_header("Checking ModelHub Components")
    
    results = {}
    
    modelhub_components = [
        ("LLMConnector", "agentos.modelhub.llm_connector"),
        ("TrainingOrchestrator", "agentos.modelhub.training.orchestrator"),
        ("LoRAUtils", "agentos.modelhub.training.lora_utils"),
        ("QLoRAUtils", "agentos.modelhub.training.qlora_utils"),
    ]
    
    for name, module_path in modelhub_components:
        try:
            module = __import__(module_path, fromlist=[name])
            results[f"ModelHub: {name}"] = True
            print_success(f"{name} imported")
        except Exception as e:
            results[f"ModelHub: {name}"] = False
            print_warning(f"{name}: {str(e)}")
    
    return results


async def check_rag_components():
    """Check RAG/CAG components"""
    print_header("Checking RAG/CAG Components")
    
    results = {}
    
    rag_components = [
        ("RAGManager", "agentos.core.rag_manager"),
        ("CAG", "agentos.core.cag"),
        ("FAISSAdapter", "agentos.core.retrieval_adapters.faiss_adapter"),
        ("ChromaAdapter", "agentos.core.retrieval_adapters.chroma_adapter"),
        ("PGVectorAdapter", "agentos.core.retrieval_adapters.pgvector_adapter"),
    ]
    
    for name, module_path in rag_components:
        try:
            module = __import__(module_path, fromlist=[name])
            results[f"RAG: {name}"] = True
            print_success(f"{name} imported")
        except Exception as e:
            results[f"RAG: {name}"] = False
            print_warning(f"{name}: {str(e)}")
    
    return results


async def check_ui_backend():
    """Check UI backend"""
    print_header("Checking UI Backend")
    
    results = {}
    
    try:
        from agentos.ui.backend.main import app
        results["FastAPI App"] = True
        print_success("FastAPI backend imported")
        
        # Check if routes are available
        routes = [route.path for route in app.routes]
        print_info(f"  Available routes: {len(routes)}")
        for route in routes[:10]:  # Show first 10
            print_info(f"    - {route}")
        if len(routes) > 10:
            print_info(f"    ... and {len(routes) - 10} more")
    except Exception as e:
        results["FastAPI App"] = False
        print_error(f"FastAPI backend: {str(e)}")
    
    return results


async def run_basic_functionality_test():
    """Run basic functionality tests"""
    print_header("Running Basic Functionality Tests")
    
    results = {}
    
    try:
        # Test Agent creation and planning
        from agentos.core.agent import Agent
        from agentos.core.umb_adapter import UMBAdapter
        
        umb = UMBAdapter(backend="simple")
        agent = Agent(name="TestAgent", skills=["coding"], memory_ref=umb)
        
        task = {"id": "test1", "description": "Test task"}
        plan = await agent.plan(task)
        
        results["Agent Planning"] = True
        print_success("Agent planning works")
        print_info(f"  Plan created for task: {plan.get('task_id')}")
        
        # Test execution
        task_node = {"id": "test1", "description": "Test execution", "type": "generic"}
        result = await agent.execute(task_node)
        
        results["Agent Execution"] = result.get("success", False)
        if result.get("success"):
            print_success("Agent execution works")
        else:
            print_warning("Agent execution returned success=False")
        
    except Exception as e:
        results["Agent Planning"] = False
        results["Agent Execution"] = False
        print_error(f"Functionality test: {str(e)}")
        import traceback
        traceback.print_exc()
    
    return results


async def main():
    """Run all system checks"""
    print_header("AgentOS System Check")
    print("Checking all components, tools, and MCP servers...\n")
    
    all_results = {}
    
    # Run all checks
    all_results["Core Components"] = await check_core_components()
    all_results["MCP Registry"] = await check_mcp_registry()
    all_results["Security Tools"] = await check_security_tools()
    all_results["CyberCore"] = await check_cybercore()
    all_results["ModelHub"] = await check_modelhub()
    all_results["RAG Components"] = await check_rag_components()
    all_results["UI Backend"] = await check_ui_backend()
    all_results["Functionality"] = await run_basic_functionality_test()
    
    # Summary
    print_header("System Check Summary")
    
    total_checks = 0
    passed_checks = 0
    
    for category, results in all_results.items():
        if isinstance(results, dict):
            category_passed = sum(1 for v in results.values() if v is True)
            category_total = sum(1 for v in results.values() if isinstance(v, bool))
            total_checks += category_total
            passed_checks += category_passed
            
            status = f"{category_passed}/{category_total}"
            if category_passed == category_total:
                print_success(f"{category}: {status}")
            elif category_passed > 0:
                print_warning(f"{category}: {status}")
            else:
                print_error(f"{category}: {status}")
    
    print(f"\n  Overall: {passed_checks}/{total_checks} checks passed")
    
    if passed_checks == total_checks:
        print_success("\nAll systems operational!")
        return 0
    else:
        print_warning(f"\n{total_checks - passed_checks} checks failed. Review errors above.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
