"""Simple system check that writes to file"""
import asyncio
import sys
from datetime import datetime

output_lines = []

def log(msg):
    print(msg)
    output_lines.append(msg)

async def main():
    log("="*60)
    log("AgentOS System Check")
    log(f"Time: {datetime.now()}")
    log("="*60)
    log("")
    
    # Test 1: Core imports
    log("1. Testing Core Components...")
    try:
        from agentos.core.agent import Agent
        from agentos.core.squad import Squad
        from agentos.core.planner import Planner
        from agentos.core.router import TaskRouter
        from agentos.core.governance import GovernanceEngine
        from agentos.core.umb_adapter import UMBAdapter
        log("   ✓ Core components imported")
    except Exception as e:
        log(f"   ✗ Core components failed: {e}")
        return
    
    # Test 2: MCP Registry
    log("\n2. Testing MCP Registry...")
    try:
        from agentos.dmsg.registry import MCPRegistry
        registry = MCPRegistry()
        mcp_count = len(registry.mcp_nodes)
        skills = registry.list_all_skills()
        log(f"   ✓ Registry initialized")
        log(f"   - Registered MCPs: {mcp_count}")
        log(f"   - Available skills: {len(skills)}")
        if mcp_count > 0:
            log("   MCPs:")
            for mcp_id, node in registry.mcp_nodes.items():
                log(f"     • {node.name} ({mcp_id[:8]}...)")
                log(f"       Domain: {node.domain}, Skills: {len(node.skills)}")
    except Exception as e:
        log(f"   ✗ Registry failed: {e}")
        import traceback
        log(traceback.format_exc())
    
    # Test 3: Security Tools
    log("\n3. Testing Security Tools...")
    security_tools = [
        ("PAT-MCP", "agentos.mcp.security.pat_mcp", "PasswordAuditToolMCP"),
        ("Network Monitor", "agentos.mcp.security.network_monitor_mcp", "NetworkMonitorMCP"),
        ("System Audit", "agentos.mcp.security.system_audit_mcp", "SystemAuditMCP"),
    ]
    for name, mod, cls in security_tools:
        try:
            module = __import__(mod, fromlist=[cls])
            getattr(module, cls)
            log(f"   ✓ {name}")
        except Exception as e:
            log(f"   ✗ {name}: {e}")
    
    # Test 4: Basic functionality
    log("\n4. Testing Basic Functionality...")
    try:
        umb = UMBAdapter(backend="simple")
        agent = Agent(name="Test", skills=["test"], memory_ref=umb)
        log(f"   ✓ Agent created: {agent.id}")
        
        task = {"id": "t1", "description": "test"}
        plan = await agent.plan(task)
        log(f"   ✓ Planning works: {plan.get('task_id')}")
        
        result = await agent.execute({"id": "t1", "description": "test", "type": "generic"})
        log(f"   ✓ Execution works: {result.get('success')}")
    except Exception as e:
        log(f"   ✗ Functionality test failed: {e}")
        import traceback
        log(traceback.format_exc())
    
    log("\n" + "="*60)
    log("Check complete!")
    log("="*60)
    
    # Write to file
    with open("system_check_results.txt", "w") as f:
        f.write("\n".join(output_lines))
    log("\nResults saved to system_check_results.txt")

if __name__ == "__main__":
    asyncio.run(main())
