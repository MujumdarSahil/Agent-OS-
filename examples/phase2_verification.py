"""
Phase 2 Verification Test Suite - Scaffolding, validation, checkpointing,
resumption, MCP plugins, and builder validation.
"""

import os
import sys
import subprocess
import shutil
import yaml
import sqlite3
import json
from datetime import datetime

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def clean_demo_dir():
    if os.path.exists("demo"):
        shutil.rmtree("demo")
        print("Cleaned up existing 'demo' directory.")

def run_cmd(cmd_list, env=None, input_str=None):
    print(f"\nRunning command: {' '.join(cmd_list)}")
    p = subprocess.Popen(
        cmd_list,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True
    )
    stdout, stderr = p.communicate(input=input_str)
    print(f"Exit code: {p.returncode}")
    if stdout:
        print(f"STDOUT:\n{stdout}")
    if stderr:
        print(f"STDERR:\n{stderr}")
    return p.returncode, stdout, stderr

def run_tests():
    print("=== STARTING PHASE 2 VERIFICATION SUITE ===")
    clean_demo_dir()

    # 1. Test: new-project scaffolding
    code, stdout, stderr = run_cmd([".\\venv\\Scripts\\agentos", "new-project", "demo"])
    assert code == 0, "new-project command failed"
    assert os.path.exists("demo/agentos.config.yaml"), "agentos.config.yaml missing"
    assert os.path.exists("demo/agents/general_assistant.yaml"), "general_assistant.yaml missing"
    
    # 2. Test: validate empty scaffold
    code, stdout, stderr = run_cmd([".\\venv\\Scripts\\agentos", "validate", "demo"])
    assert code == 0, "Validation of empty scaffold failed"

    # 3. Test: new-agent commands
    code, _, _ = run_cmd([
        ".\\venv\\Scripts\\agentos", "new-agent", "demo",
        "--name", "Researcher", "--role", "Web Fact Finder", "--goal", "Find raw facts"
    ])
    assert code == 0, "new-agent Researcher failed"
    assert os.path.exists("demo/agents/researcher.yaml"), "researcher.yaml missing"

    code, _, _ = run_cmd([
        ".\\venv\\Scripts\\agentos", "new-agent", "demo",
        "--name", "Writer", "--role", "Content Summarizer", "--goal", "Write summary"
    ])
    assert code == 0, "new-agent Writer failed"
    assert os.path.exists("demo/agents/writer.yaml"), "writer.yaml missing"

    # 4. Test: new-tool command
    code, _, _ = run_cmd([
        ".\\venv\\Scripts\\agentos", "new-tool", "demo", "--name", "data_fetcher"
    ])
    assert code == 0, "new-tool data_fetcher failed"
    assert os.path.exists("demo/tools/data_fetcher.py"), "data_fetcher.py missing"

    # Modify tools/data_fetcher.py to support simulated crash
    data_fetcher_code = (
        "import os\n"
        "from agentos.core.base import BaseTool\n\n"
        "class DataFetcher(BaseTool):\n"
        "    name: str = \"data_fetcher\"\n"
        "    description: str = \"Fetches facts from custom mock endpoint.\"\n\n"
        "    def run(self, **kwargs) -> str:\n"
        "        query = kwargs.get('query', '')\n"
        "        # Simulate crash on task 2 if FORCE_CRASH is set\n"
        "        if 'Summarize' in query and os.environ.get('FORCE_CRASH') == '1':\n"
        "            raise RuntimeError('Simulated Crash in Task 2!')\n"
        "        return f'Raw Fact: AgentOS Phase 2 checkpointing is robust. Query: {query}'\n"
    )
    with open("demo/tools/data_fetcher.py", "w", encoding="utf-8") as f:
        f.write(data_fetcher_code)

    # Update researcher tool_refs to include data_fetcher
    with open("demo/agents/researcher.yaml", "r", encoding="utf-8") as f:
        r_cfg = yaml.safe_load(f)
    r_cfg["tool_refs"] = ["data_fetcher"]
    with open("demo/agents/researcher.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(r_cfg, f)

    # 5. Test: new-crew command
    code, _, _ = run_cmd([
        ".\\venv\\Scripts\\agentos", "new-crew", "demo",
        "--name", "test_crew", "--agents", "Researcher,Writer", "--process", "sequential"
    ])
    assert code == 0, "new-crew failed"
    assert os.path.exists("demo/crews/test_crew.yaml"), "test_crew.yaml missing"

    # Write mission configuration YAML
    mission_cfg = {
        "name": "test_mission",
        "goal": "Retrieve facts and summarize them",
        "description": "Verification sequential mission",
        "crew": "test_crew",
        "tasks": [
            {
                "description": "Fetch initial facts about AgentOS Phase 2.",
                "assigned_agent": "Researcher"
            },
            {
                "description": "Summarize the retrieved facts for Phase 2.",
                "assigned_agent": "Writer"
            }
        ]
    }
    os.makedirs("demo/missions", exist_ok=True)
    with open("demo/missions/test_mission.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(mission_cfg, f)

    # 6. Test: Validate complete scaffold
    code, _, _ = run_cmd([".\\venv\\Scripts\\agentos", "validate", "demo"])
    assert code == 0, "Validation of complete scaffold failed"

    # 7. Test: Run mission and crash on task 2
    test_env = os.environ.copy()
    test_env["FORCE_CRASH"] = "1"
    test_env["AGENTOS_MOCK_LLM"] = "1"
    
    # Inject fake API key to prevent LLM router from crashing when initializing LLMClient
    test_env["OPENAI_API_KEY"] = "sk-fake-openai-key"
    test_env["GEMINI_API_KEY"] = "fake-gemini-key"

    code, stdout, stderr = run_cmd([
        ".\\venv\\Scripts\\agentos", "run", "demo", "--mission", "test_mission"
    ], env=test_env)
    
    assert code == 1, "Mission should fail with simulated crash"
    assert "Simulated Crash in Task 2!" in stdout or "Simulated Crash in Task 2!" in stderr, "Expected simulated crash message"

    # Verify SQLite checkpoint run history contains the failed state
    db_path = "demo/checkpoints/run_history.db"
    assert os.path.exists(db_path), "run_history.db missing"
    
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT task_index, status, state FROM checkpoints WHERE mission_id = 'test_mission'")
        rows = cursor.fetchall()
        print(f"SQLite checkpoints: {rows}")
        assert len(rows) > 0, "No checkpoints written to DB"
        # The latest checkpoint should have task_index = 1, status = 'failed'
        latest = rows[-1]
        assert latest[0] == 1, "Expected task index 1 to fail"
        assert latest[1] == "failed", "Expected status to be failed"
        state = json.loads(latest[2])
        # Task 1 output should be present in outputs list
        assert len(state.get("outputs", [])) == 1, "Expected task 1 output to be persisted in state"
        task1_out = state["outputs"][0]
        print(f"Task 1 persisted output: {task1_out}")

    # 8. Test: Resume mission from task 2
    test_env["FORCE_CRASH"] = "0"
    code, stdout, stderr = run_cmd([
        ".\\venv\\Scripts\\agentos", "run", "demo", "--mission", "test_mission", "--resume"
    ], env=test_env)
    
    assert code == 0, "Mission resume failed"
    # Verification of resumption: Task 2 should resume from task index 1
    assert "Resuming mission test_mission from task index 1" in stdout or "Resuming mission test_mission from task index 1" in stderr, "Mission did not resume from task index 1"

    # Verify SQLite checkpoint status is now complete
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM checkpoints WHERE mission_id = 'test_mission'")
        status = cursor.fetchone()[0]
        assert status == "completed", "Checkpoint status should be completed"

    # 9. Test: Scaffold and load MCP plugin
    code, _, _ = run_cmd([
        ".\\venv\\Scripts\\agentos", "new-mcp-plugin", "demo", "--name", "time_plugin"
    ])
    assert code == 0, "new-mcp-plugin failed"
    assert os.path.exists("demo/mcp_plugins/time_plugin/plugin.py"), "plugin.py missing"

    plugin_code = (
        "from agentos.core.base import BaseMCPPlugin, BaseTool\n"
        "from typing import List\n"
        "from datetime import datetime\n\n"
        "class TimeTool(BaseTool):\n"
        "    name: str = \"get_time\"\n"
        "    description: str = \"Returns the current date and time.\"\n"
        "    def run(self, **kwargs) -> str:\n"
        "        return f'Plugin Time: {datetime.now().isoformat()}'\n\n"
        "class MyMCPPlugin(BaseMCPPlugin):\n"
        "    def register_tools(self) -> List[BaseTool]:\n"
        "        return [TimeTool()]\n"
    )
    with open("demo/mcp_plugins/time_plugin/plugin.py", "w", encoding="utf-8") as f:
        f.write(plugin_code)

    # Load and test discover/load plugins dynamically
    from agentos.mcp.plugin_loader import discover_plugins, load_plugin
    from agentos.core.base import ToolRegistry
    
    reg = ToolRegistry()
    discovered = discover_plugins("demo")
    assert len(discovered) == 1, "Expected 1 plugin discovered"
    manifest, m_path = discovered[0]
    assert manifest.name == "time_plugin"
    
    loaded_keys = load_plugin(manifest, m_path, reg)
    assert len(loaded_keys) == 1, "Expected 1 tool registered"
    assert loaded_keys[0] == "time_plugin.get_time"
    
    tool_inst = reg.create("time_plugin.get_time")
    res_time = tool_inst.run()
    assert "Plugin Time:" in res_time, f"Plugin execution failed: {res_time}"
    print(f"MCP Plugin tool run successful: {res_time}")

    # 10. Test: build-agent command (requires LLM client, we test user confirmation)
    # We will simulate confirmation input "y" to the prompt
    code, stdout, stderr = run_cmd([
        ".\\venv\\Scripts\\agentos", "build-agent", "demo",
        "--describe", "a senior python code reviewer who checks for security issues"
    ], env=test_env, input_str="y\n")
    
    assert code == 0, "build-agent command failed"
    assert os.path.exists("demo/agents/securitycodereviewer.yaml"), "build-agent config file was not written"
    print("build-agent confirmation and config write verified successfully!")

    print("\n=== ALL PHASE 2 VERIFICATION SUITE TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    run_tests()
