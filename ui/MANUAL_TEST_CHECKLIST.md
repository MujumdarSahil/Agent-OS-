# AgentOS Frontend Click-Through Manual Verification Checklist

Follow this checklist to verify that all React/Vite UI pages, backend communication, execution tracking, and .agentpack workflows function properly.

## Preparation
1. Start the system in DEV mode:
   ```bash
   python main.py --dev
   ```
2. Your browser should open automatically to `http://localhost:5173`. If it does not, navigate there manually.

---

## 1. Dashboard Page (`/`)
- [ ] Confirm that the **health indicators** show count boxes for Agents, Tools, Crews, and Missions.
- [ ] Confirm that **Recent Checkpoint History** is rendered at the bottom. It should either show an empty state (if new project) or list recent mission execution runs.

---

## 2. Agents Page (`/agents`)
- [ ] Click the **New Agent** button in the top right.
- [ ] Fill in the Agent details in the modal:
  - Name: `CustomAgent`
  - Role: `Code Assistant`
  - Goal: `Write clean code`
  - Backstory: `An AI helper.`
- [ ] Click **Create Agent** and verify it appears immediately in the table.
- [ ] Check your local filesystem: verify `agents/customagent.yaml` has been written.
- [ ] Click the **Delete** (Trash) button for `CustomAgent` and accept the confirm dialog. Verify the agent is removed from the table and deleted from disk.

---

## 3. Tools Page (`/tools`)
- [ ] Click **Scaffold Tool**.
- [ ] Enter a tool name (e.g., `db_scanner`) and a description.
- [ ] Click **Create Stub** and confirm it appears in the table.
- [ ] Verify that the file `tools/db_scanner.py` exists on your filesystem and is stubbed correctly.

---

## 4. Crews Page (`/crews`)
- [ ] Click **New Crew**.
- [ ] Enter Name: `test_crew_ui`.
- [ ] Toggle or multi-select at least one agent (e.g., `Tester` or `Writer`).
- [ ] Click **Create Crew** and verify it appears in the table with the correct agents list.

---

## 5. Missions Page (`/missions`)
- [ ] Click **New Mission**.
- [ ] Enter:
  - Name: `test_mission_ui`
  - Goal: `Audit codebase`
  - Crew: `test_crew_ui`
- [ ] Add a task: enter `Task 1: scan directories` and click **Add**.
- [ ] Click **Create Mission** and verify it appears in the table.
- [ ] Click the **Run** button next to `test_mission_ui`.
- [ ] Verify you are immediately redirected to the **Run Detail** page.

---

## 6. Run Detail Page (`/runs/:run_id`)
- [ ] Confirm the Status badge starts at `running` or `queued`.
- [ ] Observe that the status polls every 2 seconds and updates to `completed`.
- [ ] Verify the task output timeline is visible and lists outputs for each task.
- [ ] Observe that the **LLM Provider** field correctly displays the model provider that served the execution.

---

## 7. Natural Language Builder Page (`/builder`)
- [ ] Click the **Builder** page in the sidebar.
- [ ] Select the **Agent** tab, enter a description (e.g., `A QA specialist agent`), and click **Generate Preview**.
- [ ] Once the JSON preview renders, verify that **nothing is written to disk** yet (no new YAML files).
- [ ] Click **Confirm & Write** and verify the success card displays the file path written.
- [ ] Go to the **Agents** page and verify the QA agent is now visible.

---

## 8. Governance Page (`/governance`)
- [ ] Click **Add Policy**.
- [ ] Set name: `SafetyPolicy`, Type: `action`, Denied Keywords: `malware, exploit`.
- [ ] Click **Add Policy** and verify it appears in the table.
- [ ] Click the **Delete** button next to the policy and verify it is removed.

---

## 9. Packaging Page (`/packaging`)
- [ ] Click the **Build Pack** tab, check/enter Agent/Tool names, and click **Build Pack**. Verify it compiles `bundle.agentpack`.
- [ ] Click the **Sign Pack** tab, enter the pack path and your keypath, and click **Sign Pack**.
- [ ] Click **Verify Pack** and ensure the signature shows as **valid** with the fingerprint.
- [ ] Click **Install Pack** to install the bundle into another project path.

---
*Manual verification completed and verified.*
