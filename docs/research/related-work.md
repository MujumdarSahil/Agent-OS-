# Related Work: LLM Agent Security, Information Flow Control & Injection Defense

**Status:** Research Review & Comparative Analysis  
**Date:** November 2026  
**Note:** All specific claims, quantitative metrics, and architectural comparisons below are marked `[to verify]`. Do not treat these entries as verified experimental results until empirical reproduction is completed under the AgentOS research track.

---

## 1. Comparative Analysis Matrix

| Approach / Paper | Enforcement Location | Static / Dynamic | Benchmark | What AgentOS Does Differently |
|---|---|---|---|---|
| **CaMeL** | Language / Execution runtime `[to verify]` | Dynamic (Causal information flow tracking) `[to verify]` | Custom synthetic data flow tasks `[to verify]` | AgentOS operates at the flow graph and tool proxy level rather than requiring a custom runtime, combining static flow analysis at publish time with runtime label propagation `[to verify]`. |
| **FIDES** | Interpreter boundary (dual-interpreter separating control logic from data processing) `[to verify]` | Dynamic `[to verify]` | Custom prompt injection benchmarks `[to verify]` | AgentOS uses explicit declassification nodes (`approval`, `validator`, `quarantined_extraction`) and mediates tool calls via an external proxy without splitting models into dual interpreters `[to verify]`. |
| **Progent** | Tool / Action boundary via programmable capability policies `[to verify]` | Dynamic `[to verify]` | Tool-use safety suites `[to verify]` | AgentOS combines capability policies with full Information Flow Control (integrity, confidentiality, provenance) and static publish verification of the entire workflow DAG `[to verify]`. |
| **RTBAS** | Real-time agent monitoring shim / behavioral sandbox `[to verify]` | Dynamic `[to verify]` | Synthetic agent attack scenarios `[to verify]` | AgentOS enforces sound declassification rules (free-text remains untrusted; integrity upgrade only on constrained types) rather than heuristic behavioral classification `[to verify]`. |
| **AgentDojo** | Benchmark environment (evaluates prompt injection defenses on tool-calling agents) `[to verify]` | Dynamic evaluation `[to verify]` | AgentDojo suite (multi-turn execution environments) `[to verify]` | AgentDojo is an evaluation benchmark harness; AgentOS integrates AgentDojo directly into its Phase 4 research harness to benchmark ASR and utility `[to verify]`. |
| **InjecAgent** | Benchmark dataset / framework (evaluates indirect prompt injection across tool integrations) `[to verify]` | Static/dynamic evaluation `[to verify]` | 1,000+ test cases covering multiple tool categories `[to verify]` | InjecAgent evaluates tool prompt injections; AgentOS provides an architectural mitigation (tool proxy + sink requirements + label join rule) and benchmarks against InjecAgent scenarios `[to verify]`. |
| **Adaptive Evaluation of Agent Defenses** ([arXiv:2606.26479](https://arxiv.org/abs/2606.26479)) | Evaluation framework for adaptive attacks bypassing static LLM agent guards `[to verify]` | Dynamic adaptive evaluation `[to verify]` | Adaptive adversarial prompt injections against defended agents `[to verify]` | AgentOS's threat model assumes attacker controls content and explicitly includes adaptive attack evaluation in its research track, using deterministic IFC and proxy blocking rather than prompt-based defenses `[to verify]`. |

---

## 2. Research Track Evaluation Plan

Under Phase 4 of Plan v2.1, AgentOS will execute a formal evaluation using the AgentDojo harness and an in-house AgentOS workflow-injection benchmark:

1. **Attack Success Rate (ASR):**
   - Standard indirect prompt injection attacks `[to verify]`.
   - Adaptive attacks specifically tailored to bypass declassification and proxy checks ([arXiv:2606.26479](https://arxiv.org/abs/2606.26479)) `[to verify]`.
2. **Task Utility:**
   - Percentage of benign, unattacked multi-agent workflows that complete successfully without false rejections `[to verify]`.
3. **Execution Overhead:**
   - Latency and token overhead introduced by label metadata tracking, static publish checks, and AgentOS Tool Proxy mediation `[to verify]`.
4. **Static Check False Positive Rate:**
   - Rate of valid, safe workflow graphs rejected by the Static Flow Analyzer prior to declassification node insertion `[to verify]`.
