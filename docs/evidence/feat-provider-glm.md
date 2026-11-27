# Feature Evidence: GLM Provider Integration (`feat/provider-glm`)

## 1. Summary
Added Zhipu AI (Z.ai) and OpenRouter GLM model definitions to the AgentOS provider registry, updated documentation with security guidelines, enhanced the VCR test suite with account/org ID scrubbing, and added harmless tool-call test structures.

## 2. Model Registrations (`agentos/llm/provider_registry.py`)
1. **`openrouter_glm_5_2_free`**:
   - Model Slug: `openrouter/z-ai/glm-5.2:free`
   - Key: `OPENROUTER_API_KEY`
   - Tags: `["free-tier", "openrouter"]`
   - Security Note: Free endpoint subject to daily rate limits. Upstream terms specify prompts and completions may be logged or used for model training; **do not send data labeled `secret` or sensitive internal payloads**.
2. **`zai_glm_4_7_flash`**:
   - Model Slug: `zai/glm-4.7-flash` (LiteLLM `zai/` routing to `https://api.z.ai/api/paas/v4`)
   - Key: `ZAI_API_KEY`
   - Tags: `["free-tier", "zai", "fast"]`
   - Status: Free-tier flash model via Z.ai international API.
3. **`zai_glm_5_3`**:
   - Model Slug: `zai/glm-5.3` (LiteLLM `zai/` routing to `https://api.z.ai/api/paas/v4`)
   - Key: `ZAI_API_KEY`
   - Tags: `["paid", "zai", "flagship"]`
   - Status: Paid flagship model via Z.ai international API.

## 3. Credential Handling & Security
- Handled via standard provider-key path (vault first, environment variable fallback). `agentos/security/vault.py` was unmodified.
- `ZAI_API_KEY` is configured via environment variable / `.env` (gitignored, never committed).
- New entries are documented as `UNVERIFIED` in `README.md` and registry comments pending live recording.

## 4. VCR Scrubber & Tool Testing (`agentos/tests/test_vcr_providers.py`)
- Enhanced `scrub_request` and `scrub_response` hooks in VCR to sanitize:
  - Headers: `authorization`, `api-key`, `x-api-key`, `x-account-id`, `x-org-id`, `x-organization-id`, `openai-organization`, `x-user-id`, `cookie`, `set-cookie`.
  - Bodies: Redacts `account_id`, `org_id`, `organization_id`, `user_id`, and `sk-*` API keys across both plaintext and gzip-compressed response payloads.
- Added `test_glm_tool_calling` testing parameterized harmless `get_weather(city)` tool calling via cassette replay.

## 5. Cassette Key Audit (Runtime Environment Audit)
Audited via `scripts/audit_cassette_secrets.py`, reading provider keys directly from the execution environment without writing secrets to files or terminal output.

Audit Output:
```
openai_gpt4o: matches: 0
anthropic_claude_sonnet: matches: 0
openai_gpt4o_mini: matches: 0
openrouter_claude_sonnet: matches: 0
openrouter_gpt4o: matches: 0
gemini_flash: matches: 0
deepseek_v4_flash: matches: 0
groq_llama3_3: matches: 0
groq_llama3_1_instant: matches: 0
groq_qwen3_32b: matches: 0
together_llama3_3_70b: matches: 0
together_qwen2_5_72b: matches: 0
fireworks_llama3_1_70b: matches: 0
fireworks_qwen2_5_72b: matches: 0
zai_glm_5_3: matches: 0
openrouter_mistral_7b_free: matches: 0
openrouter_laguna_s_2_1_free: matches: 0
zai_glm_4_7_flash: matches: 0
openrouter_glm_5_2_free: matches: 0
openrouter_gemma_4_31b_free: matches: 0
openrouter_nemotron_3_nano_omni_free: matches: 0
huggingface_llama3_2_1b: matches: 0
openai_compatible: matches: 0
ollama_qwen: matches: 0
ollama_llama: matches: 0
```

## 6. Test Suite & Quality Verification
- **Ruff Linter**: `All checks passed!` (`agentos`, `agentos_server`).
- **Test Suite**: `358 passed, 40 skipped, 303 warnings in 126.35s` (raw log saved to `docs/evidence/raw/feat-provider-glm.txt`).
- **UI Verification**: Providers page (`ui/src/pages/Providers.tsx`) and fallback editor dynamically consume `PROVIDER_REGISTRY`, automatically listing all new models.
