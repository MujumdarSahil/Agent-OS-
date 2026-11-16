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
- `ZAI_API_KEY` and `CLOUDFLARE_API_KEY` are safely configured in `.env` (gitignored, never committed).
- New entries are documented as `UNVERIFIED` in `README.md` and registry comments pending live recording.

## 4. VCR Scrubber & Tool Testing (`agentos/tests/test_vcr_providers.py`)
- Enhanced `scrub_request` and `scrub_response` hooks in VCR to sanitize:
  - Headers: `authorization`, `api-key`, `x-api-key`, `x-account-id`, `x-org-id`, `x-organization-id`, `openai-organization`, `x-user-id`, `cookie`, `set-cookie`.
  - Bodies: Redacts `account_id`, `org_id`, `organization_id`, `user_id`, and `sk-*` API keys across both plaintext and gzip-compressed response payloads.
- Added `test_glm_tool_calling` testing parameterized harmless `get_weather(city)` tool calling via cassette replay.

## 5. Cassette Key Prefix Grep Audit
Command:
```powershell
Select-String -Path 'agentos/tests/cassettes/*.yaml' -Pattern '8b8dc7f1bfe7','cfut_Nb2yZQRE','ERnpKvIHHFCH','sk-or-v1'
```
Output:
*(Empty - zero matches found)*

`git grep` command:
```bash
git grep -E "8b8dc7f1bfe7|cfut_Nb2yZQRE|ERnpKvIHHFCH|sk-or-v1" agentos/tests/cassettes/
```
Output:
*(Exit code 1 - zero occurrences in tracked cassettes)*

## 6. Test Suite & Quality Verification
- **Ruff Linter**: `All checks passed!` (`agentos`, `agentos_server`).
- **Test Suite**: `358 passed, 40 skipped, 303 warnings in 126.35s` (raw log saved to `docs/evidence/raw/feat-provider-glm.txt`).
- **UI Verification**: Providers page (`ui/src/pages/Providers.tsx`) and fallback editor dynamically consume `PROVIDER_REGISTRY`, automatically listing all new models.
