"""
LIVE diagnostics for the LLM provider chain (2.4c). Owner-run; never part of CI.

Keys come from the project vault (same as the app) or the environment and are never printed.
Output: provider names, model ids, status, error class, scrubbed error text (max 200 chars), timings.

    # ONE call to one provider, through AgentOSRouterLLM with CrewAI-shaped messages (system + user):
    .\\venv\\Scripts\\python.exe scripts\\llm_probe.py call groq_llama3_3

    # Check registry model ids against each keyed provider's /models list (one GET per provider):
    .\\venv\\Scripts\\python.exe scripts\\llm_probe.py models

Options: --project PATH (default: AGENTOS_PROJECT or ~/.agentos/workspace).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# OpenAI-compatible /models endpoints (prefix of the litellm model id -> base URL).
MODEL_LISTS = {
    "groq/": "https://api.groq.com/openai/v1/models",
    "together_ai/": "https://api.together.xyz/v1/models",
    "deepseek/": "https://api.deepseek.com/models",
    "openrouter/": "https://openrouter.ai/api/v1/models",
    "openai/": "https://api.openai.com/v1/models",
    "fireworks_ai/": "https://api.fireworks.ai/inference/v1/models",
}


async def _load_vault_keys(project: str) -> list[str]:
    from agentos.llm.provider_registry import export_vault_provider_keys
    from agentos.security.vault import MasterKey, Vault
    from agentos.storage import open_storage

    storage = await open_storage(project, backend="file")
    try:
        return await export_vault_provider_keys(Vault(storage.credentials, MasterKey.load(create=False)))
    finally:
        await storage.close()


def probe_call(name: str) -> int:
    from agentos.llm.provider_registry import PROVIDER_REGISTRY
    from agentos.llm.router_llm import AgentOSRouterLLM, AllProvidersFailedError

    prov = next((p for p in PROVIDER_REGISTRY if p["name"] == name), None)
    if prov is None:
        print(f"unknown provider {name!r}")
        return 2
    entry = {"provider": name, "model": prov["litellm_model"], "api_key_env": prov["api_key_env"],
             "local": prov["api_key_env"] is None, "timeout": prov.get("timeout_s")}
    records: list[dict] = []
    llm = AgentOSRouterLLM(chain=[entry], on_call=records.append, node_id="probe")
    messages = [{"role": "system", "content": "You are a support triage assistant."},
                {"role": "user", "content": "Classify: 'checkout is down'. Answer URGENT or NORMAL."}]
    started = time.perf_counter()
    try:
        llm.call(messages)
        rc = 0
    except AllProvidersFailedError:
        rc = 1
    rec = records[-1] if records else {}
    print(f"provider={name} model={prov['litellm_model']} status={rec.get('status')} "
          f"wall={round(time.perf_counter() - started, 2)}s")
    for a in rec.get("attempts", []):
        print(f"  attempt: {a.get('error_class')}: {a.get('error_message')}")
    return rc


def probe_models() -> int:
    from agentos.llm.provider_registry import PROVIDER_REGISTRY

    cache: dict[str, set[str] | str] = {}
    for p in PROVIDER_REGISTRY:
        prefix = next((k for k in MODEL_LISTS if p["litellm_model"].startswith(k)), None)
        key = os.environ.get(p["api_key_env"] or "", "").strip()
        if prefix is None or not key or p["name"] in ("openai_compatible", "omniroute"):
            print(f"{p['name']:<40} not checked ({'no key' if not key else 'no /models endpoint known'})")
            continue
        url = MODEL_LISTS[prefix]
        if url not in cache:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    data = json.loads(r.read())
                items = data.get("data", data) if isinstance(data, dict) else data
                cache[url] = {str(m.get("id")) for m in items if isinstance(m, dict)}
            except Exception as err:
                cache[url] = f"list failed: {type(err).__name__}"
        ids = cache[url]
        model_id = p["litellm_model"][len(prefix):]
        status = ids if isinstance(ids, str) else ("present" if model_id in ids else "MISSING")
        print(f"{p['name']:<40} {model_id:<60} {status}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="LIVE LLM provider diagnostics (owner-run).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("call")
    c.add_argument("provider")
    sub.add_parser("models")
    ap.add_argument("--project", default=os.environ.get("AGENTOS_PROJECT") or str(Path.home() / ".agentos" / "workspace"))
    a = ap.parse_args()
    os.environ.pop("AGENTOS_MOCK_LLM", None)
    try:
        loaded = asyncio.run(_load_vault_keys(a.project))
        print(f"vault key names loaded: {loaded}")
    except Exception as err:
        print(f"vault not loaded ({type(err).__name__}); using environment keys only")
    return probe_call(a.provider) if a.cmd == "call" else probe_models()


if __name__ == "__main__":
    sys.exit(main())
