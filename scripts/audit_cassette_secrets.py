"""
Audit script that reads API keys from the environment at runtime, searches
VCR cassettes, and prints only 'matches: N' per provider name without ever
printing key material or secret fragments.
"""
import glob
import importlib.util
import os
from dotenv import load_dotenv

# Load provider_registry directly without triggering agentos/__init__.py
spec = importlib.util.spec_from_file_location("provider_registry", "agentos/llm/provider_registry.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
PROVIDER_REGISTRY = mod.PROVIDER_REGISTRY


def audit_cassettes():
    load_dotenv()
    cassette_files = glob.glob("agentos/tests/cassettes/*.yaml")
    cassette_contents = []
    for cf in cassette_files:
        try:
            with open(cf, "r", encoding="utf-8", errors="ignore") as f:
                cassette_contents.append((cf, f.read()))
        except Exception:
            pass

    seen_providers = set()
    for prov in PROVIDER_REGISTRY:
        name = prov["name"]
        if name in seen_providers:
            continue
        seen_providers.add(name)

        key_env = prov.get("api_key_env")
        if not key_env:
            print(f"{name}: matches: 0")
            continue

        raw_key = os.environ.get(key_env, "").strip()
        if not raw_key or len(raw_key) < 6:
            print(f"{name}: matches: 0")
            continue

        # Check full key and substantial sub-fragments (>= 8 chars)
        fragments = [raw_key]
        if len(raw_key) >= 16:
            fragments.append(raw_key[:8])
            fragments.append(raw_key[-8:])
        if "." in raw_key:
            parts = raw_key.split(".")
            for part in parts:
                if len(part) >= 8:
                    fragments.append(part)

        matches = 0
        for _, content in cassette_contents:
            for frag in set(fragments):
                if frag and frag in content:
                    matches += 1
                    break

        print(f"{name}: matches: {matches}")


if __name__ == "__main__":
    audit_cassettes()
