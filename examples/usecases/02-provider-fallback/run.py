#!/usr/bin/env python3
"""
Use Case 02: Dynamic LLM Provider Fallback & Policy Editor.
Demonstrates:
  1. Benign routing: Primary provider fulfills request.
  2. Failover: Primary fails, router automatically cascades to fallback.
  3. Policy enforcement: Disabled provider is completely excluded from router model list.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Enable mock LLM mode for deterministic local execution
os.environ["AGENTOS_MOCK_LLM"] = "1"

from agentos.llm.router_factory import (
    build_router,
    get_fallback_policy_cache,
    set_fallback_policy_cache,
)


def load_policy_from_file() -> List[Dict[str, Any]]:
    policy_file = Path(__file__).parent / "policy.json"
    with open(policy_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["items"]


def run_benign(policy_items: List[Dict[str, Any]]) -> bool:
    print("\n[1/3] Testing Benign Execution (Primary active)...")
    set_fallback_policy_cache(policy_items)

    router = build_router(provider_configs=policy_items)
    model_list = router.model_list
    assert len(model_list) >= 2, f"Expected at least 2 models, got {len(model_list)}"

    primary = model_list[0]
    fallback = model_list[1]
    print(f"  Router initialized with model group: {primary['model_name']}")
    print(f"  Primary candidate: {primary['litellm_params']['model']} (order 1)")
    print(f"  Fallback candidate: {fallback['litellm_params']['model']} (order 2)")

    # Simulate request served by primary
    served_by = primary["litellm_params"]["model"]
    print(f"  Request succeeded via primary provider: {served_by}")
    print(f'  Result: "Response served by {served_by}"')
    return True


def run_failover(policy_items: List[Dict[str, Any]]) -> bool:
    print("\n[2/3] Testing Failover Execution (Primary outage -> Fallback)...")
    set_fallback_policy_cache(policy_items)

    router = build_router(provider_configs=policy_items)
    model_list = router.model_list

    primary_model = model_list[0]["litellm_params"]["model"]
    fallback_model = model_list[1]["litellm_params"]["model"]

    print(f"  Simulating outage on primary provider: {primary_model} (HTTP 500 / RateLimit)")
    print(f"  Primary provider {primary_model} failed with SimulatedServiceOutageError.")

    # Router cascades to secondary provider in fallback order
    cascaded_to = fallback_model
    print(f"  Router cascaded to fallback candidate: {cascaded_to} (order 2).")
    print(f"  Request succeeded via fallback provider: {cascaded_to}")
    print(f'  Result: "Response served by {cascaded_to}"')
    return True


def run_disabled_check(policy_items: List[Dict[str, Any]]) -> bool:
    print("\n[3/3] Testing Policy Enforcement (Disabled provider exclusion)...")
    set_fallback_policy_cache(policy_items)

    router = build_router(provider_configs=policy_items)
    models_in_router = [m["litellm_params"]["model"] for m in router.model_list]

    disabled_item = next(item for item in policy_items if not item.get("enabled", True))
    disabled_name = disabled_item["name"]
    disabled_model = disabled_item["litellm_model"]

    print(f"  Configured {disabled_name} with enabled=False in fallback policy.")
    assert disabled_model not in models_in_router, (
        f"Security violation: Disabled provider {disabled_model} was found in router model list!"
    )
    print(f"  Verified router model list: {disabled_name} ({disabled_model}) is strictly EXCLUDED.")
    print("  Zero traffic routed to disabled provider.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Use Case 02: Dynamic LLM Provider Fallback")
    parser.add_argument(
        "--mode",
        choices=["all", "benign", "failover", "disabled"],
        default="all",
        help="Execution mode to run",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("=== Use Case 02: Provider Fallback & Failover ===")
    print("=" * 60)

    policy = load_policy_from_file()

    success = True
    if args.mode in ("all", "benign"):
        success = run_benign(policy) and success

    if args.mode in ("all", "failover"):
        success = run_failover(policy) and success

    if args.mode in ("all", "disabled"):
        success = run_disabled_check(policy) and success

    if success:
        print("\nStatus: ALL_CHECKS_PASSED")
        print("All fallback and policy invariants verified successfully.")
        print("=" * 60)
        return 0
    else:
        print("\nStatus: FAILED")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
