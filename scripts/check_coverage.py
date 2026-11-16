import json
import sys

def main():
    try:
        with open("coverage.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("coverage.json not found. Run pytest --cov=agentos --cov-report=json first.")
        sys.exit(1)

    target_files = [
        "agentos/core/squad.py",
        "agentos/core/governance.py",
        "agentos/core/checkpoint.py",
        "agentos/core/federation.py",
        "agentos/core/umb_adapter.py",
        "agentos/llm/router_factory.py",
        "agentos/llm/llm_client.py",
        "agentos/llm/provider_registry.py",
    ]

    failed = False
    files_data = data.get("files", {})

    print("=== Core & LLM Coverage Check ===")
    for target in target_files:
        # Convert path delimiters if needed
        matching_key = None
        for k in files_data.keys():
            normalized_k = k.replace("\\", "/")
            if normalized_k.endswith(target):
                matching_key = k
                break

        if not matching_key:
            print(f"[FAIL] {target}: Not found in coverage data")
            failed = True
            continue

        file_cov = files_data[matching_key]
        percent = file_cov["summary"]["percent_covered"]
        if percent < 80.0:
            print(f"[FAIL] {target}: {percent:.2f}% (Below 80% target!)")
            failed = True
        else:
            print(f"[OK] {target}: {percent:.2f}%")

    if failed:
        print("=== Check Failed! ===")
        sys.exit(1)
    else:
        print("=== Check Passed! ===")

if __name__ == "__main__":
    main()
