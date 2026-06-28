"""
build_templates.py — Build all bundled template .agentpack files from source YAML.

Run this script once (or after modifying template sources) to rebuild the .agentpack files:
    python agentos/templates/build_templates.py

The generated .agentpack files in agentos/templates/packs/ should be committed to the repo
so users get them without needing to run this script.
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agentos.templates.templates import BUNDLED_TEMPLATES, build_template_pack

def main():
    print("Building AgentOS bundled template packs...\n")
    success = []
    failures = []
    
    for tmpl in BUNDLED_TEMPLATES:
        name = tmpl["name"]
        try:
            pack_path = build_template_pack(name)
            size = os.path.getsize(pack_path)
            print(f"  [OK] {name:<30} -> {os.path.basename(pack_path)} ({size:,} bytes)")
            success.append(name)
        except Exception as e:
            print(f"  [FAIL] {name:<30} FAILED: {e}")
            failures.append((name, str(e)))
    
    print(f"\nBuilt {len(success)}/{len(BUNDLED_TEMPLATES)} templates successfully.")
    if failures:
        print("\nFailed templates:")
        for name, err in failures:
            print(f"  - {name}: {err}")
        sys.exit(1)
    else:
        print("All templates built successfully!")
        print("Pack files are in: agentos/templates/packs/")

if __name__ == "__main__":
    main()
