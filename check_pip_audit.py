#!/usr/bin/env python3
import subprocess
import json
import sys
import requests

def get_severity(vuln_id):
    try:
        r = requests.get(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        sev = data.get("database_specific", {}).get("severity")
        if sev:
            return sev
        # Try aliases
        for alias in data.get("aliases", []):
            if alias.startswith("GHSA-"):
                r2 = requests.get(f"https://api.osv.dev/v1/vulns/{alias}", timeout=10)
                if r2.status_code == 200:
                    sev2 = r2.json().get("database_specific", {}).get("severity")
                    if sev2:
                        return sev2
    except Exception as e:
        print(f"Warning: Failed to fetch severity for {vuln_id}: {e}", file=sys.stderr)
    return None

def main():
    print("Running pip-audit on requirements.txt...")
    cmd = ["pip-audit", "-r", "requirements.txt", "--format", "json"]
    # Run pip-audit and capture output
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if not result.stdout.strip():
        print("pip-audit returned no output. Stderr:")
        print(result.stderr)
        sys.exit(result.returncode)
        
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Error parsing pip-audit JSON output: {e}")
        print("Raw stdout:")
        print(result.stdout)
        sys.exit(1)
        
    dependencies = data.get("dependencies", [])
    high_or_critical_vulns = []
    
    for dep in dependencies:
        name = dep.get("name")
        version = dep.get("version")
        vulns = dep.get("vulns", [])
        for vuln in vulns:
            vuln_id = vuln.get("id")
            severity = get_severity(vuln_id)
            if severity in ("HIGH", "CRITICAL"):
                high_or_critical_vulns.append({
                    "package": name,
                    "version": version,
                    "vuln_id": vuln_id,
                    "severity": severity,
                    "description": vuln.get("description", "No description provided.")
                })
            else:
                print(f"Found vulnerability {vuln_id} in {name} ({version}) with severity {severity or 'UNKNOWN'} (skipped)")

    if high_or_critical_vulns:
        print("\n[!] CRITICAL/HIGH Vulnerabilities Found:")
        for v in high_or_critical_vulns:
            print(f"  - Package: {v['package']} ({v['version']})")
            print(f"    Vuln ID: {v['vuln_id']}")
            print(f"    Severity: {v['severity']}")
            print(f"    Description: {v['description']}")
            print("-" * 60)
        sys.exit(1)
    else:
        print("\nNo HIGH or CRITICAL vulnerabilities found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
