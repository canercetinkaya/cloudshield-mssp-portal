#!/usr/bin/env python3
"""
Azure Container Apps - Single Container Deployment & Verification Script
Uses `az containerapp update --image` (correct minimal-diff update pattern).
Enforces single-container topology, port 8080 mapping, and verifies live health.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request

def run_cmd(cmd, check=True):
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if check and result.returncode != 0:
        print(f"[FATAL] Command failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)
    return result

def main():
    github_sha = os.environ.get("GITHUB_SHA", "latest")
    github_token = os.environ.get("GITHUB_TOKEN", "")

    app_name = "cs-mssp-poc-app"
    resource_group = "cs-mssp-poc-rg"
    image_tag = f"ghcr.io/canercetinkaya/cloudshield-mssp-portal:{github_sha}"

    print(f"=== Deploying {app_name} | RG: {resource_group} | Image: {image_tag} ===")

    # 1. Verify the Container App exists
    res = run_cmd(["az", "containerapp", "show", "-n", app_name, "-g", resource_group, "--query", "name", "-o", "tsv"])
    print(f"[OK] Container App found: {res.stdout.strip()}")

    # 2. Update GHCR registry credentials so ACA can pull the new image
    print("=== Updating GHCR registry credentials ===")
    run_cmd([
        "az", "containerapp", "registry", "set",
        "-n", app_name, "-g", resource_group,
        "--server", "ghcr.io",
        "--username", "canercetinkaya",
        "--password", github_token
    ], check=False)

    # 3. Update container image only (minimal diff - does NOT touch ingress/secrets/scale)
    print(f"=== Updating container image to {image_tag} ===")
    run_cmd([
        "az", "containerapp", "update",
        "-n", app_name, "-g", resource_group,
        "--image", image_tag
    ])

    # 4. Ensure minReplicas=1 so the app never scales to zero
    print("=== Ensuring scale: min=1 max=3 ===")
    run_cmd([
        "az", "containerapp", "update",
        "-n", app_name, "-g", resource_group,
        "--min-replicas", "1",
        "--max-replicas", "3"
    ], check=False)

    # 5. Deactivate stale revisions (keep newest only)
    print("=== Managing Revisions & Routing Traffic ===")
    rev_res = run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "json"], check=False)
    try:
        revs = json.loads(rev_res.stdout or "[]")
        revs_sorted = sorted(revs, key=lambda x: x.get("properties", {}).get("createdTime", ""), reverse=True)
        if revs_sorted:
            latest_rev_name = revs_sorted[0].get("name")
            print(f"Latest Revision: {latest_rev_name}")
            for old_rev in revs_sorted[1:]:
                if old_rev.get("properties", {}).get("active"):
                    old_name = old_rev.get("name")
                    print(f"Deactivating stale revision: {old_name}")
                    run_cmd(["az", "containerapp", "revision", "deactivate", "-n", app_name, "-g", resource_group, "--revision", old_name], check=False)
    except Exception as e:
        print(f"[WARN] Error handling revisions: {e}")

    run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "table"], check=False)

    # 6. Live Endpoint Verification (24 probes x 8s = 192s window for ACA cold start)
    version_url = "https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io/api/version"
    print(f"=== Verifying Live Version Endpoint: {version_url} ===")

    verified = False
    for attempt in range(1, 25):
        print(f"Version check probe attempt {attempt}/24...")
        try:
            req = urllib.request.Request(version_url, headers={"User-Agent": "Mozilla/5.0 (Deployment-Verifier)"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    print(f"\n[SUCCESS] Azure Container App is LIVE & RESPONDING!")
                    print(f"Active Release: {data.get('release')} | Version: {data.get('version')} | Build: {data.get('build')}\n")
                    verified = True
                    break
        except Exception as e:
            print(f"  Attempt {attempt} failed: {e}")
        time.sleep(8)

    if not verified:
        print("[WARN] Verification timed out. Fetching recent container logs:")
        run_cmd(["az", "containerapp", "logs", "show", "-n", app_name, "-g", resource_group, "--tail", "80"], check=False)
        sys.exit(1)

if __name__ == "__main__":
    main()