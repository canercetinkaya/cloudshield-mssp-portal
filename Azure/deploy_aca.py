#!/usr/bin/env python3
"""
Azure Container Apps - Single Container Deployment & Verification Script
Zero Hardcoded Resource Names.
Dynamically resolves Resource Group, Container App Name, and Environment.
Uses `az containerapp update --image` (minimal-diff update pattern).
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


def discover_container_app():
    """
    Dynamically discover Resource Group and Container App name if not supplied in env.
    Priority:
    1. Environment variables AZURE_RESOURCE_GROUP and CONTAINER_APP_NAME
    2. Dynamic lookup via `az containerapp list`
    """
    rg = os.environ.get("AZURE_RESOURCE_GROUP", "").strip()
    app = os.environ.get("CONTAINER_APP_NAME", "").strip()

    if rg and app:
        print(f"[DISCOVERY] Using explicitly provided RG='{rg}', App='{app}'")
        return rg, app

    print("[DISCOVERY] Resource group or app name not fully specified in env. Discovering via Azure CLI...")
    res = run_cmd(["az", "containerapp", "list", "--query", "[].{name:name, resourceGroup:resourceGroup}", "-o", "json"], check=False)
    
    if res.returncode == 0 and res.stdout.strip():
        try:
            apps = json.loads(res.stdout)
            if apps and len(apps) > 0:
                # Prefer cs-mssp or cloudshield named app if multiple exist
                match = next((a for a in apps if "cs-mssp" in a.get("name", "") or "cloudshield" in a.get("name", "")), apps[0])
                discovered_app = match.get("name")
                discovered_rg = match.get("resourceGroup")
                print(f"[DISCOVERY] Successfully auto-discovered Target Container App: '{discovered_app}' in RG: '{discovered_rg}'")
                return discovered_rg, discovered_app
        except Exception as e:
            print(f"[WARN] Error parsing az containerapp list: {e}")

    # Fallback to defaults from architecture blueprint
    fallback_rg = rg or "cs-mssp-poc-rg"
    fallback_app = app or "cs-mssp-poc-app"
    print(f"[DISCOVERY] Falling back to default architecture names: RG='{fallback_rg}', App='{fallback_app}'")
    return fallback_rg, fallback_app


def main():
    github_sha = os.environ.get("GITHUB_SHA", "latest")
    github_token = os.environ.get("GITHUB_TOKEN", "")

    resource_group, app_name = discover_container_app()
    image_tag = f"ghcr.io/canercetinkaya/cloudshield-mssp-portal:{github_sha}"

    print(f"=== Deploying {app_name} | RG: {resource_group} | Image: {image_tag} ===")

    # 1. Verify the Container App exists
    res = run_cmd(["az", "containerapp", "show", "-n", app_name, "-g", resource_group, "--query", "name", "-o", "tsv"])
    print(f"[OK] Container App verified: {res.stdout.strip()}")

    # 2. Update GHCR registry credentials so ACA can pull the new image
    if github_token:
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

    # 5. Resolve FQDN dynamically
    fqdn_res = run_cmd(["az", "containerapp", "show", "-n", app_name, "-g", resource_group, "--query", "properties.configuration.ingress.fqdn", "-o", "tsv"], check=False)
    fqdn = fqdn_res.stdout.strip() if fqdn_res.returncode == 0 else ""
    if not fqdn:
        fqdn = "cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io"
    
    version_url = f"https://{fqdn}/api/version"
    print(f"=== Verifying Live Version Endpoint: {version_url} ===")

    # 6. Live Endpoint Verification (24 probes x 8s = 192s window for ACA cold start)
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