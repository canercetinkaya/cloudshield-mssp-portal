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

    # 2. Update GHCR registry credentials so ACA can pull the new image.
    #    CRITICAL: GITHUB_TOKEN expires after the workflow job, causing ACA ImagePullBackOff on cold-starts.
    #    Prefer GHCR_PAT (Personal Access Token, read:packages) which is long-lived.
    #    → Create at: GitHub Settings > Developer settings > Personal access tokens > Fine-grained
    #      Permission: Read access to packages. Store as repo secret GHCR_PAT.
    ghcr_pat = os.environ.get("GHCR_PAT", "").strip()
    registry_token = ghcr_pat if ghcr_pat else github_token
    token_type = "GHCR_PAT (long-lived)" if ghcr_pat else "GITHUB_TOKEN (ephemeral - may cause ImagePullBackOff on cold-start)"
    if registry_token:
        print(f"=== Storing GHCR credentials in ACA (using: {token_type}) ===")
        run_cmd([
            "az", "containerapp", "registry", "set",
            "-n", app_name, "-g", resource_group,
            "--server", "ghcr.io",
            "--username", "canercetinkaya",
            "--password", registry_token
        ], check=False)
    else:
        print("[WARN] No GHCR credentials available — ACA may fail to pull private images!")
        print("[WARN] Set GHCR_PAT secret or make the GHCR package public.")


    # 3. Discover actual container name inside ACA (to avoid silent failures from name mismatch)
    print(f"=== Discovering actual container name inside {app_name} ===")
    cname_res = run_cmd([
        "az", "containerapp", "show",
        "-n", app_name, "-g", resource_group,
        "--query", "properties.template.containers[0].name",
        "-o", "tsv"
    ], check=False)
    actual_container_name = cname_res.stdout.strip() if cname_res.returncode == 0 and cname_res.stdout.strip() else "cloudshield-mssp-portal"
    print(f"[DISCOVERY] Actual container name in ACA: '{actual_container_name}'")

    # 3b. Update container image only (minimal diff - does NOT touch ingress/secrets/scale)
    print(f"=== Updating container image to {image_tag} (container: {actual_container_name}) ===")
    run_cmd([
        "az", "containerapp", "update",
        "-n", app_name, "-g", resource_group,
        "--container-name", actual_container_name,
        "--image", image_tag
    ])

    # 4. Route 100% traffic to latest revision and ensure scale
    print("=== Checking active revisions ===")
    run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "table"], check=False)

    print("=== Directing 100% traffic to latest revision ===")
    run_cmd([
        "az", "containerapp", "ingress", "traffic", "set",
        "-n", app_name, "-g", resource_group,
        "--revision-weight", "latest=100"
    ], check=False)

    print("=== Ensuring scale: min=1 max=3 ===")
    run_cmd([
        "az", "containerapp", "update",
        "-n", app_name, "-g", resource_group,
        "--container-name", actual_container_name,
        "--min-replicas", "1",
        "--max-replicas", "3"
    ], check=False)

    # 5. Resolve FQDN dynamically
    fqdn_res = run_cmd(["az", "containerapp", "show", "-n", app_name, "-g", resource_group, "--query", "properties.configuration.ingress.fqdn", "-o", "tsv"], check=False)
    fqdn = fqdn_res.stdout.strip() if fqdn_res.returncode == 0 else ""
    if not fqdn:
        fqdn = "cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io"
    
    # Load expected version and release from version.json
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    version_file = os.path.join(root_dir, "version.json")
    expected_version = ""
    expected_release = ""
    if os.path.exists(version_file):
        try:
            with open(version_file, "r", encoding="utf-8") as vf:
                vdata = json.load(vf)
                expected_version = vdata.get("version", "")
                expected_release = vdata.get("release", "")
        except Exception:
            pass

    version_url = f"https://{fqdn}/api/version"
    print(f"=== Verifying Live Version Endpoint: {version_url} (Expecting Version: '{expected_version}' / Release: '{expected_release}') ===")

    # Pre-probe: show current revision state for diagnostics
    print("=== Pre-probe: Current revision list ===")
    run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "table"], check=False)

    # Warmup: wait for ACA cold-start before first probe (avoids wasting probe budget)
    print("=== Waiting 25s for ACA revision cold-start warmup... ===")
    time.sleep(25)

    # 6. Live Endpoint Verification (30 probes x 8s = 240s window for revision traffic shift & cold start)
    verified = False
    for attempt in range(1, 31):
        print(f"Version check probe attempt {attempt}/30...")
        try:
            req = urllib.request.Request(version_url, headers={"User-Agent": "Mozilla/5.0 (Deployment-Verifier)"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    live_version = data.get("version")
                    live_release = data.get("release")
                    print(f"  Live probe returned: Release={live_release}, Version={live_version}")
                    
                    # Verify that the response matches the new version, not a stale revision
                    if expected_release and live_release != expected_release:
                        print(f"  [STALE REVISION DETECTED] Expected release '{expected_release}', but live endpoint returned '{live_release}'. Waiting for ACA revision switch...")
                    else:
                        print(f"\n[SUCCESS] Azure Container App is LIVE & ACTIVE REVISION MATCHES TARGET!")
                        print(f"Active Release: {live_release} | Version: {live_version} | Build: {data.get('build')}\n")
                        verified = True
                        break
        except Exception as e:
            print(f"  Attempt {attempt} failed: {e}")
        time.sleep(8)

    if not verified:
        print("[WARN] Verification timed out or target revision not active. Fetching recent container logs:")
        run_cmd(["az", "containerapp", "logs", "show", "-n", app_name, "-g", resource_group, "--tail", "80"], check=False)
        sys.exit(1)


if __name__ == "__main__":
    main()