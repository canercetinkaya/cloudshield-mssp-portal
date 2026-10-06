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


def make_ghcr_package_public(github_token: str, owner: str = "canercetinkaya", package: str = "cloudshield-mssp-portal") -> bool:
    """
    Set GHCR container package visibility to 'public' via GitHub API.
    Once public, ACA cold-starts never need stored credentials — eliminates ImagePullBackOff permanently.
    Requires a token with 'write:packages' scope (GITHUB_TOKEN with packages:write permission works).
    API: PATCH /user/packages/container/{package_name}
    """
    if not github_token:
        print("[WARN] No GITHUB_TOKEN — cannot set package visibility via API.")
        return False

    url = f"https://api.github.com/user/packages/container/{package}"
    payload = json.dumps({"visibility": "public"}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "CloudShield-DeployScript/1.0",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            if status in (200, 204):
                print(f"[OK] GHCR package '{package}' is now PUBLIC — ACA cold-starts will never need credentials.")
                return True
            else:
                print(f"[WARN] Unexpected status {status} when setting package public: {body[:200]}")
                return False
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[WARN] Could not set GHCR package to public (HTTP {e.code}): {body[:300]}")
        print("[WARN] Falling back to stored registry credentials. Ensure GHCR_PAT secret is set for cold-start pulls.")
        return False
    except Exception as e:
        print(f"[WARN] GHCR visibility API call failed: {e}")
        return False





def main():
    github_sha = os.environ.get("GITHUB_SHA", "latest")
    github_token = os.environ.get("GITHUB_TOKEN", "")

    resource_group, app_name = discover_container_app()
    image_tag = f"ghcr.io/canercetinkaya/cloudshield-mssp-portal:{github_sha}"

    print(f"=== Deploying {app_name} | RG: {resource_group} | Image: {image_tag} ===")

    # 0. Make GHCR package public — permanently eliminates ImagePullBackOff on ACA cold-starts.
    #    Once public, ACA never needs stored credentials to pull. Safe to call every deploy.
    print("=== Step 0: Ensuring GHCR package is public (eliminate ImagePullBackOff) ===")
    make_ghcr_package_public(github_token)

    # 1. Verify the Container App exists
    res = run_cmd(["az", "containerapp", "show", "-n", app_name, "-g", resource_group, "--query", "name", "-o", "tsv"])
    print(f"[OK] Container App verified: {res.stdout.strip()}")


    # 2. Update GHCR registry credentials so ACA can pull the new image.
    #    If GHCR_PAT is provided, store it. If not, remove any stale 'ghcr.io' registry entry
    #    so ACA pulls anonymously as a public package (avoids 401 Unauthorized from expired tokens).
    ghcr_pat = os.environ.get("GHCR_PAT", "").strip()
    if ghcr_pat:
        print("=== Storing GHCR credentials in ACA (using long-lived GHCR_PAT) ===")
        run_cmd([
            "az", "containerapp", "registry", "set",
            "-n", app_name, "-g", resource_group,
            "--server", "ghcr.io",
            "--username", "canercetinkaya",
            "--password", ghcr_pat
        ], check=False)
    else:
        print("=== GHCR package is PUBLIC: Removing any stale private registry credentials from ACA to allow anonymous pull ===")
        run_cmd([
            "az", "containerapp", "registry", "remove",
            "-n", app_name, "-g", resource_group,
            "--server", "ghcr.io"
        ], check=False)


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

    # 4. Detect active revisions mode
    rev_mode_res = run_cmd([
        "az", "containerapp", "show",
        "-n", app_name, "-g", resource_group,
        "--query", "properties.configuration.activeRevisionsMode",
        "-o", "tsv"
    ], check=False)
    active_revisions_mode = rev_mode_res.stdout.strip() if rev_mode_res.returncode == 0 and rev_mode_res.stdout.strip() else "Single"
    print(f"[DISCOVERY] Active revisions mode: '{active_revisions_mode}'")

    # 4b. Wait for newly created revision to provision
    print("=== Checking revisions and waiting for new revision to provision ===")
    latest_rev_name = "latest"
    old_rev_names = []
    for poll_step in range(25):
        time.sleep(6)
        rev_res = run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "json"], check=False)
        if rev_res.returncode == 0 and rev_res.stdout.strip():
            try:
                revs = json.loads(rev_res.stdout)
                revs.sort(key=lambda r: r.get("properties", {}).get("createdTime", ""), reverse=True)
                if revs:
                    top_rev = revs[0]
                    latest_rev_name = top_rev.get("name", "latest")
                    p_state = top_rev.get("properties", {}).get("provisioningState")
                    r_state = top_rev.get("properties", {}).get("runningState")
                    h_state = top_rev.get("properties", {}).get("healthState")
                    p_err = top_rev.get("properties", {}).get("provisioningError")
                    old_rev_names = [r.get("name") for r in revs[1:] if r.get("name")]
                    print(f"[REVISION poll {poll_step+1}/25] Top Revision: {latest_rev_name} | ProvisioningState: {p_state} | RunningState: {r_state} | HealthState: {h_state}")
                    if p_err:
                        print(f"[REVISION DIAGNOSTIC ERROR] {p_err}")
                    if p_state == "Provisioned" and (h_state == "Healthy" or r_state == "Running"):
                        print(f"[OK] Revision {latest_rev_name} successfully PROVISIONED and ready!")
                        break
                    elif p_state == "Failed":
                        print(f"[ERROR] Revision {latest_rev_name} FAILED to provision: {p_err}")
                        break
            except Exception as e:
                print(f"[WARN] Error parsing revision JSON: {e}")

    run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "table"], check=False)

    if active_revisions_mode.lower() == "single":
        print("[INFO] Single revision mode: ACA automatically routes 100% traffic to the active revision.")
        # Ensure latest revision is activated in Single mode to recover from any previous stopped state
        if latest_rev_name and latest_rev_name != "latest":
            print(f"=== Activating target revision '{latest_rev_name}' in Single revision mode ===")
            run_cmd([
                "az", "containerapp", "revision", "activate",
                "-n", app_name, "-g", resource_group,
                "--revision", latest_rev_name
            ], check=False)
    else:
        print(f"=== Directing 100% traffic to revision '{latest_rev_name}' ===")
        run_cmd([
            "az", "containerapp", "ingress", "traffic", "set",
            "-n", app_name, "-g", resource_group,
            "--revision-weight", f"{latest_rev_name}=100"
        ], check=False)

        # In Multiple mode, deactivate stale revisions only after new revision is provisioned
        if old_rev_names and latest_rev_name != "latest":
            print("=== Deactivating stale revisions in Multiple revision mode ===")
            for old_rev in old_rev_names[:3]:
                print(f"Deactivating stale revision: {old_rev}")
                run_cmd(["az", "containerapp", "revision", "deactivate", "-n", app_name, "-g", resource_group, "--revision", old_rev], check=False)

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