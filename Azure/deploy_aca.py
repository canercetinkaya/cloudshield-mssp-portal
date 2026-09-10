#!/usr/bin/env python3
"""
Azure Container Apps - Single Container Deployment & Verification Script
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
        sys.exit(result.returncode)
    return result

def main():
    github_sha = os.environ.get("GITHUB_SHA", "latest")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    
    app_name = "cs-mssp-poc-app"
    resource_group = "cloudshield"
    image_tag = f"ghcr.io/canercetinkaya/cloudshield-mssp-portal:{github_sha}"
    
    print(f"=== Deploying {app_name} with Image: {image_tag} ===")
    
    # 1. Resolve Managed Environment ID
    res = run_cmd(["az", "containerapp", "show", "-n", app_name, "-g", resource_group, "--query", "properties.managedEnvironmentId", "-o", "tsv"])
    env_id = res.stdout.strip()
    print(f"Managed Environment ID: {env_id}")
    
    # 2. Build Clean Single-Container Deployment Config (JSON is valid YAML)
    config = {
        "properties": {
            "managedEnvironmentId": env_id,
            "configuration": {
                "activeRevisionsMode": "Single",
                "ingress": {
                    "external": True,
                    "targetPort": 8080,
                    "transport": "Auto",
                    "allowInsecure": False
                },
                "registries": [
                    {
                        "server": "ghcr.io",
                        "username": "canercetinkaya",
                        "passwordSecretRef": "ghcrio-secret"
                    }
                ],
                "secrets": [
                    {
                        "name": "ghcrio-secret",
                        "value": github_token
                    }
                ]
            },
            "template": {
                "containers": [
                    {
                        "name": "cloudshield-mssp-portal",
                        "image": image_tag,
                        "resources": {
                            "cpu": 0.5,
                            "memory": "1.0Gi"
                        },
                        "env": [
                            {"name": "PORT", "value": "8080"},
                            {"name": "ENVIRONMENT", "value": "poc"}
                        ]
                    }
                ],
                "scale": {
                    "minReplicas": 1,
                    "maxReplicas": 3,
                    "rules": [
                        {
                            "name": "http-rule",
                            "http": {
                                "metadata": {
                                    "concurrentRequests": "10"
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
    
    config_file = "aca_deployment.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    print(f"Saved clean configuration to {config_file}")
    
    # 3. Apply Clean Deployment
    print("=== Applying clean single-container configuration ===")
    run_cmd(["az", "containerapp", "update", "-n", app_name, "-g", resource_group, "--yaml", config_file])
    
    # 4. Deactivate old revisions so traffic strictly routes to newest revision
    print("=== Managing Revisions & Routing Traffic ===")
    rev_res = run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "json"], check=False)
    try:
        revs = json.loads(rev_res.stdout)
        # Sort newest first
        revs_sorted = sorted(revs, key=lambda x: x.get("properties", {}).get("createdTime", ""), reverse=True)
        if revs_sorted:
            latest_rev_name = revs_sorted[0].get("name")
            print(f"Latest Revision: {latest_rev_name}")
            # Deactivate older active revisions
            for old_rev in revs_sorted[1:]:
                if old_rev.get("properties", {}).get("active"):
                    old_name = old_rev.get("name")
                    print(f"Deactivating stale revision: {old_name}")
                    run_cmd(["az", "containerapp", "revision", "deactivate", "-n", app_name, "-g", resource_group, "--revision", old_name], check=False)
    except Exception as e:
        print(f"[WARN] Error handling revisions: {e}")

    run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "table"], check=False)
    
    # 5. Live Endpoint Verification
    version_url = "https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io/api/version"
    print(f"=== Verifying Live Version Endpoint: {version_url} ===")
    
    verified = False
    for attempt in range(1, 20):
        print(f"Version check probe attempt {attempt}/19...")
        try:
            req = urllib.request.Request(version_url, headers={"User-Agent": "Mozilla/5.0 (Deployment-Verifier)"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    print(f"\n[SUCCESS] Azure Container App is LIVE & RESPONDING!")
                    print(f"Active Release: {data.get('release')} | Version: {data.get('version')} | Build: {data.get('build')}\n")
                    verified = True
                    break
        except Exception as e:
            print(f"  Attempt {attempt} failed: {e}")
        time.sleep(5)
        
    if not verified:
        print("[WARN] Verification timed out. Fetching recent container logs:")
        run_cmd(["az", "containerapp", "logs", "show", "-n", app_name, "-g", resource_group, "--tail", "60"], check=False)
        sys.exit(1)

if __name__ == "__main__":
    main()
