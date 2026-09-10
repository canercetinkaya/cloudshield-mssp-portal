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
    
    # 4. List Active Revisions
    print("=== Active Revisions & Replicas ===")
    run_cmd(["az", "containerapp", "revision", "list", "-n", app_name, "-g", resource_group, "-o", "table"], check=False)
    
    # 5. Live Endpoint Verification
    health_url = "https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io/api/health"
    print(f"=== Verifying Live Health Endpoint: {health_url} ===")
    
    verified = False
    for attempt in range(1, 15):
        print(f"Health check probe attempt {attempt}/14...")
        try:
            req = urllib.request.Request(health_url, headers={"User-Agent": "Mozilla/5.0 (Deployment-Verifier)"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8")
                    print(f"\n[SUCCESS] Azure Container App is LIVE & RESPONDING!")
                    print(f"Response: {body}\n")
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
