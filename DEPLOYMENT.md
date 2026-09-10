# CloudShield MSSP Platform — Deployment Guide

**Current Release Version:** `v2.5.13-PILOT`  
**Target Environment:** Azure Container Apps & On-Premises Docker  

---

## 1. Prerequisites

- **Docker:** Engine 24.0+ or Docker Desktop
- **Azure CLI:** `az` 2.50+ with `containerapp` extension
- **Python:** 3.11 (Standard Library only — zero pip dependencies)
- **PowerShell:** PowerShell 7.4 Core (Cross-platform)
- **Browser:** Google Chrome or Microsoft Edge (for headless vector PDF export)

---

## 2. Local Container Deployment

Build and run CloudShield locally using Docker:

```bash
# 1. Build container image
docker build -t cloudshield-mssp-portal:latest -f Docker/Dockerfile .

# 2. Run container
docker run -d -p 8080:8080 \
  --name cloudshield-portal \
  -e PORT=8080 \
  -e ENVIRONMENT=Pilot \
  cloudshield-mssp-portal:latest

# 3. Verify health
curl -f http://localhost:8080/api/health
```

Or run via Docker Compose:

```bash
docker compose -f Docker/docker-compose.yml up -d
```

---

## 3. Azure Container Apps Deployment

CloudShield utilizes automated continuous deployment to Azure Container Apps via GitHub Actions and minimal-diff Bicep templates.

### Automated CI/CD Deployment
Pushing to the `main` branch triggers:
1. `.github/workflows/ci-cd.yml` (QA and syntax validation).
2. `.github/workflows/cs-mssp-poc-app-AutoDeployTrigger-*.yml` (Builds Docker image, pushes to GHCR, and deploys to ACA).

### Manual Azure CLI Deployment
Deploy using the dynamic discovery script (`Azure/deploy_aca.py`):

```bash
# Zero hardcoded resource names — auto-discovers ACA in current subscription
python Azure/deploy_aca.py
```

---

## 4. Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `8080` | HTTP listener port for REST API and web UI |
| `ENVIRONMENT` | `pilot` | Deployment environment label (`pilot`, `production`) |
| `CLOUDSHIELD_RELEASE_CHANNEL` | `PILOT` | Release channel gate (`PILOT`, `PRODUCTION`) |
| `PORTAL_ADMIN_PASSWORD` | - | Admin credential override (prevents defaults) |

---

## 5. Health Check & Monitoring

- **Health Endpoint:** `GET /api/health`
- **Version Manifest:** `GET /api/version`
- **Container Probe:** Configured in `Dockerfile` and `docker-compose.yml`:
  ```bash
  HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -f http://localhost:8080/api/health || exit 1
  ```
