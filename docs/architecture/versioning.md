# CloudShield MSSP Platform - Single-Source Versioning Architecture

## 1. Overview
The CloudShield MSSP Platform enforces a strict Single-Source-of-Truth versioning architecture anchored at the repository root in version.json. Every component reads version metadata dynamically or derives it from this single manifest during automated release gates.

## 2. Allowed Release Channels
1. DEV: Local developer workstations and sandbox environments.
2. INTERNAL: Internal quality assurance and integration testing.
3. PILOT: Controlled customer pilot deployments. Production readiness remains explicitly false.
4. PRODUCTION: Full customer production deployments. Requires explicit manual executive approval.

## 3. Enforcement & Immutable Tags
- Direct git tag -f or tag overwriting is blocked.
- Release tags equal the manifest release value exactly (v2.5.11-PILOT).
- productionReady is decoupled from deployment and remains false throughout the pilot phase.
