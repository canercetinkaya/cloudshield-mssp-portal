# CloudShield MSSP Platform - Release Automation Process

## 1. Overview
Releases are decoupled from continuous workspace synchronization and require execution through an explicit release gate command: New-CloudShieldRelease.ps1 or automated CI/CD pipeline triggers.

## 2. Release Prerequisites
1. **Clean Working Tree:** \git status --porcelain\ must return clean.
2. **Main Branch:** Current branch must be \main\.
3. **Full Quality Gate Pass:**
   - PowerShell module tests (10 service plugins + core modules).
   - Python semantic quality gates (14 automated assertions in \	est_report_quality_gate.py\).
   - Comprehensive 65-test QA harness (\	est_comprehensive_qa.py\).
   - Version consistency validation against \ ersion.json\.
   - UTF-8 encoding audit across all source files.
4. **Single Source of Truth Versioning:**
   - Active release version is dynamically governed by `version.json` (currently `v2.5.13-PILOT`, build `2026.09.11.1`).
   - No hardcoded version strings permitted in API endpoints.
5. **Immutable Tagging:**
   - Release tag is created as an annotated git tag matching the version manifest without \--force\.
