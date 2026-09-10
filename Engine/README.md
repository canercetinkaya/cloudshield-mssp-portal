# CloudShield Reporting Engine (`Engine/`)

**Subsystem:** Core Telemetry Ingestion & PowerShell 7.4 Collector Framework  
**Parent Product:** CloudShield MSSP Platform  
**Runtime:** PowerShell 7.4 Core | Cross-Platform Linux/Windows  

---

## 1. Engine Overview

The `Engine/` subsystem is responsible for authenticating against customer Microsoft tenants, orchestrating telemetry collectors across 12 enterprise services, performing k-anonymity privacy transformations, and feeding normalized telemetry to the presentation layer.

---

## 2. Directory Map

```
Engine/
├── Core/                                   # Platform Core Engines
│   ├── Authentication.psm1                 # RFC 7523 CBA & Azure Key Vault Token Broker
│   ├── Configuration.psm1                  # Layered Tenant Configuration Loader
│   ├── Logging.psm1                        # JSONL Structured Telemetry Logger
│   ├── PrivacyEngine.psm1                  # k-Anonymity (k >= 5) & Salted SHA-256 Masking
│   ├── HealthCheck.psm1                    # Pre-flight Connectivity & Permission Validator
│   ├── TrendEngine.psm1                    # Historical Delta & Posture Shift Analysis
│   ├── ReportRenderer.psm1                 # PowerShell HTML/PDF Rendering Engine
│   ├── PluginLoader.psm1                   # Dynamic Service Plugin Discovery & Execution
│   └── Update-Version.py                   # Single-Source Version Manifest Synchronizer
│
├── Plugins/                                # 12 Modular Service Telemetry Collectors
│   ├── DefenderEndpoint/                   # SVC-MDE (EDR, TVM, ASR)
│   ├── DefenderOffice/                     # SVC-MDO (Anti-Phish, Safe Attachments, ZAP)
│   ├── DefenderIdentity/                   # SVC-MDI (Kerberos & Lateral Movement)
│   ├── DefenderCloudApps/                  # SVC-MDCA (CASB & Shadow IT)
│   ├── DefenderXdr/                        # SVC-XDR (Cross-Domain Incidents)
│   ├── PurviewClassification/              # SVC-PRV-CLASS (Sensitivity Labels & SITs)
│   ├── PurviewDlp/                         # SVC-PRV-DLP (Data Loss Prevention)
│   ├── PurviewGovernance/                  # SVC-PRV-GOV (Retention & Records)
│   ├── PurviewRiskCompliance/              # SVC-PRV-RISK (Insider Risk - Isolated App)
│   └── PurviewAiSecurity/                  # SVC-AI-SECURITY (Copilot & AI DSPM)
│
├── KQL/                                    # Advanced Hunting Query Catalog
│   ├── query-catalog/                      # Standardized Microsoft & Community KQL Queries
│   └── query-metadata/                     # Query Metadata Catalog Index (catalog-index.json)
│
├── Config/                                 # Service Catalog & Global Templates
│   └── service-catalog.json                # Service and KPI Definitions
│
├── Templates/GoldenStandard/               # Executive A4 Vector Theme
│   └── style.css                           # Print & Typography Directives
│
├── Tests/                                  # Structured Platform Test Suite
│   └── Test-Platform.ps1                   # 33 Core & Plugin Contract Tests
│
└── Invoke-CloudShieldSecurityReporting.ps1 # Primary Collection Entrypoint
```

---

## 3. Platform Verification

Execute the 33 structured platform tests verifying all core modules, plugin contracts, and dry-run execution:
```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File Engine/Tests/Test-Platform.ps1
```\n