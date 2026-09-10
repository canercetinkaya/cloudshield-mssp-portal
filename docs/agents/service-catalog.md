# Managed Service Catalog (12 Core Services)

The MSSP Platform is modularized into 12 core managed services, each defined with specific data contracts and collectors.

## 1. Microsoft Defender Services
- **SVC-MDE (Defender for Endpoint):** EDR device health, sensor hygiene, ASR rule blocks, TVM vulnerabilities, and automated investigation.
- **SVC-MDO (Defender for Office 365):** Mailbox security, Quishing/QR phish hunting, Safe Links/Attachments, and automated Zero-hour Auto Purge (ZAP).
- **SVC-MDI (Defender for Identity):** Domain Controller telemetry, Kerberoasting detection, anomalous LDAP queries, and Active Directory sensor health.
- **SVC-MDCA (Defender for Cloud Apps):** Shadow IT discovery, unsanctioned cloud app detection, and OAuth high-privilege app auditing.
- **SVC-XDR (Defender XDR Core):** Cross-workload incident correlation, automatic attack disruption, and MTTR metrics.
- **SVC-ENTRA (Entra ID Protection & PIM):** Identity risk detections, anomalous sign-ins, and Privileged Identity Management (PIM) zero-standing privilege enforcement.

## 2. Microsoft Purview Compliance Services
- **SVC-PRV-DLP (Data Loss Prevention):** Multi-workload DLP enforcement across Endpoint, Exchange, SharePoint, and Teams.
- **SVC-PRV-CLASS (Information Protection):** Sensitivity labels, automated classification, and Sensitive Information Type (SIT) hygiene.
- **SVC-PRV-GOV (Data Lifecycle Management):** Retention policies, records management, and automated de-identification.
- **SVC-PRV-RISK (Insider Risk Management):** Adaptive protection, anomalous bulk downloads, and risky user triage.
- **SVC-PRV-DSPM (Data Security Posture Management):** Multi-cloud data asset mapping and sensitive data exposure reduction.
- **SVC-AI-SECURITY (Purview AI Hub & Copilot):** AI application telemetry, sensitive data leakage prevention in GenAI interactions, and Copilot prompt protection.
