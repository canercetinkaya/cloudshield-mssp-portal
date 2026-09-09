---
name: "🚀 Feature / Capability Request"
about: Propose a new Purview, Defender XDR, or reporting capability for the MSSP platform
title: "[FEATURE] "
labels: ["enhancement", "capability"]
assignees: ""
---

### 🚀 Capability Summary
A concise proposal for the new Purview or Defender security intelligence capability.

### 🏢 MSSP Business Context
Why is this capability essential for Managed Security Service operations? How does it benefit enterprise CISOs?

### 🧩 Proposed Architecture & API Surface
- Target Microsoft API (Microsoft Graph v1.0/beta, Defender XDR Advanced Hunting, Purview DLP Store)
- Required Entra Application Permissions (Application / Delegated)
- Service Catalog ID (e.g., `SVC-NEW-01`)

### 🛡️ Zero-Trust & Privacy Validation
- Does this feature store customer data? *(Platform standard: strictly in-memory transient processing)*
- Does this feature involve sensitive PII? *(Must integrate with `PrivacyEngine.psm1` k-anonymity masking)*
