# Service Value Attribution Model (Four-Pillar Governance)

## 1. The Attribution Imperative
A primary failure mode of generic MSSP reporting is taking credit for Microsoft platform automation or, conversely, failing to articulate the engineering value provided by human analysts.
Every reported outcome, metric, and activity in CloudShield **must belong to exactly one category**:

1. **Microsoft Technology Value**
2. **KoçSistem Managed Service Value**
3. **Customer Action Value**
4. **Shared Outcome**

**Do not mix categories.**

---

## 2. Category Definitions & Boundaries

### Pillar 1: Microsoft Technology Value (Platform Automation)
- **Definition:** Native autonomous protection executed in milliseconds by Microsoft Defender XDR & Purview algorithms.
- **Components:**
  - Automated Investigation and Response (AIR) playbook executions.
  - Zero-hour Auto Purge (ZAP) for phishing and malware emails in Exchange Online.
  - SmartScreen & Microsoft Defender Antivirus real-time cloud block.
  - Built-in Microsoft Purview DLP policy enforcement at endpoint/cloud egress.
- **Reporting Stance:** Acknowledged as the foundation of customer Microsoft E5 license value.

### Pillar 2: KoçSistem Managed Service Value (Human Engineering & Operations)
- **Definition:** Proactive security engineering, threat hunting, incident triaging, and posture optimization performed by KoçSistem MSSP engineers.
- **Components:**
  - Custom KQL threat hunting campaigns (FalconFriday LOLBins, Bert-JanP detections, Token theft rules).
  - Manual incident triaging, false-positive elimination, and escalation.
  - Attack Surface Reduction (ASR) policy hardening and audit tuning.
  - BitLocker key backup recovery and ghost device hygiene investigations.
  - Purview Sensitive Information Type (SIT) fingerprinting and regex refinement.
- **Reporting Stance:** Direct operational ROI, hours saved, and proactive breach prevention.

### Pillar 3: Customer Action Value (Tenant Administration & Internal IT)
- **Definition:** Critical IT hygiene and governance actions that strictly require customer-side ownership.
- **Components:**
  - Approving hardware decommissioning for stale Active Directory / Intune computer objects.
  - Disciplinary or awareness action for employees repeatedly performing DLP user overrides.
  - Approving high-privilege Entra ID OAuth application consents.
  - Deploying firmware / hardware patches for physical endpoints lacking TPM 2.0 or SecureBoot.
- **Reporting Stance:** Clear accountability, unblocked paths, and transparent SLAs.

### Pillar 4: Shared Outcome (Joint Governance & Posture Maturity)
- **Definition:** Strategic milestones achieved jointly between customer leadership and KoçSistem.
- **Components:**
  - Zero Material Incident verification (unbroken business continuity).
  - Regulatory compliance posture attestations (KVKK md. 12, GDPR Privacy-by-Design).
  - Quarterly architecture and cloud maturity reviews.
- **Reporting Stance:** Mutually celebrated security and compliance resilience.
