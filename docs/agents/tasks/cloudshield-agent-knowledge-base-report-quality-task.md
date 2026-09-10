# CloudShield Agent Knowledge Base & Report Quality Transformation Task
**Document Version:** 1.0.0
**Authoritative Status:** Active Specification
**Scope:** CloudShield MSSP Platform Executive & Technical Reporting Engine

---

## 1. Objective & Product Strategy

Assume the primary problem is not data collection.
Assume the primary problem is that generated reports are technically correct but not executive-ready, customer-ready, or sufficiently differentiated from generic AI-generated reports.

### Strategic Priorities:
- **Executive Readability:** Clear narrative that C-Level executives can comprehend without an engineer.
- **Evidence-Backed Storytelling:** Every metric is contextualized with real telemetry.
- **Information Architecture:** Seamless flow from executive posture to deep threat hunting and governance.
- **Microsoft vs. KoçSistem Value Separation:** Rigorous attribution of automated platform protection vs. human engineering operations.
- **Customer Decision Support:** Concrete decision tables (Approved, Pending, Deferred, Recommended).
- **Visual Quality:** Pixel-perfect A4 printing, distinct badges, clear typographic hierarchy.
- **Actionability:** RACI assignments, SLA commitments, and runbook IDs for all remediation items.
- **Service Maturity Visibility:** Explicit indication of data freshness, telemetry coverage, and configuration gaps.

---

## 2. Core Governance Contracts

### A. Report Storytelling Contract
Every visible KPI must answer: **SO WHAT?**
- If a KPI cannot produce a meaningful insight, do not display that KPI.
- If an insight cannot produce an action, do not display that insight.
- If an action has no owner, do not display that action.
- Every observation must follow the strict four-stage chain:
  Evidence -> Meaning -> Risk -> Action

### B. Service Value Attribution Model
Every reported outcome must belong to exactly one category:
1. **Microsoft Technology Value:** Native platform protection, automated investigation & response (AIR), ZAP, built-in heuristics, and cloud ML detections.
2. **KoçSistem Managed Service Value:** Expert analyst triage, custom KQL threat hunting, incident escalation, attack surface reduction (ASR) optimization, false-positive tuning, and proactive architecture hardening.
3. **Customer Action Value:** Policy exception approvals, device hardware refresh (TPM/SecureBoot), BitLocker PIN enforcement, and end-user security awareness training.
4. **Shared Outcome:** Joint incident response drills, compliance attestations, and architecture review milestones.
*Do not mix categories. Maintain strict clarity on who achieved what.*

### C. Customer Decision Framework
Every executive report must contain:
- **Approved Decisions:** Actions ratified in the previous cycle with verified outcomes.
- **Pending Decisions:** Immediate authorization requests impacting security posture.
- **Deferred Decisions:** Acknowledged risks postponed with clear expiry dates.
- **Recommended Decisions:** Proactive enhancements with explicit Owner, Priority, Evidence Source, and Expected Outcome.

### D. Executive Readability Contract
A customer executive must be able to answer all six questions without engineer assistance:
1. What happened?
2. Why does it matter?
3. What value did Microsoft provide?
4. What value did KoçSistem provide?
5. What risks remain?
6. What decisions are required?

---

## 3. Quality Evaluation Dimensions (Scoring Model)

All report artifacts are scored on a scale of 0 to 10 across eight dimensions:
1. **Data Integrity (Weight: 15%):** Zero mock policy, real telemetry extraction, correct math.
2. **Privacy & Governance (Weight: 15%):** k-Anonymity masking (UPN, IP, file), KVKK/GDPR compliance, cryptographic hashes.
3. **Technical Accuracy (Weight: 10%):** Valid KQL queries, correct MITRE ATT&CK mapping, sensor coverage calculations.
4. **Service Value Evidence (Weight: 15%):** Explicit KoçSistem vs. Microsoft attribution, SLA compliance, saved engineering hours.
5. **Executive Clarity (Weight: 15%):** 30-second posture badge, executive summary narrative, zero jargon ambiguity.
6. **Visual Quality (Weight: 10%):** A4 page budgeting, no awkward table breaks, corporate branding, professional typography.
7. **Actionability (Weight: 10%):** RACI assigned runbooks, SLA timeline, prioritized backlog.
8. **Language Quality (Weight: 10%):** Professional Turkish and international terminology, grammatical consistency, correct legal disclaimers.

**Passing Threshold:** Composite Score >= 8.5 / 10.0 with no individual category < 7.0 / 10.0.

---

## 4. Execution Workflow

1. Baseline Assessment & Scoring
2. Knowledge Base Restructuring (docs/agents/)
3. Report Engine Implementation (report_generator.py)
4. Golden Fixtures & Data Contracts
5. Automated Quality Gate Harness
6. Report Generation (HTML & Vector PDF)
7. Multi-Agent Independent Review
8. Final Release Recommendation
