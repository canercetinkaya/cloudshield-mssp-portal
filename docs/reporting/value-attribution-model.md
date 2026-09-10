# CloudShield MSSP Platform - Four-Pillar Value Attribution Model

**Document Version:** 2.0.0  
**Classification:** Core Value Model  

---

## 1. The Four Non-Overlapping Pillars

To eliminate customer confusion and prove ROI, CloudShield strictly segregates security outcomes into four non-overlapping pillars:

```mermaid
flowchart TD
    subgraph P1 ["Pillar 1: Microsoft Technology Value"]
        M1["Autonomous Platform Blocks (AIR, ZAP, Antivirus)"]
        M2["Zero Human Intervention Required"]
    end

    subgraph P2 ["Pillar 2: KoçSistem Managed Service Value"]
        K1["Expert Human Engineering & Incident Triage"]
        K2["Policy Tuning & Proactive Threat Hunting"]
        K3["Approved Timesheet Worklogs (Saved Hours)"]
    end

    subgraph P3 ["Pillar 3: Customer Action Value"]
        C1["Stale Object De-provisioning (Ghost Devices)"]
        C2["DLP Business Justification & User Education"]
    end

    subgraph P4 ["Pillar 4: Shared Outcome"]
        S1["Zero Material Data Breach"]
        S2["Proactive KVKK / GDPR Compliance Defense"]
    end
```

---

## 2. Microsoft vs. KoçSistem Value Separation Rules

1. **Zero Double-Counting:** Automated Microsoft blocks (e.g., 120 Defender AV blocks) are NEVER counted as KoçSistem human actions.
2. **Evidence-Backed Saved Hours:** KoçSistem saved hours must derive strictly from approved timesheets in `Data/manual-service-activities.json`. Synthetic multipliers (`actions * 1.5`) are prohibited in customer reports.
3. **FTE Capacity Formula:**
   $$\text{FTE} = \frac{\text{ApprovedSavedHours}}{160}$$
   If saved hours are unbacked, the FTE metric must render `0.0 FTE` with an explicit notice: *"Doğrulanmış Süre Kaydı Bulunmuyor"*.
