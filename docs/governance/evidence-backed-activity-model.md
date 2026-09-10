# CloudShield MSSP Platform - Evidence-Backed KoçSistem Activity Model

**Document Version:** 2.0.0  
**Classification:** Operational Governance & Value Accounting  

---

## 1. The Activity Evidence Standard

KoçSistem managed service claims must be backed by discrete, verifiable execution records in `Data/manual-service-activities.json`.

### Minimum Required Activity Schema:
```json
{
  "activityId": "ACT-20260905-003",
  "tenantId": "c9c0ee10-6398-473c-9681-d2fffaa55531",
  "customerName": "Emre-TestTenant",
  "serviceCode": "SVC-MDE",
  "engineerUpn": "security-engineer@cloudshield-mssp.com",
  "timestamp": "2026-09-05T09:00:00Z",
  "activityType": "PostureHardening",
  "title": "Attack Surface Reduction (ASR) Kural Optimizasyonu",
  "hoursSpent": 4.0,
  "status": "Completed",
  "evidenceRef": "SEC-POSTURE-2026-014",
  "approvalStatus": "Approved"
}
```

---

## 2. Prohibition of Synthetic Multipliers

- **The Multiplier Fallacy:** Formulas of the form `saved_hours = actions * 1.5` are **prohibited** in customer reports.
- **Authoritative Source:** Saved hours must represent the exact sum of `hoursSpent` from approved activity records.
- **FTE Capacity Gain:** Calculated strictly as \(\text{FTE} = \text{Hours} / 160\). If no approved worklog exists, display `0.0 FTE` without capacity gain assertions.
