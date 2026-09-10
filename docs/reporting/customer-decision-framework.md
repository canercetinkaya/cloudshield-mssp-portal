# CloudShield MSSP Platform - Customer Decision Framework

**Document Version:** 2.0.0  
**Classification:** Executive Decision Framework  

---

## 1. The Four Quadrants

Customer reports must not end with passive charts. Page 2 features an actionable **Four-Quadrant Executive Decision Matrix**:

```mermaid
quadrantChart
    title Customer Decision Framework
    x-axis Low Executive Urgency --> High Executive Urgency
    y-axis Low Posture Impact --> High Posture Impact
    quadrant-1 Pending Decisions (Yetkilendirme Bekleyen)
    quadrant-2 Recommended Decisions (Stratejik Tavsiyeler)
    quadrant-3 Deferred Decisions (Ertelenmiş Riskler)
    quadrant-4 Approved Decisions (Onaylanmış Aksiyonlar)
```

| Quadrant | Purpose | Mandatory Fields |
| :--- | :--- | :--- |
| **1. Approved Decisions** | Verifies actions ratified and completed in the previous cycle. | Decision ID, Title, Completed At, Outcome. |
| **2. Pending Decisions** | Immediate C-Level authorization requests impacting posture. | Decision ID, Action Required, Delay Consequence, Owner. |
| **3. Deferred Decisions** | Customer-acknowledged risk acceptances with expiry tracking. | Risk ID, Justification, Expiry Date, Accepted By. |
| **4. Recommended Decisions**| KoçSistem strategic hardening advice for the upcoming cycle. | Rec ID, Strategic Advice, Priority, Owner, Expected Outcome. |
