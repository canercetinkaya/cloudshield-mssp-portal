# CloudShield MSSP Platform - Evidence-Backed KPI Model

**Document Version:** 2.0.0  
**Classification:** Metric Governance  

---

## 1. Metric Specification Contract

Every customer KPI must be formally cataloged in `Engine/Config/service-catalog.json` and map directly to an approved query in `Engine/KQL/query-metadata/catalog-index.json`.

### Schema Requirements:
```json
{
  "kpiId": "KPI-MDE-001",
  "name": "Aktif Algılayıcı Kapsama Oranı",
  "serviceCode": "SVC-MDE",
  "targetTable": "DeviceInfo",
  "sourceQueryId": "MS-MDE-001",
  "requiredFields": ["DeviceId", "OnboardingStatus", "SensorHealthState"],
  "formula": "Round((ActiveDevices / TotalAdDevices) * 100, 1)",
  "zeroDenominatorValue": "N/A"
}
```

---

## 2. Mathematical Integrity Guarantees

1. **Strict Non-Zero Denominator (`fmt_pct`):** Any metric dividing by zero or null must evaluate to `"N/A"`.
2. **Parent-Child Equality:** In categorical breakdowns (e.g., DLP override reasons), the sum of all category counts must exactly equal the parent total.
