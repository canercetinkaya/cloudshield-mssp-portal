# CloudShield MSSP Platform - Golden Fixture Validation

**Document Version:** 2.0.0  
**Classification:** Testing & Quality Assurance  

---

## 1. Golden Fixture Suite

To ensure deterministic quality evaluations without depending on live cloud credentials, the platform maintains two authoritative golden fixtures:

1. **`tests/fixtures/fixture_active_enterprise.json`:**
   - Simulates a healthy, high-activity enterprise tenant with 1,250 devices and active DLP rules.
   - Used to validate positive KPI calculations, parent-child distributions, and decision framework rendering.
2. **`tests/fixtures/fixture_clean_zero_incident.json`:**
   - Simulates a completely clean tenant with zero active alerts, zero DLP overrides, and zero incidents.
   - Used to validate zero-denominator `N/A` handling, zero-state badge assertions, and suppression of empty tables.

---

## 2. Test vs. Production Data Segregation

- Golden fixtures must **NEVER** be saved into customer output directories (`Engine/Output/<Customer>/`).
- Any artifact generated from fixtures must be explicitly marked as a `TestArtifact`.
