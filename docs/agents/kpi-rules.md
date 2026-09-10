# KPI & Data Integrity Rules (Zero Mock Policy)

## 1. Absolute Zero-Mock Standard
- **No Hallucinated Numbers:** Under no circumstances should an agent, plugin, or report generator inject static numbers into reports (e.g. "18 QR Phish", "42 Wacatac", "$385,000 USD", "840 TCKN").
- **Dynamic Shell Execution:** If telemetry is unavailable, the report generator must check `AvailabilityState` or list length and display verified clean postures.
- **Zero Incident Verified Posture:** When a customer has zero incidents or detections, report it as a verified security and compliance victory (`[Doğrulanmış Temiz / Zero Incident Verified]`, `[KVKK md. 12 Proaktif Uyum Güvencesi]`).

## 2. Mathematical Defensiveness
- **No Divide by Zero:** All percentages must use defensive maximum guards:
  ```python
  rate = round((numerator / max(denominator, 1)) * 100, 1) if denominator > 0 else 0.0
  ```
- **FTE Calculation Formula:** Strictly standardized as `(Otonom Olay x 0.25h + Uzman Eforu) / 140 saat/ay`.

## 3. Availability States
When a service cannot collect data due to permissions or licensing, it must set one of the standard `AvailabilityState` values:
- `SupportedAppOnly`: Collector succeeded via App-Only Graph/API.
- `SupportedAdvancedHunting`: Fallback succeeded via KQL Hunting API.
- `NoData`: Connected successfully, zero telemetry in period.
- `PermissionMissing`: 403 Forbidden on Entra ID App.
- `AuthenticationFailed`: 401 Unauthorized / Invalid Secret or Cert.
- `NotLicensed`: Tenant lacks the required SKU (e.g. MDE P2 or E5 Compliance).
