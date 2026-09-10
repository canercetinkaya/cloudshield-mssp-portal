# CloudShield MSSP Platform - Collection Health & Availability States

**Document Version:** 2.0.0  
**Classification:** Architectural Specification  

---

## 1. The Five Availability States

Telemetry collection across enterprise Microsoft tenants encounters diverse licensing and permission states. CloudShield strictly classifies every service into one of **five formal availability states**:

| Availability State | Definition | Reporting Behavior |
| :--- | :--- | :--- |
| **`SupportedAppOnly`** | Service fully licensed and accessible via Application permissions. | Normal KPI calculation, telemetry tables rendered. |
| **`GraphUserDelegated`**| Service accessible only with interactive delegated user tokens (e.g., PIM). | Disclosed on Page 1; renders delegated telemetry if session active. |
| **`Unloaded`** | Service not licensed or not contracted in tenant scope. | Explicitly disclosed on Page 1; service section suppressed. |
| **`CollectionFailed`** | API timeout, 401/403 authorization failure, or rate limiting. | **CRITICAL:** KPI cards suppressed; sanitized notice rendered on Page 1. |
| **`UnsupportedAppOnly`**| Microsoft Graph does not support application-only access for this feature. | Disclosed on Page 1 with technical architectural boundary notice. |

---

## 2. Page 1 Collection Health Matrix

Under Semantic Rule 9, every customer report must feature an executive completeness card on Page 1:

```html
<div class="collection-health-card">
  <h3>📡 Veri Toplama ve Servis Sağlık Durumu (Collection Health)</h3>
  <table>
    <tr><th>Servis Kodu</th><th>Servis Tanımı</th><th>Toplama Durumu</th><th>Operasyonel Kapsam</th></tr>
    <tr><td>SVC-MDE</td><td>Microsoft Defender for Endpoint</td><td><span class="pill p-ok">Tamamlandı</span></td><td>Uç Nokta EDR ve Zafiyet Telemetrisi</td></tr>
    <tr><td>SVC-PRV-DLP</td><td>Microsoft Purview DLP</td><td><span class="pill p-ok">Tamamlandı</span></td><td>Veri Kaybı Önleme ve Kural Aşımları</td></tr>
  </table>
</div>
```

---

## 3. Failure Handling & Sanitization Rules

1. **Zero Fake Metrics:** When a service is `CollectionFailed`, the generator NEVER defaults to zero counts or simulated averages.
2. **Sanitized Diagnostics:** Raw internal exceptions, stack traces, and tenant secrets are stripped. The customer report displays a clean diagnostic summary (e.g., *"Veri kaynağına erişilemedi: Yetkilendirme zaman aşımı"*).
