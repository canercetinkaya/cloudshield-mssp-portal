# CloudShield Security Reporting & Managed Services Visibility Platform
## Veri Doğruluğu ve Güvenilirlik İlkeleri (DATA_ACCURACY.md)

Bu belge, CloudShield platformunun veri kalitesi mühendisliği ilkelerini, sentetik veri yasaklarını ve üretim raporlama güvencelerini tanımlar.

---

### 1. Vazgeçilmez 10 Veri Doğruluğu Kuralı

Üretim (Production) raporlarında aşağıdaki kurallar istisnasız uygulanır:

1. **Sıfır Sentetik Çarpan:** Alarm sayısı bir katsayıyla (örn: * 80) çarpılamaz. Cihaz uyum oranları tahminî yüzdelerle (örn: * 0.85) hesaplanamaz.
2. **Sıfır Mock Veri:** Üretim raporuna hiçbir şart altında yerel test, mock veya sentetik veri aktarılamaz.
3. **Veri Yokken Sıfır Gösterilemez:** Telemetri bağlantısı kurulamadığında veya veri bulunmadığında `0` yazılamaz; durum açıkça `N/A` veya `Veri Kaynağı Yapılandırılmamış` olarak sunulur.
4. **Yanıltıcı "Temiz" İddiası Yasaktır:** İnceleme veya telemetri yokken "uyumlu", "korunuyor" veya "risk yok" iddiasında bulunulamaz.
5. **Doğrulanmamış Formül Yasaktır:** Her KPI'ın arkasında açıkça dokümante edilmiş bir KQL sorgusu veya Graph API endpoint'i bulunmalıdır.
6. **Microsoft Aksiyonları Ayrıştırılır:** Microsoft yerel mekanizmalarının yaptığı engellemeler (AIR, ZAP), CloudShield mühendislerinin işi gibi sunulamaz.
7. **Kolektör Doğrulaması:** Kolektör tarafından doğrulanmayan hiçbir veri rapora aktarılamaz.
8. **Mali Tasarruf ve Önlenen İhlal İddiası Yasaktır (Zero Fake Financial ROI):** Gerçek zarara, müşteriyle mutabık kalınmış fiyat listesine ve adli denetime dayanmayan kurgusal ROI, dolar/TL tasarruf veya "önlenen finansal zarar" iddiaları rapordan kaldırılmıştır. Lisans analizinde değer; para birimiyle değil, doğrudan hak sahipliği, aktif servis planı, ilke kapsamı ve doğrulanmış telemetri kanıtı ile ölçülür.
9. **Kolektör-Rapor Mutabakatı:** Ham kolektör çıktısı ile HTML/PDF çıktısındaki sayılar arasında birebir eşleşme (`test_collector_to_report_reconciliation.py`) sağlanmalıdır.
10. **Test Filigranı Güvencesi:** Canlı tenant üzerinde doğrulanmamış her rapor, üst kısmında belirgin bir test filigranı ile mühürlenir.

---

### 2. Eksik Veri Durum Sınıflandırması

Veri toplanamıyorsa platform şu standart durumlardan birini kullanır:
- `N/A (Veri Mevcut Değil)`
- `Veri kaynağı yapılandırılmamış`
- `Gerekli API izni bulunmuyor`
- `Gerekli ürün lisansı bulunmuyor`
- `Kolektör veri toplamayı tamamlayamadı`
- `Kısmi veri toplandı`
- `İlgili güvenlik özelliği müşteride etkin değil`
- `Yetkili veri kaynağı doğrulanamadı`

---

### 3. Merkezi KPI Kataloğu Şeması

Platform, her KPI için merkezi katalogda (`config/catalog/kpi-catalog.json`) şu 23 alanı zorunlu olarak tutar:

```json
{
  "kpi_id": "KPI-PRV-01",
  "product_family": "Microsoft Purview",
  "service_name": "Data Loss Prevention",
  "kpi_name": "Aylık Toplam DLP Kural Eşleşmesi",
  "business_meaning": "Kurum içinde hassas verilerin şirket dışına veya yetkisiz kanallara aktarılma girişimlerinin toplam hacmi.",
  "technical_definition": "Purview AuditLog üzerinde RecordType DlpPolicyChange ve DLP olaylarının dönem içi tekil toplamı.",
  "source_api": "Office 365 Management Activity API / Microsoft Graph Security",
  "endpoint_or_query": "DlpEvents | where Timestamp >= ago(30d) | count",
  "required_permission": "InformationProtectionPolicy.Read.All",
  "required_license": "Microsoft 365 E5 veya E5 Compliance",
  "calculation_formula": "sum(dlp_matches)",
  "metric_unit": "Olay",
  "collection_method": "Scheduled API Ingestion",
  "collection_frequency": "Günlük / Aylık Konsolidasyon",
  "raw_field_name": "totalMatches",
  "data_quality_status": "Canlı Tenant Üzerinde Doğrulandı",
  "provenance_table": "observed_technical_improvements",
  "executive_value_score": 9.5,
  "technical_value_score": 9.0,
  "is_synthetic_prohibited": true,
  "empty_state_behavior": "Render N/A with configuration notice",
  "reconciliation_rule": "Direct equality with collector JSON raw count",
  "last_audit_date": "2026-10-09"
}
```

---

### 4. Kriptografik Bütünlük ve Denetim İzi (SHA-256)

Her üretilen rapor, üretim anında SHA-256 kriptografik özeti ile mühürlenir. Bu özet:
- Raporun sonradan manuel olarak değiştirilmediğini kanıtlar.
- Veri sorumlusunun iç denetim ekiplerine teknik değişiklik kontrolü sağlar.
