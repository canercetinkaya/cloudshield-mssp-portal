# CloudShield Referans Lisanslama Kataloğu ve Otomatik İzleme Modeli
# (Licensing Catalog & Upstream Specification Monitor)

**Katalog Sürümü:** 1.0.0  
**Dosya Yolu:** `config/catalog/license-catalog.json`  
**İzleme Durumu Dosyası:** `config/catalog/catalog-feed-state.json`  

---

## 1. Katalog Mimarisi ve Resmi Kaynaklar

CloudShield Lisans Zekâsı Kataloğu, Microsoft Corporation tarafından yayınlanmış iki resmi teknik plan karşılaştırma dokümanını doğrudan temel alır:

1. **Enterprise Karşılaştırma Dokümanı:**
   - **Başlık:** Microsoft 365 Plan Comparison - Enterprise
   - **URL:** `https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/bade/documents/products-and-services/en-us/education/Modern-Work-Plan-Comparison-Enterprise.pdf`
   - **Kapsam:** Microsoft 365 E3, E5; Office 365 E1, E3, E5; EMS E3, E5; E5 Security & Compliance Eklentileri; Frontline F1, F3; Copilot.

2. **SMB Karşılaştırma Dokümanı:**
   - **Başlık:** Microsoft 365 Plan Comparison - Small and Medium-sized Businesses
   - **URL:** `https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/bade/documents/products-and-services/en-us/education/Modern-Work-Plan-Comparison-SMB.pdf`
   - **Kapsam:** Microsoft 365 Business Basic, Business Standard, Business Premium; Defender for Business Suite; Purview Suite; 300 Kullanıcı Tavanı.

---

## 2. Sürekli Besleme ve Aylık Otomatik Kontrol Sistemi

Microsoft resmi CDN dokümanları üzerinde yapılan değişiklikleri takip etmek ve kataloğu her zaman güncel tutmak amacıyla `Portal/api/license_catalog_updater.py` modülü geliştirilmiştir:

- **Çalışma Prensibi:**
  1. Modül, Microsoft CDN sunucularına HTTP istekleri (HEAD/akışlı GET) göndererek `ETag`, `Last-Modified`, `Content-Length` başlıklarını sorgular.
  2. Dosyanın SHA-256 özetini (hash) hesaplar ve yerel referans hash değeriyle karşılaştırır.
  3. Doküman değiştiğinde `UpdateDetected` bayrağı kaldırılır ve denetim kütüğüne (audit log) olay kaydedilir.
  4. Bir sonraki kontrol tarihi 30 gün sonrasına otomatik ötelenir (`next_scheduled_check`).
- **REST API ve Portal Tetikleme:**
  - `GET /api/licenses/catalog/feed-status`: Güncel kontrol durumu ve hash değerlerini döner.
  - `POST /api/licenses/catalog/check-updates`: Yetkili kullanıcı veya sistem zamanlayıcısı tarafından anlık kontrol tetikler.

---

## 3. Katalogda Eşleştirilen Temel SKU ve Servis Planları

| SKU Part Number | Ürün Adı | Tip | Kullanıcı Sınırı | Dahil Edilen Önemli Servis Planları |
| :--- | :--- | :--- | :--- | :--- |
| **SPE_E5** | Microsoft 365 E5 | Base | Yok | WINDEFATP, ATP_ENTERPRISE, THREAT_DEFENDER, ADALLOM_S_STANDALONE, MIPC, EQUIVIO_ANALYTICS, INTUNE_A |
| **SPE_E3** | Microsoft 365 E3 | Base | Yok | INTUNE_A, RMS_S_ENTERPRISE, EXCHANGE_S_ENTERPRISE, SHAREPOINTENTERPRISE |
| **SPE_E5_SEC** | Microsoft 365 E5 Security | Add-on | Yok | WINDEFATP, ATP_ENTERPRISE, THREAT_DEFENDER, ADALLOM_S_STANDALONE |
| **SPE_E5_COMP**| Microsoft 365 E5 Compliance | Add-on | Yok | MIPC, EQUIVIO_ANALYTICS, SAFEDOCS |
| **SPB** | Microsoft 365 Business Premium | Base | 300 | WINDEFATP (Defender for Business), INTUNE_A, MIPC, RMS_S_ENTERPRISE |
| **SMB_BUSINESS_STD** | Microsoft 365 Business Standard | Base | 300 | EXCHANGE_S_STANDARD, SHAREPOINTSTANDARD |
| **SMB_BUSINESS_BASIC**| Microsoft 365 Business Basic | Base | 300 | EXCHANGE_S_STANDARD |
| **ENTERPRISEPACK** | Office 365 E3 | Base | Yok | EXCHANGE_S_ENTERPRISE, SHAREPOINTENTERPRISE, RMS_S_ENTERPRISE |
| **COPILOT_M365** | Microsoft 365 Copilot | Add-on | Base Plan Bağlı | Microsoft 365 Copilot Hizmeti |

---

## 4. Azure Tüketim Planları Ayrımı

Katalog; Defender for Servers (Plan 1 & 2), Defender for Containers, Defender for Storage, Defender for SQL ve CSPM iş yüklerini **kullanıcı koltuk lisansı gerektirmeyen Azure abonelik tüketim modelleri** olarak tanımlar.
Bu ayrım sayesinde, sunucu veya bulut kaynakları için kullanıcı bazlı E5/E3 lisansı arama yanlışı tamamen önlenmiştir.
