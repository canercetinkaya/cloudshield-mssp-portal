# CloudShield Security Reporting & Managed Services Visibility Platform
## Canlı Veri Doğrulama ve Güvenilirlik Statüleri (LIVE_VALIDATION_STATUS.md)

CloudShield platformunda hiçbir metrik veya servis, gerçek tenant ortamında doğrulanmadan **"Hazır"**, **"Eksiksiz"** veya **"Doğrulandı"** olarak etiketlenemez. Bu belge, veri güvenilirliği ve denetim disiplini için uygulanan doğrulama standartlarını belgeler.

---

### 1. Beş Kanonik Doğrulama Statüsü

Platform, tüm iş yüklerini ve metrikleri şu 5 kesin statüden biriyle sınıflandırır:

1. **Canlı Tenant Üzerinde Doğrulandı (Verified on Live Tenant):**
   - Üretim API'sine bağlanılmış, HTTP 200 yanıtı alınmış, gerçek telemetri kayıtları çekilmiş ve rapor alanlarıyla 1-e-1 mutabakat testi (`test_collector_to_report_reconciliation.py`) başarıyla tamamlanmıştır.
2. **Kodlandı, Canlı Doğrulama Bekliyor (Coded, Awaiting Live Verification):**
   - Kolektör, veri modeli, normalizasyon ve şablon katmanları tamamlanmıştır. Ancak test ortamı dışında gerçek müşteri tenant API'si ile uçtan uca çalıştırılmamıştır.
3. **Kısmi Veri Toplanıyor / Kısmi Destekleniyor (Partial Data Collection):**
   - API'den sadece belirli alanlar çekilebilmekte, bazı alt modüller için ek izinler veya log yapılandırmaları gerekmektedir.
4. **API veya İzin Engelli (Blocked by API / Permission / License):**
   - Müşteri tenant'ında ilgili Microsoft lisansı (örn: E5 Compliance, Copilot Studio) aktif değildir veya Entra ID üzerinde admin consent verilmemiştir.
5. **Yalnızca Test / DryRun (Test / Synthetic Only):**
   - Gerçek API bağlantısı olmaksızın, yerel JSON fikstürleri veya simülasyon verisi üzerinden çalışan mod.

---

### 2. Zorunlu Test Filigranı Politikası (Watermark Banner Guard)

Bir servis veya rapor **Canlı Tenant Üzerinde Doğrulandı** statüsüne sahip değilse, üretilen HTML ve PDF raporlarının en üstüne aşağıdaki uyarı afişinin eklenmesi zorunludur:

> ⚠️ **DOĞRULAMA BEKLEYEN VERİ / TEST GÖRÜNÜMÜ:**  
> *Bu raporda yer alan bazı iş yükleri henüz canlı müşteri tenant API'si üzerinde doğrulanmamıştır. Gösterilen metrikler kodlanmış şablon tasarımını yansıtmakta olup, kesin güvenlik taahhüdü veya uyumluluk onayı teşkil etmez.*

Bu afiş, kod tarafında `get_test_data_notice_banner(is_test=...)` fonksiyonu ile yönetilir ve otomatik kalite kapıları (`tests/test_data_accuracy_gates.py`) tarafından zorunlu olarak denetlenir.

---

### 3. İş Yükü Bazlı Canlı Doğrulama Denetim Tablosu

| İş Yükü | Hedef API & Endpoint | HTTP Durumu | Dönen Alan / Kayıt | Canlı Doğrulama Durumu |
| :--- | :--- | :---: | :--- | :--- |
| **Defender for Endpoint** | `https://api.securitycenter.microsoft.com/api/machines` | 200 OK | Cihaz listesi, sensör sağlık durumu | ✅ Canlı Tenant Üzerinde Doğrulandı |
| **Defender for Office 365** | `https://graph.microsoft.com/v1.0/security/alerts_v2` | 200 OK | Phish/Malware alarmları, ZAP kayıtları | ✅ Canlı Tenant Üzerinde Doğrulandı |
| **Microsoft Intune** | `https://graph.microsoft.com/v1.0/deviceManagement/managedDevices` | 200 OK | Uyumlu/uyumsuz cihazlar, OS sürümleri | ✅ Canlı Tenant Üzerinde Doğrulandı |
| **Purview DLP** | `Office 365 Management Activity API (Dlp.All)` | 200 OK | DLP kural eşleşmeleri, bloklama olayları | ✅ Canlı Tenant Üzerinde Doğrulandı |
| **Purview Information Protection** | `https://graph.microsoft.com/beta/informationProtection/policy/labels` | - | Sensitivity label listesi | ⏳ Kodlandı, Canlı Doğrulama Bekliyor |
| **Defender for Identity** | `https://graph.microsoft.com/v1.0/security/alerts_v2` (MDI provider) | - | DC şüpheli kimlik hareketleri | ⏳ Kodlandı, Canlı Doğrulama Bekliyor |
| **Defender for Cloud Apps** | `https://graph.microsoft.com/beta/security/cloudAppSecurity` | - | Keşfedilen SaaS uygulamaları | ⏳ Kodlandı, Canlı Doğrulama Bekliyor |
| **Defender for Cloud** | `https://management.azure.com/subscriptions/{id}/providers/Microsoft.Security/assessments` | - | Secure Score, öneriler | ⏳ Kodlandı, Canlı Doğrulama Bekliyor |
| **Purview DSPM for AI** | `https://graph.microsoft.com/beta/security/aiInteractions` | 403 / Lisans Yok | Copilot etkileşim logları | 🚫 İzin veya Lisans Engelli |
| **Lisans Envanteri (Subscribed SKUs)** | `https://graph.microsoft.com/v1.0/subscribedSkus` | 200 OK | Satın alınan ve tüketilen SKU koltukları | ✅ Canlı Tenant Üzerinde Doğrulandı |
| **Kullanıcı Lisans Profilleri** | `https://graph.microsoft.com/v1.0/users?$select=...` | 200 OK | Kullanıcı rolleri ve atanan servis planları | ✅ Canlı Tenant Üzerinde Doğrulandı |
| **Microsoft CDN Lisans Kataloğu** | `https://cdn-dynmedia-1.microsoft.com/...` | 200 OK (HEAD/GET) | Enterprise & SMB karşılaştırma PDF hash doğrulaması | ✅ Canlı CDN Üzerinde Doğrulandı |

