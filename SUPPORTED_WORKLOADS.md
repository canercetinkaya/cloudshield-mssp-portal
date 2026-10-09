# CloudShield Security Reporting & Managed Services Visibility Platform
## Desteklenen Microsoft İş Yükleri Matrisi (SUPPORTED_WORKLOADS.md)

Platform, Microsoft güvenlik ve uyumluluk ekosisteminde yer alan 15 temel iş yükü için raporlama kabiliyeti sunmayı hedefler. Aşağıdaki tablo, her servisin veri kaynaklarını, rapordaki karşılıklarını, gerekli izinleri ve **mevcut doğrulama durumunu** göstermektedir.

---

### 📊 İş Yükü ve Telemetri Matrisi

| # | Microsoft İş Yükü | Toplanan Veri Türleri | Raporda Gösterilen Temel Alanlar | Gerekli İzin / Lisans | Mevcut Doğrulama Statüsü |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **1** | **Microsoft Defender for Endpoint (MDE)** | Cihaz envanteri, sensör sağlığı, TVM zafiyetleri, ASR olayları, KQL avcılık verisi | İzlenen Cihaz, Sensör Kapsamı %, Otonom Bloklar, TVM Uyum %, FalconFriday Kampanyaları | `Machine.Read.All`, `AdvancedHunting.Read.All`<br>*Lisans: MDE P2 / M365 E5* | **Canlı Tenant Üzerinde Doğrulandı** |
| **2** | **Microsoft Defender for Office 365 (MDO)** | E-posta trafiği, kimlik avı, zararlı ekler, Safe Links, ZAP tahliyeleri, karantina | Taranan Posta, Phishing/Malware Engelleri, ZAP Sayısı, Şüpheli Bildirim Triyajı | `SecurityEvents.Read.All`<br>*Lisans: MDO P2 / M365 E5* | **Canlı Tenant Üzerinde Doğrulandı** |
| **3** | **Microsoft Intune (Uç Nokta Uyum)** | Cihaz uyumluluk durumları, BitLocker/FileVault şifreleme, işletim sistemi dağılımı | Cihaz Uyum %, Şifrelenmiş Cihaz Sayısı, Platform Ayrışımı (Win/iOS/Android/macOS) | `DeviceManagementManagedDevices.Read.All`<br>*Lisans: Intune Plan 1* | **Canlı Tenant Üzerinde Doğrulandı** |
| **4** | **Microsoft Purview Data Loss Prevention (DLP)** | DLP kural eşleşmeleri, bloklama olayları, kullanıcı kural aşımları (overrides) | DLP Eşleşme, Otonom Blok, Koruma Oranı %, Override Dağılımı ve Gerekçeleri | `InformationProtectionPolicy.Read.All`<br>*Lisans: M365 E5 / E5 Compliance* | **Canlı Tenant Üzerinde Doğrulandı** |
| **5** | **Microsoft Purview Information Protection (MIP)** | Duyarlılık etiketleri (Sensitivity Labels), etiketleme trendleri, şifreleme duruşu | Etiketli Belge Hacmi, En Çok Kullanılan Etiketler, Etiket Değişiklik Kütüğü | `InformationProtectionPolicy.Read.All`<br>*Lisans: M365 E5 / E5 Information Protection* | **Kodlandı, Canlı Doğrulama Bekliyor** |
| **6** | **Microsoft Purview Sensitive Information Types (SIT)** | Standart ve özel (custom) SIT tanımları, regex ve doğruluk eşiği kuralları | Tanımlı SIT Sayısı, En Çok Tetiklenen SIT'ler (TCKN, Kredi Kartı, IBAN) | `InformationProtectionPolicy.Read.All`<br>*Lisans: M365 E5 / E5 Compliance* | **Kodlandı, Canlı Doğrulama Bekliyor** |
| **7** | **Microsoft Defender for Identity (MDI)** | DC telemetrisi, NTLMv1/v2 kullanımı, şüpheli Kerberos biletleri, kimlik alarmları | Sağlıklı DC Sayısı, Güvensiz Protokol Kullanımı, Şüpheli Kimlik Hareketleri | `SecurityAlert.Read.All`, `IdentityLogonEvents`<br>*Lisans: MDI / M365 E5* | **Kodlandı, Canlı Doğrulama Bekliyor** |
| **8** | **Microsoft Defender for Cloud Apps (MDCA)** | Shadow IT keşif verisi, onaylı/onaysız SaaS uygulamaları, riskli OAuth izinleri | Keşfedilen SaaS Uygulamaları, Yüksek Riskli Uygulama Sayısı, Sanction/Unsanction | `CloudAppSecurity.Read.All`<br>*Lisans: MDCA / M365 E5* | **Kodlandı, Canlı Doğrulama Bekliyor** |
| **9** | **Microsoft Defender for Cloud (MDC / CSPM)** | Azure Secure Score, bulut güvenlik önerileri, açık yönetim portları | Secure Score %, Kritik Güvenlik Önerileri, İnternete Açık Kaynaklar | `Microsoft.Security/assessments/read`<br>*Lisans: Defender CSPM / Cloud Workload* | **Kodlandı, Canlı Doğrulama Bekliyor** |
| **10** | **Microsoft Purview Insider Risk Management** | İç tehdit politikası göstergeleri, veri dışarı sızdırma risk skorları | Aktif Politika Sayısı, Yüksek Riskli Kullanıcı Trendleri | `AuditLog.Read.All`, `SecurityAlert.Read.All`<br>*Lisans: M365 E5 Insider Risk* | **Kodlandı, Canlı Doğrulama Bekliyor** |
| **11** | **Microsoft Purview Communication Compliance** | Kurumsal iletişim denetim kuralları, uygunsuz içerik ve çıkar çatışması | Eşleşen İletişim Olayları, İncelenen Mesaj Oranı | `Compliance.Read.All`<br>*Lisans: M365 E5 Communication Compliance* | **Kodlandı, Canlı Doğrulama Bekliyor** |
| **12** | **Microsoft Purview Data Lifecycle Management** | Saklama (retention) ilkeleri, otomatik etiketleme ve silme kuralları | Aktif Saklama İlkeleri, Konum Kapsamı (SPO/OD/EXO) | `InformationProtectionPolicy.Read.All`<br>*Lisans: M365 E3/E5* | **Kısmi Destekleniyor** |
| **13** | **Microsoft Purview Records Management** | Kayıt (record) tanımları, imha (disposition) inceleme süreçleri | Kayıt Olarak İşaretlenen Öğe Sayısı, İmha Bekleyenler | `RecordsManagement.Read.All`<br>*Lisans: M365 E5 Compliance* | **Kısmi Destekleniyor** |
| **14** | **Microsoft Purview DSPM (Data Security Posture)** | Çoklu bulut veri depoları, hassas veri haritası, erişim riskleri | Taranan Veri Deposu Hacmi, Hassas Veri Yoğunluğu | `DataSecurityPosture.Read.All`<br>*Lisans: Purview DSPM* | **Kodlandı, Canlı Doğrulama Bekliyor** |
| **15** | **Microsoft Purview DSPM for AI** | Copilot ve GenAI etkileşimlerinde hassas veri kullanımı, AI prompt riskleri | AI Güvenlik Olayları, Prompt Sızıntı Denetimi, Etiketli Veri Tüketimi | `SecurityEvents.Read.All`, `AuditLog.Read.All`<br>*Lisans: Microsoft 365 Copilot & Purview E5* | **İzin veya Lisans Engelli** |

---

### 🔍 Statü Tanımları

- **Canlı Tenant Üzerinde Doğrulandı:** Gerçek müşteri/tenant API bağlantısı kurulmuş, telemetri JSON formatında çekilmiş, rapor şablonuna başarıyla aktarılmış ve mutabakat testi tamamlanmıştır.
- **Kodlandı, Canlı Doğrulama Bekliyor:** Kolektör modülü ve rapor şablonu tamamen geliştirilmiş, sentetik veri ile test edilmiş; ancak henüz canlı müşteri tenant'ında API çağrısı ile son kontrolü yapılmamıştır.
- **Kısmi Destekleniyor:** Genel uyumluluk ve yönetişim başlıkları altında temel telemetri alınmakta; spesifik API derinleştirmesi fazlı olarak ilerletilmektedir.
- **İzin veya Lisans Engelli:** İlgili özelliğin API erişimi için müşteride henüz etkinleştirilmemiş ek E5/Copilot lisansı veya Graph admin consent izni gerekmektedir.
- **Test/DryRun:** Tenant bağlantısı kurulmadan, yerel JSON fixture üzerinden çalışan geliştirme modu.
- **Planlandı:** Yol haritasında tanımlanmış, henüz kodlama aşamasına geçilmemiş iş yükü.
