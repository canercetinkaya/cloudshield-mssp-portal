# CloudShield Microsoft Security Managed Services Reporting Platform (`CloudShieldSecurityReporting`)

**CloudShield Microsoft Security Managed Services Reporting Platform**, Microsoft Defender ve Microsoft Purview ürün ailelerinin tamamını kapsayan, bağımsız satın alınan hizmetleri tekil veya birleşik olarak raporlayabilen, kurumsal düzeyde eklenti (plug-in) tabanlı bir MSSP yönetim ve raporlama çözümüdür.

---

## 🌟 Öne Çıkan Özellikler

- **Modüler ve Bağımsız Servis Mimarisi:** Müşteri yalnızca *Yönetilen E-Posta Güvenliği (MDO)* veya yalnızca *Yönetilen Uç Nokta Güvenliği (MDE)* alıyorsa, yalnızca ilgili servise özel müstakil rapor üretir. Birden fazla hizmet alıyorsa tek bir konsolide yönetici raporu sunar.
- **CloudShield İnsan Gücü vs. Otonom Koruma Ayrımı:** Microsoft sistemlerinin otonom (Auto-IR, ZAP, Safe Links) çözdüğü tehditler ile CloudShield SOC analistlerinin müdahale ettiği vakaları ayrıştırır; müşteriye kazandırılan analist saatini hesaplar.
- **Ayın Proaktif Tehdit Avı:** Her ay yürütülen proaktif KQL av operasyonlarını ve analist bulgularını öne çıkarır.
- **Kurumsal Kimlik Doğrulama:** RFC 7523 Certificate-Based Authentication (CBA / JWT Assertion) ile sıfır dış kütüphane bağımlılığı ve DPAPI şifreli Client Secret desteği.
- **Diferansiyel Gizlilik (KVKK/GDPR Uyumlu):** $k$-anonymity ($k \ge 5$) ve tenant bazlı dinamik tuzlu (salted) SHA256 kullanıcı maskeleme motoru.
- **Yüksek Çözünürlüklü Vektörel PDF:** Microsoft Edge / Chromium headless motoru ile CSS baskı ve sayfalama kurallarına tam uyumlu vektörel PDF çıktısı.
- **Çoklu İletim:** Microsoft Graph API (`Mail.Send`) ve Modern SMTP desteği ile servise özel e-posta yönlendirme (Örn: E-posta raporu Exchange ekibine, EDR raporu Sistem ekibine).

---

## 📂 Dizin Yapısı

```
CloudShieldSecurityReporting/
├── Core/                                   # Platform Çekirdek Motorları
│   ├── Authentication.psm1                 # CBA (RFC 7523), Secret ve DPAPI
│   ├── Configuration.psm1                  # Katmanlı konfigürasyon yöneticisi
│   ├── Logging.psm1                        # JSONL yapılandırılmış günlükleme
│   ├── PrivacyEngine.psm1                  # k-anonymity ve SHA256 tuzlama
│   ├── HealthCheck.psm1                    # Pre-flight API ve ortam denetimi
│   ├── TrendEngine.psm1                    # Tarihsel KPI trend ve delta analizi
│   ├── ReportRenderer.psm1                 # HTML derleyici ve Headless Edge PDF
│   ├── MailEngine.psm1                     # Graph ve SMTP rapor iletimi
│   └── PluginLoader.psm1                   # Eklenti keşif ve yaşam döngüsü
│
├── Plugins/                                # Bağımsız Servis Eklentileri
│   ├── DefenderEndpoint/                   # SVC-MDE (Uç Nokta Koruması - EDR)
│   ├── DefenderOffice/                     # SVC-MDO (E-Posta Güvenliği - MDO/EOP)
│   ├── DefenderIdentity/                   # SVC-MDI (Kimlik Koruması - MDI)
│   ├── DefenderCloudApps/                  # SVC-MDCA (Bulut Güvenliği - CASB)
│   ├── DefenderXdr/                        # SVC-XDR (Birleşik Olay & MTTR)
│   ├── PurviewClassification/              # SVC-PRV-CLASS (Veri Envanteri & SIT)
│   ├── PurviewDlp/                         # SVC-PRV-DLP (Veri Kaybı Önleme)
│   ├── PurviewGovernance/                  # SVC-PRV-GOV (Saklama & İmha)
│   ├── PurviewRiskCompliance/              # SVC-PRV-RISK (İç Tehdit - İzole App)
│   └── PurviewAiSecurity/                  # SVC-AI-SECURITY (Copilot & AI Postürü)
│
├── Config/                                 # Konfigürasyon Şablonları ve Katalog
│   ├── service-catalog.json                # Tüm servis ve paket tanımları
│   ├── global.config.template.json         # CloudShield kurumsal marka ayarları
│   └── customer.config.template.json       # Müşteri tenant konfigürasyon şablonu
│
├── ManualInput/                            # Operasyonel Dış Girdiler
│   └── customer-manual-metrics.template.json # SOC biletleri ve ayın tehdit avı
│
├── Templates/ModernCorporate/              # CloudShield Kurumsal Rapor Teması
│   └── style.css                           # Lacivert/Kırmızı tipografi ve print CSS
│
├── Tests/                                  # Test Süiti
│   └── Test-Platform.ps1                   # Birim ve entegrasyon testleri (28/28)
│
├── Install-CloudShieldSecurityReporting.ps1  # İnteraktif Kurulum Sihirbazı
├── Invoke-CloudShieldSecurityReporting.ps1   # Rapor Üretim Motoru
└── Create-ScheduledTask.ps1                # Windows Görev Zamanlayıcı Kurulumu
```

---

## 🚀 Hızlı Başlangıç

### 1. İnteraktif Kurulum (Önerilen)
Sihirbaz ortamı tarar, sertifikaları keşfeder, servisleri seçtirir ve yapılandırmayı tamamlar:
```powershell
.\Install-CloudShieldSecurityReporting.ps1 -Interactive
```

### 2. Simülasyon / Test Raporu Üretme (DryRun)
Gerçek API bağlantısı olmadan örnek kurumsal veriyle tam bir birleşik PDF ve HTML rapor üretmek için:
```powershell
.\Invoke-CloudShieldSecurityReporting.ps1 -DryRun -Pdf
```

### 3. Tekil (Müstakil) Servis Raporu Üretme
Müşterinin yalnızca aldığı tek bir servisi (Örn: MDO E-posta Güvenliği) raporlamak için:
```powershell
.\Invoke-CloudShieldSecurityReporting.ps1 -ServiceCode SVC-MDO -DryRun -Pdf
```

### 4. Üretim Ortamında Aylık Rapor Üretimi ve E-Posta İletimi
```powershell
.\Invoke-CloudShieldSecurityReporting.ps1 -Mode Monthly -Pdf -SendMail
```

### 5. Otomatik Görev Zamanlayıcı Kurulumu
Her ayın ilk günü sabah 08:30'da otomatik çalışması için:
```powershell
.\Create-ScheduledTask.ps1 -Mode Monthly -Time "08:30"
```

### 6. Platform Bütünlük Testlerini Çalıştırma
```powershell
.\Tests\Test-Platform.ps1
```

---

## 🛡️ Güvenlik ve Uyumluluk Notları
1. **İzole Uygulama (Isolated App):** Hassas uyumluluk servisleri (`SVC-PRV-RISK`) için müşteri tenant'ında bağımsız bir App Registration kullanılır; SOC analistleri ile çalışan mahremiyeti ayrıştırılır.
2. **DPAPI:** İstemci gizli anahtarları veya parolalar Windows DPAPI ile yerel olarak şifrelenir; düz metin olarak diskte tutulmaz.
3. **Sıfır Tahmin (Zero Guesswork):** Tüm API çağrıları Microsoft Learn üzerinde doğrulanmış resmi Graph ve MDE endpoint'lerine dayanır.
