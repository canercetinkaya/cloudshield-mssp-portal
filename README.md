# CloudShield MSSP Platform: Enterprise Managed Security & Compliance Portal

[![Release](https://img.shields.io/badge/Release-v2.5.15-PILOT-brightgreen.svg)](https://github.com/canercetinkaya/cloudshield-mssp-portal/releases/tag/v2.5.15-PILOT)
[![Channel](https://img.shields.io/badge/Channel-Pilot%20Validation-yellow.svg)](#release-channels)
[![CI/CD Pipeline](https://github.com/canercetinkaya/cloudshield-mssp-portal/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/canercetinkaya/cloudshield-mssp-portal/actions/workflows/ci-cd.yml)
[![Azure Deployment](https://github.com/canercetinkaya/cloudshield-mssp-portal/actions/workflows/cs-mssp-poc-app-AutoDeployTrigger-e70e00a1-3ae4-4b88-a6be-343e239cba38.yml/badge.svg)](https://github.com/canercetinkaya/cloudshield-mssp-portal/actions/workflows/cs-mssp-poc-app-AutoDeployTrigger-e70e00a1-3ae4-4b88-a6be-343e239cba38.yml)
[![Security Policy](https://img.shields.io/badge/Security-Zero%20Trust%20%2B%20Least%20Privilege-orange.svg)](SECURITY.md)

**CloudShield MSSP Platform**, **CloudShield MSSP Yönetilen Güvenlik Hizmetleri** operasyonları için özel olarak geliştirilmiş kurumsal, çok kiracılı (multi-tenant) bir güvenlik orkestrasyonu, yönetim ve raporlama SaaS portalıdır. 

Canlı Microsoft Defender XDR ve Microsoft Purview ortamlarına bağlanarak C-Level yöneticiler (CISO, CIO) ve operasyon ekipleri için yönetim kurulu seviyesinde güvenlik karneleri, uyum raporları ve doğrulanabilir tehdit analizleri sunar.

---

## 🚀 Canlı Dağıtım ve Erişim

- **Canlı Portal URL:** [https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io/](https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io/)
- **Aktif Sürüm:** 2.5.15-PILOT (Build: 2026.09.16.1)
- **Hosting Altyapısı:** Azure Container Apps (Sunucusuz Linux Container)
- **Kimlik Doğrulama:** Microsoft Entra ID OIDC SSO (Pilot kanalında zorunlu)

---

## 🎯 Temel Özellikler & Değer Önerisi

1. **Tek Kiracılı Yönetici Kokpiti (Executive Cockpit):**
   - Müşteri bazında filtrelendiğinde devreye giren özel C-Level yönetim ekranı.
   - **4 Sütunlu Değer Atıf Modeli:** Microsoft otonom engellemeleri ile CloudShield kıdemli mühendislik saatlerini net olarak ayrıştırır.
   - **6 Kritik Yönetici Sorusu:** Ne Oldu? Neden Önemli? Microsoft Ne Sağladı? CloudShield Ne Sağladı? Kalan Riskler? Alınacak Kararlar?

2. **İnteraktif Karar Çerçevesi (Customer Decision Framework):**
   - Onaylanmış, Bekleyen, Ertelenmiş ve Tavsiye Edilen kararları portal üzerinden onaylama ve audit loglama.

3. **%100 Dinamik Veri & Sıfır Kurgu (Zero Fiction):**
   - Sahte veri, tahmini rakam veya uydurma tasarruf hesabı içermez; her metrik doğrulanmış KQL / Graph API sorgusuna dayanır.

4. **3 Adımlı Kiracı Onboarding Sihirbazı:**
   - GUID doğrulamalı, Microsoft Entra ID Admin Consent bağlantısı üreten pratik müşteri entegrasyonu.

---

## 🛠️ Desteklenen Servis Modülleri (12 Enterprise Servis)

| Kod | Servis Adı | Kapsam | Birincil Veri Kaynağı |
| :--- | :--- | :---: | :--- |
| **SVC-MDE** | Microsoft Defender for Endpoint | Uç Nokta & TVM | DeviceInfo, Alerts, Vulnerabilities |
| **SVC-MDO** | Microsoft Defender for Office 365 | E-Posta Güvenliği | EmailEvents, Phish, ZAP |
| **SVC-MDI** | Microsoft Defender for Identity | Kimlik Tehditleri | IdentityLogonEvents, Lateral Movement |
| **SVC-MDCA**| Microsoft Defender for Cloud Apps | Bulut CASB | CloudAppEvents, OAuth Apps |
| **SVC-XDR** | Microsoft Defender XDR | Birleşik Olaylar | Incidents, AlertEvidence |
| **SVC-INTUNE**| Microsoft Intune | Cihaz Uyumu | ManagedDevices, Compliance |
| **SVC-ENTRA-PIM**| Entra ID PIM & Protection | Kimlik Yönetişimi | RiskyUsers, Elevation Logs |
| **SVC-PRV-DLP**| Microsoft Purview DLP | Veri Sızıntısı | DlpEvents, File Activity |
| **SVC-PRV-CLASS**| Information Protection | Hassas Veri | Sensitivity Labels, SITs |
| **SVC-PRV-GOV**| Purview Data Lifecycle | Yaşam Döngüsü | Retention, Disposition |
| **SVC-PRV-RISK**| Purview Insider Risk | İç Tehditler | Insider Policies, Audit |
| **SVC-AI-SECURITY**| Purview AI Hub | GenAI Güvenliği | Copilot Interactions, Audit.General |

---

## 🏛️ Mimari Özet

`mermaid
flowchart LR
    Browser["Web Tarayıcı (SPA)<br/>Tailwind / Modern JS"] --> API["REST API Gateway<br/>(Portal/api/server.py)"]
    API --> RBAC["RBAC & Yetki Motoru<br/>(Portal/api/rbac_engine.py)"]
    API --> Generator["Raporlama Motoru<br/>(Portal/api/report_generator.py)"]
    Generator --> PSEngine["PowerShell 7.4 Collector<br/>(Engine/Plugins/)"]
    PSEngine --> MSGraph["Microsoft Graph & XDR APIs"]
    Generator --> PDFEngine["Headless Chromium<br/>Vektörel PDF Çıktısı"]
`

---

## 💻 Yerel Geliştirme ve Test

### Gereksinimler
- Python 3.11 (Yalnızca Standart Kütüphane — Harici pip paket bağımlılığı yoktur)
- PowerShell 7.4+ (pwsh)
- Headless Chrome veya Edge (Vektörel PDF üretimi için)

### Hızlı Başlangıç
`powershell
# 1. Depoyu klonlayın
git clone https://github.com/canercetinkaya/cloudshield-mssp-portal.git
cd cloudshield-mssp-portal

# 2. Portalı başlatın (Port 8080)
python Portal/api/server.py 8080
`

### Otomasyon Test Paketleri
`powershell
# Tam Kapsamlı QA Test Paketi
python test_comprehensive_qa.py

# Semantik Rapor Kalite Kapısı (14 Kural)
python test_report_quality_gate.py

# RBAC Yetkilendirme Testleri (11 Güvenlik Kuralı)
python test_rbac_authorization.py
`

---

## 📁 Proje Dizin Yapısı

- Portal/ — Web arayüzü (web/index.html) ve REST API sunucusu (pi/).
- Engine/ — PowerShell veri toplayıcıları (Plugins/) ve raporlama motoru.
- Docker/ — Dockerfile, docker-compose ve container giriş betikleri.
- Azure/ — Bicep altyapı şablonları ve Azure Container Apps dağıtım araçları.
- Data/ — Veritabanı (cloudshield_rbac.db), sürüm ve kiracı konfigürasyonları.
- docs/ — Mimari, güvenlik, raporlama modelleri ve kalite kapısı dokümantasyonu.
  - docs/archive/ — Geçmiş dönem denetim, onay ve doğrulama raporları arşivi.

---

## 📄 Yetkilendirme & Lisans

Telif Hakkı &copy; 2026 **CloudShield MSSP Security Operations** / **CloudShield MSSP Global Operations**.  
Gizli ve Özel Mülkiyettir.
