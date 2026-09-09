# KoçSistem Managed Security Operations & Reporting Platform (MSSP Portal)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcanercetinkaya%2Fkocsistem-mssp-portal%2Fmain%2FAzure%2Fazuredeploy.json)
![Architecture](https://img.shields.io/badge/Architecture-Azure%20Container%20Apps%20Serverless-blue.svg)
![Cost Optimization](https://img.shields.io/badge/MCT%20Friendly-Zero%20Idle%20Cost%20($0%2Fmo)-brightgreen.svg)
![Security](https://img.shields.io/badge/Zero%20Trust-Entra%20ID%20SSO%20%2B%20Least%20Privilege-orange.svg)
![Zero SOC Strict](https://img.shields.io/badge/MSSP%20Engineering-Dedicated%20Managed%20Services-purple.svg)

**KoçSistem Managed Security Operations & Reporting Platform**, kurumsal müşterilerimizin Microsoft Defender XDR (Endpoint, Office 365, Identity, Cloud Apps) ve Microsoft Purview (DLP, Risk & Uyum, Veri Yaşam Döngüsü) ortamlarını tek merkezden izleyen, çok kiracılı (multi-tenant), yüksek güvenlikli bir SaaS yönetim ve otomatik raporlama portalıdır.

---

## 🌟 Öne Çıkan Yetkinlikler

1. **Çok Kiracılı (Multi-Tenant) İzolasyon & Güvenlik:**
   - Her müşteri verisi ve API yapılandırması bellek seviyesinde tam izole edilir; geçici yapılandırmalar işlem bitiminde anında temizlenir.
   - Test ve müşteri demoları için ayrılmış `KoçSistem Demo & Test Ortamı (Sandbox)` kiracısı ile canlı müşteri ortamları ayrıştırılmıştır.

2. **Zamanlanmış Dağıtım & E-posta Otomasyon Paneli:**
   - Aylık veya haftalık periyotlarda otomatik vektörel PDF ve interaktif HTML rapor üretimi.
   - Microsoft Graph `SendMail` API ve Exchange Online üzerinden yönetici listelerine güvenli teslimat ve denetim logu (audit trail).
   - Arayüz üzerinden tek tıkla **"🚀 Şimdi Raporu Üret ve E-posta ile Gönder"** anlık tetikleme.

3. **Gelişmiş KQL Avcılık Sorgu Motoru (KqlQueryEngine):**
   - Microsoft Defender XDR ve Graph Hunting API ile doğrudan entegre 15+ endüstri standardı KQL sorgusu (C2 iletişimi, PowerShell gizleme, mimikatz tespiti, USB veri sızıntısı, toplu indirme anomalileri).

4. **Sıfır Eforla Müşteri Onboarding (PowerShell & REST API):**
   - Basitleştirilmiş arayüz formu veya tek satırlık PowerShell komutu:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\Scripts\New-CustomerTenantOnboarding.ps1 `
       -TenantId "<MUSTERI-TENANT-GUID>" `
       -CustomerName "Müşteri Şirket Adı" `
       -ContactEmail "ciso@musteri.com"
     ```
   - Entra ID üzerinde En Az Yetki (Least-Privilege) prensibiyle salt-okunur izinlere sahip uygulama kaydı açılır, admin consent linki üretilir ve portala otomatik kaydedilir.

5. **MCT Azure Kredisi Dostu Sunucusuz Mimari (Zero Idle Cost):**
   - Azure Container Apps `scale to zero (minReplicas: 0)` mimarisi ile istek olmadığında \$0 tüketim.
   - Azure Key Vault ve Managed Identity ile sıfır şifre sızıntısı (Zero-Trust).

---

## 🚀 Azure'a Tek Tıkla Dağıtım (Deploy to Azure)

Azure MCT veya kurumsal aboneliğinizde sistemi ayağa kaldırmak için aşağıdaki butona tıklayın:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcanercetinkaya%2Fkocsistem-mssp-portal%2Fmain%2FAzure%2Fazuredeploy.json)

### Dağıtılan Azure Kaynakları:
- **Azure Container Apps:** Web Portalı ve Python REST API
- **Azure Key Vault:** Müşteri kimlik bilgileri ve sertifikaları (RBAC korumalı)
- **Azure Storage Account:** Rapor arşivi ve JSON veri depolama
- **Log Analytics Workspace:** 30 günlük operasyonel audit logları

---

## 💻 Yerel Geliştirme ve Test

```powershell
# 1. Depoyu klonlayın
git clone https://github.com/canercetinkaya/kocsistem-mssp-portal.git
cd kocsistem-mssp-portal

# 2. Portalı yerel ortamda başlatın (Tarayıcı otomatik açılır)
powershell -ExecutionPolicy Bypass -File .\Portal\Start-LocalPortal.ps1
```
Varsayılan adres: `http://localhost:8080`

---

## 🔒 Güvenlik ve Uyum İlkeleri
- **SOC Ayrımı:** Bu platform KoçSistem SOC ekiplerinden tamamen bağımsız olup, KoçSistem Microsoft Yönetilen Güvenlik ve Uyum Hizmetleri mühendislik kapsamındadır.
- **KVKK / GDPR:** Tüm hassas kullanıcı ve dosya isimleri raporlama aşamasında k-Anonymity ilkelerine göre dinamik olarak maskelenir (`a***.y***@sirket.com`).

---
**Telif Hakkı © 2026 KoçSistem Bilgi ve İletişim Hizmetleri A.Ş.**
