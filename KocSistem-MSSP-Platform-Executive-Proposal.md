# KOÇSİSTEM SİBER GÜVENLİK YÖNETİLEN HİZMETLERİ
## Yeni Nesil MSSP Operasyon, Çoklu Tenant Yönetimi ve Raporlama SaaS Platformu
### Yönetim Kurulu ve Birim Yöneticileri İçin Ürün Teklifi & Fizibilite Raporu

**Hazırlayan:** Caner Çetinkaya | Siber Güvenlik Çözüm Mimarı & Kıdemli Otomasyon Mühendisi  
**Tarih:** 2026-09-09  
**Sürüm:** 2.0.0 (Bulut & SaaS Hazır)  
**Hedef Kitle:** Siber Güvenlik Direktörlüğü, Yönetilen Hizmetler (MSSP) Liderliği, SOC Yönetimi  

---

## 1. YÖNETİCİ ÖZETİ (EXECUTIVE SUMMARY)

KoçSistem, Türkiye'nin lider sistem entegratörü ve yönetilen güvenlik hizmet sağlayıcısı (MSSP) olarak 30'u aşkın kurumsal müşteriye Microsoft Defender XDR ve Microsoft Purview ürün ailesi üzerinden 7/24 operasyonel yönetim ve uyum danışmanlığı sunmaktadır.

Ancak operasyon ekiplerimizin her müşterinin bağımsız satın aldığı hizmetlere (Örn: Yalnızca MDE alan müşteri, sadece Purview DLP alan finans kurumu veya tam E5 Security alan holding) göre ayrı portallara girip manuel veri toplaması, her ay sonu günlerce süren raporlama eforu oluşturmakta ve ciddi bir **"Portal Yorgunluğu" (Portal Fatigue)** yaratmaktadır.

Bu proje ile geliştirilen **"KoçSistem MSSP Platformu"**, dağınık Windows Görev Zamanlayıcı (Task Scheduler) scriptlerini aşarak; **merkezi, web tabanlı, Azure üzerinde sunucusuz (serverless) çalışan, tek tıkla GDAP ile müşteri ortamına zıplayabilen ve modüler aylık raporlar üreten kurumsal bir SaaS ürününe** dönüştürülmüştür.

> [!IMPORTANT]
> **Öne Çıkan Değer:**
> Bu platform sayesinde KoçSistem mühendislik ekipleri ayda **120+ adam/saat operasyonel raporlama yükünden kurtulmakta**, müşteri memnuniyeti anlık şeffaf dashboard'lar ile en üst seviyeye taşınmaktadır.

---

## 2. MEVCUT DURUM ANALİZİ VE DARBOĞAZLAR (PROBLEM STATEMENT)

| Mevcut Sorun | Operasyona ve İşe Etkisi | Yeni Platformun Çözümü |
|---|---|---|
| **Portal Yorgunluğu (Portal Fatigue)** | Mühendisler günde 30+ tenant için `security.microsoft.com` ve `purview.microsoft.com` arasında yüzlerce kez hesap/tenant değiştirmektedir. | **Merkezi Çoklu-Tenant Dashboard**: Tek ekranda tüm müşterilerin uç nokta sayısı, hayalet cihazları ve kritik alarmları listelenir. |
| **Hizmet Bağımsızlığı & Paket Ayrıştırma** | Müşteriler hizmetleri ayrı ayrı almaktadır (Örn: Sadece MDO/EOP veya sadece Purview). Genel raporlar müşterinin almadığı hizmetlerin boş sayfalarını içermekteydi. | **Dinamik Checkbox Tabanlı Servis Motoru**: Yalnızca müşterinin sözleşmesinde olan servisler (`SVC-MDE`, `SVC-PRV-DLP` vb.) raporda yer alır. |
| **Ay Sonu Manuel Rapor Hazırlama** | Her ayın ilk 5 iş günü analistler ekran görüntüsü alıp Word/PowerPoint'e yapıştırmakta; teknik analiz yerine evrak işi yapmaktadır. | **Tek Tıkla Vektörel PDF Üretimi**: 45 saniyede Microsoft Graph ve KQL üzerinden toplanan verilerle kurumsal mühürlü PDF ve HTML üretilir. |
| **Ekip İçi Yetki ve Görünürlük Karmaşası** | EDR uzmanı Purview DLP verilerini görmemeli, Purview uzmanı sunucu uç noktalarıyla ilgilenmemelidir. | **Granüler RBAC (Rol Bazlı Erişim)**: EDR Takımı, Purview Takımı ve SOC Tier 3 uzmanları yalnızca kendi uzmanlık alanlarına erişir. |
| **Müşteri Ortamına Giriş Gecikmesi** | Alarm durumunda müşterinin tenant id'sini bulup portala girmek 3-5 dakika sürmektedir. | **GDAP Deep Link Entegrasyonu**: Dashboard'daki tek butona tıklayarak müşterinin ilgili portalına yetkili oturumla anında geçilir. |

---

## 3. ÜRÜN ÖZELLİKLERİ VE MİMARİ BİLEŞENLER

```
+---------------------------------------------------------------------------------------------------------+
|                              KOÇSİSTEM MSSP PORTAL - FONKSİYONEL MİMARİ                                 |
+---------------------------------------------------------------------------------------------------------+
|                                    KULLANICI VE GÜVENLİK KATMANI                                        |
|  [Entra ID SSO Entegrasyonu]  |  [Rol Bazlı Yetkilendirme (RBAC)]  |  [Müşteri İzolasyonu (Multi-Tenant)] |
+---------------------------------------------------------------------------------------------------------+
|                                        OPERASYONEL MODÜLLER                                             |
|                                                                                                         |
|  1. ÇOKLU-TENANT GÖZLEM (MONITORING):                                                                  |
|     * Tüm müşterilerin toplam uç nokta, hayalet cihaz (Ghost Device) ve açık kritik alarm dökümü       |
|     * Tek tıkla Microsoft Defender ve Microsoft Purview portallarına GDAP context geçişi                 |
|                                                                                                         |
|  2. RAPORLAMA STÜDYOSU (REPORTING STUDIO):                                                              |
|     * Modüler Servis Seçimi: MDE, MDO, MDI, MDCA, XDR, Purview DLP, Sınıflandırma, Risk, Copilot/AI    |
|     * Hazır Satış Paketleri: PKG-05 (Essential), PKG-07 (Advanced XDR), PKG-10 (Full E5 MSSP)          |
|     * Anlık Rapor Üretimi: Arka planda PowerShell 7.4 motoru ve Chromium ile vektörel PDF çıktısı      |
|                                                                                                         |
|  3. MÜŞTERİ YÖNETİM MERKEZİ:                                                                            |
|     * Yeni müşteri tenantı onboarding (Tenant ID, Kimlik Doğrulama, Alınan Hizmetler)                  |
|     * Canlı API ve Graph bağlantı sağlık testi (Ping/Smoke Test)                                        |
+---------------------------------------------------------------------------------------------------------+
|                                         TEKNOLOJİ YIĞINI                                                |
|  Ön Yüz: Tailwind CSS, HTML5, Vanilla JS (Zero-build, hafif, anlık yüklenme)                            |
|  API Sunucusu: Python 3 Standard Library REST API (Dış kütüphane bağımlılığı yok)                       |
|  Motor: PowerShell 7.4 Core (KQL, Microsoft Graph API, Exchange Online, Güvenli REST)                    |
|  Bulut Altyapısı: Azure Container Apps (Sunucusuz, Consumption Tier), Azure Key Vault, Azure Storage    |
+---------------------------------------------------------------------------------------------------------+
```

---

## 4. KOÇSİSTEM YÖNETİLEN HİZMET KATALOĞU UYUMU

Müşterilerin KoçSistem'den satın alabildiği tüm bağımsız servisler platformda birebir ayrıştırılmıştır:

```
[MÜŞTERİ HİZMET SEÇİMİ]
 ├── [X] SVC-MDE        : Microsoft Defender for Endpoint (Uç Nokta Koruması & Hayalet Cihaz Takibi)
 ├── [X] SVC-MDO        : Microsoft Defender for Office 365 & EOP (E-Posta Güvenliği & ZAP)
 ├── [ ] SVC-MDI        : Microsoft Defender for Identity (Active Directory & Kimlik Tehditleri)
 ├── [X] SVC-MDCA       : Microsoft Defender for Cloud Apps (Gölge BT & Yetkisiz SaaS Kullanımı)
 ├── [X] SVC-XDR        : Microsoft Defender XDR (Bütünleşik Olaylar & MTTR Analizi)
 ├── [X] SVC-PRV-DLP    : Microsoft Purview Data Loss Prevention (Veri Sızıntısı Önleme)
 ├── [ ] SVC-PRV-CLASS  : Microsoft Purview Veri Sınıflandırma & Etiketleme
 ├── [ ] SVC-PRV-GOV    : Microsoft Purview Veri Yaşam Döngüsü & Saklama (Retention)
 ├── [ ] SVC-PRV-RISK   : Microsoft Purview İç Tehdit (Insider Risk) & eDiscovery
 ├── [ ] SVC-AI-SECURITY: Microsoft Purview AI Güvenliği (Copilot & LLM Güvenli Kullanımı)
 └── [X] MSSP Operasyonel Katma Değer: KoçSistem Yönetilen Güvenlik & Uyum Mühendisliği (FTE Kapasitesi & Stratejik Yol Haritası)
```

---

## 5. YATIRIM GETİRİSİ (ROI) VE VERİMLİLİK METRİKLERİ

| Metrik | Eski Yöntem (Manuel/Dağınık) | KoçSistem MSSP Platformu | Kazanç / İyileşme |
|---|---|---|---|
| **Müşteri Başına Aylık Rapor Eforu** | 4 - 6 Adam/Saat | **1 Dakika (Otomatik)** | **%98 Zaman Tasarrufu** |
| **30 Müşteri İçin Aylık Toplam Efor** | 150 Adam/Saat | **~2 Adam/Saat (Kontrol)** | **Ayda 148 Mühendis Saati Kurtarılır** |
| **Parasal Tasarruf (Mühendis Maliyeti)** | ~$4.500 / Ay | ~$60 / Ay (İnceleme) | **Yılda ~$53.000 Operasyonel Tasarruf** |
| **SLA Kaçırma Oranı** | Ay sonu yoğunluklarında %5 - %10 | **%0 (Otomatik Zamanlama)** | **%100 Sözleşme SLA Uyumu** |
| **Müşteri Memnuniyeti (NPS)** | Standart statik tablolar | Dinamik, mühürlü, net özetler | **Müşteri Sadakati & Ek Servis Satışı** |

---

## 6. BULUT GEÇİŞ VE KONUŞLANDIRMA STRATEJİSİ

Proje, şirkete herhangi bir maliyet veya risk oluşturmadan aşamalı olarak hayata geçirilebilir:

### 1. Aşama: PoC ve Test Doğrulaması (Mevcut Durum - Tamamlandı)
- MCT Azure Kredisi ($100-$150/ay) üzerinde Azure Container Apps ile ayağa kaldırıldı.
- Aylık altyapı maliyeti: **<$5 / Ay** (Sunucusuz çalışma ve sıfıra ölçeklenme sayesinde).
- 4 adet temsil edici kurumsal müşteri tenant'ı ile test edildi ve rapor çıktıları üretildi.

### 2. Aşama: KoçSistem İç Pilot Dağıtımı (2-3 Hafta)
- KoçSistem kurumsal Azure aboneliğine `Deploy-ToAzure.ps1` betiği ile tek tıkla dağıtım.
- KoçSistem Entra ID SSO entegrasyonu (Mühendisler kendi şirket hesaplarıyla giriş yapar).
- Seçilecek 3 pilot kurumsal müşterinin canlı telemetrisiyle ilk ay sonu raporlarının üretilmesi.

### 3. Aşama: Genel Kullanıma Açılış (Tam Canlı)
- Tüm 30+ müşterinin portala eklenmesi.
- Müşterilere özel salt-okunur portal arayüzü (Müşteri kendi rapor geçmişini portaldan indirebilir).
- KoçSistem SOC ITSM (ServiceNow / Jira) entegrasyonu ile otomatik bilet kapatma metrikleri.

---

## 7. SONUÇ VE TAVSİYE EDİLEN KARAR

Bu platform; yalnızca bir "raporlama aracı" değil, KoçSistem'in Microsoft Güvenlik Yönetilen Hizmetleri pazarındaki teknik yetkinliğini, otomasyon gücünü ve operasyonel kalitesini doğrudan kanıtlayan bir **rekabet avantajı (Competitive Edge)** ürünüdür.

**Önerilen Karar:**
Projenin KoçSistem iç Azure ortamında pilot olarak devreye alınması ve MSSP operasyon ekiplerinin kullanımına açılması için onay verilmesi arz olunur.
