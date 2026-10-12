# CloudShield Security Reporting & Managed Services Visibility Platform
## Örnek Raporlar (Sample Reports Showcase)

Bu dizindeki tüm raporlar **tamamen sentetik gösterim verisi** ile üretilmiştir. Gerçek müşteri adı, canlı tenant kimliği, kurum verisi, kişisel veri veya gizli bilgi **içermez**.

> [!WARNING]
> **ÖRNEK / SENTETİK VERİ UYARISI:**
> Bu raporlar yalnızca platformun raporlama formatını, görsel hiyerarşisini, yönetici özetlerini ve yönetilen hizmet görünürlüğü mimarisini sergilemek amacıyla oluşturulmuştur. Gerçek müşteri veya canlı tenant ortamını yansıtmaz. Raporlardaki hiçbir sayısal veri finansal tasarruf, kesin mevzuat uyumu veya önlenmiş zarar teminatı teşkil etmez.

---

### 📂 Örnek Rapor Kataloğu

| Rapor Türü | Kapsanan İş Yükleri | Formatlar | Açıklama |
| :--- | :--- | :--- | :--- |
| **Konsolide Güvenlik & Uyum Raporu** | MDE, MDO, Intune, Purview DLP | [HTML](sample_consolidated_report.html) \| [PDF](sample_consolidated_report.pdf) | Çoklu servis alan C-Level yöneticiler için çapraz koruma karnesi ve yönetilen hizmet görünürlüğü. |
| **Microsoft Defender for Endpoint (EDR)** | Uç Nokta Koruması (MDE) | [HTML](sample_mde_report.html) \| [PDF](sample_mde_report.pdf) | Cihaz sensör kapsamı, otonom bloklamalar, ASR kural durumu ve FalconFriday avcılık kampanyaları. |
| **Microsoft Defender for Office 365** | E-Posta & İletişim (MDO) | [HTML](sample_mdo_report.html) \| [PDF](sample_mdo_report.pdf) | Oltalama, zararlı ekler, Safe Links / Safe Attachments, ZAP aksiyonları ve kullanıcı bildirim triyajı. |
| **Microsoft Intune Cihaz Uyum & Hijyen** | Uç Nokta Hijyeni & MDM/MAM | [HTML](sample_intune_report.html) \| [PDF](sample_intune_report.pdf) | Platform bazlı cihaz dağılımı, BitLocker / FileVault şifreleme oranı, uyumluluk ilkeleri ve N-1 OS analizi. |
| **Microsoft Purview DLP Raporu** | Veri Kaybı Önleme (Purview DLP) | [HTML](sample_purview_dlp_report.html) \| [PDF](sample_purview_dlp_report.pdf) | Hassas bilgi türü (SIT) eşleşmeleri, kullanıcı kural aşımları (overrides) ve telemetriden türetilmiş politika tuning'i. |

---

### 🛠️ Örnek Raporları Yeniden Üretme Komutu

Örnek raporları yerel ortamda tazelemek için aşağıdaki komut çalıştırılabilir:

```bash
# Python ile örnek rapor üretimi (HTML + Headless Edge/Chrome PDF)
python Scripts/generate_sample_reports.py
```

Rapor üretim motoru `Portal/api/report_generator.py` modülü üzerinden çalışır, sentetik veri damgasını otomatik ekler ve `docs/samples/` dizinine çıktı verir.
