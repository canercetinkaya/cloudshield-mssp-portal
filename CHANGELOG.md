# Değişiklik Günlüğü (CHANGELOG.md)

Bu proje [Semantik Sürümleme (SemVer)](https://semver.org/lang/tr/) prensiplerine uyar.

---

## [3.1.0] - 2026-10-09 (v3.1.0-REPORTING-VISIBILITY)

### Stratejik Ürün Konumlandırması & Yeniden Tasarım
- **Ürün Yeniden Adlandırma:** Ürün adı resmi olarak **"CloudShield Security Reporting & Managed Services Visibility Platform"** olarak tescillendi.
- **Kapsam Sadeleştirmesi:** Platformun SIEM, SOAR, SOC analist kuyruğu veya incident yönetim aracı olmadığı netleştirildi; odak noktası tamamen Microsoft güvenlik ve uyumluluk raporlaması ve yönetilen hizmet görünürlüğü olarak sınırlandı.

### Mimariden Kaldırılanlar (Sıfır Bürokrasi & Sıfır Bilet)
- **CR ve Bilet Sistemlerinin Tasfiyesi:** CR ID, Change Request, Ticket ID, Ticket Referansı, ServiceNow, Jira ve Azure DevOps work item kavramları koddan, veritabanından ve raporlardan tamamen kaldırıldı.
- **Manuel Mühendislik Saatinin Kaldırılması:** Mühendislerin rapor üretmek için sisteme operasyonel saat girmesi zorunluluğu iptal edildi.
- **Sentetik Çarpanların Temizlenmesi:** Alarm sayılarını çarpan (* 80), cihaz oranlarını tahminleyen (* 0.85) veya DC sayılarına yapay ekleme yapan (+6) tüm kurgusal kodlar temizlendi.
- **Doğrulanmamış İddiaların Kaldırılması:** Kanıtlanmamış finansal tasarruf, kurgusal ROI ve mevzuata %100 kesin uyum iddiaları şablonlardan çıkarıldı.

### Yeni Özellikler & Veri Kalitesi Geliştirmeleri
- **Gözlemlenen Teknik Değişiklikler Modeli:** Raporlara `Bu ay gerçekleştirilen iyileştirmeler` bölümü eklendi; doğrudan tenant denetim kütükleri (Purview AuditLog, Entra DirectoryAudit, MDE SecurityCenter) ve politika değişikliklerinden otomatik türetilmeye başlandı.
- **Veritabanı Migrasyonu 004:** `database/migrations/004_observed_technical_improvements.sql` ile telemetri kaynaklı iyileştirmeler tablosu oluşturuldu.
- **5 Kanonik Doğrulama Statüsü:** Tüm iş yükleri için denetim disiplini getirildi (`Canlı Tenant Üzerinde Doğrulandı`, `Kodlandı, Canlı Doğrulama Bekliyor`, `Kısmi Destekleniyor`, `İzin veya Lisans Engelli`, `Test/DryRun`).
- **Zorunlu Test Filigranı:** Canlı tenant üzerinde doğrulanmamış şablonlara otomatik uyarı afişi eklendi.
- **Kolektör-Rapor Mutabakat Testi:** Ham kolektör JSON çıktısı ile HTML/PDF çıktısını 1-e-1 denetleyen otomatik test paketi (`tests/test_collector_to_report_reconciliation.py`) eklendi.
- **Örnek Raporlar Vitrini:** `docs/samples/` altında açıkça sentetik veri etiketi taşıyan HTML ve PDF örnek raporlar yayınlandı.
- **Container Sıkılaştırması:** Multi-stage Dockerfile, non-root `cloudshield` kullanıcısı, OCI etiketleri ve `.dockerignore` dosyası eklendi.

---

## [3.0.0] - 2026-10-03 (v3.0.0-ENTERPRISE)
- **Veritabanı Migrasyonu 002:** 12 aylık zaman serisi trend motoru ve kimlik bilgisi sağlık döngüsü tabloları eklendi.
- **İki Dilli Raporlama:** Türkçe ve İngilizce tam dinamik HTML ve PDF rapor üretimi sağlandı.
- **Müşteri Self-Servis Portalı:** Çoklu kiracı ayrımı ve katı kiracı izolasyon duvarı (403 Forbidden) getirildi.

---

## [2.5.15] - 2026-09-16 (v2.5.15-PILOT)
- **Tekil Kiracı Yönetici Kokpiti:** 4 Sütunlu değer atıf modeli ve 6 soruluk yönetici bilgi notu tasarlandı.
- **Müşteri Karar Çerçevesi:** Onaylanan, Bekleyen, Ertelenen ve Önerilen aksiyon matrisi eklendi.
