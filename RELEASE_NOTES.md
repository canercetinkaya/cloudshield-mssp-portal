# Sürüm Notları (RELEASE_NOTES.md)
## CloudShield Security Reporting & Managed Services Visibility Platform
### Sürüm: `v3.1.0-REPORTING-VISIBILITY` (Build: 2026.10.09.1)

---

### 🌟 Sürüm Özeti

Bu sürüm, platformun stratejik konumlandırmasını kesinleştirir: **CloudShield**, geniş kapsamlı bir SOC/SIEM platformu değil; Microsoft güvenlik ve uyumluluk servislerini yönetilen hizmet olarak alan kurumsal müşteriler için **aylık güvenlik raporlama ve yönetilen hizmet görünürlüğü platformudur**.

Bu sürümle birlikte operasyonel bürokrasi (CR, bilet, ServiceNow, Jira, mühendis saati) sistemden bütünüyle temizlenmiş; yerini doğrudan Microsoft tenant'ından toplanan denetim kütüklerine ve gözlemlenen teknik iyileştirmelere bırakmıştır.

---

### 🚀 Temel Yenilikler

1. **Gözlemlenen Teknik İyileştirmeler Modeli:**
   - Raporda *"Bu ay gerçekleştirilen iyileştirmeler"* başlığı altında; DLP politika değişiklikleri, hassas bilgi türü (SIT) optimizasyonları, ASR kural sıkılaştırmaları, Intune BitLocker ilkeleri ve Defender for Cloud öneri kapanışları otomatik olarak gösterilir.
   - Hiçbir mühendislik formu doldurmaya gerek kalmaz.

2. **Sıfır Sentetik Çarpan & Tam Veri Şeffaflığı:**
   - Sentetik trafik çarpanları, tahmini yüzdeler ve yapay cihaz eklemeleri koddan tamamen çıkarılmıştır.
   - Veri toplanamadığında yanıltıcı "0" yazılmaz; durum açıkça `N/A`, `Yapılandırılmamış` veya `İzin Yok` olarak sunulur.

3. **5 Kanonik Denetim Statüsü:**
   - Desteklenen 15 Microsoft iş yükünün her biri için gerçek API durumu açıkça ilan edilir. Canlı tenant üzerinde doğrulanmamış hiçbir servis "Hazır" olarak sunulmaz.

4. **Otomatik Örnek Rapor Üretimi:**
   - `docs/samples/` altında CISO ve yöneticilere platformun yeteneklerini sergileyen, sentetik veri damgası taşıyan HTML ve PDF örnekleri yer alır.

5. **Güçlendirilmiş Container İmajı:**
   - Non-root kullanıcı (`cloudshield`), OCI standart etiketleri, multi-stage mimari ve kapsamlı `.dockerignore` ile secret ve cache sızıntısı önlenmiştir.

---

### ⚠️ Kırıcı Değişiklikler (Breaking Changes)

- **CR ve Bilet Alanları Kaldırıldı:** API ve rapor şablonlarında yer alan `ticket_ref`, `ticketId`, `engineer_role`, `hours_spent` alanları kullanımdan kaldırılmıştır.
- **Migration 004 Zorunluluğu:** Yeni sürüm `observed_technical_improvements` tablosunu gerektirir. `init_db()` çalıştırıldığında otomatik uygulanır.
- **Tek Replika Zorunluluğu:** SQLite veri bütünlüğü için Container Apps üzerinde `MAX_REPLICAS=1` kuralı zorunludur.

---

### 📋 Hazırlık Değerlendirmesi

- **Birim Testleri:** 92 / 92 Başarılı
- **Kapsamlı QA:** 60 / 60 Başarılı
- **Mutabakat Testi:** 9 / 9 Başarılı
- **Statü:** **GO WITH CONDITIONS (Kontrollü Pilot Müşteriler İçin Hazır)**
