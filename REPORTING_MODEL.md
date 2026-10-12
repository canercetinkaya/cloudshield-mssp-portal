# CloudShield Security Reporting & Managed Services Visibility Platform
## Aylık Raporlama ve Yönetilen Hizmet Görünürlük Modeli (REPORTING_MODEL.md)

Bu belge, CloudShield platformunun temel raporlama felsefesini, yönetici anlatım mimarisini ve telemetriye dayalı yönetilen hizmet değer modelini tanımlar.

---

### 1. Her Ay Cevap Verilen 13 Temel Soru

Müşteri raporu salt sayı veya ham alarm istatistiği sunmaz. Her iş yükü için şu 13 kritik soruya açık ve doğrulanabilir cevap verir:

1. **Bu ay ne oldu?** (Operasyon ve telemetri özeti)
2. **Geçen aya göre ne değişti?** (12 aylık trend ve yönelim)
3. **Hangi riskler arttı?** (Yeni tetiklenen tehdit vektörleri)
4. **Hangi riskler azaldı?** (Uygulanan sıkılaştırmalar ve tecrit edilen açıklar)
5. **Hangi yeni riskler ortaya çıktı?** (İlk kez gözlemlenen anomaliler veya kurallar)
6. **Microsoft otomatik olarak ne tespit etti veya engelledi?** (Makine hızında otonom koruma kalkanı)
7. **CloudShield ekibi müşteri için ne yaptı?** (Politika optimizasyonu, ASR sıkılaştırması, kural tuning'i)
8. **Müşteri ekibi hangi aksiyonları tamamladı?** (Donanım yükseltmeleri, yönetici onayları)
9. **Hangi riskler halen açık?** (Yetkilendirme bekleyen politikalar veya istisnalar)
10. **Hangi aksiyonların müşteri tarafından onaylanması gerekiyor?** (P1 öncelikli karar matrisi)
11. **Önümüzdeki ay hangi konulara odaklanılmalı?** (Gelecek ayın güvenlik hedefleri)
12. **Yönetilen hizmet müşteriye hangi ölçülebilir değeri sağladı?** (Kazanılan mühendislik zamanı ve koruma duruşu)
13. **Hangi veriler toplanamadı ve nedeni nedir?** (Eksik telemetri, izin veya lisans gerekçesiyle şeffaf bildirim)

---

### 2. Gözlemlenen Teknik Değişiklikler Modeli (Sıfır Bilet / Sıfır CR)

Mühendislerin manuel olarak faaliyet girmesi veya müşteriye "CR-2026-08-4412" gibi anlamsız bilet numaraları gösterilmesi mimariden **tamamen kaldırılmıştır**.

Tüm iyileştirmeler doğrudan sistemde gözlemlenebilen teknik değişikliklerden türetilir:
- **Kaynaklar:** Purview AuditLog, Entra DirectoryAudit, MDE SecurityCenter Audit, MDCA DiscoveredApp Events, Azure Activity Logs.
- **Aktör Sınıflandırması:**
  - *Doğrulanabiliyorsa:*
    - **Microsoft tarafından otomatik gerçekleştirilen aksiyon** (ZAP tahliyesi, AIR otonom izolasyon)
    - **CloudShield kimliği/uygulaması tarafından gerçekleştirilen değişiklik** (DLP regex tuning, ASR kural sıkılaştırması)
    - **Müşteri yöneticisi tarafından gerçekleştirilen değişiklik** (Kullanıcı yetkilendirmesi, aygıt kaydı)
  - *Aktör doğrulanamıyorsa:*
    - **Ortamda gözlemlenen teknik değişiklik**
    - **Aktörü doğrulanamayan konfigürasyon değişikliği**

---

### 3. Dört Temel Değer Sütunu (Service Value Attribution Model)

Her raporun ilk sayfasında yer alan atıf ızgarası (attribution grid), hizmetin değerini 4 ayrı sütuna bölerek şeffaflık sağlar:

1. **Microsoft Otonom Savunma Kalkanı:**
   - Makine hızında çalışan yapay zeka ve yerel algoritmaların (EDR AV, Safe Links, ZAP, Defender AIR) engellediği hacim.
2. **CloudShield Yönetilen Hizmet Değeri:**
   - Kural optimizasyonu, yanlış pozitiflerin elenmesi, istisna analizi ve kuruma kazandırılan uzmanlık saatleri.
3. **Müşteri Bilişim & Yönetim Eforu:**
   - Cihaz şifreleme, kullanıcı eğitimi ve müşteri ekiplerince yürütülen kurumsal uyum aksiyonları.
4. **Artık Risk & Karar Matrisi:**
   - Henüz kapatılmamış, CISO ve yönetim kurulunun onayını bekleyen stratejik kararlar (P0/P1/P2).

---

### 4. Boş Durum (Empty-State) ve Sıfır İddiası Garantisi

Veri yokken veya tespit bulunmazken raporlama kuralları:
- Veri toplanamıyorsa asla `0` yazılmaz; durum `N/A`, `Yapılandırılmamış` veya `İzin Gerekli` olarak belirtilir.
- O ay hiçbir DLP kural aşımı veya sızıntı olmamışsa: *"Dönem içinde telemetriye yansıyan harici sızıntı veya kural eşleşmesi saptanmamıştır (0 Tespit / Doğrulanmış Temiz Durum)"* ifadesi kullanılır.
- Lisansı olmayan ürün için *"0 Risk / Korunuyor"* denilemez; lisans eksikliği açıkça belirtilir.
