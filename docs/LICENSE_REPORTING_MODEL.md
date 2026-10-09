# CloudShield 20 Bölümlü Lisans Raporlama Modeli
# (20-Section Monthly Health-Check & Value Realization Report Specification)

**Sürüm:** 3.2.0  
**Tarih:** 2026-10-09  
**Platform:** CloudShield Security Reporting & Managed Services Visibility Platform  

---

## 1. Raporlama Modelinin Amacı

CloudShield Aylık Lisans Sağlık ve Değer Gerçekleştirme Raporu; kurumsal yöneticilere, CISO'lara ve BT liderlerine yönelik hazırlanmış kapsamlı bir değerlendirme dokümanıdır.

Raporun temel ilkeleri:
1. **20 Bölümlü Eksiksiz Yapı:** Her bölüm lisanslama zincirinin ayrı bir halkasını (envanter, kişi ataması, servis planı, ilke, telemetri, optimizasyon) inceler.
2. **Yönetici ve Teknik Görünüm Dengesi:** İlk sayfalar C-Level yöneticiler için özet skorlar sunarken, sonraki sayfalar mühendislik ekipleri için detaylı kullanıcı ve politika listelerini içerir.
3. **HTML ve Vektörel PDF Formatı:** Hem modern web tarayıcısında interaktif incelemeye hem de kurumsal yönetim kurulu sunumları için A4 vektörel PDF çıktısına uygundur.

---

## 2. 20 Bölümün Detaylı Dökümü

| Bölüm # | Bölüm Başlığı | Kapsam ve Açıklama |
|---|---|---|
| **Bölüm 1** | Yönetici Özeti (Executive Summary) | Kiracının genel lisans sağlık skoru, toplam koltuk sayısı, değer gerçekleştirme oranı. |
| **Bölüm 2** | Lisans Envanteri ve SKU Dağılımı | Satın alınan tüm SKU'ların ad, koltuk, aktif ve boşta dağılım tablosu. |
| **Bölüm 3** | 5 Katmanlı Değer Gerçekleştirme Matrisi | 15 iş yükünün 5 hiyerarşik katmandaki durumu ve 14 kanonik statü sınıflandırması. |
| **Bölüm 4** | Persona Bazlı Lisanslama Analizi | Executive, Admin, Finance, HR, Dev, Frontline bazında lisans uygunluk karnesi. |
| **Bölüm 5** | Mükerrer ve Çakışan Lisanslar | E5+E3, E5+E5 Sec gibi üst üste binen lisans atamalarının dökümü. |
| **Bölüm 6** | Eklenti (Add-on) Ön Koşul Denetimi | Baz lisansı olmadan atanmış add-on paketlerinin tespiti. |
| **Bölüm 7** | Atıl ve Boşta Kalan Lisanslar | Satın alınmış ancak kullanıcılara atanmamış atıl koltukların listesi. |
| **Bölüm 8** | Pasif / Ayrılmış Hesap Lisans Riski | `accountEnabled=False` olan hesaplarda gereksiz asılı kalmış lisanslar. |
| **Bölüm 9** | KOBİ 300 Kullanıcı Tavanı Uyumu | Business Basic, Standard ve Premium toplamının 300 sınırına mesafesi. |
| **Bölüm 10** | Azure Tüketim Modeli İş Yükleri | Defender for Servers, Containers, Storage, SQL ve CSPM kaynak durumu. |
| **Bölüm 11** | Güvenlik İlkesi ve Kapsam Boşlukları | Lisansı olup da güvenlik ilkesi (DLP, ASR vb.) atanmamış kullanıcılar. |
| **Bölüm 12** | Telemetri ve Canlı Kanıt Doğrulaması | Son 30 gün içinde güvenlik telemetrisi üreten aktif iş yükleri. |
| **Bölüm 13** | Lisans Sürüm (Tier) Boşlukları | E3 olup Plan 2 gerektiren özelliklerin kullanılamama durumları. |
| **Bölüm 14** | Konuk (Guest) ve Harici Kullanıcı Denetimi | Dış kullanıcılara yapılmış hatalı kurumsal lisans atamaları. |
| **Bölüm 15** | Hizmet Hesapları ve Otomasyon Lisansları | Servis hesapları ve paylaşılan posta kutularında lisanslama hijyeni. |
| **Bölüm 16** | Grup Bazlı vs Doğrudan Atama Oranı | Grup tabanlı yönetim olgunluğu ve operasyonel sürdürülebilirlik. |
| **Bölüm 17** | Değer Kaybı ve Optimizasyon Fırsatları | Yapılandırma eksikliği nedeniyle boşa giden güvenlik yatırım alanları. |
| **Bölüm 18** | Lisans Kataloğu ve Besleme Durumu | Microsoft resmi CDN dokümanlarının kontrol tarihi, sürümü ve SHA-256 özeti. |
| **Bölüm 19** | Ay Sonu Anlık Durum Karşılaştırması (Snapshot Diff) | Bir önceki aya göre lisans adedi, atama ve değer oranındaki değişim trendi. |
| **Bölüm 20** | Öncelikli Eylem Planı ve Öneriler | Kıdemli güvenlik mühendisliği tarafından önerilen öncelikli iyileştirme adımları. |

---

## 3. Rapor Üretim ve Vektörel PDF Mimarisi

- **HTML Şablon Motoru:** `Portal/api/license_report_generator.py` modülü `build_license_report_html` fonksiyonu ile modern CSS Grid ve Flexbox kullanan duyarlı bir HTML üretir.
- **Vektörel PDF Dönüşümü:** `generate_license_pdf` fonksiyonu, sistemdeki Microsoft Edge veya Chromium headless motorunu çağırarak print CSS (`@media print`, `page-break-inside: avoid`) kurallarıyla yüksek çözünürlüklü vektörel PDF çıktısı oluşturur.
- **Canlı ve Sentetik Güvenliği:** Veriler canlı API'den toplanmamışsa, her sayfanın üstüne "DİKKAT: SENTETİK TEST SİMÜLASYONU" uyarısı eklenir.
