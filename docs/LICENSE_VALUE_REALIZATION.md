# CloudShield 5 Katmanlı Güvenlik Değer Gerçekleştirme Modeli
# (5-Layer Security Value Realization Architecture)

**Sürüm:** 3.2.0  
**Tarih:** 2026-10-09  
**Platform:** CloudShield Security Reporting & Managed Services Visibility Platform  

---

## 1. Mimarinin Amacı ve Zero Fake ROI Prensibi

Geleneksel lisans yönetimi yaklaşımları yalnızca satın alınan ve atanan koltuk adetlerini sayar; organizasyona tahmini maliyet tasarrufu veya farazi yatırım geri dönüşü (ROI) iddiaları sunar. 

**CloudShield Değer Gerçekleştirme Modeli (Value Realization Engine)** ise iki temel prensip üzerine kuruludur:

1. **Zero Fake Financial ROI Prensibi:** Doğrulanmış müşteri fiyat listesi olmaksızın raporda hiçbir para birimi (USD, EUR, TL) cinsinden farazi tasarruf veya hayali finansal kazanç metriği üretilmez. Değer; doğrudan **gerçekleşen güvenlik kapsamı, konfigüre edilmiş ilke sayısı, telemetri kanıtı ve korunan koltuk oranı** üzerinden ölçülür.
2. **Uçtan Uca 5 Katmanlı Doğrulama:** Bir güvenlik lisansının varlığı, organizasyonun korunduğu anlamına gelmez. Bir iş yükünün gerçek güvenlik değeri üretmesi için 5 teknik halkanın tamamının eksiksiz tamamlanması gerekir.

---

## 2. 5 Katmanlı Doğrulama Mimarisi

CloudShield mimarisi, incelenen her güvenlik ve uyumluluk iş yükünü aşağıdaki 5 ardışık katmanda denetler:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. HAK SAHİPLİĞİ (Entitlement)                              │
│    Tenant'ta geçerli ve aktif bir SKU satın alınmış mı?     │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. KULLANICI ATAMASI (Assignment)                           │
│    Lisans, hedeflenen çalışan profiline atanmış mı?         │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. SERVİS PLANI ETKİNLİĞİ (Service Plan Active)             │
│    SKU içindeki teknik yetenek (plan) Enabled durumda mı?   │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. KONFİGÜRASYON VE İLKE KAPSAMI (Configuration & Policy)   │
│    Güvenlik veya uyumluluk ilkesi tanımlanıp dağıtılmış mı? │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. TELEMETRİ VE KANIT (Evidence & Telemetry)                │
│    Sistem canlı olay, bloklama veya log üretiyor mu?        │
└─────────────────────────────────────────────────────────────┘
```

### Katman Detayları:
1. **Katman 1 - Hak Sahipliği (Entitlement):** Microsoft Graph `/v1.0/subscribedSkus` üzerinden kiracının aktif abonelikleri doğrulanır.
2. **Katman 2 - Kullanıcı Ataması (Assignment):** Satın alınan koltukların doğrudan kullanıcıya veya dinamik güvenlik gruplarına atanıp atanmadığı kontrol edilir.
3. **Katman 3 - Servis Planı Etkinliği (Service Plan Active):** Kullanıcıya atanan SKU içinde ilgili teknik servisin (`assignedPlans.servicePlanId`) provizyon durumu denetlenir (örn: yönetici tarafından elle kapatılmış veya lisans çakışması nedeniyle devre dışı bırakılmış planlar yakalanır).
4. **Katman 4 - Konfigürasyon ve İlke Kapsamı (Configuration & Policy Coverage):** Güvenlik ürününün tenant'ta aktive edilip edilmediği; DLP ilkeleri, ASR kuralları, Koşullu Erişim (Conditional Access) veya EDR ilkesinin ilgili kullanıcı/cihazları hedefleyip hedeflemediği kontrol edilir.
5. **Katman 5 - Gerçek Telemetri ve Kanıt (Telemetry & Evidence):** İş yükünün son 30 gün içinde canlı olay, tehdit engelleme, uyarı veya denetim kaydı üretip üretmediği doğrulanır.

---

## 3. 14 Kanonik Statü Sözlüğü (Canonical Status Dictionary)

Her iş yükü ve kullanıcı analizi, aşağıdaki 14 standart teknik durumdan biriyle etiketlenir:

| # | Kanonik Statü Kodu | Türkçe Tanım | Teknik Anlamı & Aksiyon |
|---|---|---|---|
| 1 | `STATUS_VERIFIED_VALUE_REALIZED` | Doğrulandı, Değer Gerçekleşiyor | 5 katmanın tamamı başarıyla geçildi; ilke aktif ve telemetri kanıtı mevcut. |
| 2 | `STATUS_CONFIGURED_NO_TELEMETRY` | Yapılandırıldı, Telemetri Bekleniyor | İlke uygulanmış ancak son dönemde tetiklenen olay yok (güvenli/temiz durum veya pasif cihaz). |
| 3 | `STATUS_PLAN_ACTIVE_NOT_CONFIGURED` | Servis Planı Aktif, Yapılandırılmadı | Kullanıcıda lisans ve plan aktif, ancak merkezi güvenlik ilkesi atanmamış (**Değer Kaybı**). |
| 4 | `STATUS_SERVICE_PLAN_DISABLED` | Servis Planı Devre Dışı | SKU kullanıcıya atanmış ancak ilgili güvenlik alt planı yönetici tarafından kapatılmış. |
| 5 | `STATUS_UNASSIGNED_ENTITLEMENT` | Atanmamış Hak / Boşta Lisans | Lisans satın alınmış fakat havuzda boşta bekliyor (maliyet optimizasyonu fırsatı). |
| 6 | `STATUS_DUPLICATE_ENTITLEMENT` | Mükerrer / Üst Üste Binen Lisans | Kullanıcıya aynı anda kapsayıcı ve kapsanan lisanslar atanmış (örn: E5 + E3 veya E5 + E5 Sec). |
| 7 | `STATUS_MISSING_PREREQUISITE` | Ön Koşul Lisansı Eksik | Eklenti (add-on) atanmış ancak gerektirdiği temel baz lisans eksik veya uyumsuz. |
| 8 | `STATUS_UNDER_LICENSED` | Eksik Lisanslama | Kullanıcı profili yüksek güvenlik gerektiriyor ancak düşük baz paket atanmış. |
| 9 | `STATUS_INACTIVE_USER_LICENSED` | Pasif Kullanıcıda Lisans Asılı | `accountEnabled=False` olan devre dışı hesapta lisans kalmış (geri kazanım gerekir). |
| 10 | `STATUS_CROSS_TENANT_ANOMALY` | Kiracı Dışı / Anomali Atama | Konuk (Guest) veya harici kullanıcıya uygunsuz kurumsal güvenlik lisansı atanması. |
| 11 | `STATUS_AZURE_CONSUMPTION_MODEL` | Azure Tüketim Modeli | İş yükü kullanıcı lisansı değil Azure tüketim kaynağıdır (Defender for Cloud). |
| 12 | `STATUS_API_PERMISSION_BLOCKED` | API / İzin Engeli | İlgili iş yükünün telemetri veya ilke durumu Graph/Azure API izin kısıtı nedeniyle doğrulanamadı. |
| 13 | `STATUS_TIER_GAP` | Lisans Katmanı / Sürüm Eksikliği | İlke için Plan 2 gerekirken organizasyonda yalnızca Plan 1 mevcut. |
| 14 | `STATUS_TEST_SYNTHETIC` | Sentetik / Simülasyon Verisi | Canlı kiracı bağlantısı yok; test ve demo amaçlı sentetik modelleme. |

---

## 4. Değer Gerçekleştirme Skorlama Metodolojisi

Modül, tenant genelinde ve her iş yükü bazında aşağıdaki matematiksel formüllerle nesnel metrikler üretir:

### 1. Değer Gerçekleştirme Oranı (Value Realization Rate - VRR)
$$\text{VRR} = \left( \frac{\text{Doğrulanmış Değer Üreten Koltuk Sayısı}}{\text{Satın Alınan Toplam Koltuk Sayısı}} \right) \times 100$$

### 2. Koltuk Kullanım Oranı (Seat Utilization Rate)
$$\text{Kullanım Oranı} = \left( \frac{\text{Atanmış Aktif Koltuk Sayısı}}{\text{Satın Alınan Toplam Koltuk Sayısı}} \right) \times 100$$

### 3. Değer Açığı (Security Value Gap)
$$\text{Değer Açığı} = \text{Atanmış Koltuk Sayısı} - \text{İlke Kapsamında ve Telemetri Üreten Koltuk Sayısı}$$

Bu açık, **organizasyonun lisans parasını ödediği ancak yapılandırma eksikliği nedeniyle korunamadığı** kullanıcı sayısını net olarak gösterir.
