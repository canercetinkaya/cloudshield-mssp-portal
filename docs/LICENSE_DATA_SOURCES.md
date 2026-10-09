# CloudShield Lisans Veri Kaynakları ve API Mimarisi
# (License Data Sources & API Architecture)

**Sürüm:** 3.2.0  
**Tarih:** 2026-10-09  
**Platform:** CloudShield Security Reporting & Managed Services Visibility Platform  

---

## 1. Giriş ve Veri Akışı

CloudShield Lisans Zekâsı Modülü, kurumsal Microsoft kiracısının lisans, kullanıcı, rol ve güvenlik telemetri verilerini toplamak için resmi ve salt-okunur (read-only) Microsoft Graph ve Azure REST API uç noktalarını kullanır.

Veri toplama motoru iki farklı çalışma modunu destekler:
1. **Canlı Kiracı Modu (Live Production Mode):** Entra ID App Registration (Service Principal) üzerinden güvenli OAuth2 Client Credentials akışıyla canlı API'ye bağlanır.
2. **Sentetik / Simülasyon Modu (Synthetic Test Mode):** Canlı kimlik bilgisi verilmediğinde veya DryRun çalıştırıldığında, açıkça `STATUS_TEST_SYNTHETIC` etiketiyle izole edilmiş gerçekçi test veri setlerini kullanır.

---

## 2. Kullanılan Microsoft Graph API Uç Noktaları

| İşlem | Uç Nokta | HTTP Metodu | Gerekli İzin | Toplanan Veri Alanları |
|---|---|---|---|---|
| **Kiracı Lisans Envanteri** | `/v1.0/subscribedSkus` | `GET` | `Organization.Read.All` | `skuId`, `skuPartNumber`, `prepaidUnits.enabled`, `consumedUnits`, `servicePlans` (`servicePlanId`, `servicePlanName`, `provisioningStatus`, `appliesTo`) |
| **Kullanıcı ve Lisans Atamaları** | `/v1.0/users` | `GET` | `User.Read.All` | `id`, `userPrincipalName`, `displayName`, `mail`, `jobTitle`, `department`, `accountEnabled`, `assignedLicenses` (`skuId`), `assignedPlans` (`servicePlanId`, `capabilityStatus`, `provisioningStatus`) |
| **Dizin Rolleri (Persona Analizi)** | `/v1.0/directoryRoles` | `GET` | `RoleManagement.Read.Directory` veya `Directory.Read.All` | `id`, `displayName`, `roleTemplateId`, `members` (Global Admin, Security Admin, Compliance Admin vb.) |
| **Purview DLP İlkeleri** | `/v1.0/security/informationProtection/policy` | `GET` | `InformationProtectionPolicy.Read.All` | İlke durumu, hedef kullanıcı/grup kapsamı, kural tetiklenme sayıları |
| **Defender for Endpoint Cihazlar** | `/v1.0/security/alerts_v2` & Defender Security API | `GET` | `SecurityAlert.Read.All`, `Machine.Read.All` | Onboarded cihazlar, aktif sensör durumu, son telemetri zaman damgası |

---

## 3. Azure Kaynak Tüketim Modeli Veri Kaynakları

Kullanıcı koltuk lisansı gerektirmeyen Defender for Cloud iş yükleri için Azure Resource Graph ve ARM REST API kullanılır:

- **Microsoft.Security/pricings:** `/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2024-01-01`
  - `VirtualMachines` (Servers Plan 1 & Plan 2)
  - `Containers`
  - `StorageAccounts`
  - `SqlServers`
  - `CloudPosture` (Defender CSPM)

Bu uç noktalardan gelen veriler, kullanıcı koltuk tablosuna karıştırılmadan ayrı `Azure Consumption Model` kartlarında gösterilir.

---

## 4. Test Simülasyonu ve Sentetik Veri İzolasyonu

CloudShield, test ve demo verilerinin canlı kurumsal çıktılara karışmasını engellemek için katı izolasyon kuralları uygular:

- Canlı kimlik doğrulama başarısız olduğunda veya parametre olarak belirtilmediğinde toplayıcı otomatik olarak sentetik fikstür moduna geçer.
- Üretilen tüm nesneler `is_synthetic: true` bayrağı taşır.
- Rapor başlığı ve PDF çıktısının üst kısmında kırmızı/sarı uyarı kutusu ile:
  > **DİKKAT: SENTETİK TEST SİMÜLASYONU**  
  > Bu rapordaki değerler gerçek müşteri kiracı telemetrisine dayanmamaktadır. Test ve şablon doğrulama amacıyla üretilmiştir.
  ibaresi zorunlu olarak basılır.
- Veritabanı tablolarında sentetik veriler `tenant_id` bazında ayrıştırılır ve canlı kiracı sorgularına kesinlikle dahil edilmez.
