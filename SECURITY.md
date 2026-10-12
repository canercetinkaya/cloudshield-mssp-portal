# Güvenlik Politikası (SECURITY.md)
## CloudShield Security Reporting & Managed Services Visibility Platform

Bu belge, CloudShield platformunun güvenlik ilkelerini, desteklenen sürümlerini, kimlik doğrulama ve yetkilendirme standartlarını ve güvenlik açığı bildirim sürecini açıklar.

---

### 1. Desteklenen Sürümler

Güvenlik güncellemeleri ve hata düzeltmeleri aşağıdaki sürümler için sağlanır:

| Sürüm Ailesi | Güncel Etiket | Durum | Güvenlik Desteği |
| :--- | :--- | :--- | :---: |
| **v3.2.x** | `v3.2.0-LICENSE-INTELLIGENCE` | **Aktif Sürüm (Controlled Pilot)** | ✅ Tam Destek |
| **v3.1.x** | `v3.1.0-REPORTING-VISIBILITY` | Önceki Sürüm | ⚠️ Kritik Güvenlik Yamaları |
| **< v3.1** | Legacy Sürümler | Kullanım Dışı | ❌ Desteklenmiyor |

---

### 2. Temel Güvenlik İlkeleri

CloudShield, Microsoft güvenlik ve uyumluluk verilerini raporlarken aşağıdaki güvenlik standartlarını uygular:

#### 2.1. Kimlik Bilgisi ve Gizli Anahtar Yönetimi
- **Sıfır Açık Metin Secret:** Kod deposunda müşteri anahtarları, sertifikalar, API token'ları veya yönetici parolaları barındırılmaz.
- **Azure Key Vault & Managed Identity:** Bulut dağıtımlarında (Azure Container Apps) kimlik bilgileri Key Vault üzerinden çekilir. Uygulama, Key Vault'a statik şifrelerle değil, Azure Managed Identity ve en az yetkili `Key Vault Secrets User` (salt-okunur) RBAC rolü ile erişir.
- **Ortam Değişkenleri:** Yerel ve CI/CD ortamlarında yapılandırmalar güvenli ortam değişkenleri üzerinden yönetilir; `.env` ve yerel veritabanı dosyaları git takibinden hariç tutulur.

#### 2.2. En Az Yetki (Least Privilege) ve Salt-Okunur API Erişimi
- Platform yalnızca raporlama, durum tespiti ve lisans optimizasyon görünürlüğü sunar.
- Müşteri ortamlarında **kesinlikle hiçbir kaynak oluşturulmaz, değiştirilmez veya silinmez**.
- Kullanılan Microsoft Graph ve Defender API izinleri tamamen salt-okunurdur:
  - **Lisans Zekâsı:** `Organization.Read.All`, `Reports.Read.All`, `Directory.Read.All`
  - **Uç Nokta ve Posta:** `Machine.Read.All`, `SecurityEvents.Read.All`
  - **Intune ve Purview:** `DeviceManagementManagedDevices.Read.All`, `InformationProtectionPolicy.Read.All`
- Asla `Directory.ReadWrite.All` veya kiracı konfigürasyonunu değiştirebilecek yazma yetkileri talep edilmez. Eksik izin durumlarında sistem işlemi durdurmaz; ilgili bölümü şeffafça `İzin Yok` / `N/A` olarak raporlar.

#### 2.3. Kimlik Doğrulama ve Oturum Yönetimi
- **Canlı Ortamda Entra ID OIDC SSO:** Üretim ortamında yerel kullanıcı adı/şifre girişi devre dışıdır (`403 Forbidden`). Oturumlar Microsoft Entra ID üzerinden Authorization Code Flow ve PKCE (RFC 7636) ile açılır.
- **Güvenli Çerezler:** Oturum kimlikleri `HttpOnly`, `Secure`, `SameSite=Strict` bayraklarına sahip çerezler içinde saklanır. İstemci tarafında (localStorage / sessionStorage) hassas token tutulmaz.

#### 2.4. Müşteri ve Kiracı İzolasyonu
- Çok kiracılı (multi-tenant) mimaride her API çağrısı oturum açan kullanıcının müşteri kimliği ve yetkili olduğu servis kodları ile doğrulanır.
- Çapraz kiracı (cross-tenant) erişim girişimleri doğrudan reddedilir.
- Rapor dosyaları rasgele dosya yolları üzerinden değil, sistemde kayıtlı tekil `report_id` değerleri doğrulanarak (`/api/reports/{id}/download`) güvenli şekilde sunulur.

#### 2.5. Veri Mahremiyeti, Maskeleme ve KVKK / GDPR Uyumu
- E-posta gövdeleri, dosya içerikleri veya kişisel mesajlar çekilmez ve diske kaydedilmez; yalnızca sayısal telemetri ve metaveriler işlenir.
- Kullanıcı kimlikleri ve dosya isimleri dinamik olarak maskelenir (`k-anon***@domain.com`, `Finans_Raporu_***.xlsx`).
- Test veya simülasyon (DryRun) verilerinin canlı raporlara karışması engellenir.

#### 2.6. Veri Bütünlüğü ve Tek Replika Mimarisi
- SQLite veritabanının eşzamanlı yazma problemlerinden korunması amacıyla sistem tek replika (`MAX_REPLICAS=1`) kuralı ile çalışacak şekilde kilitlenmiştir.

---

### 3. Güvenlik Açığı Bildirimi (Vulnerability Disclosure)

Platformda bir güvenlik açığı veya veri güvenliği riski tespit ettiğinizde, sorumlu bildirim ilkelerine uygun şekilde hareket etmenizi rica ederiz.

> [!CAUTION]
> Güvenlik açıklarını lütfen **herkese açık GitHub Issue** olarak bildirmeyiniz.

Bildirim adımları:
1. GitHub deposundaki **Security > Advisories > Report a vulnerability** ekranını kullanınız:  
   https://github.com/canercetinkaya/cloudshield-mssp-portal/security/advisories
2. Bildiriminize etkilenen uç nokta, bulgunun teknik detayı ve yeniden üretme (PoC) adımlarını ekleyiniz.
3. Güvenlik bildirimleri 48 saat içinde değerlendirilir ve doğrulanan bulgular için öncelikli yama süreci başlatılır.
