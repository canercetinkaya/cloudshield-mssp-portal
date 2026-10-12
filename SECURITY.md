# Güvenlik Politikası ve Zero Trust Mimarisi (SECURITY.md)
## CloudShield Security Reporting & Managed Services Visibility Platform

Bu belge, CloudShield platformunun güvenlik standartlarını, veri gizliliği yaklaşımını ve güvenlik açığı bildirim prosedürlerini açıklar.

---

### 1. Desteklenen Sürümler

Güvenlik güncellemeleri ve yamaları aşağıdaki sürümler için aktif olarak sağlanır:

| Sürüm | Yayın Etiketi | Durum | Destek |
| :--- | :--- | :--- | :---: |
| **v3.1.x** | `v3.1.0-REPORTING-VISIBILITY` | **Aktif Sürüm (Controlled Pilot)** | ✅ Tam Destek |
| **v3.0.x** | `v3.0.0-ENTERPRISE` | Önceki Sürüm | ⚠️ Yalnızca Güvenlik Yaması |
| **< v3.0** | Legacy Sürümler | Kullanım Dışı | ❌ Desteklenmiyor |

---

### 2. Zero Trust Güvenlik İlkeleri

1. **Git Deposunda Sıfır Açık Metin Secret:**
   - Müşteri tenant gizli anahtarları, sertifikalar, API token'ları veya yönetici parolaları depoya commit edilemez.
   - Tüm kimlik bilgileri Azure Key Vault veya ortam değişkenleri (`ENVIRONMENT VARIABLES`) üzerinden temin edilir.
   - `.gitignore` ve `.dockerignore` kuralları tüm yerel yapılandırma ve veritabanlarını (`*.db`, `.env`) kesin olarak dışlar.

2. **Managed Identity ve En Az Yetki (Least Privilege):**
   - Bulut ortamında (Azure Container Apps) Key Vault erişimi için Kullanıcı Tanımlı veya Sistem Tanımlı Managed Identity kullanılır; bağlantı dizesi veya statik credential kullanılmaz.
   - Kimlik bilgisi için yalnızca `Key Vault Secrets User` (salt okunur) RBAC rolü verilir.

3. **Üretim Ortamında Zorunlu Entra ID OIDC SSO:**
   - Üretim ortamında yerel parola ile giriş (`/api/auth/login`) varsayılan olarak kapalıdır (`403 Forbidden`).
   - Tüm oturumlar Microsoft Entra ID OIDC Authorization Code Flow ve PKCE (RFC 7636) ile açılır.
   - Oturum çerezleri `HttpOnly; Secure; SameSite=Strict; Path=/` bayrakları ile korunur.

4. **Çok Boyutlu Yetkilendirme ve Kiracı İzolasyonu:**
   - Her API isteği, müşteri kimliği ve abone olunan servis kimliği (`customer_id`, `service_code`) kontrolünden geçer.
   - Yetkisiz çapraz kiracı (cross-tenant) erişimleri fail-closed mantığıyla `403 Forbidden` ile engellenir.
   - Rapor indirmeleri rastgele dosya yoluyla değil, merkezi `report_id` kaydı (`/api/reports/{id}/download`) üzerinden doğrulanarak teslim edilir.

5. **Veri Gizliliği, KVKK ve Maskeleme:**
   - Ham e-posta içerikleri, dosya gövdeleri veya kişisel veriler diske kaydedilmez.
   - Kullanıcı kimlikleri ve dosya adları dinamik olarak maskelenir (`k-anon***@domain.com`, `Mali_Rapor_***.xlsx`).

6. **SQLite Tek Replika Güvenlik Kilidi:**
   - SQLite veritabanı bozulmasını önlemek için sistem tek replika (`MAX_REPLICAS=1`) ile kilitlidir. Çoklu replika tespit edildiğinde açılış fail-closed ile durdurulur.

---

### 3. Güvenlik Açığı Bildirimi (Vulnerability Disclosure)

Platformda bir güvenlik açığı veya hassas veri sızıntısı riski tespit ettiğinizde:

> [!CAUTION]
> Güvenlik açıklarını lütfen **herkese açık GitHub Issue** olarak bildirmeyiniz.

Açıkları güvenli şekilde bildirmek için:
- **GitHub Private Vulnerability Reporting:** Projenin GitHub arayüzünde bulunan **Security > Advisories > Report a vulnerability** seçeneğini kullanınız:
  `https://github.com/canercetinkaya/cloudshield-mssp-portal/security/advisories`
- Bildiriminize etkilenen endpoint, teknik detaylar ve yeniden üretme (PoC) adımlarını ekleyiniz. Bildirimler 48 saat içinde incelenerek yanıtlanır.
