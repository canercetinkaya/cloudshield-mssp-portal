# CloudShield Lisans İzinleri, Güvenlik ve RBAC Modeli
# (License Permissions, Security & RBAC Model)

**Sürüm:** 3.2.0  
**Tarih:** 2026-10-09  
**Platform:** CloudShield Security Reporting & Managed Services Visibility Platform  

---

## 1. En Az Yetki (Least Privilege) ve Zero Write Impact Prensibi

CloudShield Platformu, müşteri kiracılarına bağlanırken **Zero Trust** ve **En Az Yetki (Least Privilege)** ilkelerine sıkı sıkıya bağlı kalır.

### Zero Write Impact Güvencesi:
- **Salt-Okunur Erişim (Read-Only):** Modül, kiracı üzerinde kesinlikle herhangi bir yazma, güncelleme, silme veya yapılandırma işlemi yapmaz.
- **Lisans Değişikliği Yapılmaz:** Kullanıcılara lisans atama, lisans geri çekme veya SKU iptal etme yetkisi istenmez.
- **İlke Değişikliği Yapılmaz:** DLP, Defender veya Koşullu Erişim ilkelerinde hiçbir değişiklik yapılmaz; yalnızca durumları okunur.

---

## 2. Gerekli Microsoft Graph API İzinleri

Entra ID üzerinde kayıt edilen çok kiracılı veya tek kiracılı App Registration için gereken minimum uygulama (Application) izinleri şunlardır:

| İzin Adı | Tür | İzin Açıklaması | Kullanım Amacı |
|---|---|---|---|
| `Organization.Read.All` | Application | Read organization information | Kiracının satın aldığı SKU'ları, toplam ve tüketilen koltuk sayılarını (`/v1.0/subscribedSkus`) okumak için zorunludur. |
| `User.Read.All` | Application | Read all users' full profiles | Kullanıcı profillerini, iş unvanlarını, departmanlarını ve atanmış lisansları (`/v1.0/users`) analiz etmek için zorunludur. |
| `Directory.Read.All` | Application | Read directory data | Dizin rollerini (Global Admin, Security Admin vb.) ve gruplara atanmış lisansları tespit etmek için gereklidir. |
| `SecurityEvents.Read.All` | Application | Read your organization's security events | Güvenlik telemetrisi ve olay kanıtlarını (Katman 5) doğrulamak için salt-okunur kullanılır. |

> [!IMPORTANT]
> `User.ReadWrite.All`, `Directory.ReadWrite.All` veya `Organization.ReadWrite.All` gibi yazma izinleri **kesinlikle talep edilmez ve reddedilir**.

---

## 3. CloudShield Portal İçi Rol Bazlı Erişim Kontrolü (RBAC)

Lisans Zekâsı ve Değer Gerçekleştirme Modülü, portal kullanıcıları için fail-closed (varsayılan red) güvenlik mimarisiyle korunur.

### Tanımlı Yeni İzinler:
1. `licenses:view`: Lisans envanterini, değer gerçekleştirme özetini, kullanıcı atamalarını ve raporları görüntüleme yetkisi.
2. `licenses:manage`: Lisans senkronizasyonunu tetikleme (`POST /api/licenses/collect`) ve katalog güncelleme kontrolünü çalıştırma (`POST /api/licenses/catalog/check-updates`) yetkisi.

### Rol - İzin Eşleştirme Tablosu:

| Rol Adı | `licenses:view` | `licenses:manage` | Açıklama & Erişim Sınırı |
|---|:---:|:---:|---|
| **PlatformAdmin** | Evet | Evet | Tüm müşteri kiracılarında tam görüntüleme ve tetikleme yetkisi. |
| **SecurityEngineer** | Evet | Evet | Yetkili olduğu kiracılarda lisans verilerini görüntüleme ve toplama tetikleme. |
| **ComplianceSpecialist** | Evet | Hayır | Uyum ve lisans kapsam raporlarını salt-okunur inceleme. |
| **CustomerCISO** | Evet | Hayır | Yalnızca kendi kurumsal kiracısına ait lisans ve değer raporlarını görüntüleme. |
| **CustomerViewer** | Evet | Hayır | Yalnızca kendi kurumsal kiracısına ait özet lisans kartlarını görüntüleme. |
| **Auditor** | Evet | Hayır | Bağımsız denetim amaçlı salt-okunur inceleme. |

---

## 4. Çok Kiracılı İzolasyon (Tenant Isolation)

- Tüm veri erişim katmanı fonksiyonları (`db.py` ve `server.py`) istek sahibinin oturumundaki `customer_id` / `tenant_id` değerini doğrular.
- Müşteri CISO veya Viewer rolündeki kullanıcılar, yetkili olmadıkları başka bir kiracının lisans envanterine veya raporuna kesinlikle erişemez (HTTP 403 Forbidden).
