# CloudShield Security Reporting & Managed Services Visibility Platform
## Kontrollü Pilot Kılavuzu ve Dağıtım Sınırları (CONTROLLED_PILOT.md)

Bu belge, platformun ilk kurumsal pilot müşterilere açılması öncesinde geçerli olan teknik sınırları, geçici çalışma kısıtlarını ve üretim hedef mimarisini açıklar.

---

### 1. Kontrollü Pilot Kapsamı ve Hedefi

Kontrollü Pilot aşaması, platformun seçilmiş ilk kurumsal müşterilerde canlı API telemetrisini toplamasını, raporlama şablonlarını doğrulamasını ve yönetilen hizmet görünürlüğü sağlamasını hedefler. Bu aşama genel erişime açık (General Availability - GA) ticari bulut yayını değildir.

---

### 2. Mimari Kısıtlar ve Sınırlar

#### 1. SQLite ve Tek Replika Sınırı (Single-Replica Constraint)
- **Mevcut Durum:** Platformun ilişkisel veri katmanı yerel SQLite (`cloudshield_rbac.db`) ve WAL (Write-Ahead Logging) modunu kullanmaktadır.
- **Kritik Güvenlik Kısıtı:** Paylaşımlı ağ depolama alanlarında (Azure Files / SMB) birden fazla container replikasının eşzamanlı yazma işlemi yapması, SQLite veritabanı sayfalarında sessiz bozulmaya (silent page corruption) yol açar.
- **Kural:** Azure Container Apps üzerinde `MAX_REPLICAS=1` olmak **zorundadır**. Kod katmanında `verify_replica_safety()` bekçisi birden fazla replika tespit ettiğinde açılışı doğrudan durdurur (fail-closed).
- **Hedef Mimari:** Faz 3 kapsamında **Azure Database for PostgreSQL (Flexible Server)** servisine geçiş yapılacaktır.

#### 2. In-Memory Rate Limiting
- **Mevcut Durum:** API kaba kuvvet (brute-force) koruması bellek içi (in-memory) sayaç ile çalışmaktadır.
- **Hedef Mimari:** Yatayda ölçeklenebilen Azure Cache for Redis entegrasyonu.

#### 3. Ağ İzolasyonu ve Private Endpoint
- **Mevcut Durum:** API portala HTTPS üzerinden TLS 1.3 ile erişilmektedir.
- **Hedef Mimari:** Azure Key Vault ve Container App ortamlarının VNet Entegrasyonu ve Private Endpoint arkasına alınması.

#### 4. Microsoft Lisans ve İzin Bağımlılıkları
- Müşterinin tenant'ında M365 E5 / E5 Compliance lisansı veya ilgili iş yükü aktif değilse, o servis için rapor üretimi engellenir ve raporda `Lisans Bulunmuyor` uyarısı verilir.

---

### 3. Pilot Karar Matrisi (GO / GO WITH CONDITIONS / NO-GO)

Pilot müşterilere hizmet sunulurken aşağıdaki denetim sonucu esas alınır:

| Karar | Koşullar | Operasyonel Aksiyon |
| :--- | :--- | :--- |
| **GO** | Tüm 15 iş yükü canlı tenant üzerinde test edilmiş, sıfır sentetik veri, PostgreSQL devrede, tam CI/CD. | Genel kullanıma aç (GA). |
| **GO WITH CONDITIONS**<br>*(Mevcut Durum)* | Tek replika sınırı aktif (`MAX_REPLICAS=1`), MDE/MDO/Intune/Purview canlı doğrulanmış, diğer iş yükleri "Canlı Doğrulama Bekliyor" statüsünde, test filigranı koruması devrede, sıfır bilet/CR modeli uygulanmış. | **Sadece Kontrollü Pilot Müşterilerde Aç.** |
| **NO-GO** | Mock veri sızıntısı var, replika sayısı > 1, sentetik çarpanlar devrede, tenant izolasyon testi başarısız. | Dağıtımı derhal durdur ve geri al (Rollback). |

---

### 4. Geri Alım (Rollback) Prosedürü

Azure Container Apps üzerinde yeni bir dağıtımda sorun yaşanması halinde:
```bash
# Önceki kararlı revizyona anında geri dön
az containerapp revision activate \
  --name cloudshield-reporting-app \
  --resource-group rg-cloudshield-prod \
  --revision <onceki-kararli-revizyon-adi>

# Trafiği önceki revizyona yönlendir (%100)
az containerapp ingress traffic set \
  --name cloudshield-reporting-app \
  --resource-group rg-cloudshield-prod \
  --revision-weight <onceki-kararli-revizyon-adi>=100
```
