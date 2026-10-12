# CloudShield Security Reporting & Managed Services Visibility Platform
## Ürün Kapsamı ve Konumlandırma Belgesi (PRODUCT_SCOPE.md)

Bu belge, **CloudShield Security Reporting & Managed Services Visibility Platform** ürününün kapsamını, işlevsel sınırlarını ve mimari konumlandırmasını resmi olarak tanımlar.

---

### 1. Ürünün Temel Misyonu ve Tanımı

**CloudShield Security Reporting & Managed Services Visibility Platform**, Microsoft güvenlik ve uyumluluk ekosistemini (Microsoft Defender ve Microsoft Purview) yönetilen hizmet (Managed Services) olarak alan kurumsal müşteriler için tasarlanmış; **güvenilir, müşteri bazlı, iş yükü özelinde aylık güvenlik ve uyumluluk raporları üreten, yönetilen hizmet görünürlüğü sağlayan ve raporları güvenli şekilde sunan** bir raporlama platformudur.

Platformun temel amacı:
- Dağınık Microsoft portallarındaki teknik telemetriyi tek bir çatı altında birleştirmek,
- Yönetilen hizmet ekiplerinin müşteri ortamında gerçekleştirdiği teknik iyileştirmeleri şeffafça görünür kılmak,
- C-Level yöneticiler (CISO, CIO, Yönetim Kurulu) için eyleme dönüştürülebilir, anlaşılır ve veri doğruluğu kanıtlanmış raporlar üretmektir.

---

### 2. Platform Ne Değildir? (Kapsam Dışı Alanlar)

Platformun sınırları ve odağı net olarak belirlenmiştir:

| Alan / Teknoloji | Kapsam Durumu | Açıklama |
| :--- | :--- | :--- |
| **SIEM (Security Information & Event Management)** | ❌ Kapsam Dışı | Platform bir log toplama veya SIEM çözümü (Microsoft Sentinel alternatifi) değildir. |
| **SOAR (Security Orchestration, Automation & Response)** | ❌ Kapsam Dışı | Karmaşık olay müdahale playbook'ları veya SOAR orkestrasyonu içermez. |
| **SOC Analist Çalışma Alanı (Workbench)** | ❌ Kapsam Dışı | Gerçek zamanlı alarm izleme ekranı veya SOC L1/L2 alarm kuyruğu değildir. |
| **Olay Yönetimi (Incident / Case Management)** | ❌ Kapsam Dışı | Olay inceleme ve delil toplama Defender XDR ve Sentinel konsollarında yürütülür. |
| **ITSM / Bilet (Ticket / CR) Yönetim Sistemi** | ❌ Kapsam Dışı | ServiceNow, Jira veya Azure DevOps alternatifi değildir; bilet takibi yapmaz. |
| **MDR (Managed Detection & Response) Aracısı** | ❌ Kapsam Dışı | Canlı tehdit avı operasyonunun yerini almaz; operasyonun aylık değerini raporlar. |

---

### 3. Temel Platform Yetenekleri (Kapsam İçi)

1. **Çoklu Kiracı Telemetri Toplama (Multi-Tenant Telemetry Ingestion):**
   - Microsoft Graph API, Defender Advanced Hunting KQL ve Purview denetim kütüklerine güvenli bağlantı (CBA / GDAP / Service Principal).
2. **Normalizasyon ve Veri Modeli:**
   - 15 farklı Microsoft iş yükünden toplanan verilerin standart veri şemasına ve KPI kataloğuna dönüştürülmesi.
3. **Doğrulanmış KPI Üretimi ve Veri Bütünlüğü (Data Provenance):**
   - Her metrik için kaynak sorgu, endpoint ve zaman damgası tutulur; sentetik çarpanlar kesinlikle reddedilir.
4. **Gözlemlenen Teknik Değişiklikler Modeli:**
   - Bilet (ticket) veya CR girişi gerektirmeksizin, tenant konfigürasyonundaki somut politika/kural değişikliklerinin otomatik raporlanması.
5. **Raporlama Stüdyosu & Çoklu Format Dağıtımı:**
   - Vektörel HTML5 ve baskıya hazır yüksek kaliteli PDF çıktısı (SHA-256 kriptografik mühür ile).
6. **Zero Trust Erişim ve Kiracı İzolasyonu:**
   - OIDC PKCE kimlik doğrulama, RBAC ve müşteriler arası veri sızıntısını engelleyen fail-closed izolasyon duvarı.

---

### 4. Hedef Kitle ve Kullanım Senaryoları

- **Müşteri CISO ve Bilgi Güvenliği Yöneticileri:** Yönetilen hizmetin kuruma kattığı somut güvenlik çıktısını ve açık riskleri tek raporda görür.
- **Yönetilen Hizmet (Managed Services) Liderleri:** Müşteriye sunulan hizmetin operasyonel ve teknik katma değerini kanıtlar.
- **Güvenlik ve Uyum Mühendisleri:** Yapılandırılan DLP, ASR, Safe Links ve Intune politikalarının performansını izler.
