# KoçSistem Managed Security Operations & Reporting Platform (MSSP Portal)
# Azure Bulut Dağıtım, Güvenlik ve RBAC Aktivasyon Kılavuzu

Bu kılavuz, yerel ortamda çalışan KoçSistem MSSP Portal ve Raporlama Motoru'nu **Azure MCT (Microsoft Certified Trainer) aboneliğiniz** üzerinde sıfırdan canlıya nasıl alacağınızı, modern **Zero-Trust Passwordless** mimari ile nasıl güvenceye alacağınızı ve KoçSistem kurumsal ortamına nasıl taşıyacağınızı adım adım anlatmaktadır.

---

## 1. Mimari Tasarım & Güvenlik Modeli (Passwordless Zero-Trust)

Platform, MCT aylık kredinizi ($100 - $150/ay) tüketmemek ve kurumsal güvenlik standartlarına (ISO 27001, SOC 2, KVKK) tam uyum sağlamak üzere **Sunucusuz (Serverless Container)** ve **Şifresiz Kimlik (Managed Identity)** mimarisiyle tasarlanmıştır:

```
                                  +-------------------------------------------------------------------+
                                  |                         AZURE BULUT ORTAMI                        |
                                  |                                                                   |
+----------------------+          |  +-------------------------------------------------------------+  |
|                      |  HTTPS   |  |              Azure Container Apps (Sunucusuz)               |  |
|  KoçSistem           | ----------> |  - Web Arayüzü (Tailwind SPA, Tenant Switcher)             |  |
|  Güvenlik Mühendisi  |          |  - Python REST API (Zero-dependency Backend)                   |  |
|                      | <---------- |  - PowerShell 7.4 Core Raporlama Motoru                     |  |
+----------------------+  PDF/HTML|  - Headless Chromium (Vektörel PDF Üretimi)                   |  |
                                  |  +-------------------------------------------------------------+  |
                                  |               | (Managed Identity)            | (Managed Identity)|
                                  |               v                               v                   |
                                  |  +---------------------------+  +------------------------------+  |
                                  |  |      Azure Key Vault      |  |     Azure Storage (Blob)     |  |
                                  |  |  RBAC: Secrets User       |  |  RBAC: Blob Data Contributor |  |
                                  |  |  RBAC: Certificate User   |  |  - Rapor Arşivi (PDF/HTML)   |  |
                                  |  |  - Müşteri Secret'ları    |  |  - Şifreli Veri Deposu       |  |
                                  |  |  - Müşteri Sertifikası    |  |                              |  |
                                  |  +---------------------------+  +------------------------------+  |
                                  +-------------------------------------------------------------------+
                                                                   |
                                                                   | Microsoft Graph / XDR API
                                                                   v
                                  +-------------------------------------------------------------------+
                                  | MÜŞTERİ TENANTLARI (Anadolu Finans, Bosphorus Lojistik...)         |
                                  | GDAP / Multi-Tenant Service Principal ile Güvenli Bağlantı       |
                                  +-------------------------------------------------------------------+
```

### RBAC Yetki Ayrımı ve En Az Yetki (Least-Privilege) Matrisi

| Rol Tanımı | Rol ID (GUID) | Atanan Varlık | Erişim Kapsamı | Güvenlik Amacı |
|---|---|---|---|---|
| **Key Vault Secrets User** | `4633458b-17de-408a-b874-0445c86b69e6` | Container App System Identity | Key Vault | Müşteri Client Secret değerlerini sadece bellek içinde okur. Secret yazamaz veya silemez. |
| **Key Vault Certificate User** | `db79e9a7-68ee-4b58-9aeb-b90e7c24fcba` | Container App System Identity | Key Vault | CBA (Sertifika tabanlı doğrulama) için müşteri sertifikalarını ve özel anahtarları okur. |
| **Storage Blob Data Contributor** | `ba92f5b4-2d11-453d-a403-e96b0029c9fe` | Container App System Identity | Storage Account | Üretilen PDF/HTML raporlarını şifreli blob depoya kaydeder ve okur. |
| **Key Vault Administrator** | `00482a5a-887f-4fb3-b391-77e1613c4fc0` | Dağıtımı Yapan Mühendis (Admin) | Key Vault | Müşteri secret/sertifikalarını Key Vault'a yükler ve yönetir. |

### Aylık Maliyet Tablosu (MCT Bütçesi)
| Servis | Yapılandırma | Aylık Tahmini Maliyet | MCT Kredi Durumu |
|---|---|---|---|
| **Azure Container Apps** | 0.5 vCPU, 1.0 GiB RAM, Min Replicas: 0 | **$0.00 - $4.00** | Aylık ilk 180.000 vCPU/sn ve 360.000 GiB/sn **ücretsizdir**. İstek yokken 0'a iner. |
| **Azure Storage Account** | Standart LRS Blob (Hot/Cool) | **$0.20 - $0.50** | 10 GB PDF arşiv saklama maliyeti ihmal edilebilir düzeydedir. |
| **Azure Key Vault** | Standard Tier (RBAC Modu) | **$0.03** | 10.000 istek başına $0.03. |
| **Log Analytics** | Per-GB (Aylık 5GB Ücretsiz) | **$0.00** | İlk 5 GB veri yazma ücretsizdir. |
| **TOPLAM TAHMİNİ** | Tam Fonksiyonel MSSP SaaS | **~$3.00 - $5.00 / Ay** | **MCT kredinizin %95'inden fazlası cebinizde kalır!** |

---

## 2. Secret Güvenliği ve Plain-Text Sızıntı Önleme Prensipleri

Platform mimarisinde **hiçbir müşteri parolası, istemci gizli anahtarı (client secret) veya özel sertifika düz metin (plain-text) olarak saklanmaz veya aktarılmaz**:

1. **Ortam Değişkeni (Container App `env`) Güvenliği**:
   - Konteyner ortam değişkenlerine (`env.value`) yalnızca hassas olmayan genel kaynak tanımlayıcıları (`PORT`, `AZURE_STORAGE_ACCOUNT`, `AZURE_KEYVAULT_URL`, `ENVIRONMENT`) verilir.
   - Hiçbir API anahtarı veya secret ortam değişkenine düz metin yazılmaz. Böylece `az containerapp show` veya Azure Portal incelemelerinde secret ifşası imkansız kılınır.
2. **Uygulama İçi Dinamik Çözümleme (In-Memory Resolution)**:
   - Raporlama motoru (`Authentication.psm1`) bir müşteri için token alacağı zaman, Azure Container Apps Managed Identity uç noktası (`IDENTITY_ENDPOINT` / IMDS) üzerinden Key Vault için kısa ömürlü bir Bearer token alır.
   - Sır/sertifika bellek içinde Key Vault REST API'sinden çekilir, Entra ID token isteğinde kullanılır ve bellekten temizlenir.
   - Dosya sistemine veya diske hiçbir zaman yazılmaz.
3. **Azure RBAC ile Key Vault İzolasyonu**:
   - Eski ve tehlikeli "Access Policy" modeli yerine modern Azure RBAC modeli (`enableRbacAuthorization: true`) uygulanmıştır.
   - Container App kimliği yalnızca okuma rolüne (`Key Vault Secrets User`) sahiptir; kasadaki sırları silemez, değiştiremez veya dışarıya aktaramaz.

---

## 3. Tek Komutla Otomatik Dağıtım (1-Click Deployment)

Dağıtım betikleri, ortam gereksinimlerini otomatik denetler, oturumu doğrular, yönetici nesne kimliğini tespit eder ve Bicep şablonunu konuşlandırır.

### Yöntem 1: PowerShell ile Tek Komut Dağıtım (Önerilen)

```powershell
# Azure klasörüne geçin
cd "KocSistemMSSPPortal\Azure"

# Varsayılan PoC / MCT Dağıtımı (Kaynak Grubu: rg-kocsistem-mssp-poc, Bölge: westeurope)
.\Deploy-ToAzure.ps1

# Özel Kaynak Grubu, Bölge ve Abonelik ile Dağıtım:
.\Deploy-ToAzure.ps1 -ResourceGroupName "rg-kocsistem-mssp-prod" -Location "westeurope" -EnvironmentType "prod" -SubscriptionId "<Abonelik-ID>"
```

### Yöntem 2: Bash / Azure Cloud Shell ile Tek Komut Dağıtım

```bash
# Betiğe çalıştırma izni verin ve başlatın
chmod +x deploy-to-azure.sh
./deploy-to-azure.sh -g rg-kocsistem-mssp-poc -l westeurope -e poc

# Kurumsal Prod Ortamı İçin:
./deploy-to-azure.sh -g rg-kocsistem-mssp-prod -l westeurope -e prod -s "<Abonelik-ID>"
```

### Yöntem 3: Doğrudan Azure CLI One-Liner (Komut Satırından Tek Satır)

Eğer betik çalıştırmadan doğrudan Azure CLI ile dağıtmak isterseniz:

```bash
# 1. Kaynak Grubu Oluşturun
az group create --name rg-kocsistem-mssp-poc --location westeurope

# 2. Bicep Dağıtımını Başlatın (Kullanıcı Object ID'si otomatik aktarılır)
az deployment group create \
  --resource-group rg-kocsistem-mssp-poc \
  --template-file main.bicep \
  --parameters prefix="kocsistem-mssp" environmentType="poc" adminPrincipalId="$(az ad signed-in-user show --query id -o tsv)"
```

---

## 4. Müşteri Secret ve Sertifikalarını Key Vault'a Yükleme

Dağıtım tamamlandıktan sonra çıktı olarak verilen Key Vault adı (örn: `kocsistem-mssp-abc123sa-kv`) üzerine müşteri kimlik bilgileri şu komutlarla eklenir:

### A. Müşteri Client Secret Ekleme
```bash
# Anadolu Finans A.Ş. için Client Secret tanımlama
az keyvault secret set \
  --vault-name "<KeyVault-Adi>" \
  --name "AnadoluFinans-ClientSecret" \
  --value "Müşteri-EntraID-Secret-Değeri"
```

### B. Müşteri Özel Sertifikası (PFX / Certificate-Based Auth) Ekleme
```bash
# Kurumsal PFX sertifikasını Key Vault'a yükleme
az keyvault certificate import \
  --vault-name "<KeyVault-Adi>" \
  --name "BosphorusLogistics-Cert" \
  --file "C:\Sertifikalar\Bosphorus-Auth.pfx" \
  --password "PfxParolasi"
```

Portaldaki `Data/tenants.json` veya arayüz üzerindeki müşteri düzenleme ekranında:
- `Auth.Method`: `Secret` veya `Certificate`
- `Auth.KeyVaultSecretName`: Key Vault'ta verdiğiniz ad (örn: `AnadoluFinans-ClientSecret`)
yazıldığında platform otomatik olarak Managed Identity ile bu sırrı güvenli şekilde çözer.

---

## 5. Dağıtım Sonrası Doğrulama Adımları

Dağıtım tamamlandıktan sonra sistemin sağlıklı çalıştığını doğrulamak için:

1. **Sağlık Kontrolü Uç Noktası**:
   Tarayıcınızda veya terminalde:
   ```bash
   curl -i https://<ContainerApp-FQDN>/api/health
   ```
   Dönen yanıt: `{"status": "Healthy", "version": "2.0.0"}`
2. **Managed Identity RBAC Doğrulaması**:
   Azure CLI ile Container App'e atanan rolleri denetleyin:
   ```bash
   az role assignment list --assignee <containerAppPrincipalId> --all -o table
   ```
   Çıktıda şu roller görülmelidir:
   - `Key Vault Secrets User` (Key Vault kapsamında)
   - `Key Vault Certificate User` (Key Vault kapsamında)
   - `Storage Blob Data Contributor` (Storage Account kapsamında)
3. **Log Analytics İzleme**:
   Azure Portal -> Container Apps -> **Log Stream** veya **Logs** sekmesinden çalışan PowerShell ve Python servislerinin canlı çıktılarını izleyebilirsiniz.

---

## 6. Test Ortamından KoçSistem Kurumsal Ortamına (Production) Taşıma

1. **Abonelik & Kaynak Grubu Değişikliği**:
   `Deploy-ToAzure.ps1 -EnvironmentType "prod" -ResourceGroupName "rg-kocsistem-mssp-prod" -SubscriptionId "<KocSistem-Kurumsal-ID>"`
2. **Özel Alan Adı (Custom Domain) & SSL**:
   Container Apps -> **Custom domains** menüsünden `mssp.kocsistem.com.tr` alan adı eklenir. Azure'un sunduğu ücretsiz yönetilen sertifika (Managed Certificate) ile SSL otomatik bağlanır.
3. **Kurumsal Entra ID SSO / MFA Entegrasyonu**:
   Portal kimlik doğrulama katmanına KoçSistem Entra ID Enterprise App eklenerek şirket personeli dışındaki erişimler koşullu erişim (Conditional Access) ilkeleriyle engellenir.
