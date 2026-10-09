# Dağıtım ve Kurulum Kılavuzu (DEPLOYMENT.md)
## CloudShield Security Reporting & Managed Services Visibility Platform
**Güncel Sürüm:** `v3.1.0-REPORTING-VISIBILITY` (Build: 2026.10.09.1)  
**Hedef Ortam:** Azure Container Apps & On-Premises Docker / Kubernetes

---

### 1. Ön Gereksinimler

- **Docker:** Engine 24.0+ veya Docker Desktop
- **Python:** Python 3.11+ (Standart Kütüphane — sıfır zorunlu harici bağımlılık)
- **PowerShell:** PowerShell 7.4+ Core (Platformlar arası)
- **PDF Motoru:** Google Chrome veya Microsoft Edge (Vektörel PDF üretimi için)
- **Azure CLI:** `az` 2.50+ (`containerapp` eklentisi ile)

---

### 2. Yerel Container Dağıtımı

Uygulamayı Docker ile yerel ortamda çalıştırmak için:

```bash
# 1. Container imajını derleyin
docker build -t cloudshield-reporting-platform:3.1.0 -f Docker/Dockerfile .

# 2. Container'ı tek replika ve güvenli değişkenlerle başlatın
docker run -d -p 8080:8080 \
  --name cloudshield-app \
  -e PORT=8080 \
  -e ENVIRONMENT=production \
  -e MAX_REPLICAS=1 \
  -e CLOUDSHIELD_SESSION_SECRET=yerel-gelistirme-icin-guclu-gizli-anahtar-32karakter \
  cloudshield-reporting-platform:3.1.0

# 3. Sağlık durumunu doğrulayın
curl -f http://localhost:8080/api/health
```

Docker Compose ile başlatmak için:
```bash
docker compose -f Docker/docker-compose.yml up -d
```

---

### 3. Çevre Değişkenleri Kataloğu (Configuration Variables)

| Değişken Adı | Amaç | Zorunlu mu? | Güvenlik / Mimari Notu |
| :--- | :--- | :---: | :--- |
| `PORT` | Web sunucu dinleme portu | Opsiyonel (Varsayılan: `8080`) | Non-privileged port kullanılmalıdır. |
| `ENVIRONMENT` | Çalışma ortamı (`production` / `development`) | Zorunlu | `production` modunda yerel şifre ile giriş engellenir. |
| `MAX_REPLICAS` | Maksimum container replika sayısı | Zorunlu | SQLite WAL modu gereği **kesinlikle `1` olmalıdır**. |
| `CLOUDSHIELD_SESSION_SECRET` | Oturum çerezlerini imzalayan 256-bit anahtar | Zorunlu (Prod) | En az 32 karakter olmalı, Key Vault'tan beslenmelidir. |
| `ENTRA_CLIENT_ID` | Microsoft Entra ID Uygulama (Client) ID | Zorunlu (Prod) | OIDC SSO oturum açma akışı için gereklidir. |
| `ENTRA_TENANT_ID` | Platform yetkili Entra ID Kiracı ID | Zorunlu (Prod) | Token doğrulaması ve JWKS için kullanılır. |
| `KEY_VAULT_URL` | Azure Key Vault HTTPS adresi | Opsiyonel (Azure) | Managed Identity ile müşteri secret'larını okumak için. |
| `CLOUDSHIELD_ALLOW_LOCAL_AUTH` | Yerel parola girişini açma anahtarı | Opsiyonel (Varsayılan: `false`) | Yalnızca izole geliştirme ortamında `true` yapılmalıdır. |

---

### 4. Azure Container Apps Dağıtımı (Controlled Pilot)

Platform Azure üzerinde Bicep şablonu (`Azure/main.bicep`) ve minimal yetkili Managed Identity ile çalışır:

1. **Ölçekleme Kilidi:** `Azure/main.bicep` dosyasında `minReplicas: 1` ve `maxReplicas: 1` olarak ayarlanmıştır.
2. **Kayıt Defteri (Registry):** GitHub Container Registry (`ghcr.io/canercetinkaya/cloudshield-mssp-portal`) veya Azure Container Registry (ACR).
3. **Key Vault Yetkisi:** Container App Managed Identity'sine Key Vault üzerinde `Key Vault Secrets User` RBAC rolü verilir.

```bash
# Dağıtım sihirbazını çalıştırma
python Azure/deploy_aca.py
```

---

### 5. Geri Alım (Rollback) ve Kurtarma

Yeni bir container revizyonunda beklenmedik bir hata gözlemlendiğinde:
```bash
az containerapp revision activate \
  --name cloudshield-reporting-app \
  --resource-group rg-cloudshield-prod \
  --revision <onceki-calisan-revizyon>

az containerapp ingress traffic set \
  --name cloudshield-reporting-app \
  --resource-group rg-cloudshield-prod \
  --revision-weight <onceki-calisan-revizyon>=100
```
