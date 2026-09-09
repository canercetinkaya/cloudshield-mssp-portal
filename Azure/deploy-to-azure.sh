#!/usr/bin/env bash
# ==============================================================================
# KoçSistem Managed Security Operations & Reporting Platform (MSSP Portal)
# Azure Otomatik Dağıtım Betiği (Azure CLI / Bash / Azure Cloud Shell)
# ==============================================================================

set -e

RESOURCE_GROUP="rg-kocsistem-mssp-poc"
LOCATION="westeurope"
SUBSCRIPTION_ID=""
PREFIX="kocsistem-mssp"
ENVIRONMENT="poc"
ADMIN_PRINCIPAL_ID=""

while getopts "g:l:s:p:e:a:h" opt; do
  case $opt in
    g) RESOURCE_GROUP="$OPTARG" ;;
    l) LOCATION="$OPTARG" ;;
    s) SUBSCRIPTION_ID="$OPTARG" ;;
    p) PREFIX="$OPTARG" ;;
    e) ENVIRONMENT="$OPTARG" ;;
    a) ADMIN_PRINCIPAL_ID="$OPTARG" ;;
    h)
      echo "Kullanım: ./deploy-to-azure.sh [-g resource-group] [-l location] [-s subscription-id] [-p prefix] [-e env] [-a admin-id]"
      exit 0
      ;;
    \?)
      echo "Geçersiz parametre: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BICEP_FILE="$SCRIPT_DIR/main.bicep"

echo ""
echo "================================================================================"
echo "  KoçSistem MSSP Platformu - Azure Bulut Kurulum Sihirbazı (Azure CLI)"
echo "  Sunucusuz (Serverless ACA), Key Vault RBAC & Passwordless Zero-Trust"
echo "================================================================================"
echo ""

# 1. Azure CLI Kontrolü
if ! command -v az &> /dev/null; then
    echo "[HATA] Azure CLI (az) bulunamadı! Lütfen Azure CLI kurunuz veya bu betiği shell.azure.com üzerinde çalıştırınız."
    exit 1
fi

# 2. Azure Oturum & Abonelik Kontrolü
echo "[1/5] Azure oturumu doğrulanıyor..."
ACCOUNT_JSON=$(az account show --output json 2>/dev/null || echo "")
if [ -z "$ACCOUNT_JSON" ]; then
    echo "  -> Azure oturumu başlatılıyor..."
    az login --output none
    ACCOUNT_JSON=$(az account show --output json)
fi

if [ -n "$SUBSCRIPTION_ID" ]; then
    echo "  -> Abonelik değiştiriliyor: $SUBSCRIPTION_ID"
    az account set --subscription "$SUBSCRIPTION_ID"
    ACCOUNT_JSON=$(az account show --output json)
fi

ACTIVE_SUB_NAME=$(echo "$ACCOUNT_JSON" | grep -o '"name": *"[^"]*"' | head -1 | cut -d'"' -f4)
ACTIVE_SUB_ID=$(echo "$ACCOUNT_JSON" | grep -o '"id": *"[^"]*"' | head -1 | cut -d'"' -f4)
echo "  [OK] Aktif Abonelik: $ACTIVE_SUB_NAME ($ACTIVE_SUB_ID)"

# Yönetici Object ID tespiti
if [ -z "$ADMIN_PRINCIPAL_ID" ]; then
    ADMIN_PRINCIPAL_ID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")
fi

if [ -n "$ADMIN_PRINCIPAL_ID" ]; then
    echo "  [OK] Yönetici Object ID: $ADMIN_PRINCIPAL_ID (Key Vault Administrator rolü atanacak)"
fi

# 3. Kaynak Grubu Doğrulama
echo "[2/5] Kaynak Grubu doğrulanıyor ($RESOURCE_GROUP - $LOCATION)..."
RG_EXISTS=$(az group exists --name "$RESOURCE_GROUP")
if [ "$RG_EXISTS" != "true" ]; then
    echo "  -> Kaynak grubu oluşturuluyor: $RESOURCE_GROUP"
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
fi
echo "  [OK] Kaynak Grubu hazır."

# 4. Resource Providers Kaydı
echo "[3/5] Azure Resource Provider kayıtları kontrol ediliyor..."
PROVIDERS=("Microsoft.App" "Microsoft.OperationalInsights" "Microsoft.KeyVault" "Microsoft.Storage")
for p in "${PROVIDERS[@]}"; do
    az provider register --namespace "$p" --wait 2>/dev/null || true
done
echo "  [OK] Resource Provider kayıtları aktif."

# 5. Bicep Dağıtımı
echo "[4/5] Altyapı şablonu (main.bicep) Azure ortamına konuşlandırılıyor..."
echo "  (Container Apps Environment, Storage, Key Vault ve RBAC rol atamaları oluşturuluyor...)"

DEPLOYMENT_NAME="mssp-deploy-$(date +%Y%m%d%H%M%S)"
CLI_PARAMS=("prefix=$PREFIX" "environmentType=$ENVIRONMENT")

if [ -n "$ADMIN_PRINCIPAL_ID" ]; then
    CLI_PARAMS+=("adminPrincipalId=$ADMIN_PRINCIPAL_ID")
fi

DEPLOY_OUTPUT=$(az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$BICEP_FILE" \
    --parameters "${CLI_PARAMS[@]}" \
    --name "$DEPLOYMENT_NAME" \
    --output json)

PORTAL_URL=$(echo "$DEPLOY_OUTPUT" | grep -o '"portalUrl": *{[^}]*"value": *"[^"]*"' | grep -o '"value": *"[^"]*"' | cut -d'"' -f4)
STORAGE_NAME=$(echo "$DEPLOY_OUTPUT" | grep -o '"storageAccountName": *{[^}]*"value": *"[^"]*"' | grep -o '"value": *"[^"]*"' | cut -d'"' -f4)
KV_URI=$(echo "$DEPLOY_OUTPUT" | grep -o '"keyVaultUri": *{[^}]*"value": *"[^"]*"' | grep -o '"value": *"[^"]*"' | cut -d'"' -f4)
KV_NAME=$(echo "$DEPLOY_OUTPUT" | grep -o '"keyVaultName": *{[^}]*"value": *"[^"]*"' | grep -o '"value": *"[^"]*"' | cut -d'"' -f4)
APP_NAME=$(echo "$DEPLOY_OUTPUT" | grep -o '"containerAppName": *{[^}]*"value": *"[^"]*"' | grep -o '"value": *"[^"]*"' | cut -d'"' -f4)
APP_IDENTITY=$(echo "$DEPLOY_OUTPUT" | grep -o '"containerAppPrincipalId": *{[^}]*"value": *"[^"]*"' | grep -o '"value": *"[^"]*"' | cut -d'"' -f4)

echo ""
echo "================================================================================"
echo "  TEBRİKLER! KOÇSİSTEM MSSP PLATFORMU AZURE ÜZERİNDE BAŞARIYLA YAYINLANDI!"
echo "================================================================================"
echo ""
echo "  [+] Canlı Portal URL (HTTPS)      : $PORTAL_URL"
echo "  [+] Azure Key Vault URL           : $KV_URI"
echo "  [+] Key Vault Adı                 : $KV_NAME"
echo "  [+] Rapor Arşiv Deposu (Blob)     : $STORAGE_NAME"
echo "  [+] Container App Adı             : $APP_NAME"
echo "  [+] Container App Managed Identity: $APP_IDENTITY"
echo ""
echo "  Güvenlik & RBAC Doğrulaması:"
echo "  -> Key Vault Secrets User      : Managed Identity'e ATANDI (Okuma yetkisi)"
echo "  -> Key Vault Certificate User  : Managed Identity'e ATANDI (CBA sertifika yetkisi)"
echo "  -> Storage Blob Data Contrib   : Managed Identity'e ATANDI (Rapor yazma yetkisi)"
if [ -n "$ADMIN_PRINCIPAL_ID" ]; then
    echo "  -> Key Vault Administrator     : $ADMIN_PRINCIPAL_ID kullanıcısına ATANDI"
fi
echo ""
echo "  Müşteri Kiracısı Secret Ekleme (Örnek Komut):"
echo "  az keyvault secret set --vault-name '$KV_NAME' --name 'AnadoluFinans-Secret' --value '<Client-Secret>'"
echo ""
echo "  Maliyet Durumu: Sunucusuz (Min Replicas = 0)."
echo "  Trafik olmadığında $0 maliyetle sıfıra iner, MCT kredinizi harcamaz."
echo "================================================================================"
echo ""
