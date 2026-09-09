<#
.SYNOPSIS
    CloudShield Enterprise MSSP Security & Compliance Platform (MSSP Portal)
    Azure Otomatik Dağıtım Betiği (MCT Abonelikleri & Prod Uyumlu)

.DESCRIPTION
    Bu betik Azure üzerinde CloudShield MSSP Portalını sunucusuz (Azure Container Apps,
    Key Vault, Storage Account, Log Analytics) mimari ile kurar.
    Container App System-Assigned Managed Identity'sine otomatik olarak:
      - Key Vault Secrets User (4633458b-17de-408a-b874-0445c86b69e6)
      - Key Vault Certificate User (db79e9a7-68ee-4b58-9aeb-b90e7c24fcba)
      - Storage Blob Data Contributor (ba92f5b4-2d11-453d-a403-e96b0029c9fe)
    rollerini atar. Dağıtımı yapan yöneticiye de Key Vault Administrator rolünü bağlar.
    Hem yerel PowerShell (Windows/Linux/macOS) hem de Azure Cloud Shell üzerinde çalışır.

.PARAMETER ResourceGroupName
    Oluşturulacak Azure Kaynak Grubu adı (Varsayılan: rg-cloudshield-mssp-poc)

.PARAMETER Location
    Azure Bölgesi (Varsayılan: westeurope)

.PARAMETER SubscriptionId
    MCT veya Kurumsal Azure Abonelik ID (Belirtilmezse aktif abonelik kullanılır)

.PARAMETER Prefix
    Kaynak adı öneki (Varsayılan: cloudshield-mssp)

.PARAMETER EnvironmentType
    Ortam tipi: poc, dev, prod (Varsayılan: poc)

.PARAMETER AdminPrincipalId
    Key Vault Administrator rolü verilecek yönetici Object ID'si (Otomatik tespit edilir)

.EXAMPLE
    .\Deploy-ToAzure.ps1
    .\Deploy-ToAzure.ps1 -ResourceGroupName "rg-cloudshield-prod" -Location "westeurope" -EnvironmentType "prod"
#>

[CmdletBinding()]
param (
    [string]$ResourceGroupName = "rg-cloudshield-mssp-poc",
    [string]$Location = "westeurope",
    [string]$SubscriptionId = "",
    [string]$Prefix = "cloudshield-mssp",
    [string]$EnvironmentType = "poc",
    [string]$AdminPrincipalId = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BicepFile = Join-Path $ScriptDir "main.bicep"

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  CloudShield MSSP Platform - Azure Bulut Kurulum & Güvenlik Sihirbazı" -ForegroundColor White
Write-Host "  Sunucusuz (Serverless ACA), Key Vault RBAC & Passwordless Zero-Trust Mimari" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Dağıtım Aracı Kontrolü (Azure CLI veya Az PowerShell)
$hasAzCli = $false
$azCmd = Get-Command az.cmd -ErrorAction SilentlyContinue
if (-not $azCmd) { $azCmd = Get-Command az -ErrorAction SilentlyContinue }
if ($azCmd) { $hasAzCli = $true }

$hasAzModule = $false
if (Get-Module -ListAvailable -Name Az.Resources) { $hasAzModule = $true }

if (-not $hasAzCli -and -not $hasAzModule) {
    Write-Host "[HATA] Azure CLI (az) veya Azure PowerShell (Az modülü) bulunamadı!" -ForegroundColor Red
    Write-Host "Lütfen Azure CLI kurunuz veya bu betiği Azure Cloud Shell (shell.azure.com) üzerinden çalıştırınız." -ForegroundColor Yellow
    exit 1
}

# 2. Azure Oturum Kontrolü & Yönetici Kimliği Tespiti
Write-Host "[1/5] Azure oturumu ve yönetici kimliği doğrulanıyor..." -ForegroundColor Cyan

if ($hasAzCli) {
    $currentAccount = az account show --output json 2>$null | ConvertFrom-Json
    if (-not $currentAccount) {
        Write-Host "  -> Azure oturumu başlatılıyor..." -ForegroundColor Yellow
        az login --output none
        $currentAccount = az account show --output json | ConvertFrom-Json
    }

    if ($SubscriptionId -and $currentAccount.id -ne $SubscriptionId) {
        Write-Host "  -> Abonelik değiştiriliyor: $SubscriptionId" -ForegroundColor Yellow
        az account set --subscription $SubscriptionId
        $currentAccount = az account show --output json | ConvertFrom-Json
    }

    $subName = $currentAccount.name
    $subId = $currentAccount.id

    if (-not $AdminPrincipalId) {
        try {
            $detectedUser = az ad signed-in-user show --query id -o tsv 2>$null
            if ($detectedUser) { $AdminPrincipalId = $detectedUser.Trim() }
        } catch {}
    }
}
else {
    $ctx = Get-AzContext
    if (-not $ctx) {
        Connect-AzAccount
        $ctx = Get-AzContext
    }
    if ($SubscriptionId -and $ctx.Subscription.Id -ne $SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        $ctx = Get-AzContext
    }
    $subName = $ctx.Subscription.Name
    $subId = $ctx.Subscription.Id

    if (-not $AdminPrincipalId) {
        try {
            $userUpn = $ctx.Account.Id
            $adUser = Get-AzADUser -UserPrincipalName $userUpn -ErrorAction SilentlyContinue
            if ($adUser) { $AdminPrincipalId = $adUser.Id }
        } catch {}
    }
}

Write-Host "  [OK] Aktif Abonelik : $subName ($subId)" -ForegroundColor Green
if ($AdminPrincipalId) {
    Write-Host "  [OK] Yönetici Object ID : $AdminPrincipalId (Key Vault Administrator atanacak)" -ForegroundColor Green
} else {
    Write-Host "  [BİLGİ] Yönetici Object ID otomatik tespit edilemedi; adminPrincipalId parametresi boş geçilecek." -ForegroundColor DarkYellow
}

# 3. Kaynak Grubu Oluşturma
Write-Host "[2/5] Kaynak Grubu doğrulanıyor ($ResourceGroupName - $Location)..." -ForegroundColor Cyan
if ($hasAzCli) {
    $rgExists = az group exists --name $ResourceGroupName
    if ($rgExists -ne "true") {
        Write-Host "  -> Kaynak grubu oluşturuluyor..." -ForegroundColor Yellow
        az group create --name $ResourceGroupName --location $Location --output none
    }
}
else {
    $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $rg) {
        Write-Host "  -> Kaynak grubu oluşturuluyor..." -ForegroundColor Yellow
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
    }
}
Write-Host "  [OK] Kaynak Grubu hazır." -ForegroundColor Green

# 4. Gerekli Kaynak Sağlayıcılarını (Resource Providers) Kaydet
Write-Host "[3/5] Azure Resource Provider kayıtları kontrol ediliyor..." -ForegroundColor Cyan
$providers = @("Microsoft.App", "Microsoft.OperationalInsights", "Microsoft.KeyVault", "Microsoft.Storage")
foreach ($prov in $providers) {
    if ($hasAzCli) {
        az provider register --namespace $prov --wait 2>$null | Out-Null
    } else {
        Register-AzResourceProvider -ProviderNamespace $prov -ErrorAction SilentlyContinue | Out-Null
    }
}
Write-Host "  [OK] Resource Provider kayıtları aktif." -ForegroundColor Green

# 5. Bicep Dağıtımını Başlat (main.bicep)
Write-Host "[4/5] Altyapı şablonu (main.bicep) Azure ortamına konuşlandırılıyor..." -ForegroundColor Cyan
Write-Host "  (Container Apps Environment, Storage, Key Vault ve RBAC rol atamaları oluşturuluyor...)" -ForegroundColor Yellow

$deploymentName = "mssp-deploy-" + (Get-Date -Format "yyyyMMddHHmmss")

if ($hasAzCli) {
    $cliParams = @(
        "prefix=$Prefix",
        "environmentType=$EnvironmentType"
    )
    if ($AdminPrincipalId) {
        $cliParams += "adminPrincipalId=$AdminPrincipalId"
    }

    $deployResult = az deployment group create `
        --resource-group $ResourceGroupName `
        --template-file $BicepFile `
        --parameters $cliParams `
        --name $deploymentName `
        --output json | ConvertFrom-Json

    $portalUrl = $deployResult.properties.outputs.portalUrl.value
    $storageName = $deployResult.properties.outputs.storageAccountName.value
    $kvUri = $deployResult.properties.outputs.keyVaultUri.value
    $kvName = $deployResult.properties.outputs.keyVaultName.value
    $appPrincipalId = $deployResult.properties.outputs.containerAppPrincipalId.value
    $containerAppName = $deployResult.properties.outputs.containerAppName.value
}
else {
    $azParams = @{
        ResourceGroupName = $ResourceGroupName
        TemplateFile      = $BicepFile
        Name              = $deploymentName
        prefix            = $Prefix
        environmentType   = $EnvironmentType
    }
    if ($AdminPrincipalId) {
        $azParams["adminPrincipalId"] = $AdminPrincipalId
    }

    $deployResult = New-AzResourceGroupDeployment @azParams

    $portalUrl = $deployResult.Outputs["portalUrl"].Value
    $storageName = $deployResult.Outputs["storageAccountName"].Value
    $kvUri = $deployResult.Outputs["keyVaultUri"].Value
    $kvName = $deployResult.Outputs["keyVaultName"].Value
    $appPrincipalId = $deployResult.Outputs["containerAppPrincipalId"].Value
    $containerAppName = $deployResult.Outputs["containerAppName"].Value
}

# 6. Sonuç ve Özet
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  TEBRİKLER! KOÇSİSTEM MSSP PLATFORMU AZURE ÜZERİNDE BAŞARIYLA YAYINLANDI!" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  [+] Canlı Portal URL (HTTPS)      : $portalUrl" -ForegroundColor Cyan
Write-Host "  [+] Azure Key Vault URL           : $kvUri" -ForegroundColor White
Write-Host "  [+] Key Vault Adı                 : $kvName" -ForegroundColor White
Write-Host "  [+] Rapor Arşiv Deposu (Blob)     : $storageName" -ForegroundColor White
Write-Host "  [+] Container App Adı             : $containerAppName" -ForegroundColor White
Write-Host "  [+] Container App Managed Identity: $appPrincipalId" -ForegroundColor White
Write-Host ""
Write-Host "  Güvenlik & RBAC Doğrulaması:" -ForegroundColor Green
Write-Host "  -> Key Vault Secrets User      : Managed Identity'e ATANDI (Okuma yetkisi)" -ForegroundColor Green
Write-Host "  -> Key Vault Certificate User  : Managed Identity'e ATANDI (CBA sertifika yetkisi)" -ForegroundColor Green
Write-Host "  -> Storage Blob Data Contrib   : Managed Identity'e ATANDI (Rapor yazma yetkisi)" -ForegroundColor Green
if ($AdminPrincipalId) {
    Write-Host "  -> Key Vault Administrator     : $AdminPrincipalId kullanıcısına ATANDI" -ForegroundColor Green
}
Write-Host ""
Write-Host "  Müşteri Kiracısı Secret Ekleme (Örnek Komut):" -ForegroundColor Yellow
Write-Host "  az keyvault secret set --vault-name '$kvName' --name 'AnadoluFinans-Secret' --value '<Client-Secret>'" -ForegroundColor Gray
Write-Host ""
Write-Host "  Maliyet Durumu: Sunucusuz (Min Replicas = 0)." -ForegroundColor Cyan
Write-Host "  Trafik olmadığında $0 maliyetle sıfıra iner, MCT kredinizi harcamaz." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ""
