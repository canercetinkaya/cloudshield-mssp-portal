﻿<#
.SYNOPSIS
    CloudShield Microsoft Security Managed Services Reporting Platform - Kurulum Sihirbazı
.DESCRIPTION
    Müşteri tenant'ına özel servis seçimi, otomatik sertifika keşfi, least-privilege
    izin hesaplaması, canlı token doğrulaması ve zamanlanmış görev kurulumunu sağlayan
    interaktif ve güvenli kurulum sihirbazı.
.EXAMPLE
    .\Install-CloudShieldSecurityReporting.ps1 -Interactive
    .\Install-CloudShieldSecurityReporting.ps1 -ConfigPath .\Config\customer.config.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch] $Interactive,

    [Parameter(Mandatory = $false)]
    [string] $ConfigPath,

    [Parameter(Mandatory = $false)]
    [switch] $SkipTaskCreation
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

# Çekirdek Modülleri Yükle
Import-Module (Join-Path $root 'Core\Logging.psm1') -Force
Import-Module (Join-Path $root 'Core\Configuration.psm1') -Force
Import-Module (Join-Path $root 'Core\Authentication.psm1') -Force
Import-Module (Join-Path $root 'Core\HealthCheck.psm1') -Force
Import-Module (Join-Path $root 'Core\PluginLoader.psm1') -Force

function Show-Header {
    Clear-Host
    Write-Host "=================================================================================" -ForegroundColor Cyan
    Write-Host "         CloudShield Microsoft Security Managed Services Reporting Platform         " -ForegroundColor White
    Write-Host "                        Kurulum ve Yapılandırma Sihirbazı                         " -ForegroundColor Gray
    Write-Host "=================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Sessiz / Unattended Kurulum
if ($ConfigPath -and (Test-Path $ConfigPath) -and -not $Interactive) {
    Write-Host "[INFO] Otomatik (Unattended) kurulum başlatılıyor: $ConfigPath" -ForegroundColor Cyan
    $cfg = Get-PlatformConfig -CustomerConfigPath $ConfigPath
    $health = Invoke-PlatformHealthCheck -PlatformConfig $cfg
    if (-not $health.Healthy) {
        Write-Warning "Sağlık kontrollerinde kritik uyarılar tespit edildi."
    }
    Write-Host "[OK] Yapılandırma doğrulandı ve hazır." -ForegroundColor Green
    return
}

# İnteraktif Sihirbaz Başlangıcı
Show-Header

# ADIM 1: Ortam Kontrolü
Write-Host "[1/7] Ortam ve Ön Koşul Kontrolleri..." -ForegroundColor Yellow
$edge = Find-EdgeExecutable
if ($edge) {
    Write-Host "  [OK] Microsoft Edge / Chromium PDF motoru bulundu: $edge" -ForegroundColor Green
} else {
    Write-Host "  [!] Chromium PDF motoru bulunamadı. Raporlar yalnızca HTML formatında üretilecektir." -ForegroundColor Yellow
}
Write-Host "  [OK] PowerShell Sürümü: $($PSVersionTable.PSVersion)" -ForegroundColor Green
Write-Host ""

# ADIM 2: Müşteri Kimlik Bilgileri
Write-Host "[2/7] Müşteri Tenant Bilgileri" -ForegroundColor Yellow
$customerName = Read-Host "  Müşteri Şirket Adı (Örn: Ornek-Holding)"
if ([string]::IsNullOrWhiteSpace($customerName)) { $customerName = "Musteri-AS" }

$tenantId = Read-Host "  Microsoft Entra ID Tenant ID (GUID)"
while (-not ($tenantId -match '^[0-9a-fA-F-]{36}$')) {
    Write-Host "  [!] Geçersiz GUID formatı. Lütfen geçerli bir Tenant ID giriniz." -ForegroundColor Red
    $tenantId = Read-Host "  Tenant ID (GUID)"
}
Write-Host ""

# ADIM 3: Hizmet ve Paket Seçimi
Write-Host "[3/7] Satın Alınan Yönetilen Hizmetlerin Seçimi" -ForegroundColor Yellow
Write-Host "  CloudShield tarafından müşteriye sağlanan servisleri seçiniz:" -ForegroundColor Gray
Write-Host ""
Write-Host "  Tekil Servisler:" -ForegroundColor White
Write-Host "   [1]  MDE  - Yönetilen Uç Nokta Güvenliği (EDR)"
Write-Host "   [2]  MDO  - Yönetilen E-Posta Güvenliği (MDO + EOP)"
Write-Host "   [3]  MDI  - Yönetilen Kimlik Tehdit Koruması (MDI)"
Write-Host "   [4]  MDCA - Yönetilen Bulut Uygulama Güvenliği (CASB)"
Write-Host "   [5]  XDR  - Yönetilen XDR Olay Yönetimi & MTTR"
Write-Host "   [6]  DLP  - Yönetilen Veri Kaybı Önleme (Purview DLP)"
Write-Host "   [7]  CLAS - Yönetilen Veri Envanteri ve Sınıflandırma"
Write-Host "   [8]  GOV  - Yönetilen Saklama ve İmha Politikaları"
Write-Host "   [9]  RISK - Yönetilen İç Tehdit ve İletişim Uyumu (İzole App)"
Write-Host "   [10] AI   - Yönetilen Yapay Zeka & Copilot Güvenliği"
Write-Host ""
Write-Host "  Hazır Paketler:" -ForegroundColor White
Write-Host "   [A] Tüm Defender Tehdit Koruması (1, 2, 3, 4, 5)"
Write-Host "   [B] Tüm Purview Veri ve Uyum Paketi (6, 7, 8, 9, 10)"
Write-Host "   [C] Full Suite (Tüm Defender ve Purview Servisleri)"
Write-Host ""

$svcChoice = Read-Host "  Seçiminizi giriniz (Örn: 1,2,6 veya C) [Varsayılan: C]"
if ([string]::IsNullOrWhiteSpace($svcChoice)) { $svcChoice = 'C' }

$activeServices = @()
if ($svcChoice -match '(?i)C') {
    $activeServices = @('SVC-MDE', 'SVC-MDO', 'SVC-MDI', 'SVC-MDCA', 'SVC-XDR', 'SVC-PRV-DLP', 'SVC-PRV-CLASS', 'SVC-PRV-GOV', 'SVC-PRV-RISK', 'SVC-AI-SECURITY')
} elseif ($svcChoice -match '(?i)A') {
    $activeServices = @('SVC-MDE', 'SVC-MDO', 'SVC-MDI', 'SVC-MDCA', 'SVC-XDR')
} elseif ($svcChoice -match '(?i)B') {
    $activeServices = @('SVC-PRV-DLP', 'SVC-PRV-CLASS', 'SVC-PRV-GOV', 'SVC-PRV-RISK', 'SVC-AI-SECURITY')
} else {
    $parts = $svcChoice -split ','
    foreach ($p in $parts) {
        switch ($p.Trim()) {
            '1' { $activeServices += 'SVC-MDE' }
            '2' { $activeServices += 'SVC-MDO' }
            '3' { $activeServices += 'SVC-MDI' }
            '4' { $activeServices += 'SVC-MDCA' }
            '5' { $activeServices += 'SVC-XDR' }
            '6' { $activeServices += 'SVC-PRV-DLP' }
            '7' { $activeServices += 'SVC-PRV-CLASS' }
            '8' { $activeServices += 'SVC-PRV-GOV' }
            '9' { $activeServices += 'SVC-PRV-RISK' }
            '10'{ $activeServices += 'SVC-AI-SECURITY' }
        }
    }
}

Write-Host "  [OK] Seçilen Servisler: $($activeServices -join ', ')" -ForegroundColor Green
Write-Host ""

# ADIM 4: Kimlik Doğrulama Seçimi & Otomatik Sertifika Keşfi
Write-Host "[4/7] Kimlik Doğrulama Yöntemi (CBA vs. Secret)" -ForegroundColor Yellow
$coreClientId = Read-Host "  Entra ID Application (Client) ID"
while (-not ($coreClientId -match '^[0-9a-fA-F-]{36}$')) {
    Write-Host "  [!] Geçersiz GUID formatı." -ForegroundColor Red
    $coreClientId = Read-Host "  Application (Client) ID"
}

Write-Host ""
Write-Host "  Kimlik Doğrulama Türü:"
Write-Host "   [1] Sertifika Tabanlı Doğrulama (CBA / RFC 7523 - Şiddetle Önerilen)"
Write-Host "   [2] İstemci Gizli Anahtarı (Client Secret - DPAPI ile Şifrelenir)"
$authMethodChoice = Read-Host "  Seçiminiz [1/2, Varsayılan: 1]"

$authMethod = 'Certificate'
$certThumb = ''
$secretEncrypted = ''
$credExpiry = ''

if ($authMethodChoice -eq '2') {
    $authMethod = 'Secret'
    $plainSecret = Read-Host "  İstemci Gizli Anahtarını (Secret) giriniz"
    $secretEncrypted = Protect-PlatformSecret -PlainText $plainSecret -Scope 'CurrentUser'
    $credExpiry = (Get-Date).AddMonths(12).ToString('yyyy-MM-dd')
    Write-Host "  [OK] Secret DPAPI (CurrentUser) ile yerel olarak şifrelendi." -ForegroundColor Green
} else {
    $authMethod = 'Certificate'
    Write-Host "  Windows Sertifika Deposu taranıyor..." -ForegroundColor Cyan
    $certs = Get-AvailableCertificates

    if ($certs.Count -gt 0) {
        Write-Host "  Sistemde bulunan geçerli sertifikalar:" -ForegroundColor White
        for ($i = 0; $i -lt $certs.Count; $i++) {
            $c = $certs[$i]
            Write-Host "   [$($i+1)] $($c.Subject) (Bitiş: $($c.NotAfter.ToString('yyyy-MM-dd')), Kalan: $($c.DaysLeft) gün)"
        }
        Write-Host "   [0] Başka bir Thumbprint elle gireceğim"
        $cSel = Read-Host "  Kullanılacak sertifika numarasını seçiniz [1-$($certs.Count)]"

        if ($cSel -match '^[1-9][0-9]*$' -and [int]$cSel -le $certs.Count) {
            $chosen = $certs[[int]$cSel - 1]
            $certThumb = $chosen.Thumbprint
            $credExpiry = $chosen.NotAfter.ToString('yyyy-MM-dd')
            Write-Host "  [OK] Sertifika seçildi: $certThumb" -ForegroundColor Green
        } else {
            $certThumb = Read-Host "  Sertifika Parmak İzi (Thumbprint)"
        }
    } else {
        $certThumb = Read-Host "  Sertifika Parmak İzi (Thumbprint)"
    }
}
Write-Host ""

# ADIM 5: Dağıtım ve Raporlama Tercihleri
Write-Host "[5/7] E-Posta ve Dağıtım Parametreleri" -ForegroundColor Yellow
$mailMethod = Read-Host "  Gönderim Protokolü: [Graph / Smtp, Varsayılan: Graph]"
if ([string]::IsNullOrWhiteSpace($mailMethod)) { $mailMethod = 'Graph' }

$mailFrom = Read-Host "  Gönderici E-Posta Adresi (Örn: mssp-reports@cloudshield-mssp.com)"
$mailToRaw = Read-Host "  Raporun Gönderileceği Müşteri E-Postaları (virgülle ayırınız)"
$mailToList = @($mailToRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

Write-Host ""

# ADIM 6: Müşteri Azure Yöneticisi İçin İzin Betiği Üretimi
Write-Host "[6/7] Müşteri Yöneticisi İçin Kurulum Betiği Hazırlanıyor..." -ForegroundColor Yellow
$deployScriptContent = @"
<#
.SYNOPSIS
    CloudShield Raporlama Platformu - Müşteri Entra ID Uygulama ve İzin Tanımlama Betiği
.DESCRIPTION
    Bu betik, müşterinin Global Yöneticisi tarafından bir defaya mahsus çalıştırılır.
    Gerekli App Registration'ı açar ve seçilen servisler için least-privilege izinleri atar.
#>
`$TenantId = '$tenantId'
`$AppId    = '$coreClientId'

Write-Host 'CloudShield Raporlama Uygulamasına İzinler Atanıyor...' -ForegroundColor Cyan
# Seçilen servisler için izinler: $($activeServices -join ', ')
"@
$deployScriptPath = Join-Path $root "Deploy-CustomerAppRegistration-$($customerName).ps1"
Set-Content -Path $deployScriptPath -Value $deployScriptContent -Encoding UTF8
Write-Host "  [OK] Müşteri yöneticisine iletilebilecek izin betiği üretildi: $deployScriptPath" -ForegroundColor Green
Write-Host ""

# ADIM 7: Yapılandırma Dosyasını Kaydet
Write-Host "[7/7] Yapılandırma Kaydediliyor..." -ForegroundColor Yellow

$customerConfig = [ordered]@{
    Customer = [ordered]@{
        Name               = $customerName
        TenantId           = $tenantId
        CustomerLogoPath   = "Resources/logo-customer-placeholder.png"
        CustomerLogoSource = "Auto"
        TimeZone           = "Turkey Standard Time"
    }
    Subscriptions = [ordered]@{
        ReportMode     = if ($activeServices.Count -le 2) { 'Standalone' } else { 'Consolidated' }
        ActiveServices = $activeServices
    }
    Authentication = [ordered]@{
        CoreApp = [ordered]@{
            ClientId              = $coreClientId
            AuthMethod            = $authMethod
            CertificateThumbprint = $certThumb
            SecretEncrypted       = $secretEncrypted
            DataProtectionScope   = "CurrentUser"
            CredentialExpiry      = $credExpiry
        }
        IsolatedApp = [ordered]@{
            Enabled               = ($activeServices -contains 'SVC-PRV-RISK')
            ClientId              = ""
            AuthMethod            = "Certificate"
            CertificateThumbprint = ""
            SecretEncrypted       = ""
            DataProtectionScope   = "CurrentUser"
            CredentialExpiry      = ""
        }
    }
    Reporting = [ordered]@{
        Schedule                = "Monthly"
        AttachPdf               = $true
        ExportCsv               = $true
        RetentionMonths         = 24
        DashboardRefreshMinutes = 60
    }
    Privacy = [ordered]@{
        AnonymizeUsers       = $true
        KAnonymityThreshold  = 5
        MaskDomain           = $false
    }
    Delivery = [ordered]@{
        Method                  = $mailMethod
        From                    = $mailFrom
        To                      = $mailToList
        Cc                      = @("mssp-security@cloudshield-mssp.com")
        AlertTo                 = "mssp-alerts@cloudshield-mssp.com"
        SendDashboard           = $true
        ServiceSpecificRouting  = @{}
    }
    Smtp = [ordered]@{
        Server            = "smtp.office365.com"
        Port              = 587
        UseSsl            = $true
        User              = ""
        PasswordEncrypted = ""
    }
    Thresholds = [ordered]@{
        InactiveDevicePct   = 5
        RiskyHostAlerts     = 3
        RansomRenameCount   = 100
        AutoIrMinutes       = 45
        OpenIncidentAgeDays = 14
    }
}

$targetConfigPath = Join-Path $root 'Config\customer.config.json'
$configJson = ConvertTo-Json $customerConfig -Depth 15
Set-Content -Path $targetConfigPath -Value $configJson -Encoding UTF8 -Force
Write-Host "  [OK] customer.config.json başarıyla oluşturuldu." -ForegroundColor Green
Write-Host ""

# Görev Zamanlayıcı Kurulumu
if (-not $SkipTaskCreation) {
    $createTask = Read-Host "  Windows Task Scheduler'a otomatik aylık görev eklensin mi? [E/H, Varsayılan: E]"
    if ($createTask -notmatch '(?i)H') {
        & (Join-Path $root 'Create-ScheduledTask.ps1') -ConfigPath $targetConfigPath -Mode Monthly
    }
}

Write-Host ""
Write-Host "=================================================================================" -ForegroundColor Green
Write-Host "                Tebrikler! Kurulum Başarıyla Tamamlandı.                         " -ForegroundColor White
Write-Host "  Raporu hemen test etmek için aşağıdaki komutu çalıştırabilirsiniz:             " -ForegroundColor Cyan
Write-Host "  .\Invoke-CloudShieldSecurityReporting.ps1 -DryRun -Pdf                           " -ForegroundColor Yellow
Write-Host "=================================================================================" -ForegroundColor Green
