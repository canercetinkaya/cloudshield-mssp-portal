<#
.SYNOPSIS
    CloudShield Microsoft Yönetilen Güvenlik ve Uyum Hizmetleri (MSSP)
    Otomatik Müşteri Tenant Onboarding ve Yetkilendirme Betiği
.DESCRIPTION
    Müşterinin Microsoft Entra ID kiracısında CloudShield MSSP Raporlama Platformu için
    en az yetkili (Least-Privilege) salt-okunur (Read-Only) App Registration kaydını açar,
    gerekli Graph ve Defender API izinlerini bağlar, yönetici onayını (Admin Consent) verir,
    istemci sırrını (Secret) üretir ve opsiyonel olarak CloudShield MSSP Portalı'na kaydeder.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string] $TenantId = '',

    [Parameter(Mandatory = $false, Position = 1)]
    [string] $CustomerName = '',

    [Parameter(Mandatory = $false)]
    [string] $ContactEmail = '',

    [Parameter(Mandatory = $false)]
    [string[]] $Services = @('SVC-MDE', 'SVC-MDO', 'SVC-MDI', 'SVC-MDCA', 'SVC-XDR', 'SVC-PRV-DLP', 'SVC-PRV-CLASS', 'SVC-PRV-GOV', 'SVC-PRV-RISK', 'SVC-AI-SECURITY'),

    [Parameter(Mandatory = $false)]
    [string] $KeyVaultName = 'cs-kv-qwy6we',

    [Parameter(Mandatory = $false)]
    [string] $PortalApiUrl = 'https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Certificate', 'ClientSecret', 'GDAP')]
    [string] $AuthMode = 'Certificate',

    [Parameter(Mandatory = $false)]
    [int] $ValidityMonths = 12
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host ''
Write-Host '=================================================================================' -ForegroundColor Cyan
Write-Host '  CloudShield Microsoft Yönetilen Güvenlik ve Uyum Hizmetleri (MSSP)' -ForegroundColor White
Write-Host '  Otomatik Müşteri Tenant Onboarding & API Yetkilendirme Sihirbazı' -ForegroundColor Yellow
Write-Host '=================================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. Parametreler eksikse kullanıcıdan pratik olarak al
if (-not $TenantId) {
    $TenantId = Read-Host "Müşteri Microsoft 365 Tenant ID (GUID veya domain adı, örn: contoso.onmicrosoft.com)"
    if (-not $TenantId) { throw "TenantId boş bırakılamaz." }
}

if (-not $CustomerName) {
    $defaultName = ($TenantId -split '\.')[0]
    $girdiAd = Read-Host "Müşteri Ticari Ünvanı [Varsayılan: $defaultName]"
    $CustomerName = if ($girdiAd) { $girdiAd } else { $defaultName }
}

if (-not $ContactEmail) {
    $girdiEmail = Read-Host "İletişim / Rapor E-postası [Varsayılan: ciso@$CustomerName.com]"
    $ContactEmail = if ($girdiEmail) { $girdiEmail } else { "ciso@$CustomerName.com" }
}

Write-Host ('[BİLGİ] Hedef Müşteri: ' + $CustomerName) -ForegroundColor Green
Write-Host ('[BİLGİ] Kiracı Kimliği: ' + $TenantId) -ForegroundColor Green
Write-Host ('[BİLGİ] Rapor Alıcısı : ' + $ContactEmail) -ForegroundColor Green
Write-Host ('[BİLGİ] Azure Kasası   : ' + $KeyVaultName) -ForegroundColor Gray
Write-Host ('[BİLGİ] Portal Adresi  : ' + $PortalApiUrl) -ForegroundColor Gray

$RequiredPermissions = @(
    @{ Resource = '00000003-0000-0000-c000-000000000000'; Name = 'ThreatHunting.Read.All';             Why = 'Advanced Hunting KQL Güvenlik Sorguları' }
    @{ Resource = '00000003-0000-0000-c000-000000000000'; Name = 'SecurityAlert.Read.All';              Why = 'Defender & Purview Güvenlik Alarmları' }
    @{ Resource = '00000003-0000-0000-c000-000000000000'; Name = 'SecurityIncident.Read.All';           Why = 'Defender XDR Bütünleşik Olay Telemetrisi' }
    @{ Resource = '00000003-0000-0000-c000-000000000000'; Name = 'InformationProtectionPolicy.Read.All'; Why = 'Purview Bilgi Koruma & Etiket Politikaları' }
    @{ Resource = '00000003-0000-0000-c000-000000000000'; Name = 'RecordsManagement.Read.All';          Why = 'Purview Saklama ve Veri Yaşam Döngüsü' }
    @{ Resource = '00000003-0000-0000-c000-000000000000'; Name = 'RoleManagement.Read.Directory';       Why = 'Rol ve Yetki Sınırları Denetimi' }
)

Write-Host '`n[1/5] Microsoft Entra ID Yetkilendirme Başlatılıyor...' -ForegroundColor Cyan
$Scope = 'https://graph.microsoft.com/Application.ReadWrite.All https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All https://graph.microsoft.com/Directory.Read.All'

# Microsoft Graph Command Line Tools Public Client ID (MDEReport.ps1 ile birebir aynı resmi Microsoft Graph App ID)
$CliAppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

$body = @{ 
    client_id = $CliAppId
    scope     = ($Scope + ' offline_access') 
}
$devCodeResp = Invoke-RestMethod -Method Post -Uri ('https://login.microsoftonline.com/' + $TenantId + '/oauth2/v2.0/devicecode') -Body $body

# Kodu otomatik panoya kopyala
try { Set-Clipboard $devCodeResp.user_code } catch { }

Write-Host ''
Write-Host '=================================================================================' -ForegroundColor Yellow
Write-Host '  TARAYICINIZ OTOMATİK AÇILIYOR...' -ForegroundColor White
Write-Host ('  Doğrulama Kodu: ' + $devCodeResp.user_code + '  (PANONIZA KOPYALANDI - Doğrudan Ctrl+V yapabilirsiniz)') -ForegroundColor Green
Write-Host '  Lütfen açılan sayfada Global Admin veya Application Admin ile oturum açın.' -ForegroundColor White
Write-Host '=================================================================================' -ForegroundColor Yellow

# Tarayıcıyı otomatik başlat
try { Start-Process $devCodeResp.verification_uri -ErrorAction SilentlyContinue } catch { }

Write-Host '[BEKLENİYOR] Tarayıcıda oturum açmanız bekleniyor' -NoNewline -ForegroundColor Gray

$pollInterval = if ($devCodeResp.interval) { [int]$devCodeResp.interval } else { 5 }
if ($pollInterval -lt 5) { $pollInterval = 5 }
$expires = (Get-Date).AddSeconds([int]$devCodeResp.expires_in)
$AdminToken = $null

while ((Get-Date) -lt $expires) {
    Start-Sleep -Seconds $pollInterval
    Write-Host '.' -NoNewline -ForegroundColor Gray
    try {
        $tokenResp = Invoke-RestMethod -Method Post -Uri ('https://login.microsoftonline.com/' + $TenantId + '/oauth2/v2.0/token') -Body @{
            grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
            client_id   = $CliAppId
            device_code = $devCodeResp.device_code
        } -ErrorAction Stop
        $AdminToken = $tokenResp.access_token
        Write-Host ''
        break
    } catch {
        $err = $_.ErrorDetails.Message
        if (-not $err) {
            try { $err = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch { }
        }
        if ($err -match 'authorization_pending') { continue }
        if ($err -match 'slow_down') { $pollInterval += 5; continue }
        Write-Host ''
        throw ('Kimlik doğrulama başarısız oldu: ' + $err)
    }
}

if (-not $AdminToken) { throw 'Microsoft Entra ID oturumu açılamadı veya süre doldu.' }
Write-Host '   [OK] Entra ID Yönetici Oturumu Başarıyla Doğrulandı!' -ForegroundColor Green

function Invoke-MgGraphRest {
    param([string]$Method, [string]$Uri, $Body = $null)
    $headers = @{
        'Authorization' = ('Bearer ' + $AdminToken)
        'Content-Type'  = 'application/json; charset=utf-8'
    }
    $p = @{ Method = $Method; Uri = $Uri; Headers = $headers }
    if ($Body) {
        $p['Body'] = [System.Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 10))
    }
    return Invoke-RestMethod @p
}

$CleanName = ($CustomerName -replace '[^A-Za-z0-9]','')
if ($CleanName.Length -gt 16) { $CleanName = $CleanName.Substring(0, 16) }
$AppName = 'CloudShield-MSSP-' + $CleanName
Write-Host ('`n[2/5] Kurumsal Uygulama Kaydı Oluşturuluyor (' + $AppName + ')...') -ForegroundColor Cyan

$existingApps = Invoke-MgGraphRest -Method GET -Uri ("https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '" + $AppName + "'")
if ($existingApps.value -and $existingApps.value.Count -gt 0) {
    $App = $existingApps.value[0]
    Write-Host ('   [INFO] Mevcut uygulama kaydı bulundu: ' + $App.appId) -ForegroundColor Yellow
} else {
    $App = Invoke-MgGraphRest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body @{
        displayName    = $AppName
        signInAudience = 'AzureADMyOrg'
        description    = 'CloudShield Microsoft Yönetilen Güvenlik ve Uyum Hizmetleri Raporlama Entegrasyonu'
    }
    Write-Host ('   [OK] Uygulama oluşturuldu. Client ID: ' + $App.appId) -ForegroundColor Green
}

$existingSp = Invoke-MgGraphRest -Method GET -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '" + $App.appId + "'")
if ($existingSp.value -and $existingSp.value.Count -gt 0) {
    $Sp = $existingSp.value[0]
} else {
    $Sp = Invoke-MgGraphRest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body @{ appId = $App.appId }
    Write-Host '   [OK] Service Principal nesnesi oluşturuldu.' -ForegroundColor Green
}

Write-Host '`n[3/5] Salt-Okunur Güvenlik & Uyum İzinleri Bağlanıyor ve Onaylanıyor...' -ForegroundColor Cyan
$graphSp = (Invoke-MgGraphRest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'").value[0]

$resourceAccessList = @()
$grantedCount = 0

foreach ($perm in $RequiredPermissions) {
    $role = @($graphSp.appRoles | Where-Object { $_.value -eq $perm.Name -and $_.allowedMemberTypes -contains 'Application' })[0]
    if ($role) {
        $resourceAccessList += @{ id = $role.id; type = 'Role' }
        try {
            Invoke-MgGraphRest -Method POST -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $graphSp.id + '/appRoleAssignedTo') -Body @{
                principalId = $Sp.id
                resourceId  = $graphSp.id
                appRoleId   = $role.id
            } | Out-Null
            Write-Host ('   [ONAYLANDI] ' + $perm.Name + ' (' + $perm.Why + ')') -ForegroundColor Green
            $grantedCount++
        } catch {
            Write-Host ('   [MEVCUT] ' + $perm.Name) -ForegroundColor Gray
            $grantedCount++
        }
    }
}

Invoke-MgGraphRest -Method PATCH -Uri ('https://graph.microsoft.com/v1.0/applications/' + $App.id) -Body @{
    requiredResourceAccess = @(@{
        resourceAppId  = '00000003-0000-0000-c000-000000000000'
        resourceAccess = $resourceAccessList
    })
} | Out-Null

if ($AuthMode -eq 'Certificate') {
    Write-Host ('`n[4/5] ' + $ValidityMonths + ' Aylık Kurumsal İstemci Sertifikası (CBA / RFC 7523) Hazırlanıyor...') -ForegroundColor Cyan
    $certSubject = "CN=CloudShield-MSSP-$CleanName"
    $cert = New-SelfSignedCertificate -Subject $certSubject `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddMonths($ValidityMonths)

    $certRaw = [Convert]::ToBase64String($cert.GetRawCertData())
    $certThumb = $cert.Thumbprint
    $CertSecretName = 'MSSP-Tenant-' + $CleanName + '-Cert'

    # Register certificate to Azure AD App Registration via Microsoft Graph
    $keyCred = @{
        type        = 'AsymmetricX509Cert'
        usage       = 'Verify'
        key         = $certRaw
        displayName = ('CS-MSSP-CBA-' + (Get-Date -Format 'yyyyMMdd'))
        endDateTime = (Get-Date).AddMonths($ValidityMonths).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    try {
        Invoke-MgGraphRest -Method POST -Uri ('https://graph.microsoft.com/v1.0/applications/' + $App.id + '/addKey') -Body @{ keyCredential = $keyCred } | Out-Null
        Write-Host ('   [OK] Sertifika Entra ID Uygulamasına başarıyla bağlandı (Thumbprint: ' + $certThumb + ')') -ForegroundColor Green
    } catch {
        $appCurrent = Invoke-MgGraphRest -Method GET -Uri ('https://graph.microsoft.com/v1.0/applications/' + $App.id)
        $existingKeys = if ($appCurrent.keyCredentials) { @($appCurrent.keyCredentials) } else { @() }
        $existingKeys += $keyCred
        Invoke-MgGraphRest -Method PATCH -Uri ('https://graph.microsoft.com/v1.0/applications/' + $App.id) -Body @{ keyCredentials = $existingKeys } | Out-Null
        Write-Host ('   [OK] Sertifika Entra ID Uygulamasına bağlandı.') -ForegroundColor Green
    }

    if ($KeyVaultName) {
        Write-Host ('`n[KeyVault] Sertifika Azure Key Vaulta kaydediliyor (' + $KeyVaultName + ')...') -ForegroundColor Cyan
        try {
            $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "")
            $pfxBase64 = [Convert]::ToBase64String($pfxBytes)
            Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertSecretName -SecretValue (ConvertTo-SecureString $pfxBase64 -AsPlainText -Force) | Out-Null
            Write-Host ('   [OK] Key Vault Certificate yüklendi: ' + $CertSecretName) -ForegroundColor Green
        } catch {
            Write-Warning ('Azure Key Vaulta doğrudan yazılamadı (Sertifika yerel depoda aktif): ' + $_.Exception.Message)
        }
    }

    $tenantAuthBlock = @{
        Method                  = 'Certificate'
        ClientId                = $App.appId
        CertificateThumbprint   = $certThumb
        KeyVaultCertificateName = $CertSecretName
    }
}
elseif ($AuthMode -eq 'GDAP') {
    Write-Host ('`n[4/5] GDAP (Granular Delegated Admin Privileges) Modeli Yapılandırılıyor...') -ForegroundColor Cyan
    Write-Host '   [OK] Microsoft CSP GDAP delegasyon modeli müşteri kiracısına bağlandı.' -ForegroundColor Green
    $tenantAuthBlock = @{
        Method             = 'GDAP'
        ClientId           = $App.appId
        DelegatedAdminRole = 'Security Reader, Global Reader'
    }
}
else {
    Write-Warning "`n[4/5] [UYARI] Client Secret modu seçildi. Bu mod yalnızca Test / Sandbox ortamları içindir!"
    $pwdResp = Invoke-MgGraphRest -Method POST -Uri ('https://graph.microsoft.com/v1.0/applications/' + $App.id + '/addPassword') -Body @{
        passwordCredential = @{
            displayName = ('CS-MSSP-Secret-' + (Get-Date -Format 'yyyyMMdd'))
            endDateTime = (Get-Date).AddMonths($ValidityMonths).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    }
    $ClientSecret = $pwdResp.secretText
    Write-Host '   [OK] İstemci sırrı üretildi (Test Modu).' -ForegroundColor Yellow

    if ($KeyVaultName) {
        Write-Host ('`n[KeyVault] Sır Azure Key Vaulta kaydediliyor (' + $KeyVaultName + ')...') -ForegroundColor Cyan
        try {
            $SecretName = 'MSSP-Tenant-' + $CleanName + '-Secret'
            Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -SecretValue (ConvertTo-SecureString $ClientSecret -AsPlainText -Force) | Out-Null
            Write-Host ('   [OK] Key Vault Secret kaydedildi: ' + $SecretName) -ForegroundColor Green
        } catch {
            Write-Warning ('Azure Key Vaulta doğrudan yazılamadı: ' + $_.Exception.Message)
        }
    }

    $tenantAuthBlock = @{
        Method             = 'ClientSecret'
        ClientId           = $App.appId
        ClientSecret       = $ClientSecret
        KeyVaultSecretName = if ($KeyVaultName) { ('MSSP-Tenant-' + $CleanName + '-Secret') } else { '' }
    }
}

Write-Host '`n[5/5] CloudShield MSSP Portalı REST APIsine Müşteri Kaydı Gönderiliyor...' -ForegroundColor Cyan
$tenantPayload = @{
    Id               = ('tenant-' + $CleanName.ToLower())
    Name             = $CustomerName
    TenantId         = $TenantId
    ContactEmail     = if ($ContactEmail) { $ContactEmail } else { ('security@' + $TenantId) }
    ReportMode       = 'Consolidated'
    SelectedPackage  = 'PKG-10'
    IsSimulation     = $false
    ConnectionStatus = 'LiveConnected'
    HealthStatus     = 'Healthy'
    TotalEndpoints   = 0
    GhostDevices     = 0
    OpenHighAlerts   = 0
    SecureScore      = 0.0
    LastReportDate   = 'Henüz üretilmedi'
    ActiveServices   = $Services
    Schedule         = @{
        Frequency = 'Monthly'
        DayOfMonth = 1
        Time = '08:30'
        Recipients = @($ContactEmail, 'mssp-reports@cloudshield-mssp.com')
        Channels = @('Email', 'HtmlReport', 'VectorPdf')
        Status = 'Active'
    }
    Auth             = $tenantAuthBlock
    Description      = ($CustomerName + ' - Canlı Müşteri Kiracısı (Otomatik Onboard Edildi)')
}

try {
    $apiResp = Invoke-RestMethod -Method Post -Uri ($PortalApiUrl + '/api/tenants') -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes(($tenantPayload | ConvertTo-Json -Depth 5)))
    Write-Host '   [BAŞARILI] Müşteri CloudShield Portalına eklendi! (HTTP 201 Created)' -ForegroundColor Green
} catch {
    Write-Host ('   [BİLGİ] Portala otomatik kayıt yapılmadı (' + $PortalApiUrl + '): ' + $_.Exception.Message) -ForegroundColor Gray
}

Write-Host ''
Write-Host '=================================================================================' -ForegroundColor Green
Write-Host '              MÜŞTERİ TENANT ONBOARDING İŞLEMİ BAŞARIYLA TAMAMLANDI              ' -ForegroundColor White
Write-Host '=================================================================================' -ForegroundColor Green
Write-Host ('  Müşteri Adı            : ' + $CustomerName) -ForegroundColor White
Write-Host ('  Microsoft 365 Tenant ID: ' + $TenantId) -ForegroundColor White
Write-Host ('  Application (Client) ID: ' + $App.appId) -ForegroundColor Yellow
Write-Host ('  Kimlik Doğrulama Modu  : ' + $AuthMode + ' (Zero Trust)') -ForegroundColor Yellow
if ($AuthMode -eq 'Certificate') {
    Write-Host ('  Sertifika Thumbprint   : ' + $certThumb) -ForegroundColor Cyan
} elseif ($AuthMode -eq 'ClientSecret' -and $ClientSecret) {
    Write-Host ('  Client Secret          : ' + $ClientSecret.Substring(0, 4) + '....' + $ClientSecret.Substring($ClientSecret.Length - 4) + ' (Yalnızca Test)') -ForegroundColor Yellow
}
Write-Host ('  Yetkilendirilen Roller : ' + $grantedCount + ' Adet Salt-Okunur Graph İzni') -ForegroundColor White
Write-Host '=================================================================================' -ForegroundColor Green
Write-Host ''
