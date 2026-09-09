# Core/Configuration.psm1 - KoçSistem Security Reporting Platform
# Configuration management, DPAPI secret encryption/decryption, validation.
[CmdletBinding()]
param()

Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

$Script:RootPath = Split-Path -Parent $PSScriptRoot

function Protect-PlatformSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $PlainText,
        [Parameter(Mandatory = $false)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string] $Scope = 'CurrentUser'
    )

    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $dataScope = if ($Scope -eq 'LocalMachine') {
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        } else {
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        }
        $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $dataScope)
        return [Convert]::ToBase64String($protectedBytes)
    }
    catch {
        throw "Secret DPAPI ile şifrelenemedi: $($_.Exception.Message)"
    }
}

function Unprotect-PlatformSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $EncryptedBase64,
        [Parameter(Mandatory = $false)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string] $Scope = 'CurrentUser'
    )

    if ([string]::IsNullOrWhiteSpace($EncryptedBase64)) {
        return ''
    }

    try {
        $bytes = [Convert]::FromBase64String($EncryptedBase64)
        $dataScope = if ($Scope -eq 'LocalMachine') {
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        } else {
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        }
        $unprotectedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, $dataScope)
        return [System.Text.Encoding]::UTF8.GetString($unprotectedBytes)
    }
    catch {
        # Fallback: Eğer CurrentUser ile açılamadıysa LocalMachine veya tersini dene
        try {
            $altScope = if ($Scope -eq 'LocalMachine') {
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            } else {
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            }
            $unprotectedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, $altScope)
            return [System.Text.Encoding]::UTF8.GetString($unprotectedBytes)
        }
        catch {
            throw "Secret DPAPI ile çözülemedi. Kurulumu yapan kullanıcı hesabı ile çalıştığından emin olun."
        }
    }
}

function Get-ServiceCatalog {
    [CmdletBinding()]
    param()

    $catalogPath = Join-Path $Script:RootPath 'Config\service-catalog.json'
    if (-not (Test-Path $catalogPath)) {
        throw "Servis kataloğu bulunamadı: $catalogPath"
    }

    $raw = Get-Content -Path $catalogPath -Raw -Encoding UTF8
    return ConvertFrom-Json $raw
}

function Get-PlatformConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $CustomerConfigPath
    )

    # 1. Global Config Yükleme
    $globalPath = Join-Path $Script:RootPath 'Config\global.config.json'
    if (-not (Test-Path $globalPath)) {
        $globalPath = Join-Path $Script:RootPath 'Config\global.config.template.json'
    }

    $globalConfig = $null
    if (Test-Path $globalPath) {
        $globalConfig = ConvertFrom-Json (Get-Content -Path $globalPath -Raw -Encoding UTF8)
    } else {
        throw "Global yapılandırma dosyası bulunamadı: $globalPath"
    }

    # 2. Customer Config Yükleme
    if (-not $CustomerConfigPath) {
        $CustomerConfigPath = Join-Path $Script:RootPath 'Config\customer.config.json'
        if (-not (Test-Path $CustomerConfigPath)) {
            $CustomerConfigPath = Join-Path $Script:RootPath 'Config\customer.config.template.json'
        }
    }

    if (-not (Test-Path $CustomerConfigPath)) {
        throw "Müşteri yapılandırma dosyası bulunamadı: $CustomerConfigPath"
    }

    $customerConfig = ConvertFrom-Json (Get-Content -Path $CustomerConfigPath -Raw -Encoding UTF8)

    # 3. Manuel Metrik Dosyasını Yükleme (Varsa)
    $manualMetricsPath = Join-Path $Script:RootPath 'ManualInput\customer-manual-metrics.json'
    if (-not (Test-Path $manualMetricsPath)) {
        $manualMetricsPath = Join-Path $Script:RootPath 'ManualInput\customer-manual-metrics.template.json'
    }

    $manualMetrics = $null
    if (Test-Path $manualMetricsPath) {
        try {
            $manualMetrics = ConvertFrom-Json (Get-Content -Path $manualMetricsPath -Raw -Encoding UTF8)
        }
        catch {}
    }

    # 4. Servis Kataloğu ile Doğrulama
    $catalog = Get-ServiceCatalog
    $activeServices = @()

    if ($customerConfig.Subscriptions.ActiveServices) {
        $activeServices = @($customerConfig.Subscriptions.ActiveServices)
    }
    elseif ($customerConfig.Subscriptions.SelectedPackage) {
        $pkgKey = $customerConfig.Subscriptions.SelectedPackage
        if ($catalog.Packages.PSObject.Properties[$pkgKey]) {
            $activeServices = @($catalog.Packages.$pkgKey.Services)
        }
    }

    return [PSCustomObject]@{
        GlobalConfig       = $globalConfig
        CustomerConfig     = $customerConfig
        ActiveServices     = $activeServices
        ServiceCatalog     = $catalog
        ManualMetrics      = $manualMetrics
        CustomerConfigPath = $CustomerConfigPath
        RootPath           = $Script:RootPath
    }
}

Export-ModuleMember -Function Protect-PlatformSecret, Unprotect-PlatformSecret, Get-ServiceCatalog, Get-PlatformConfig
