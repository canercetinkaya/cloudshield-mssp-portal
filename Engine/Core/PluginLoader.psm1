﻿# Core/PluginLoader.psm1 - CloudShield Security Reporting Platform
# Dynamic plugin discovery, contract enforcement, and lifecycle orchestration.
[CmdletBinding()]
param()

$Script:RootPath = Split-Path -Parent $PSScriptRoot
$Script:LoadedPlugins = [ordered]@{}

$Script:MandatoryFunctions = @(
    'Get-ServiceMetadata',
    'Get-ServiceDependencies',
    'Get-ServicePermissions',
    'Test-ServiceConnection',
    'Get-ServiceRawData',
    'Get-ServiceKpis',
    'Get-ServiceHtmlSection',
    'Get-ServiceManagedActions'
)

function Get-RegisteredPlugins {
    [CmdletBinding()]
    param()

    $pluginsDir = Join-Path $Script:RootPath 'Plugins'
    if (-not (Test-Path $pluginsDir)) {
        return @()
    }

    $discovered = @()
    $pluginFolders = Get-ChildItem -Path $pluginsDir -Directory

    foreach ($folder in $pluginFolders) {
        $manifestPath = Join-Path $folder.FullName 'plugin.json'
        if (Test-Path $manifestPath) {
            try {
                $manifest = ConvertFrom-Json (Get-Content -Path $manifestPath -Raw -Encoding UTF8)
                $discovered += [PSCustomObject]@{
                    ServiceCode  = $manifest.ServiceCode
                    Name         = $manifest.Name
                    DisplayName  = $manifest.DisplayName
                    Category     = $manifest.Category
                    FolderPath   = $folder.FullName
                    Manifest     = $manifest
                    MainScript   = Join-Path $folder.FullName "$($folder.Name).Plugin.psm1"
                }
            }
            catch {
                Write-Warning "Plugin manifestosu yüklenemedi: $manifestPath ($($_.Exception.Message))"
            }
        }
    }
    return $discovered
}

function Import-ServicePlugin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $ServiceCode
    )

    if ($Script:LoadedPlugins.Contains($ServiceCode)) {
        return $Script:LoadedPlugins[$ServiceCode]
    }

    $all = Get-RegisteredPlugins
    $target = $all | Where-Object { $_.ServiceCode -eq $ServiceCode }

    if (-not $target) {
        throw "Servis eklentisi bulunamadı: $ServiceCode"
    }

    if (-not (Test-Path $target.MainScript)) {
        throw "Eklenti ana betiği bulunamadı: $($target.MainScript)"
    }

    # Modülü bellekten import et
    $mod = Import-Module -Name $target.MainScript -PassThru -Force -ErrorAction Stop

    # Sözleşme fonksiyonlarını doğrula
    $missingFuncs = @()
    foreach ($fn in $Script:MandatoryFunctions) {
        if (-not ($mod.ExportedFunctions.ContainsKey($fn))) {
            $missingFuncs += $fn
        }
    }

    if ($missingFuncs.Count -gt 0) {
        throw "Eklenti '$ServiceCode' standart arayüz sözleşmesini karşılamıyor. Eksik fonksiyonlar: $($missingFuncs -join ', ')"
    }

    $pluginInstance = [PSCustomObject]@{
        ServiceCode = $ServiceCode
        Metadata    = & $mod.ExportedFunctions['Get-ServiceMetadata'].ScriptBlock
        Module      = $mod
        Manifest    = $target.Manifest
        Folder      = $target.FolderPath
    }

    $Script:LoadedPlugins[$ServiceCode] = $pluginInstance
    return $pluginInstance
}

function Get-CombinedServicePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $ActiveServices
    )

    $allPerms = @()
    foreach ($svc in $ActiveServices) {
        try {
            $plugin = Import-ServicePlugin -ServiceCode $svc
            $perms = & $plugin.Module.ExportedFunctions['Get-ServicePermissions'].ScriptBlock
            if ($perms) {
                foreach ($p in $perms) {
                    $allPerms += [PSCustomObject]@{
                        ServiceCode = $svc
                        Resource    = $p.Resource
                        Name        = $p.Name
                        Scope       = $p.Scope
                        Why         = $p.Why
                    }
                }
            }
        }
        catch {
            # Henüz dosyası oluşturulmamış veya mock olan servisler
        }
    }
    return $allPerms
}

function Invoke-AllActiveCollectors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        [datetime] $StartDate,
        [Parameter(Mandatory = $true)]
        [datetime] $EndDate,
        [Parameter(Mandatory = $false)]
        [string] $Mode = 'Monthly',
        [Parameter(Mandatory = $false)]
        [switch] $DryRun
    )

    $results = [ordered]@{}
    foreach ($svcCode in $PlatformConfig.ActiveServices) {
        try {
            $plugin = Import-ServicePlugin -ServiceCode $svcCode
            $fn = $plugin.Module.ExportedFunctions['Get-ServiceRawData']
            
            $rawData = & $fn.ScriptBlock -PlatformConfig $PlatformConfig `
                                         -StartDate $StartDate `
                                         -EndDate $EndDate `
                                         -Mode $Mode `
                                         -DryRun:$DryRun

            $results[$svcCode] = $rawData
        }
        catch {
            Write-Warning "Kolektör çalıştırılamadı ($svcCode): $($_.Exception.Message)"
            $results[$svcCode] = $null
        }
    }
    return $results
}

function Invoke-AllActiveKpis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        $RawDataMap,
        [Parameter(Mandatory = $false)]
        [string] $Mode = 'Monthly'
    )

    $kpis = [ordered]@{}
    foreach ($svcCode in $PlatformConfig.ActiveServices) {
        try {
            $plugin = Import-ServicePlugin -ServiceCode $svcCode
            $fn = $plugin.Module.ExportedFunctions['Get-ServiceKpis']
            $svcRaw = if ($RawDataMap.Contains($svcCode)) { $RawDataMap[$svcCode] } else { $null }

            $kpiResult = & $fn.ScriptBlock -PlatformConfig $PlatformConfig `
                                          -RawData $svcRaw `
                                          -Mode $Mode

            $kpis[$svcCode] = $kpiResult
        }
        catch {
            Write-Warning "KPI üretilemedi ($svcCode): $($_.Exception.Message)"
            $kpis[$svcCode] = $null
        }
    }
    return $kpis
}

function Invoke-AllActiveHtmlSections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        $KpiMap,
        [Parameter(Mandatory = $false)]
        $TrendMap = $null
    )

    $sections = [ordered]@{}
    foreach ($svcCode in $PlatformConfig.ActiveServices) {
        try {
            $plugin = Import-ServicePlugin -ServiceCode $svcCode
            $fn = $plugin.Module.ExportedFunctions['Get-ServiceHtmlSection']
            $svcKpi = if ($KpiMap.Contains($svcCode)) { $KpiMap[$svcCode] } else { $null }
            $svcTrend = if ($TrendMap -and $TrendMap.Contains($svcCode)) { $TrendMap[$svcCode] } else { $null }

            $html = & $fn.ScriptBlock -PlatformConfig $PlatformConfig `
                                      -KpiData $svcKpi `
                                      -TrendData $svcTrend

            $sections[$svcCode] = $html
        }
        catch {
            Write-Warning "HTML bölümü üretilemedi ($svcCode): $($_.Exception.Message)"
            $sections[$svcCode] = "<div class='error-box'>Bölüm yüklenemedi: $svcCode</div>"
        }
    }
    return $sections
}

Export-ModuleMember -Function Get-RegisteredPlugins, Import-ServicePlugin, Get-CombinedServicePermissions, `
                              Invoke-AllActiveCollectors, Invoke-AllActiveKpis, Invoke-AllActiveHtmlSections