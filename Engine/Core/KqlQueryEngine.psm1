<#
.SYNOPSIS
    CloudShield Microsoft Security Reporting Platform - Advanced KQL & Hunting Query Engine
.DESCRIPTION
    Microsoft Defender XDR, Defender for Endpoint (MDE), Office (MDO), Identity (MDI),
    Cloud Apps (MDCA) ve Microsoft Purview için Microsoft Graph /security/runHuntingQuery
    üzerinden çalışan kurumsal KQL avlama sorgularını yönetir.
#>
[CmdletBinding()]
param()

function Invoke-GraphHuntingQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Query,

        [Parameter(Mandatory = $true)]
        [string] $AccessToken,

        [Parameter(Mandatory = $false)]
        [string] $QueryName = 'KqlQuery'
    )

    $uri = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery'
    $body = @{ Query = $Query } | ConvertTo-Json

    try {
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type'  = 'application/json; charset=utf-8'
        }
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
        return @{
            Success = $true
            Results = $resp.results
            Count   = if ($resp.results) { $resp.results.Count } else { 0 }
            Error   = ''
        }
    }
    catch {
        return @{
            Success = $false
            Results = @()
            Count   = 0
            Error   = $_.Exception.Message
        }
    }
}

function Get-StandardHuntQueries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime] $StartDate = (Get-Date).AddDays(-30),

        [Parameter(Mandatory = $false)]
        [datetime] $EndDate = (Get-Date)
    )

    $s = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $e = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $win = "| where Timestamp >= datetime($s) and Timestamp < datetime($e)"

    $queries = [ordered]@{}

    # 1. MDE - Antivirus Detections & Remediation
    $queries['AntivirusDetections'] = @"
DeviceEvents
$win
| where ActionType == "AntivirusDetection"
| extend AF = parse_json(AdditionalFields)
| extend Tehdit = tostring(AF.ThreatName), Temizlendi = tostring(AF.WasRemediated)
| summarize Adet = count(), Cihaz = dcount(DeviceId) by Tehdit, Temizlendi
| top 10 by Adet desc
"@

    # 2. MDE - Attack Surface Reduction (ASR) Rules
    $queries['AsrBreakdown'] = @"
DeviceEvents
$win
| where ActionType startswith "Asr"
| extend Mod = case(ActionType endswith "Blocked", "Blok",
                    ActionType endswith "Audited", "Denetim",
                    "Diger")
| extend Kural = replace_string(replace_string(ActionType, "Asr", ""), "Blocked", "")
| extend Kural = replace_string(Kural, "Audited", "")
| summarize Adet = count(), Cihaz = dcount(DeviceId) by Mod, Kural
| order by Adet desc
"@

    # 3. MDE - Web Protection & SmartScreen Blocks
    $queries['WebProtection'] = @"
DeviceEvents
$win
| where ActionType in ("SmartScreenUrlWarning","SmartScreenUserOverride","SmartScreenAppWarning","ExploitGuardNetworkProtectionBlocked")
| extend AF = parse_json(AdditionalFields)
| summarize Adet = count(), Cihaz = dcount(DeviceId) by ActionType, Deneyim = tostring(AF.Experience)
"@

    # 4. MDE - Ransomware Rapid File Renames
    $queries['RansomwareBehavior'] = @"
DeviceFileEvents
$win
| where ActionType == "FileRenamed"
| summarize Gunluk = count() by DeviceName, Gun = bin(Timestamp, 1d)
| where Gunluk > 100
| summarize Adet = count(), Toplam = sum(Gunluk) by DeviceName
"@

    # 5. MDE - Tampering & Defense Degradation Attempts
    $queries['TamperingAttempts'] = @"
DeviceEvents
$win
| where ActionType in~ ("TamperingAttempt", "AntivirusTroubleshootModeEvent", "SecurityLogCleared")
| extend Olay = case(ActionType =~ "TamperingAttempt", "Kurcalama girisimi",
                     ActionType =~ "AntivirusTroubleshootModeEvent", "Sorun giderme modu",
                     "Guvenlik gunlugu temizlendi")
| summarize Adet = count(), Cihaz = dcount(DeviceId) by Olay
"@

    # 6. MDE - Unonboarded Ghost Devices (Scope Gap)
    $queries['ScopeGaps'] = @"
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, OnboardingStatus, OSPlatform, DeviceType) by DeviceId
| summarize Cihaz = dcount(DeviceId) by OnboardingStatus, OSPlatform
| order by Cihaz desc
"@

    # 7. MDO - Email Phishing, Malware & ZAP Post-Delivery
    $queries['EmailThreats'] = @"
EmailEvents
$win
| where ThreatTypes has_any ("Phish", "Malware", "Spam")
| summarize Adet = count(), AliciSayisi = dcount(RecipientEmailAddress) by ThreatTypes, DeliveryAction
"@

    # 8. MDI - Active Directory & Identity Attacks (DCSync, Kerberoasting)
    $queries['IdentityAnomalies'] = @"
IdentityDirectoryEvents
$win
| where ActionType in ("DCSync", "Kerberoasting", "MassRecon", "SensitiveGroupMemberAddition")
| summarize Adet = count(), HedefSayisi = dcount(TargetDeviceName) by ActionType
"@

    # 9. MDCA - Shadow IT & Unsanctioned Cloud Apps
    $queries['ShadowItCloudApps'] = @"
CloudAppEvents
$win
| summarize Adet = count(), TekilKullanici = dcount(AccountDisplayName) by AppName
| top 10 by Adet desc
"@

    # 10. MITRE ATT&CK Techniques Distribution
    $queries['MitreAttackDistribution'] = @"
AlertInfo
$win
| where isnotempty(AttackTechniques)
| summarize arg_min(Timestamp, AttackTechniques, Severity) by AlertId
| mv-expand Teknik = todynamic(AttackTechniques) to typeof(string)
| where isnotempty(Teknik)
| summarize Adet = count() by Teknik
| top 10 by Adet desc
"@

    # 11. MDE - Tamper Protection Inactive Devices (Zero-Tolerance Security Risk)
    $queries['TamperProtectionStatus'] = @"
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, IsTamperProtected, OSPlatform, DeviceName) by DeviceId
| where IsTamperProtected == false or isempty(IsTamperProtected)
| project DeviceId, DeviceName, OSPlatform, TamperStatus = "Inactive"
| top 20 by DeviceName asc
"@

    # 12. MDE - Device Discovery Unmanaged Rogue Devices
    $queries['UnmanagedRogueDevices'] = @"
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, OnboardingStatus, DeviceName, IPAddresses, OSPlatform) by DeviceId
| where OnboardingStatus in ("CanBeOnboarded", "Unsupported", "InsufficientInfo")
| project DeviceId, DeviceName, OSPlatform, OnboardingStatus, IPAddresses
| top 50 by Timestamp desc
"@

    # 13. MDE - CISA Known Exploited Vulnerabilities (KEV) Top 5
    $queries['CisaKevTop5'] = @"
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where IsExploitAvailable == 1 or VulnerabilitySeverityLevel =~ "Critical"
| summarize AffectedDevices = dcount(DeviceId) by CveId, VulnerabilitySeverityLevel
| top 5 by AffectedDevices desc
"@

    # 14. MDE - Progressive Ghost Devices (7d, 14d, 30d+)
    $queries['ProgressiveGhostDevices'] = @"
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceId, DeviceName, OSPlatform
| extend InactivityDays = datetime_diff('day', now(), LastSeen)
| where InactivityDays >= 7
| extend Category = case(
    InactivityDays between (7 .. 14), "Warning_7_14d",
    InactivityDays between (15 .. 30), "Critical_14_30d",
    "Hygiene_30d_Plus"
)
| summarize DeviceCount = dcount(DeviceId) by Category
"@

    return $queries
}

function Get-KqlCatalogQueries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Service = '',

        [Parameter(Mandatory = $false)]
        [string] $Package = ''
    )

    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $indexPath = Join-Path $root 'Engine\KQL\query-metadata\catalog-index.json'

    if (-not (Test-Path $indexPath)) {
        return @()
    }

    try {
        $raw = Get-Content $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $items = @($raw)

        if (-not [string]::IsNullOrWhiteSpace($Service)) {
            $items = @($items | Where-Object { $_.service -eq $Service })
        }
        if (-not [string]::IsNullOrWhiteSpace($Package)) {
            $items = @($items | Where-Object { $_.package -eq $Package })
        }

        # QueryFile içeriklerini de yükle
        foreach ($item in $items) {
            if ($item.queryFile) {
                $fullQueryPath = Join-Path $root $item.queryFile
                if (Test-Path $fullQueryPath) {
                    $item | Add-Member -NotePropertyName 'kqlContent' -NotePropertyValue (Get-Content $fullQueryPath -Raw -Encoding UTF8) -Force
                }
            }
        }

        return $items
    }
    catch {
        Write-Warning "KQL Kataloğu okunamadı: $($_.Exception.Message)"
        return @()
    }
}

function Get-KqlQueryPackages {
    [CmdletBinding()]
    param()

    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $pkgDir = Join-Path $root 'Engine\KQL\query-packages'

    if (-not (Test-Path $pkgDir)) {
        return @()
    }

    $pkgFiles = Get-ChildItem -Path $pkgDir -Filter 'package.json' -Recurse
    $packages = @()

    foreach ($pf in $pkgFiles) {
        try {
            $p = Get-Content $pf.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $packages += $p
        }
        catch { }
    }

    return $packages
}

Export-ModuleMember -Function Invoke-GraphHuntingQuery, Get-StandardHuntQueries, Get-KqlCatalogQueries, Get-KqlQueryPackages
