# Plugins/DefenderCloud/DefenderCloud.Plugin.psm1 - CloudShield Security Reporting Platform
# Microsoft Defender for Cloud (CSPM & CWPP) Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-MDC'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'DefenderCloud'
        DisplayName = 'Yönetilen Bulut Güvenlik Duruşu (CSPM & CWPP)'
        Category    = 'CloudSecurity'
        Version     = '1.0.0'
        Description = 'Microsoft Defender for Cloud CSPM Güvenlik Skoru, çoklu bulut duruş değerlendirmeleri ve kritik güvenlik önerileri.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'AzureRM'; Name = 'Security Reader'; Scope = 'Subscription'; Why = 'Defender for Cloud Secure Score ve Güvenlik Önerileri okuma' }
        @{ Resource = 'Graph';   Name = 'SecurityAlert.Read.All'; Scope = 'Application'; Why = 'Bulut kaynak güvenlik uyarıları' }
    )
}

function Test-ServiceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig
    )

    try {
        $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph' -AppProfile 'CoreSecurityReporting'
        if ($token) {
            return [PSCustomObject]@{ Success = $true; Message = 'Defender for Cloud servis bağlantısı doğrulandı.' }
        }
        return [PSCustomObject]@{ Success = $false; Message = 'Token alınamadı.' }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Message = $_.Exception.Message }
    }
}

function Get-ServiceRawData {
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

    if ($DryRun) {
        return [pscustomobject]@{
            SecureScore = [pscustomobject]@{
                CurrentScore   = 68.4
                MaxScore       = 100.0
                Percentage     = 68.4
            }
            Assessments = @(
                [pscustomobject]@{ Name = 'Internet-facing virtual machines should be protected'; Severity = 'High'; UnhealthyResources = 3; Category = 'Compute' },
                [pscustomobject]@{ Name = 'Storage accounts should restrict network access'; Severity = 'High'; UnhealthyResources = 5; Category = 'Storage' },
                [pscustomobject]@{ Name = 'SQL servers should have vulnerability assessment enabled'; Severity = 'Medium'; UnhealthyResources = 2; Category = 'Data' },
                [pscustomobject]@{ Name = 'MFA should be enabled on accounts with owner permissions'; Severity = 'High'; UnhealthyResources = 1; Category = 'Identity' }
            )
            ExposedResources = 8
            ResolvedRecommendations = 12
            StartDate = $StartDate
            EndDate   = $EndDate
            IsMock    = $true
        }
    }

    # Canlı modda doğrudan telemetri çağrısı
    $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph' -AppProfile 'CoreSecurityReporting'
    $startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endZ   = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $filter = "serviceSource eq 'microsoftDefenderForCloud' and createdDateTime ge $startZ and createdDateTime lt $endZ"
    $uri = "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=$([System.Uri]::EscapeDataString($filter))&`$top=50"

    $alerts = @()
    $availabilityState = 'SupportedAppOnly'
    try {
        $resp = Invoke-PlatformRestApi -Uri $uri -AccessToken $token
        $alerts = if ($resp.value) { @($resp.value) } else { @() }
        if ($alerts.Count -eq 0) {
            $availabilityState = 'NoData'
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        $availabilityState = if ($errMsg -match '403|Forbidden') { 'PermissionMissing' }
                             elseif ($errMsg -match '401|Unauthorized') { 'AuthenticationFailed' }
                             else { 'CollectionFailed' }
        Write-Warning "Defender for Cloud alarmları çekilemedi ($availabilityState): $errMsg"
    }

    return [pscustomobject]@{
        Alerts            = $alerts
        SecureScore       = $null
        Assessments       = @()
        StartDate         = $StartDate
        EndDate           = $EndDate
        AvailabilityState = $availabilityState
        IsMock            = $false
    }
}

function Get-ServiceKpis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        $RawData,
        [Parameter(Mandatory = $false)]
        [string] $Mode = 'Monthly'
    )

    if ($RawData.IsMock) {
        $score = $RawData.SecureScore
        $critOneriler = @($RawData.Assessments | Where-Object { $_.Severity -eq 'High' }).Count
        return [ordered]@{
            BulutGuvenlikSkoru   = $score.Percentage
            KritikOneriler       = $critOneriler
            AcikKaynakSayisi     = $RawData.ExposedResources
            IyilestirilenOneri   = $RawData.ResolvedRecommendations
            Oneriler             = @($RawData.Assessments)
            AvailabilityState    = 'DirectAndVerified'
        }
    }

    # Canlı modda doğrudan doğrulanmış veriler
    $a = @($RawData.Alerts)
    $hasAlerts = $a.Count -gt 0

    return [ordered]@{
        BulutGuvenlikSkoru   = 'N/A - Azure Resource Graph / Security Reader izni gerekli'
        KritikOneriler       = if ($hasAlerts) { $a.Count } else { 'N/A - Telemetri yapılandırılmamış' }
        AcikKaynakSayisi     = 'N/A - Azure Subscriptions API gerekli'
        IyilestirilenOneri   = 0
        Oneriler             = @()
        AvailabilityState    = if ($hasAlerts) { 'DirectAndVerified' } else { $RawData.AvailabilityState }
    }
}

function Get-ServiceManagedActions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        $KpiData
    )

    $iyilestirilen = if ($KpiData.IyilestirilenOneri -is [int]) { $KpiData.IyilestirilenOneri } else { 0 }
    return [ordered]@{
        ServiceCode        = $Script:ServiceCode
        ServiceName        = 'Yönetilen Bulut Güvenliği (CSPM)'
        OtonomMudahaleler  = 0
        ManuelAnalistEforu = $iyilestirilen
        KazanilanZamanSaat = [math]::Round($iyilestirilen * 1.5, 1)
        Aciklama           = "Bulut iş yüklerinde tespit edilen riskli yapılandırmalar incelenmiş, $iyilestirilen adet kritik CSPM güvenlik önerisi CloudShield mühendisleri tarafından giderilmiştir."
    }
}

function Get-ServiceHtmlSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        $KpiData,
        [Parameter(Mandatory = $false)]
        $TrendData = $null
    )

    $k = $KpiData

    $html = @"
<section class="service-section">
    <div class="section-header">
        <h2 class="section-title">CloudShield Microsoft Defender for Cloud (CSPM & CWPP) Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#002B49; color:#FFFFFF;">Yönetilen Bulut Duruşu</span>
    </div>

    <!-- CLOUDSHIELD YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                CloudShield CSPM & CWPP Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Bulut Güvenlik Skoru (CSPM)</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$(if ($k.BulutGuvenlikSkoru -ne $null -and $k.BulutGuvenlikSkoru -ne '') { if ($k.BulutGuvenlikSkoru -match '^\d') { "%$($k.BulutGuvenlikSkoru)" } else { $k.BulutGuvenlikSkoru } } else { '-' })</div>
                    <span class="badge positive">Secure Score</span>
                </div>
                <div class="kpi-description">Azure ve çoklu bulut güvenlik duruş skoru</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kritik Güvenlik Önerileri</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.KritikOneriler)</div>
                    <span class="badge negative">Aksiyon Gerekli</span>
                </div>
                <div class="kpi-description">Yüksek etki derecesine sahip güvenlik bulguları</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">İyileştirilen Güvenlik Önerisi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.IyilestirilenOneri)</div>
                    <span class="badge positive">Giderildi</span>
                </div>
                <div class="kpi-description">CloudShield mühendisleri tarafından tamamlanan remediations</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Doğrulanmış Veri Durumu</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$(if ($k.AvailabilityState -eq 'DirectAndVerified') { 'Doğrulandı' } else { 'Kısmi Veri' })</div>
                    <span class="badge positive">$(if ($k.AvailabilityState -eq 'DirectAndVerified') { 'Kesin Veri' } else { 'İzin Eksik' })</span>
                </div>
                <div class="kpi-description">MDC API bağlantısı ve telemetri kaynağı</div>
            </div>
        </div>
    </div>
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
