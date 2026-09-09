# Plugins/DefenderCloudApps/DefenderCloudApps.Plugin.psm1 - KoçSistem Security Reporting Platform
# Microsoft Defender for Cloud Apps (CASB) Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-MDCA'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'DefenderCloudApps'
        DisplayName = 'Yönetilen Bulut Uygulama Güvenliği (CASB)'
        Category    = 'CloudApp'
        Version     = '1.0.0'
        Description = 'Gölge BT keşfi, risk skorlaması, onaysız uygulama engellemeleri, OAuth app governance ve SaaS anomalileri.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Graph'; Name = 'SecurityAlert.Read.All'; Scope = 'Application'; Why = 'MDCA anomali ve uyarı telemetrisi' }
        @{ Resource = 'Graph'; Name = 'ThreatHunting.Read.All'; Scope = 'Application'; Why = 'CloudAppEvents KQL sorguları' }
        @{ Resource = 'Graph'; Name = 'Application.Read.All';   Scope = 'Application'; Why = 'OAuth uygulama izinleri ve risk analizi' }
    )
}

function Test-ServiceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig
    )

    try {
        $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph'
        if ($token) {
            return [PSCustomObject]@{ Success = $true; Message = 'Graph API MDCA bağlantısı başarılı.' }
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
            ShadowItDiscovery = [pscustomobject]@{
                TotalDiscoveredApps = 482
                HighRiskApps        = 34
                MediumRiskApps      = 112
                LowRiskApps         = 336
                SanctionedApps      = 86
                UnsanctionedBlocked = 28
            }
            TopRiskyUploadApps = @(
                [pscustomobject]@{ AppName = 'WeTransfer'; UploadGb = 42.4; UserCount = 18; RiskScore = 3; Status = 'Unsanctioned (Blocked)' },
                [pscustomobject]@{ AppName = 'Mega.nz'; UploadGb = 18.2; UserCount = 6; RiskScore = 2; Status = 'Unsanctioned (Blocked)' },
                [pscustomobject]@{ AppName = 'Anonfiles'; UploadGb = 6.8; UserCount = 3; RiskScore = 1; Status = 'Unsanctioned (Blocked)' },
                [pscustomobject]@{ AppName = 'Telegram Web'; UploadGb = 5.1; UserCount = 14; RiskScore = 4; Status = 'Monitored' }
            )
            OAuthAppGovernance = [pscustomobject]@{
                TotalOAuthApps        = 64
                HighPrivilegeApps     = 14
                SuspiciousConsentApps = 2
            }
            SaaSAnomalies = @(
                [pscustomobject]@{ AnomalyType = 'Impossible Travel Activity'; Count = 6; Severity = 'High' },
                [pscustomobject]@{ AnomalyType = 'Mass File Download (SaaS Exfiltration)'; Count = 3; Severity = 'High' },
                [pscustomobject]@{ AnomalyType = 'Unusual Multiple Failed Logons to SaaS'; Count = 18; Severity = 'Medium' }
            )
            StartDate = $StartDate
            EndDate   = $EndDate
            IsMock    = $true
        }
    }

    $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph'
    $startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endZ   = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $filter = "serviceSource eq 'microsoftDefenderForCloudApps' and createdDateTime ge $startZ and createdDateTime lt $endZ"
    $uri = "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=$([System.Uri]::EscapeDataString($filter))&`$top=50"

    $alerts = @()
    try {
        $resp = Invoke-PlatformRestApi -Uri $uri -AccessToken $token
        $alerts = @($resp.value)
    }
    catch {
        Write-Warning "MDCA alarmları çekilemedi: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Alerts    = $alerts
        StartDate = $StartDate
        EndDate   = $EndDate
        IsMock    = $false
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
        $sit = $RawData.ShadowItDiscovery
        $oauth = $RawData.OAuthAppGovernance

        return [ordered]@{
            ToplamKesfedilenUygulama = $sit.TotalDiscoveredApps
            YuksekRiskliUygulama     = $sit.HighRiskApps
            EngellenenOnaysizApp     = $sit.UnsanctionedBlocked
            OnayliKurumsalApp        = $sit.SanctionedApps
            EnRiskliYuklemeler       = @($RawData.TopRiskyUploadApps)
            YuksekYetkiliOAuth       = $oauth.HighPrivilegeApps
            SupheliOAuthApp          = $oauth.SuspiciousConsentApps
            SaaSAnomalileri          = @($RawData.SaaSAnomalies)
        }
    }

    $a = @($RawData.Alerts)
    return [ordered]@{
        ToplamKesfedilenUygulama = 0
        YuksekRiskliUygulama     = 0
        EngellenenOnaysizApp     = 0
        OnayliKurumsalApp        = 0
        EnRiskliYuklemeler       = @()
        YuksekYetkiliOAuth       = 0
        SupheliOAuthApp          = 0
        SaaSAnomalileri          = @()
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

    return [ordered]@{
        ServiceCode        = $Script:ServiceCode
        ServiceName        = 'Yönetilen Bulut Güvenliği (CASB)'
        OtonomMudahaleler  = $KpiData.EngellenenOnaysizApp
        ManuelAnalistEforu = $KpiData.YuksekRiskliUygulama + $KpiData.YuksekYetkiliOAuth
        KazanilanZamanSaat = [math]::Round(($KpiData.EngellenenOnaysizApp * 20) / 60.0, 1)
        Aciklama           = "Ağda tespit edilen $($KpiData.ToplamKesfedilenUygulama) bulut servisinden $($KpiData.EngellenenOnaysizApp) onaysız uygulama MDE üzerinden otonom engellenmiş, KoçSistem analistleri $($KpiData.YuksekRiskliUygulama) adet yüksek riskli servisi ve $($KpiData.YuksekYetkiliOAuth) adet yüksek yetkili OAuth uygulamasını güvenlik denetiminden geçirmiştir."
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
        <h2 class="section-title">KoçSistem Microsoft Defender for Cloud Apps (MDCA) Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#002B49; color:#FFFFFF;">Yönetilen Bulut Güvenliği</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                KoçSistem MDCA Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom Gölge BT Engeli</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.EngellenenOnaysizApp)</div>
                    <span class="badge positive">Otonom</span>
                </div>
                <div class="kpi-description">Uç noktalarda MDE üzerinden otonom engellenen yetkisiz SaaS uygulamaları</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">KoçSistem Bulut Uzman Eylemi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.YuksekRiskliUygulama + $k.YuksekYetkiliOAuth)</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">İncelenen yüksek riskli bulut servisleri ve yetkili OAuth izin denetimleri</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kuruma Kazandırılan Efor</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$([math]::Round(($k.EngellenenOnaysizApp * 20) / 60.0, 1)) Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">Gölge BT risk analizleri ve erişim kontrol politikaları ile kazanılan mesai</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Onaylı Bulut Hijyeni</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">%$([math]::Round((($k.OnayliKurumsalApp) / [math]::Max($k.ToplamKesfedilenUygulama, 1)) * 100, 1))</div>
                    <span class="badge positive">Uyumlu</span>
                </div>
                <div class="kpi-description">Kurumsal politika ile onaylanmış güvenli bulut servis oranı</div>
            </div>
        </div>
    </div>

    <!-- ÜRÜNE ÖZEL ÇEKİRDEK GÜVENLİK METRİKLERİ -->
    <div class="kpi-grid">
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Keşfedilen Gölge BT (Shadow IT)</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.ToplamKesfedilenUygulama)</div>
            </div>
            <div class="kpi-description">Ağda ve uç noktalarda tespit edilen SaaS servisleri</div>
        </div>

        <div class="kpi-card $(if ($k.YuksekRiskliUygulama -gt 0) { 'highlight' })">
            <div class="kpi-title">Yüksek Riskli Uygulama</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.YuksekRiskliUygulama)</div>
                <span class="badge negative">Risk Skoru: 0-3</span>
            </div>
            <div class="kpi-description">Güvenlik sertifikası olmayan servisler</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Engellenen Onaysız Servis</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.EngellenenOnaysizApp)</div>
                <span class="badge positive">Uç Noktada Bloklu</span>
            </div>
            <div class="kpi-description">MDE entegrasyonuyla erişimi kesilen servisler</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Yüksek Yetkili OAuth Apps</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.YuksekYetkiliOAuth)</div>
                <span class="badge $(if ($k.SupheliOAuthApp -gt 0) { 'negative' } else { 'neutral' })">$(if ($k.SupheliOAuthApp -gt 0) { "$($k.SupheliOAuthApp) Şüpheli" } else { 'Uyumlu' })</span>
            </div>
            <div class="kpi-description">Posta veya dosyalara tam erişim yetkisi olanlar</div>
        </div>
    </div>

    <!-- GÖLGE BT VERİ YÜKLEME TABLOSU -->
    <h3 style="font-size:14px; margin-top:16px; color:var(--ks-navy);">En Çok Veri Yüklenen Riskli ve Onaysız Bulut Depolama Alanları</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Uygulama Adı</th>
                <th>Toplam Yüklenen Veri</th>
                <th>Kullanan Kişi</th>
                <th>Risk Skoru</th>
                <th>Durum / Önlem</th>
            </tr>
        </thead>
        <tbody>
            $(foreach ($app in @($k.EnRiskliYuklemeler)) {
                "<tr>
                    <td><strong>$($app.AppName)</strong></td>
                    <td>$($app.UploadGb) GB</td>
                    <td>$($app.UserCount)</td>
                    <td><span class='badge negative'>$($app.RiskScore) / 10</span></td>
                    <td><span class='badge $(if ($app.Status -match 'Blocked') { 'positive' } else { 'neutral' })'>$($app.Status)</span></td>
                </tr>"
            })
        </tbody>
    </table>
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
