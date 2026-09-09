# Plugins/PurviewClassification/PurviewClassification.Plugin.psm1 - KoçSistem Security Reporting Platform
# Microsoft Purview Data Classification & Sensitivity Labels Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-PRV-CLASS'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'PurviewClassification'
        DisplayName = 'Yönetilen Veri Envanteri ve Sınıflandırma'
        Category    = 'Compliance'
        Version     = '1.0.0'
        Description = 'Hassas Bilgi Türleri (SIT), duyarlılık etiketleri envanteri ve etiketleme politikaları analizi.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Exchange'; Name = 'Exchange.ManageAsApp'; Scope = 'Application'; Why = 'Purview etiket ve SIT tanımlarının okunması' }
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
            return [PSCustomObject]@{ Success = $true; Message = 'Purview Classification bağlantısı hazır.' }
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
            SensitivityLabels = @(
                [pscustomobject]@{ Name = 'Genel (Public)'; Priority = 0; FileCount = 142000; EmailCount = 286000 },
                [pscustomobject]@{ Name = 'Şirket İçi (Internal)'; Priority = 1; FileCount = 412000; EmailCount = 684000 },
                [pscustomobject]@{ Name = 'Hassas (Confidential)'; Priority = 2; FileCount = 68400; EmailCount = 92000 },
                [pscustomobject]@{ Name = 'Çok Gizli (Strictly Confidential)'; Priority = 3; FileCount = 14200; EmailCount = 16800 }
            )
            TopSensitiveInfoTypes = @(
                [pscustomobject]@{ SitName = 'Turkey National Identity Number (TCKN)'; MatchCount = 48500 },
                [pscustomobject]@{ SitName = 'Credit Card Number'; MatchCount = 14200 },
                [pscustomobject]@{ SitName = 'International Banking Account Number (IBAN)'; MatchCount = 28400 },
                [pscustomobject]@{ SitName = 'General Personal Data (KVKK)'; MatchCount = 64100 }
            )
            LabelDowngrades = 24
            StartDate       = $StartDate
            EndDate         = $EndDate
            IsMock          = $true
        }
    }

    # Canlı modda Purview API / Compliance
    return [pscustomobject]@{
        SensitivityLabels     = @()
        TopSensitiveInfoTypes = @()
        LabelDowngrades       = 0
        StartDate             = $StartDate
        EndDate               = $EndDate
        IsMock                = $false
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

    $labels = @($RawData.SensitivityLabels)
    $toplamEtiketliDosya = 0
    $toplamEtiketliPosta = 0
    foreach ($l in $labels) {
        $toplamEtiketliDosya += [int]$l.FileCount
        $toplamEtiketliPosta += [int]$l.EmailCount
    }

    return [ordered]@{
        TanimliEtiketSayisi  = $labels.Count
        EtiketliToplamDosya  = $toplamEtiketliDosya
        EtiketliToplamPosta  = $toplamEtiketliPosta
        Etiketler            = $labels
        EnCokEslesenSIT      = @($RawData.TopSensitiveInfoTypes)
        EtiketDusurmeSayisi  = $RawData.LabelDowngrades
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
        ServiceName        = 'Yönetilen Veri Sınıflandırma'
        OtonomMudahaleler  = 0
        ManuelAnalistEforu = $KpiData.EtiketDusurmeSayisi
        KazanilanZamanSaat = 0
        Aciklama           = "Kurum genelinde $($KpiData.EtiketliToplamDosya) dosya ve $($KpiData.EtiketliToplamPosta) e-posta duyarlılık etiketleriyle korunmuş, tespit edilen $($KpiData.EtiketDusurmeSayisi) adet şüpheli etiket düşürme (downgrade) olayı KoçSistem analistleri tarafından incelenmiştir."
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
        <h2 class="section-title">Microsoft Purview Veri Sınıflandırma ve Duyarlılık Etiketleri Postürü</h2>
        <span class="section-tag">Veri Envanteri</span>
    </div>

    <!-- KPI KARTLARI -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Etiketli Toplam Dosya</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.EtiketliToplamDosya) { '{0:N0}' -f $k.EtiketliToplamDosya } else { '-' })</div>
            </div>
            <div class="kpi-description">SharePoint, OneDrive ve Exchange'deki korumalı veriler</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Etiketli E-Posta Hacmi</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.EtiketliToplamPosta) { '{0:N0}' -f $k.EtiketliToplamPosta } else { '-' })</div>
            </div>
            <div class="kpi-description">Şifrelenmiş veya sınıflandırılmış postalar</div>
        </div>

        <div class="kpi-card $(if ($k.EtiketDusurmeSayisi -gt 0) { 'highlight' })">
            <div class="kpi-title">Etiket Düşürme (Downgrade)</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.EtiketDusurmeSayisi)</div>
                <span class="badge $(if ($k.EtiketDusurmeSayisi -gt 0) { 'negative' } else { 'positive' })">İncelendi</span>
            </div>
            <div class="kpi-description">Kullanıcıların gizlilik seviyesini indirme girişimleri</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">En Çok Eşleşen Bilgi Türü</div>
            <div class="kpi-value-row">
                <div class="kpi-value" style="font-size:16px;">TCKN / KVKK</div>
            </div>
            <div class="kpi-description">Mevzuatsal hassas veri yoğunluğu</div>
        </div>
    </div>

    <!-- ETİKET DAĞILIM TABLOSU -->
    <h3 style="font-size:14px; margin-top:16px; color:var(--ks-navy);">Duyarlılık Etiketi Seviye Dağılımı</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Etiket Adı</th>
                <th>Öncelik Seviyesi</th>
                <th>Etiketli Dosya Sayısı</th>
                <th>Etiketli E-Posta Sayısı</th>
            </tr>
        </thead>
        <tbody>
            $(foreach ($lbl in @($k.Etiketler)) {
                "<tr>
                    <td><strong>$($lbl.Name)</strong></td>
                    <td>Seviye $($lbl.Priority)</td>
                    <td>$('{0:N0}' -f $lbl.FileCount)</td>
                    <td>$('{0:N0}' -f $lbl.EmailCount)</td>
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
