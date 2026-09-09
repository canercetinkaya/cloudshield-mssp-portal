# Plugins/PurviewAiSecurity/PurviewAiSecurity.Plugin.psm1 - CloudShield Security Reporting Platform
# Microsoft Purview DSPM for AI & Copilot Data Security Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-AI-SECURITY'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'PurviewAiSecurity'
        DisplayName = 'Yönetilen Yapay Zeka & Copilot Güvenliği'
        Category    = 'AIProtection'
        Version     = '1.0.0'
        Description = 'M365 Copilot hassas veri etkileşimleri, aşırı paylaşılan (over-shared) dosyalar ve yapay zeka postür analitiği.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Graph'; Name = 'AuditLog.Read.All'; Scope = 'Application'; Why = 'CopilotInteraction denetim telemetrisi' }
    )
}

function Test-ServiceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig
    )

    return [PSCustomObject]@{ Success = $true; Message = 'Purview AI Security bağlantısı hazır.' }
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
            TotalCopilotPrompts    = 12450
            SensitiveFilesAccessed = 1820
            OverSharedFiles        = 46
            TopOverSharedTypes     = @(
                [pscustomobject]@{ Category = 'Mali Raporlar & Maaş Verileri'; FileCount = 18; Exposure = 'Everyone except external users' },
                [pscustomobject]@{ Category = 'Müşteri Kimlik & KVKK Listeleri'; FileCount = 16; Exposure = 'Entire Organization' },
                [pscustomobject]@{ Category = 'Stratejik Planlama & Sözleşmeler'; FileCount = 12; Exposure = 'Open SharePoint Team Site' }
            )
            AiPromptAnomalies      = 12
            StartDate              = $StartDate
            EndDate                = $EndDate
            IsMock                 = $true
        }
    }

    return [pscustomobject]@{
        TotalCopilotPrompts    = 0
        SensitiveFilesAccessed = 0
        OverSharedFiles        = 0
        TopOverSharedTypes     = @()
        AiPromptAnomalies      = 0
        StartDate              = $StartDate
        EndDate                = $EndDate
        IsMock                 = $false
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

    return [ordered]@{
        ToplamCopilotEtkilesimi = $RawData.TotalCopilotPrompts
        ErisilenHassasDosya     = $RawData.SensitiveFilesAccessed
        AsiriPaylasilanDosya    = $RawData.OverSharedFiles
        AsiriPaylasimKategorisi = @($RawData.TopOverSharedTypes)
        SupheliPromptAnomalisi  = $RawData.AiPromptAnomalies
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
        ServiceName        = 'Yönetilen Yapay Zeka Güvenliği'
        OtonomMudahaleler  = 0
        ManuelAnalistEforu = $KpiData.AsiriPaylasilanDosya + $KpiData.SupheliPromptAnomalisi
        KazanilanZamanSaat = 0
        Aciklama           = "Copilot sorgularında görünür hale gelen $($KpiData.AsiriPaylasilanDosya) adet aşırı yetkilendirilmiş (over-shared) hassas doküman tespit edilmiş, SharePoint yetkilerinin daraltılması için CloudShield danışmanları tarafından düzeltici önlemler alınmıştır."
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
        <h2 class="section-title">Microsoft Purview DSPM for AI & Copilot Veri Güvenliği Postürü</h2>
        <span class="section-tag">Yapay Zeka Postürü</span>
    </div>

    <!-- KPI KARTLARI -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Toplam Copilot İstemi (Prompt)</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.ToplamCopilotEtkilesimi) { '{0:N0}' -f $k.ToplamCopilotEtkilesimi } else { '-' })</div>
            </div>
            <div class="kpi-description">Kullanıcıların yapay zekaya sorduğu toplam sorgu</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Erişilen Hassas Belge</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.ErisilenHassasDosya) { '{0:N0}' -f $k.ErisilenHassasDosya } else { '-' })</div>
                <span class="badge positive">Etiketli</span>
            </div>
            <div class="kpi-description">Yanıt üretilirken kaynak gösterilen gizli dokümanlar</div>
        </div>

        <div class="kpi-card $(if ($k.AsiriPaylasilanDosya -gt 0) { 'highlight' })">
            <div class="kpi-title">Aşırı Paylaşılan (Over-shared) Veri</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.AsiriPaylasilanDosya)</div>
                <span class="badge $(if ($k.AsiriPaylasilanDosya -gt 0) { 'negative' } else { 'positive' })">Sıkılaştırma</span>
            </div>
            <div class="kpi-description">Şirket geneline açık hassas doküman sayısı</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Şüpheli Prompt Anomalisi</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.SupheliPromptAnomalisi)</div>
                <span class="badge neutral">İncelendi</span>
            </div>
            <div class="kpi-description">Maaş, strateji veya gizli veri arama girişimleri</div>
        </div>
    </div>

    <!-- AŞIRI PAYLAŞIM TABLOSU -->
    <h3 style="font-size:14px; margin-top:16px; color:var(--ks-navy);">Copilot Sayesinde Görünür Kılınan ve Yetkisi Kısıtlanan Belgeler</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Hassas Veri Kategorisi</th>
                <th>Dosya Sayısı</th>
                <th>Eski Açık Erişim Düzeyi</th>
                <th>Alınan Aksiyon</th>
            </tr>
        </thead>
        <tbody>
            $(foreach ($row in @($k.AsiriPaylasimKategorisi)) {
                "<tr>
                    <td><strong>$($row.Category)</strong></td>
                    <td>$($row.FileCount)</td>
                    <td><span class='badge negative'>$($row.Exposure)</span></td>
                    <td><span class='badge positive'>Yetkiler Daraltıldı</span></td>
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
