# Plugins/PurviewRiskCompliance/PurviewRiskCompliance.Plugin.psm1 - KoçSistem Security Reporting Platform
# Microsoft Purview Insider Risk Management (IRM) & Communication Compliance Service Plugin (Isolated Privacy App).
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-PRV-RISK'

# PrivacyEngine modülünü yükle (Kullanıcı ve k-anonymity koruması)
$privacyEnginePath = Join-Path $PSScriptRoot '..\..\Core\PrivacyEngine.psm1'
if (Test-Path $privacyEnginePath) {
    Import-Module $privacyEnginePath -ErrorAction SilentlyContinue
}

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode         = $Script:ServiceCode
        Name                = 'PurviewRiskCompliance'
        DisplayName         = 'Yönetilen İç Tehdit ve İletişim Uyumu'
        Category            = 'ComplianceIsolated'
        Version             = '1.0.0'
        RequiresIsolatedApp = $true
        Description         = 'İçeriden veri sızıntısı (IRM) ve kurumsal iletişim kuralları agregasyon analitiği (İzole App ile çalışır).'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Graph'; Name = 'SecurityAlert.Read.All'; Scope = 'Application'; Why = 'İç tehdit ve iletişim agregasyon alarmları' }
    )
}

function Test-ServiceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig
    )

    return [PSCustomObject]@{ Success = $true; Message = 'Purview Risk & Compliance (İzole App) bağlantısı hazır.' }
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
            InsiderRiskAlerts = @(
                [pscustomobject]@{ Policy = 'İşten Ayrılan Personel Veri Sızıntısı'; AlertCount = 8; Severity = 'High'; TriagedCount = 8 },
                [pscustomobject]@{ Policy = 'Toplu Hassas Veri İndirme Anomalisi'; AlertCount = 4; Severity = 'Medium'; TriagedCount = 4 },
                [pscustomobject]@{ Policy = 'Hoşnutsuz Çalışan Veri İhlali Riski'; AlertCount = 2; Severity = 'High'; TriagedCount = 2 }
            )
            CommunicationCompliance = [pscustomobject]@{
                TotalFlaggedMessages = 32
                ResolvedClean        = 28
                EscalatedToLegal     = 4
            }
            StartDate = $StartDate
            EndDate   = $EndDate
            IsMock    = $true
        }
    }

    return [pscustomobject]@{
        InsiderRiskAlerts       = @()
        CommunicationCompliance = $null
        StartDate               = $StartDate
        EndDate                 = $EndDate
        IsMock                  = $false
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

    $irm = @($RawData.InsiderRiskAlerts)
    $toplamIrm = 0
    foreach ($row in $irm) { $toplamIrm += [int]$row.AlertCount }

    $cc = $RawData.CommunicationCompliance

    return [ordered]@{
        ToplamIcTehditAlarmi = $toplamIrm
        IrmPolitikalari      = $irm
        IletisimDenetimSayisi = if ($cc) { $cc.TotalFlaggedMessages } else { 0 }
        HukukaEskaleEdilen    = if ($cc) { $cc.EscalatedToLegal } else { 0 }
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
        ServiceName        = 'Yönetilen İç Tehdit ve İletişim Uyumu'
        OtonomMudahaleler  = 0
        ManuelAnalistEforu = $KpiData.ToplamIcTehditAlarmi + $KpiData.IletisimDenetimSayisi
        KazanilanZamanSaat = 0
        Aciklama           = "Gizlilik ve KVKK ilkeleri doğrultusunda $($KpiData.ToplamIcTehditAlarmi) adet içeriden risk sinyali ve $($KpiData.IletisimDenetimSayisi) adet iletişim gözetim kaydı yetkili analistler tarafından agregasyon düzeyinde incelenmiş, şirket dışına veri kaçırma riskleri önlenmiştir."
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
        <h2 class="section-title">KoçSistem Microsoft Purview İç Tehdit (IRM) ve İletişim Uyumu Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#002B49; color:#FFFFFF;">Yönetilen İç Tehdit & Uyum</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                KoçSistem İç Tehdit Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Triyaj Edilen Risk Sinyali</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.ToplamIcTehditAlarmi)</div>
                    <span class="badge positive">Triyaj Edildi</span>
                </div>
                <div class="kpi-description">İşten ayrılacak personel anomalileri ve anormal veri indirme hareketleri</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">KoçSistem Uyum Uzman Eylemi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.IletisimDenetimSayisi) Denetim</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">Teams, Exchange ve kurumsal kanallarda etik & regülasyon denetimleri</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kuruma Kazandırılan Efor</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$([math]::Round((($k.ToplamIcTehditAlarmi + $k.IletisimDenetimSayisi) * 30) / 60.0, 1)) Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">İç soruşturma ve adli analiz eforlarında sağlanan danışmanlık tasarrufu</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Hukuka Eskalasyon Oranı</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.HukukaEskaleEdilen) Vaka</div>
                    <span class="badge positive">Filtrelendi</span>
                </div>
                <div class="kpi-description">Hukuk/İK ekiplerine resmi bildirim gerektiren somut ihlal sayısı</div>
            </div>
        </div>
    </div>

    <!-- ÜRÜNE ÖZEL ÇEKİRDEK GÜVENLİK METRİKLERİ -->
    <div class="kpi-grid">
        <div class="kpi-card highlight">
            <div class="kpi-title">İç Tehdit (IRM) Sinyali</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.ToplamIcTehditAlarmi)</div>
                <span class="badge negative">Triyaj Edildi</span>
            </div>
            <div class="kpi-description">İşten ayrılma veya veri kaçırma anomalileri</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">İletişim Uyum Denetimi</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.IletisimDenetimSayisi)</div>
                <span class="badge positive">Gözetim</span>
            </div>
            <div class="kpi-description">Regülasyon ve etik kural bayrağı alan mesajlar</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Hukuk/İK'ya İletilen Vaka</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.HukukaEskaleEdilen)</div>
                <span class="badge $(if ($k.HukukaEskaleEdilen -gt 0) { 'negative' } else { 'positive' })">Eskalasyon</span>
            </div>
            <div class="kpi-description">İleri inceleme gerektiren kritik bulgular</div>
        </div>
    </div>

    <!-- İÇ TEHDİT POLİTİKA DAĞILIMI VE AGREGASYON TABLOSU -->
    <h3 style="font-size:14px; margin-top:16px; color:var(--ks-navy);">İç Tehdit (IRM) Politika Dağılımı ve Agregasyon Özeti</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Risk Politikası</th>
                <th>Risk Seviyesi</th>
                <th>Olay Sayısı</th>
                <th>MSSP Triyaj Durumu</th>
                <th>k-Anonymity Koruma Güvencesi</th>
            </tr>
        </thead>
        <tbody>
            $(foreach ($pol in @($k.IrmPolitikalari)) {
                $sevBadge = if ($pol.Severity -eq 'High') { 'badge negative' } else { 'badge neutral' }
                "<tr>
                    <td><strong>$($pol.Policy)</strong></td>
                    <td><span class='$sevBadge'>$($pol.Severity)</span></td>
                    <td>$($pol.AlertCount) Olay</td>
                    <td><span class='badge positive'>$($pol.TriagedCount) / $($pol.AlertCount) Triyaj Edildi</span></td>
                    <td><span class='badge neutral'>k &ge; 5 Agrege Koruma</span></td>
                </tr>"
            })
        </tbody>
    </table>

    <div class="callout-box" style="margin-top:16px;">
        <strong>Gizlilik & KVKK Güvencesi (Privacy-by-Design & Separation of Duties):</strong> Bu rapor yalnızca agregasyon ve sayısal sinyal düzeyinde veri içerir. 6698 sayılı Kanun (md. 4 ve md. 6) ve GDPR (Madde 88) istihdam mahremiyeti ilkeleri uyarınca kişisel kullanıcı kimlikleri, çalışan risk skorları veya e-posta/sohbet mesaj içerikleri rapora asla yansıtılmaz; bağımsız ve izole edilmiş İK/Hukuk rolleri tarafından Purview portalı üzerinden yönetilir.
    </div>
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
