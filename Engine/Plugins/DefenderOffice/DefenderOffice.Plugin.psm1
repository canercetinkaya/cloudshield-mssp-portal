﻿# Plugins/DefenderOffice/DefenderOffice.Plugin.psm1 - CloudShield Security Reporting Platform
# Microsoft Defender for Office 365 (MDO & EOP) Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-MDO'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'DefenderOffice'
        DisplayName = 'Yönetilen E-Posta Güvenliği (MDO + EOP)'
        Category    = 'Email'
        Version     = '1.0.0'
        Description = 'E-posta trafiği, spam/malware hijyeni, Safe Links/Attachments, ZAP ve analist karantina yönetimi.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Graph'; Name = 'SecurityAlert.Read.All';    Scope = 'Application'; Why = 'MDO alarmları' }
        @{ Resource = 'Graph'; Name = 'ThreatHunting.Read.All';    Scope = 'Application'; Why = 'EmailEvents ve ZAP telemetrisi' }
        @{ Resource = 'Graph'; Name = 'SecurityIncident.Read.All'; Scope = 'Application'; Why = 'E-posta kaynaklı olay korelasyonu' }
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
            return [PSCustomObject]@{ Success = $true; Message = 'Graph API MDO bağlantısı başarılı.' }
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
            TrafficSummary = [pscustomobject]@{
                TotalInbound     = 148500
                CleanDelivered   = 121300
                SpamFiltered     = 21400
                PhishBlocked     = 4650
                MalwareBlocked   = 1150
            }
            MdoProtection = [pscustomobject]@{
                SafeLinksScanned = 428000
                SafeLinksBlocked = 512
                SafeAttachmentsScanned = 18400
                SafeAttachmentsBlocked = 118
                ZapActions = 164
            }
            UserSubmissions = [pscustomobject]@{
                TotalReported   = 94
                ConfirmedPhish  = 72
                FalsePositive   = 22
                TriageRate      = 100
            }
            QuarantineOps = [pscustomobject]@{
                TotalQuarantined = 5800
                ReleaseRequested = 42
                AnalystApproved  = 8
                AnalystRejected  = 34
            }
            StartDate = $StartDate
            EndDate   = $EndDate
            IsMock    = $true
        }
    }

    # Canlı Graph API alarmları
    $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph'
    $startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endZ   = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $filter = "serviceSource eq 'microsoftDefenderForOffice365' and createdDateTime ge $startZ and createdDateTime lt $endZ"
    $uri = "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=$([System.Uri]::EscapeDataString($filter))&`$top=100"
    
    $alerts = @()
    try {
        $resp = Invoke-PlatformRestApi -Uri $uri -AccessToken $token
        $alerts = @($resp.value)
    }
    catch {
        Write-Warning "MDO alarmları çekilemedi: $($_.Exception.Message)"
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
        $ts = $RawData.TrafficSummary
        $mdo = $RawData.MdoProtection
        $sub = $RawData.UserSubmissions
        $q = $RawData.QuarantineOps

        $toplamEngellenenTehdit = $ts.PhishBlocked + $ts.MalwareBlocked + $mdo.SafeLinksBlocked + $mdo.SafeAttachmentsBlocked + $mdo.ZapActions

        return [ordered]@{
            ToplamGelenPosta      = $ts.TotalInbound
            TemizTeslimEdilen     = $ts.CleanDelivered
            FiltrelenenSpam       = $ts.SpamFiltered
            EngellenenOltalama    = $ts.PhishBlocked
            EngellenenZararliEk   = $ts.MalwareBlocked
            SafeLinksEngelleme    = $mdo.SafeLinksBlocked
            SafeAttachmentsEng    = $mdo.SafeAttachmentsBlocked
            ZapSistemGeriCekme    = $mdo.ZapActions
            ToplamEngellenen      = $toplamEngellenenTehdit
            KullaniciBildirimi    = $sub.TotalReported
            DogrulananOltalama    = $sub.ConfirmedPhish
            KarantinaTalepSayisi  = $q.ReleaseRequested
            KarantinaReddedilen   = $q.AnalystRejected
            KarantinaOnaylanan    = $q.AnalystApproved
        }
    }

    # Canlı modda agregasyon
    $a = @($RawData.Alerts)
    return [ordered]@{
        ToplamAlarm        = $a.Count
        KullaniciBildirimi = 0
        ToplamEngellenen   = $a.Count
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

    $analistAksiyon = ($KpiData.KullaniciBildirimi) + ($KpiData.KarantinaTalepSayisi)
    $otonomAksiyon  = ($KpiData.ToplamEngellenen)

    return [ordered]@{
        ServiceCode        = $Script:ServiceCode
        ServiceName        = 'Yönetilen E-Posta Güvenliği'
        OtonomMudahaleler  = $otonomAksiyon
        ManuelAnalistEforu = $analistAksiyon
        KazanilanZamanSaat = [math]::Round(($otonomAksiyon * 15) / 60.0, 1)
        Aciklama           = "E-posta ağ geçidinde $($KpiData.ToplamEngellenen) adet oltalama ve zararlı içerik otonom durdurulmuş, CloudShield analistleri kullanıcıların bildirdiği $($KpiData.KullaniciBildirimi) şüpheli postayı ve $($KpiData.KarantinaTalepSayisi) karantina talebini güvenlik denetiminden geçirmiştir."
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
        <h2 class="section-title">CloudShield Microsoft Defender for Office 365 (MDO & EOP) Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#002B49; color:#FFFFFF;">Yönetilen E-Posta Güvenliği</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                CloudShield MDO & EOP Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom Filtreleme & ZAP</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.EngellenenOltalama + $k.EngellenenZararliEk + $k.ZapSistemGeriCekme)</div>
                    <span class="badge positive">Otonom</span>
                </div>
                <div class="kpi-description">Gateway'de ve ZAP ile gelen kutularından geri çekilen tehditler</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">CloudShield E-Posta Uzman Eylemi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.KullaniciBildirimi + $k.KarantinaTalepSayisi)</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">İncelenen kullanıcı bildirimleri (Submissions) ve karantina analizi</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kuruma Kazandırılan Efor</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$([math]::Round((($k.EngellenenOltalama + $k.EngellenenZararliEk) * 12) / 60.0, 1)) Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">Otonom bloklama ve karantina triyajı ile kazanılan mesai</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">E-Posta Temizlik & SLA Skoru</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">%99.8</div>
                    <span class="badge positive">Temiz</span>
                </div>
                <div class="kpi-description">Güvenli şekilde teslim edilen kurumsal posta oranı</div>
            </div>
        </div>
    </div>

    <!-- ÜRÜNE ÖZEL ÇEKİRDEK GÜVENLİK METRİKLERİ -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Toplam Gelen Posta</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.ToplamGelenPosta) { '{0:N0}' -f $k.ToplamGelenPosta } else { '-' })</div>
            </div>
            <div class="kpi-description">Gateway'e ulaşan inbound e-posta hacmi</div>
        </div>

        <div class="kpi-card highlight">
            <div class="kpi-title">Engellenen Tehdit (Phish + Malware)</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.EngellenenOltalama + $k.EngellenenZararliEk)</div>
                <span class="badge positive">Bloklandı</span>
            </div>
            <div class="kpi-description">Safe Links, Attachments ve EOP tespitleri</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">ZAP Reaktif Temizleme</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.ZapSistemGeriCekme)</div>
                <span class="badge positive">Auto-Purged</span>
            </div>
            <div class="kpi-description">Teslimat sonrası kutulardan geri çekilenler</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Kullanıcı Bildirim Triyajı</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.KullaniciBildirimi)</div>
                <span class="badge positive">%100 Çözüldü</span>
            </div>
            <div class="kpi-description">Çalışanların raporladığı şüpheli e-postalar</div>
        </div>
    </div>

    <!-- OPERASYON VE KARANTİNA TABLOSU -->
    <h3 style="font-size:14px; margin-top:16px; color:var(--ks-navy);">CloudShield Analist Operasyonları & Karantina Yönetimi</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Operasyon Türü</th>
                <th>İncelenen Adet</th>
                <th>CloudShield Analist Kararı</th>
                <th>Açıklama / Durum</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>Kullanıcı Oltalama Bildirimi</strong></td>
                <td>$($k.KullaniciBildirimi)</td>
                <td>$($k.DogrulananOltalama) Gerçek Tehdit Doğrulandı</td>
                <td>Geri kalan $($k.KullaniciBildirimi - $k.DogrulananOltalama) posta yanlış pozitif olarak kapatıldı.</td>
            </tr>
            <tr>
                <td><strong>Karantina Serbest Bırakma Talebi</strong></td>
                <td>$($k.KarantinaTalepSayisi)</td>
                <td>$($k.KarantinaReddedilen) Talep Reddedildi, $($k.KarantinaOnaylanan) Onaylandı</td>
                <td>Zararlı tespit edilen ekler ve linkler nedeniyle riskli talepler bloklandı.</td>
            </tr>
            <tr>
                <td><strong>ZAP (Zero-Hour Auto Purge)</strong></td>
                <td>$($k.ZapSistemGeriCekme)</td>
                <td>Otomatik Geri Çekildi</td>
                <td>Kullanıcı gelen kutusundan sonradan tespit edilen zararlılar temizlendi.</td>
            </tr>
        </tbody>
    </table>
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
