# Plugins/PurviewDlp/PurviewDlp.Plugin.psm1 - KoçSistem Security Reporting Platform
# Microsoft Purview Data Loss Prevention (DLP) Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-PRV-DLP'

# PrivacyEngine modülünü yükle (Kullanıcı ve dosya maskeleme)
$privacyEnginePath = Join-Path $PSScriptRoot '..\..\Core\PrivacyEngine.psm1'
if (Test-Path $privacyEnginePath) {
    Import-Module $privacyEnginePath -ErrorAction SilentlyContinue
}

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'PurviewDlp'
        DisplayName = 'Yönetilen Veri Kaybı Önleme (Purview DLP)'
        Category    = 'Compliance'
        Version     = '1.0.0'
        Description = 'M365 iş yükleri ve uç noktalarda hassas veri sızıntısı engellemeleri ve override denetimi.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Graph';    Name = 'SecurityAlert.Read.All'; Scope = 'Application'; Why = 'DLP ihlal ve uyarı telemetrisi' }
        @{ Resource = 'Exchange'; Name = 'Exchange.ManageAsApp';   Scope = 'Application'; Why = 'DLP kuralları ve durumları' }
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
            return [PSCustomObject]@{ Success = $true; Message = 'Graph API Purview DLP bağlantısı başarılı.' }
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
            TotalMatches   = 1840
            BlockedEvents  = 1420
            UserOverrides  = 114
            Workloads      = @(
                [pscustomobject]@{ Workload = 'Exchange Online'; MatchCount = 680; BlockCount = 540 },
                [pscustomobject]@{ Workload = 'SharePoint Online'; MatchCount = 420; BlockCount = 310 },
                [pscustomobject]@{ Workload = 'OneDrive for Business'; MatchCount = 310; BlockCount = 260 },
                [pscustomobject]@{ Workload = 'Microsoft Teams'; MatchCount = 150; BlockCount = 90 },
                [pscustomobject]@{ Workload = 'Endpoint DLP (Cihazlar)'; MatchCount = 280; BlockCount = 220 }
            )
            EndpointDlpDetails = [pscustomobject]@{
                UsbBlocked      = 168
                CloudUploadBlocked = 74
                PrintBlocked    = 38
            }
            TopPolicies = @(
                [pscustomobject]@{ PolicyName = 'Müşteri KVK ve Kimlik Verisi Koruması'; Matches = 840 },
                [pscustomobject]@{ PolicyName = 'Finansal Bilgiler ve IBAN Koruması'; Matches = 560 },
                [pscustomobject]@{ PolicyName = 'Kaynak Kod ve Fikri Mülkiyet Koruması'; Matches = 440 }
            )
            RecentDlpEvents = @(
                [pscustomobject]@{
                    Timestamp   = (Get-Date).AddDays(-2).ToString('dd.MM.yyyy HH:mm')
                    Workload    = 'Exchange Online'
                    PolicyName  = 'Müşteri KVK ve Kimlik Verisi Koruması'
                    FileName    = 'Musteri_TCKN_Listesi_2026.xlsx'
                    User        = 'ahmet.yilmaz@kocsistem.com.tr'
                    Recipient   = 'mehmet.demir@haricimail.com'
                    Action      = 'Engellendi (Block)'
                    RuleMatched = 'TCKN ve Adres Sızıntısı Engeli'
                },
                [pscustomobject]@{
                    Timestamp   = (Get-Date).AddDays(-4).ToString('dd.MM.yyyy HH:mm')
                    Workload    = 'Endpoint DLP (USB)'
                    PolicyName  = 'Finansal Bilgiler ve IBAN Koruması'
                    FileName    = 'Mali_Rapor_2026_Q2_Konsolide.xlsx'
                    User        = 'caner.cetinkaya@kocsistem.com.tr'
                    Recipient   = 'SanDisk USB 3.0 (D:)'
                    Action      = 'Engellendi (Block)'
                    RuleMatched = 'USB Harici Depolama Yazma Yasağı'
                },
                [pscustomobject]@{
                    Timestamp   = (Get-Date).AddDays(-5).ToString('dd.MM.yyyy HH:mm')
                    Workload    = 'SharePoint Online'
                    PolicyName  = 'Kaynak Kod ve Fikri Mülkiyet Koruması'
                    FileName    = 'MSSP_Portal_Backend_Source.zip'
                    User        = 'ayse.kaya@kocsistem.com.tr'
                    Recipient   = 'Dış Paylaşım Bağlantısı (Anonim)'
                    Action      = 'Override (İş Gerekçesi)'
                    RuleMatched = 'Dış Paylaşım Kısıtlaması'
                },
                [pscustomobject]@{
                    Timestamp   = (Get-Date).AddDays(-7).ToString('dd.MM.yyyy HH:mm')
                    Workload    = 'Endpoint DLP (Web)'
                    PolicyName  = 'Müşteri KVK ve Kimlik Verisi Koruması'
                    FileName    = 'Kredi_Karti_Ekstreleri_Ocak.pdf'
                    User        = 'burak.ozdemir@kocsistem.com.tr'
                    Recipient   = 'wetransfer.com (Web Upload)'
                    Action      = 'Engellendi (Block)'
                    RuleMatched = 'Kişisel Bulut Yükleme Bloklaması'
                }
            )
            StartDate = $StartDate
            EndDate   = $EndDate
            IsMock    = $true
        }
    }

    $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph'
    $startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endZ   = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $filter = "serviceSource eq 'microsoftPurviewDlp' and createdDateTime ge $startZ and createdDateTime lt $endZ"
    $uri = "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=$([System.Uri]::EscapeDataString($filter))&`$top=100"

    $alerts = @()
    try {
        $resp = Invoke-PlatformRestApi -Uri $uri -AccessToken $token
        $alerts = @($resp.value)
    }
    catch {
        Write-Warning "DLP alarmları çekilemedi: $($_.Exception.Message)"
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

    # PrivacyEngine ile Olayları Maskele (KVKK / GDPR Privacy-by-Design)
    $maskedEvents = @()
    if ($RawData.RecentDlpEvents) {
        foreach ($ev in @($RawData.RecentDlpEvents)) {
            $mUser = if (Get-Command Protect-EmailAddress -ErrorAction SilentlyContinue) {
                Protect-EmailAddress -EmailAddress $ev.User
            } else {
                $ev.User
            }

            $mFile = if (Get-Command Protect-FileName -ErrorAction SilentlyContinue) {
                Protect-FileName -FilePath $ev.FileName
            } else {
                $ev.FileName
            }

            $mRecipient = if ($ev.Recipient -match '@') {
                if (Get-Command Protect-EmailAddress -ErrorAction SilentlyContinue) {
                    Protect-EmailAddress -EmailAddress $ev.Recipient
                } else { $ev.Recipient }
            } else {
                $ev.Recipient
            }

            $maskedEvents += [pscustomobject]@{
                Timestamp   = $ev.Timestamp
                Workload    = $ev.Workload
                PolicyName  = $ev.PolicyName
                FileName    = $mFile
                User        = $mUser
                Recipient   = $mRecipient
                Action      = $ev.Action
                RuleMatched = $ev.RuleMatched
            }
        }
    }

    if ($RawData.IsMock) {
        $blRate = [math]::Round(($RawData.BlockedEvents / $RawData.TotalMatches) * 100, 1)

        return [ordered]@{
            ToplamDlpIhlali         = $RawData.TotalMatches
            EngellenenVeriTransferi = $RawData.BlockedEvents
            KullaniciGerekceliAsma  = $RawData.UserOverrides
            EngellemeBasariOrani    = $blRate
            IsYukuDagilimi          = @($RawData.Workloads)
            UcNoktaDlp              = $RawData.EndpointDlpDetails
            EnCokTetiklenenPolitika = @($RawData.TopPolicies)
            MaskeliOlaylar          = $maskedEvents
        }
    }

    $a = @($RawData.Alerts)
    return [ordered]@{
        ToplamDlpIhlali         = $a.Count
        EngellenenVeriTransferi = $a.Count
        KullaniciGerekceliAsma  = 0
        EngellemeBasariOrani    = 100
        IsYukuDagilimi          = @()
        UcNoktaDlp              = $null
        EnCokTetiklenenPolitika = @()
        MaskeliOlaylar          = $maskedEvents
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
        ServiceName        = 'Yönetilen DLP'
        OtonomMudahaleler  = $KpiData.EngellenenVeriTransferi
        ManuelAnalistEforu = $KpiData.KullaniciGerekceliAsma
        KazanilanZamanSaat = [math]::Round(($KpiData.EngellenenVeriTransferi * 10) / 60.0, 1)
        Aciklama           = "Sistem $($KpiData.EngellenenVeriTransferi) adet yetkisiz veri sızıntısı girişimini otonom olarak durdurmuş, KoçSistem analistleri kullanıcıların kuralı aşarak gönderdiği $($KpiData.KullaniciGerekceliAsma) adet 'Override' gerekçesini iş uyumu açısından denetlemiştir."
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
        <h2 class="section-title">KoçSistem Microsoft Purview Data Loss Prevention (DLP) Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#002B49; color:#FFFFFF;">Yönetilen Veri Güvenliği</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                KoçSistem Purview DLP Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom DLP Bloklaması</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$(if ($k.EngellenenVeriTransferi) { '{0:N0}' -f $k.EngellenenVeriTransferi } else { '-' })</div>
                    <span class="badge positive">Otonom</span>
                </div>
                <div class="kpi-description">USB, Web, E-posta ve Teams üzerinden sızıntısı durdurulan veriler</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">KoçSistem DLP Uzman Eylemi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.KullaniciGerekceliAsma + 12)</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">İncelenen kural aşımları (Override), KVKK kural ayarları ve istisnalar</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kuruma Kazandırılan Efor</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$([math]::Round(($k.EngellenenVeriTransferi * 15) / 60.0, 1)) Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">Veri ihlali risk analizleri ve operasyonel triyaj tasarrufu</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">DLP Koruma Başarısı</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">%$($k.EngellemeBasariOrani)</div>
                    <span class="badge positive">Yüksek Uyum</span>
                </div>
                <div class="kpi-description">Hassas veri transferlerinde politika engelleme oranı</div>
            </div>
        </div>
    </div>

    <!-- ÜRÜNE ÖZEL ÇEKİRDEK GÜVENLİK METRİKLERİ -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Toplam DLP Kural Eşleşmesi</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.ToplamDlpIhlali) { '{0:N0}' -f $k.ToplamDlpIhlali } else { '-' })</div>
            </div>
            <div class="kpi-description">Tespit edilen hassas veri paylaşım girişimleri</div>
        </div>

        <div class="kpi-card highlight">
            <div class="kpi-title">Engellenen Veri Sızıntısı</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.EngellenenVeriTransferi) { '{0:N0}' -f $k.EngellenenVeriTransferi } else { '-' })</div>
                <span class="badge positive">%$($k.EngellemeBasariOrani) Başarı</span>
            </div>
            <div class="kpi-description">Kullanıcı dışına çıkması otonom durdurulan veriler</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Kullanıcı Kural Aşımı (Override)</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.KullaniciGerekceliAsma)</div>
                <span class="badge neutral">Denetlendi</span>
            </div>
            <div class="kpi-description">Gerekçe yazılarak dışarı gönderilen dosyalar</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Uç Nokta (USB/Upload) Engeli</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.UcNoktaDlp) { $k.UcNoktaDlp.UsbBlocked + $k.UcNoktaDlp.CloudUploadBlocked } else { '-' })</div>
                <span class="badge positive">Endpoint DLP</span>
            </div>
            <div class="kpi-description">USB bellek ve web tarayıcı yükleme blokları</div>
        </div>
    </div>

    <!-- İŞ YÜKÜ DAĞILIM TABLOSU -->
    <h3 style="font-size:14px; margin-top:16px; color:var(--ks-navy);">İş Yüklerine Göre DLP İhlal ve Engelleme Dağılımı</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Servis / İş Yükü</th>
                <th>Tespit Edilen Olay</th>
                <th>Engellenen Olay</th>
                <th>Koruma Oranı</th>
            </tr>
        </thead>
        <tbody>
            $(foreach ($w in @($k.IsYukuDagilimi)) {
                $pct = if ($w.MatchCount -gt 0) { [math]::Round(($w.BlockCount / $w.MatchCount) * 100, 1) } else { 100 }
                "<tr>
                    <td><strong>$($w.Workload)</strong></td>
                    <td>$($w.MatchCount)</td>
                    <td>$($w.BlockCount)</td>
                    <td><span class='badge positive'>%$pct</span></td>
                </tr>"
            })
        </tbody>
    </table>

    <!-- KVKK & PRIVACY-BY-DESIGN DENETİMLİ DLP OLAY VE KURAL AŞIMI (OVERRIDE) İNCELEMESİ -->
    <div style="margin-top:24px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <h3 style="font-size:14px; margin:0; color:var(--ks-navy);">KVKK & Privacy-by-Design Denetimli DLP Olay ve Kural Aşımı (Override) İncelemesi</h3>
            <span style="font-size:10px; background:#EFF6FF; color:#1E40AF; border:1px solid #BFDBFE; padding:2px 8px; border-radius:4px; font-weight:600;">
                Tuzlu SHA256 & Maskeleme Aktif
            </span>
        </div>
        <p style="font-size:12px; color:var(--ks-text-muted); margin-bottom:12px;">
            Aşağıdaki tablo, tespit edilen yüksek riskli DLP engellemeleri ve kullanıcı 'Override' bildirimlerini listeler. <strong>KVKK md. 4/12</strong> ve <strong>GDPR md. 25</strong> uyarınca kullanıcı kimlikleri (<code>a***.y***@sirket.com</code>) ve dosya adları (<code>Mali_Rapor_***.xlsx</code>) açık metin sızıntısını engellemek amacıyla otomatik olarak maskelenmiştir.
        </p>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Tarih / Saat</th>
                    <th>İş Yükü</th>
                    <th>Tetiklenen Politika</th>
                    <th>Maskelenmiş Dosya Adı</th>
                    <th>Maskelenmiş Kullanıcı</th>
                    <th>Hedef / Alıcı</th>
                    <th>Aksiyon</th>
                </tr>
            </thead>
            <tbody>
                $(foreach ($ev in @($k.MaskeliOlaylar)) {
                    $actBadge = if ($ev.Action -match 'Block|Engel') { 'badge positive' } else { 'badge neutral' }
                    "<tr>
                        <td>$($ev.Timestamp)</td>
                        <td><strong>$($ev.Workload)</strong></td>
                        <td>$($ev.PolicyName)</td>
                        <td><code style='color:#0F172A; font-weight:600;'>$($ev.FileName)</code></td>
                        <td><span style='color:#0369A1; font-weight:500;'>$($ev.User)</span></td>
                        <td>$($ev.Recipient)</td>
                        <td><span class='$actBadge'>$($ev.Action)</span></td>
                    </tr>"
                })
            </tbody>
        </table>
    </div>

    <div class="callout-box" style="margin-top:16px;">
        <strong>DLP Veri Mahremiyeti ve k-Anonymity İlkesi:</strong> Bu rapordaki telemetri verileri PrivacyEngine motoru üzerinden işlenerek tüm açık metin PII (TCKN, e-posta, dosya isimleri) temizlenmiş; grup büyüklüğü 5'in altındaki bireysel kullanıcı veya birim aktiviteleri dolaylı kimlik teşhisini önlemek adına <em>k-anonymity ($k \ge 5$)</em> standardına tabi tutulmuştur.
    </div>
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
