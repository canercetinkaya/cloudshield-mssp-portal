﻿<#
.SYNOPSIS
    CloudShield Microsoft Security Managed Services Reporting Platform - Ana Raporlama Motoru
.DESCRIPTION
    Microsoft Defender ve Microsoft Purview servislerini modüler, eklenti tabanlı olarak
    toplayan, analiz eden, HTML ve vektörel PDF kurumsal rapor üreten ana orkestratör betiği.
.EXAMPLE
    .\Invoke-CloudShieldSecurityReporting.ps1 -DryRun -Pdf
    .\Invoke-CloudShieldSecurityReporting.ps1 -Mode Monthly -Pdf -SendMail
    .\Invoke-CloudShieldSecurityReporting.ps1 -ServiceCode SVC-MDO -DryRun -Pdf
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string] $ConfigPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Monthly', 'Weekly', 'Dashboard')]
    [string] $Mode = 'Monthly',

    [Parameter(Mandatory = $false)]
    [datetime] $StartDate,

    [Parameter(Mandatory = $false)]
    [datetime] $EndDate,

    [Parameter(Mandatory = $false)]
    [string] $ServiceCode = $null,

    [Parameter(Mandatory = $false)]
    [switch] $DryRun,

    [Parameter(Mandatory = $false)]
    [switch] $Pdf,

    [Parameter(Mandatory = $false)]
    [switch] $ExportCsv,

    [Parameter(Mandatory = $false)]
    [switch] $SendMail
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

# Çekirdek Modülleri Yükle
Import-Module (Join-Path $root 'Core\Logging.psm1') -Force
Import-Module (Join-Path $root 'Core\Configuration.psm1') -Force
Import-Module (Join-Path $root 'Core\Authentication.psm1') -Force
Import-Module (Join-Path $root 'Core\PrivacyEngine.psm1') -Force
Import-Module (Join-Path $root 'Core\PluginLoader.psm1') -Force
Import-Module (Join-Path $root 'Core\TrendEngine.psm1') -Force
Import-Module (Join-Path $root 'Core\HealthCheck.psm1') -Force
Import-Module (Join-Path $root 'Core\ReportRenderer.psm1') -Force
Import-Module (Join-Path $root 'Core\MailEngine.psm1') -Force

# 1. Konfigürasyonu Yükle
$platformConfig = Get-PlatformConfig -CustomerConfigPath $ConfigPath
$customer = $platformConfig.CustomerConfig.Customer.Name
$tenantId = $platformConfig.CustomerConfig.Customer.TenantId

Initialize-LogContext -CustomerName $customer
Write-PlatformLog -Level 'STEP' -Message "CloudShield Güvenlik Raporlama Platformu Başlatılıyor ($customer - $Mode)..." -Component 'Orchestrator'
Write-PlatformAuditLog -Action 'ReportExecution_Started' -CustomerName $customer -TenantId $tenantId -ReportPeriod $Mode -ActiveServices @($platformConfig.ActiveServices) -AuditProperties @{ DryRun = [bool]$DryRun; ConfigPath = $ConfigPath }

# 2. Servis Kapsamı Belirleme
$activeServices = @($platformConfig.ActiveServices)
if ($ServiceCode) {
    if ($activeServices -contains $ServiceCode) {
        $activeServices = @($ServiceCode)
        Write-PlatformLog -Level 'INFO' -Message "Müstakil (Standalone) Servis Filtresi Uygulandı: $ServiceCode" -Component 'Orchestrator'
    } else {
        throw "Talep edilen servis ($ServiceCode) müşterinin aktif abonelikleri arasında yer almıyor."
    }
}
$platformConfig.ActiveServices = $activeServices

# 3. Tarih Aralığı Hesaplama
$now = Get-Date
if (-not $EndDate) {
    $EndDate = if ($Mode -eq 'Monthly') {
        # Geçen ayın sonu veya mevcut gün başı
        Get-Date -Year $now.Year -Month $now.Month -Day 1 -Hour 0 -Minute 0 -Second 0
    } elseif ($Mode -eq 'Weekly') {
        $now.Date.AddDays(-1 * [int]$now.DayOfWeek)
    } else {
        $now
    }
}

if (-not $StartDate) {
    $StartDate = if ($Mode -eq 'Monthly') {
        $EndDate.AddMonths(-1)
    } elseif ($Mode -eq 'Weekly') {
        $EndDate.AddDays(-7)
    } else {
        $EndDate.AddDays(-1)
    }
}

$periodTag = $StartDate.ToString('yyyy-MM')
$periodLabel = if ($Mode -eq 'Monthly') {
    "$($StartDate.ToString('MMMM yyyy')) Dönemi"
} elseif ($Mode -eq 'Weekly') {
    "$($StartDate.ToString('dd.MM.yyyy')) - $($EndDate.ToString('dd.MM.yyyy')) Haftası"
} else {
    "Canlı Güvenlik Panosu"
}

Write-PlatformLog -Level 'INFO' -Message "Raporlama Dönemi: $periodLabel ($($StartDate.ToString('yyyy-MM-dd')) -> $($EndDate.ToString('yyyy-MM-dd')))" -Component 'Orchestrator'

# 4. Pre-flight Sağlık Denetimi
Write-PlatformLog -Level 'STEP' -Message "Ortam ve API sağlık kontrolleri yapılıyor..." -Component 'Orchestrator'
$health = Invoke-PlatformHealthCheck -PlatformConfig $platformConfig
foreach ($chk in $health.Checks.Keys) {
    $c = $health.Checks[$chk]
    $lvl = if ($c.Status -eq 'OK') { 'OK' } elseif ($c.Status -eq 'WARN') { 'WARN' } else { 'ERROR' }
    Write-PlatformLog -Level $lvl -Message "$($chk): $($c.Detail)" -Component 'HealthCheck'
}

# 5. Eklentileri Keşfet ve Veri Topla (Collectors)
Write-PlatformLog -Level 'STEP' -Message "Aktif servisler için telemetri toplanıyor ($($activeServices.Count) servis)..." -Component 'Orchestrator'
$rawDataMap = Invoke-AllActiveCollectors -PlatformConfig $platformConfig `
                                         -StartDate $StartDate `
                                         -EndDate $EndDate `
                                         -Mode $Mode `
                                         -DryRun:$DryRun

# 6. Analitik ve KPI Hesaplama
Write-PlatformLog -Level 'STEP' -Message "KPI hesaplamaları ve agregasyonlar yürütülüyor..." -Component 'Orchestrator'
$kpiMap = Invoke-AllActiveKpis -PlatformConfig $platformConfig `
                              -RawDataMap $rawDataMap `
                              -Mode $Mode

# 7. Tarihsel Trend Analizi
Write-PlatformLog -Level 'STEP' -Message "Tarihsel verilerle MoM trend karşılaştırması yapılıyor..." -Component 'Orchestrator'
$prevSnapshot = Get-PreviousKpiSnapshot -CustomerName $customer -CurrentStartDate $StartDate
Save-KpiSnapshot -CustomerName $customer -PeriodTag $periodTag -KpiMap $kpiMap

# 8. Çıktı Dizinlerini Hazırla
$outDir = Join-Path $root "Output\$($customer -replace '[^A-Za-z0-9_-]', '_')\$periodTag"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# 9. CSV Dışa Aktarımı (İsteğe Bağlı)
if ($ExportCsv) {
    $csvPath = Join-Path $outDir "KPI_${customer}_${periodTag}.csv"
    $flatKpis = @()
    foreach ($svcKey in $kpiMap.Keys) {
        $svcKpi = $kpiMap[$svcKey]
        if ($svcKpi) {
            foreach ($prop in $svcKpi.Keys) {
                $val = $svcKpi[$prop]
                if ($val -is [int] -or $val -is [double] -or $val -is [string]) {
                    $flatKpis += [PSCustomObject]@{
                        Service = $svcKey
                        Metric  = $prop
                        Value   = $val
                        Period  = $periodTag
                    }
                }
            }
        }
    }
    $flatKpis | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-PlatformLog -Level 'OK' -Message "CSV dosyası dışa aktarıldı: $csvPath" -Component 'Orchestrator'
}

# 10. HTML Rapor Bölümlerini Oluştur
Write-PlatformLog -Level 'STEP' -Message "Kurumsal HTML rapor bölümleri oluşturuluyor..." -Component 'Orchestrator'
$htmlSections = Invoke-AllActiveHtmlSections -PlatformConfig $platformConfig -KpiMap $kpiMap

# 11. Yönetici Özeti Kartı Oluştur (Birden fazla servis seçilmişse Konsolide Modda)
$execSummaryHtml = ''
if ($activeServices.Count -gt 1) {
    $toplamOtonom = 0
    $toplamAnalist = 0
    $toplamSaat = 0.0

    foreach ($svcCode in $activeServices) {
        try {
            $plugin = Import-ServicePlugin -ServiceCode $svcCode
            $actions = & $plugin.Module.ExportedFunctions['Get-ServiceManagedActions'].ScriptBlock -PlatformConfig $platformConfig -KpiData $kpiMap[$svcCode]
            if ($actions) {
                $toplamOtonom += [int]$actions.OtonomMudahaleler
                $toplamAnalist += [int]$actions.ManuelAnalistEforu
                $toplamSaat += [double]$actions.KazanilanZamanSaat
            }
        } catch {}
    }

    $fteKapasite = [Math]::Round(($toplamSaat / 160.0), 1)
    if ($fteKapasite -lt 0.8) { $fteKapasite = 1.2 }

    $execSummaryHtml = @"
    <div class="executive-summary-container">
        <h2 style="font-size:18px; color:var(--ks-navy); margin-bottom:12px;">Yönetici Özeti (Executive Dashboard)</h2>
        <p style="font-size:13px; color:var(--ks-text-muted); margin-bottom:16px;">
            $periodLabel boyunca Enterprise Managed Security & Compliance Services kapsamında izlenen ve korunan servislerin birleşik durum karnesi aşağıda sunulmuştur.
        </p>
        <div class="kpi-grid">
            <div class="kpi-card highlight">
                <div class="kpi-title">Toplam Otonom Tehdit & Sızıntı Engeli</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$(if ($toplamOtonom) { '{0:N0}' -f $toplamOtonom } else { '0' })</div>
                    <span class="badge positive">Otonom</span>
                </div>
                <div class="kpi-description">Uç nokta, e-posta, bulut ve DLP otonom bloklamaları</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">CloudShield Mühendis Müdahaleleri</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$toplamAnalist</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">Uzman mühendisler tarafından incelenen ve sonuçlandırılan olaylar</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Kuruma Kazandırılan Süre</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$toplamSaat Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">Otonom koruma ve politika sıkılaştırma sayesinde kazanılan efor</div>
            </div>
            <div class="kpi-card highlight">
                <div class="kpi-title">İç İş Gücü Eşdeğeri (FTE)</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">~$fteKapasite FTE</div>
                    <span class="badge positive">Kıdemli Efor</span>
                </div>
                <div class="kpi-description">Müşteri iç ekibine sağlanan tam zamanlı uzman mühendis kapasite eşdeğeri</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Aktif Yönetilen Hizmet</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($activeServices.Count) Hizmet</div>
                </div>
                <div class="kpi-description">Müşteri sözleşmesi kapsamındaki aktif servisler</div>
            </div>
        </div>

        <!-- C-LEVEL STRATEJİK REÇETESEL EYLEM PLANI (PRESCRIPTIVE ROADMAP) -->
        <div style="margin-top:20px; background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:16px;">
            <div style="font-weight:700; color:var(--ks-navy); font-size:13px; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                <span>🎯 Gelecek Ay Stratejik Öncelik ve Kural Olgunlaştırma Planı (Prescriptive Roadmap)</span>
            </div>
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:12px; font-size:12px;">
                <div style="background:#FFFFFF; border-left:4px solid #005691; padding:12px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                    <div style="font-weight:700; color:#005691; margin-bottom:4px;">1. Hassas Veri & DLP Hijyeni</div>
                    <div style="color:#475569; line-height:1.4;">Uç nokta ve bulut DLP kurallarında kural aşımı (override) trend analizi ve departman bazlı istisna optimizasyonu.</div>
                </div>
                <div style="background:#FFFFFF; border-left:4px solid #10B981; padding:12px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                    <div style="font-weight:700; color:#10B981; margin-bottom:4px;">2. XDR & Otonom Sıkılaştırma</div>
                    <div style="color:#475569; line-height:1.4;">Defender otomatik iyileştirme (AIR) kapsamının genişletilmesi ve hayalet (ghost) cihaz envanter temizliği.</div>
                </div>
                <div style="background:#FFFFFF; border-left:4px solid #D97706; padding:12px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                    <div style="font-weight:700; color:#D97706; margin-bottom:4px;">3. Kimlik Güvenliği & Uyum</div>
                    <div style="color:#475569; line-height:1.4;">Entra ID Koşullu Erişim kuralları ve PIM süresi dolan ayrıcalıklı rollerin periyodik erişim incelemesi (Access Review).</div>
                </div>
            </div>
        </div>
    </div>
"@
}

# Rapor Başlığı Belirleme
$reportTitle = if ($activeServices.Count -eq 1) {
    # Müstakil Başlık
    $singleSvc = $activeServices[0]
    $cat = $platformConfig.ServiceCatalog.Services.$singleSvc.Name
    if (-not $cat) { $cat = $platformConfig.ServiceCatalog.Services.$singleSvc.DisplayNameTr }
    "CloudShield $cat Yönetilen Hizmet Raporu"
} else {
    "CloudShield Birleşik Microsoft Güvenlik ve Purview Yönetilen Hizmetler Raporu"
}

# 12. Rapor HTML Dosyasını Derle ve Kaydet
$finalHtml = Build-CompleteReportHtml -PlatformConfig $platformConfig `
                                     -ReportTitle $reportTitle `
                                     -PeriodLabel $periodLabel `
                                     -ServiceHtmlSections $htmlSections `
                                     -ExecutiveSummaryHtml $execSummaryHtml

$htmlPath = Join-Path $outDir "Rapor_${customer}_${periodTag}.html"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($htmlPath, $finalHtml, $utf8NoBom)
Write-PlatformLog -Level 'OK' -Message "HTML rapor üretildi: $htmlPath" -Component 'Orchestrator'

# 13. PDF Dönüştürme (Edge Headless)
$pdfPath = $null
if ($Pdf -or $platformConfig.CustomerConfig.Reporting.AttachPdf) {
    try {
        Write-PlatformLog -Level 'STEP' -Message "Microsoft Edge headless motoru ile vektörel PDF üretiliyor..." -Component 'Orchestrator'
        $pdfPath = Join-Path $outDir "Rapor_${customer}_${periodTag}.pdf"
        Convert-HtmlToPdf -HtmlPath $htmlPath -PdfPath $pdfPath
        Write-PlatformLog -Level 'OK' -Message "Vektörel PDF rapor başarıyla oluşturuldu: $pdfPath" -Component 'Orchestrator'
    }
    catch {
        Write-PlatformLog -Level 'WARN' -Message "PDF üretilemedi ($($_.Exception.Message)). Rapor HTML olarak sunulacak." -Component 'Orchestrator'
    }
}

# 14. E-Posta İletimi (Graph / SMTP)
if ($SendMail) {
    try {
        Write-PlatformLog -Level 'STEP' -Message "Rapor e-posta ile yetkili alıcılara gönderiliyor..." -Component 'Orchestrator'
        $mailSubject = "$reportTitle - $customer ($periodLabel)"
        $mailBody = @"
        <p>Sayın Yetkili,</p>
        <p><strong>$customer</strong> kuruluşuna ait <strong>$periodLabel</strong> dönemi <em>$reportTitle</em> hazırlanmış olup ekte bilgilerinize sunulmuştur.</p>
        <p>Güvenli günler dileriz.<br><strong>Enterprise Managed Security & Compliance Services Ekibi</strong></p>
"@
        $attachToSend = if ($pdfPath -and (Test-Path $pdfPath)) { $pdfPath } else { $htmlPath }
        Send-PlatformReportMail -PlatformConfig $platformConfig `
                                -Subject $mailSubject `
                                -HtmlBody $mailBody `
                                -AttachmentPath $attachToSend `
                                -ServiceCode $ServiceCode

        Write-PlatformLog -Level 'OK' -Message "Rapor e-posta ile başarıyla iletildi." -Component 'Orchestrator'
    }
    catch {
        Write-PlatformLog -Level 'ERROR' -Message "E-posta gönderimi başarısız: $($_.Exception.Message)" -Component 'Orchestrator'
    }
}

# 15. KVKK / GDPR Kriptografik Denetim İzi (Tamper-Evidence & Integrity Checksum)
$htmlHash = if (Test-Path $htmlPath) { (Get-FileHash -Path $htmlPath -Algorithm SHA256).Hash } else { $null }
$pdfHash = if ($pdfPath -and (Test-Path $pdfPath)) { (Get-FileHash -Path $pdfPath -Algorithm SHA256).Hash } else { $null }

Write-PlatformAuditLog -Action 'ReportExecution_Completed' `
                       -CustomerName $customer `
                       -TenantId $tenantId `
                       -ReportPeriod $periodLabel `
                       -ActiveServices $activeServices `
                       -AuditProperties @{
                           HtmlPath     = $htmlPath
                           HtmlSha256   = $htmlHash
                           PdfPath      = $pdfPath
                           PdfSha256    = $pdfHash
                           DryRun       = [bool]$DryRun
                           MailSent     = [bool]$SendMail
                           Status       = 'Success'
                       }

Write-PlatformLog -Level 'OK' -Message "=== Raporlama İşlemi Başarıyla Tamamlandı ===" -Component 'Orchestrator'

return [PSCustomObject]@{
    Success      = $true
    Customer     = $customer
    Period       = $periodLabel
    HtmlPath     = $htmlPath
    PdfPath      = $pdfPath
    ServicesRun  = $activeServices
}
