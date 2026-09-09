﻿# Core/ReportRenderer.psm1 - CloudShield Security Reporting Platform
# HTML assembly, Base64 embedding, and Headless Edge vector PDF generation.
[CmdletBinding()]
param()

$Script:RootPath = Split-Path -Parent $PSScriptRoot

function Get-ImageAsDataUri {
    param([string] $RelativeOrAbsolutePath)

    if (-not $RelativeOrAbsolutePath) { return '' }

    $fullPath = if ([System.IO.Path]::IsPathRooted($RelativeOrAbsolutePath)) {
        $RelativeOrAbsolutePath
    } else {
        Join-Path $Script:RootPath $RelativeOrAbsolutePath
    }

    if (-not (Test-Path $fullPath)) { return '' }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($fullPath)
        $b64 = [Convert]::ToBase64String($bytes)
        $ext = [System.IO.Path]::GetExtension($fullPath).ToLower().TrimStart('.')
        $mime = switch ($ext) {
            'png'  { 'image/png' }
            'jpg'  { 'image/jpeg' }
            'jpeg' { 'image/jpeg' }
            'svg'  { 'image/svg+xml' }
            default { 'image/png' }
        }
        return "data:$mime;base64,$b64"
    }
    catch {
        return ''
    }
}

function Convert-HtmlToPdf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $HtmlPath,
        [Parameter(Mandatory = $true)]
        [string] $PdfPath
    )

    $edgePath = Find-EdgeExecutable
    if (-not $edgePath) {
        throw "Microsoft Edge veya Google Chrome bulunamadı, PDF üretilemiyor."
    }

    $uri = [System.Uri]::new((Resolve-Path $HtmlPath).Path).AbsoluteUri
    $argList = @(
        '--headless',
        '--disable-gpu',
        '--no-pdf-header-footer',
        '--run-all-compositor-stages-before-draw',
        "--print-to-pdf=`"$PdfPath`"",
        "`"$uri`""
    )

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $edgePath
    $pinfo.Arguments = $argList -join ' '
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true

    $proc = [System.Diagnostics.Process]::Start($pinfo)
    $proc.WaitForExit(30000)

    if (-not (Test-Path $PdfPath) -or (Get-Item $PdfPath).Length -eq 0) {
        throw "PDF dosyası üretilemedi veya boyutu 0 bayt."
    }

    return (Get-Item $PdfPath).FullName
}

function Build-CompleteReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        [string] $ReportTitle,
        [Parameter(Mandatory = $true)]
        [string] $PeriodLabel,
        [Parameter(Mandatory = $true)]
        [hashtable] $ServiceHtmlSections,
        [Parameter(Mandatory = $false)]
        [string] $ExecutiveSummaryHtml = ''
    )

    $global = $PlatformConfig.GlobalConfig
    $cust = $PlatformConfig.CustomerConfig

    # Logolar
    $kocLogoUri = Get-ImageAsDataUri -RelativeOrAbsolutePath $global.Provider.LogoPath
    $custLogoUri = Get-ImageAsDataUri -RelativeOrAbsolutePath $cust.Customer.CustomerLogoPath

    # CSS Yükleme
    $cssPath = Join-Path $Script:RootPath 'Templates\ModernCorporate\style.css'
    $cssContent = ''
    if (Test-Path $cssPath) {
        $cssContent = Get-Content -Path $cssPath -Raw -Encoding UTF8
    }

    $sectionsCombined = ($ServiceHtmlSections.Values -join "`n`n")

    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$ReportTitle - $($cust.Customer.Name)</title>
    <style>
        $cssContent
    </style>
</head>
<body>

    <!-- ÜST BİLGİ / HEADER -->
    <header class="report-header">
        <div class="header-container">
            <div class="brand-left">
                $(if ($kocLogoUri) { "<img src='$kocLogoUri' class='logo-provider' alt='CloudShield'>" } else { "<span class='brand-text'>CloudShield</span>" })
            </div>
            <div class="header-title-block">
                <h1>$ReportTitle</h1>
                <div class="subtitle">$($cust.Customer.Name) &bull; $PeriodLabel</div>
            </div>
            <div class="brand-right">
                $(if ($custLogoUri) { "<img src='$custLogoUri' class='logo-customer' alt='Müşteri'>" } else { "<span class='client-name'>$($cust.Customer.Name)</span>" })
            </div>
        </div>
    </header>

    <main class="report-body">
        $(if ($ExecutiveSummaryHtml) {
            "<section class='executive-summary-container'>$ExecutiveSummaryHtml</section>"
        })

        <!-- MODÜLER SERVİS BÖLÜMLERİ -->
        $sectionsCombined
    </main>

    <!-- ALT BİLGİ / FOOTER & GİZLİLİK TAAHHÜDÜ -->
    <footer class="report-footer" style="background-color:#0F172A; color:#94A3B8; padding:24px 32px; font-size:11px; border-top:2px solid #E2E8F0; margin-top:40px; border-radius:8px;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px; border-bottom:1px solid #334155; padding-bottom:12px;">
            <div style="max-width:72%;">
                <div style="font-weight:700; color:#F8FAFC; font-size:12px; margin-bottom:4px;">
                    Enterprise Managed Security & Compliance Services &bull; Gizlilik ve Regülasyon Taahhüdü
                </div>
                <div style="line-height:1.5; color:#CBD5E1;">
                    Bu rapor; <strong>6698 sayılı KVKK (md. 4 ve md. 12)</strong>, <strong>AB GDPR (Madde 5, 25 ve 32 - Privacy by Design)</strong> ve <strong>ISO/IEC 27001:2022 (A.8.11, A.8.15)</strong> gereksinimlerine tam uyumlu olarak üretilmiştir. Raporlanan tüm olaylarda kullanıcı kimlikleri, e-posta adresleri ve dosya adları tuzlu SHA-256 ve k-Anonymity ($k \ge 5$) algoritmalarıyla tek yönlü maskelenmiştir.
                </div>
            </div>
            <div style="text-align:right;">
                <span style="display:inline-block; background-color:#DC2626; color:#FFFFFF; font-weight:700; font-size:10px; padding:3px 8px; border-radius:4px; margin-bottom:4px;">TLP:AMBER &bull; TİCARİ SIR</span>
                <div style="color:#94A3B8; font-size:10px;">Müşteriye Özel ve Gizli</div>
            </div>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; font-size:10px; color:#64748B;">
            <div>
                <strong>Etik ve Çalışan Hakları Bildirimi:</strong> Bu rapor bir çalışan performans, verimlilik veya kişisel davranış gözetimi niteliği taşımamakta olup; münhasıran teknik bilgi güvenliği ve Purview politika eşleşmelerini yansıtır.
            </div>
            <div>
                Rapor Tarihi: $((Get-Date).ToString('dd.MM.yyyy HH:mm')) &bull; Denetim İzli (Audit Logged)
            </div>
        </div>
    </footer>

</body>
</html>
"@

    return $html
}

Export-ModuleMember -Function Get-ImageAsDataUri, Convert-HtmlToPdf, Build-CompleteReportHtml
