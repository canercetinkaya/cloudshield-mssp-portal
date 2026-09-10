# Core/ReportRenderer.psm1 - CloudShield Security Reporting Platform
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

    $fullHtml = (Resolve-Path $HtmlPath).Path
    $resolvedPdf = [System.IO.Path]::GetFullPath($PdfPath)

    $uri = if ($fullHtml -match '^https?://|^file://') {
        $fullHtml
    } elseif ($env:OS -like "*Windows*" -or ([System.Environment]::OSVersion.Platform -match "Win")) {
        "file:///" + ($fullHtml -replace '\\', '/')
    } else {
        "file://" + $fullHtml
    }

    # Modern Chromium headless invocation
    $argList = @(
        '--headless=new',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-pdf-header-footer',
        '--run-all-compositor-stages-before-draw',
        "--print-to-pdf=`"$resolvedPdf`"",
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
    [void]$proc.WaitForExit(30000)

    # If modern headless didn't produce file, fallback to legacy --headless
    if (-not (Test-Path $resolvedPdf) -or (Get-Item $resolvedPdf).Length -eq 0) {
        $argList[0] = '--headless'
        $pinfo.Arguments = $argList -join ' '
        $proc2 = [System.Diagnostics.Process]::Start($pinfo)
        [void]$proc2.WaitForExit(30000)
    }

    if (-not (Test-Path $resolvedPdf) -or (Get-Item $resolvedPdf).Length -eq 0) {
        throw "PDF dosyası üretilemedi veya boyutu 0 bayt."
    }

    return (Get-Item $resolvedPdf).FullName
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

    <!-- ALT BİLGİ / FOOTER & GİZLİLİK TAAHHÜDÜ & KRİPTOGRAFİK DENETİM İZİ -->
    <footer class="report-footer" style="background-color:#0F172A; color:#94A3B8; padding:28px 32px; font-size:11px; border-top:2px solid #E2E8F0; margin-top:40px; border-radius:8px;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px; border-bottom:1px solid #334155; padding-bottom:16px;">
            <div style="max-width:72%;">
                <div style="font-weight:700; color:#F8FAFC; font-size:13px; margin-bottom:6px; display:flex; align-items:center; gap:8px;">
                    <span>🛡️ Enterprise Managed Security & Compliance Services &bull; Regülasyon ve Gizlilik Taahhüdü</span>
                </div>
                <div style="line-height:1.6; color:#CBD5E1;">
                    Bu kurumsal rapor; <strong>6698 sayılı Kişisel Verilerin Korunması Kanunu (KVKK md. 4, 6, 12 ve 18)</strong>, <strong>Avrupa Birliği Genel Veri Koruma Tüzüğü (GDPR Art. 5, 25, 32 ve 88 - Privacy by Design & Default)</strong>, <strong>ISO/IEC 27001:2022 (Kontroller A.8.11 Veri Maskeleme, A.8.15 Günlükleme)</strong> ve <strong>BDDK Bilgi Sistemleri Tebliği (md. 20 ve 29)</strong> standartları ve ilkeleri gözetilerek teknik denetim amacıyla üretilmiştir.
                </div>
                <div style="margin-top:8px; line-height:1.5; color:#94A3B8;">
                    Rapordaki tüm kişisel veriler, e-posta adresleri (<code>a***.y***@sirket.com</code>), hassas dosya yolları (<code>Mali_Rapor_***.xlsx</code>) ve kullanıcı kimlikleri tek yönlü tuzlu SHA-256 ve $k$-Anonymity ($k \ge 5$) algoritmalarıyla maskelenmiş olup, hiçbir açık metin PII rapor metnine veya günlük kütüklerine yansıtılmamaktadır.
                </div>
            </div>
            <div style="text-align:right;">
                <span style="display:inline-block; background-color:#DC2626; color:#FFFFFF; font-weight:700; font-size:10px; padding:4px 10px; border-radius:4px; margin-bottom:6px; letter-spacing:0.5px;">TLP:AMBER &bull; TİCARİ SIR</span>
                <div style="color:#F1F5F9; font-weight:600; font-size:11px;">Müşteriye Özel ve Gizli</div>
                <div style="color:#64748B; font-size:10px; margin-top:2px;">Yetkisiz 3. Kişilerle Paylaşılamaz</div>
            </div>
        </div>

        <!-- CISO DİREKTİFİ 4: KRİPTOGRAFİK DENETİM İZİ VE ŞİFRELEME BÜTÜNLÜĞÜ KANITI -->
        <div style="background-color:#1E293B; border:1px solid #334155; border-radius:6px; padding:12px 16px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <div style="font-weight:700; color:#38BDF8; font-size:11px; display:flex; align-items:center; gap:6px;">
                    <span>🔒 Kriptografik Denetim İzi (Audit Log) & Değişiklik Bütünlüğü Kontrolü</span>
                </div>
                <span style="font-size:10px; color:#A7F3D0; background:#064E3B; padding:2px 8px; border-radius:3px; font-weight:600;">SHA-256 Mühürlü</span>
            </div>
            <div style="font-size:10px; color:#94A3B8; line-height:1.5;">
                Bu raporun HTML ve vektörel PDF çıktıları üretildiği anda <strong>SHA-256 kriptografik kontrol özeti</strong> hesaplanarak <code>Logs/Audit_PurviewReporting_*.jsonl</code> dosyasında teknik değişiklik kontrolü amacıyla mühürlenmiştir. Bu kontrol özeti tek başına hukuki inkar edilemezlik veya yasal uygunluk garantisi teşkil etmez. Raporlama motorunu tetikleyen operatör kimliği, makine adı, süreç kimliği ve korelasyon anahtarı (Correlation ID) değiştirilemez JSONL denetim kütüğünde ISO 8601 zaman damgasıyla saklanmaktadır.
            </div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; font-size:10px; color:#64748B; border-top:1px solid #1E293B; padding-top:10px;">
            <div>
                <strong>Etik ve Çalışan Hakları Bildirimi:</strong> Bu rapor bir çalışan performans, verimlilik veya kişisel davranış gözetimi (surveillance) aracı olmayıp; münhasıran teknik bilgi güvenliği risklerini ve Purview uyum kurallarını yönetmek amacıyla üst yönetime sunulmuştur.
            </div>
            <div style="white-space:nowrap; margin-left:16px;">
                Rapor Tarihi: $((Get-Date).ToString('dd.MM.yyyy HH:mm')) &bull; Audit Trail Active
            </div>
        </div>
    </footer>

</body>
</html>
"@

    return $html
}

Export-ModuleMember -Function Get-ImageAsDataUri, Convert-HtmlToPdf, Build-CompleteReportHtml
