<#
.SYNOPSIS
    CloudShield Enterprise Security Reporting Platform - Tek Tıkla Yerel Başlatıcı (PowerShell)

.DESCRIPTION
    Bu betik, CloudShield MSSP Platformu'nu yerel geliştirme veya operasyon ortamında
    uçtan uca doğrular, veritabanını hazırlar, bağımlılıkları kontrol eder ve
    portalı tarayıcıda otomatik olarak açar.

.PARAMETER Port
    Portalın dinleyeceği TCP port numarası (Varsayılan: 8080).

.PARAMETER NoBrowser
    Portalı başlattıktan sonra tarayıcıyı otomatik açma adımını atlar.

.EXAMPLE
    .\Start-CloudShieldPortal.ps1
    .\Start-CloudShieldPortal.ps1 -Port 8080
#>

[CmdletBinding()]
param (
    [int]$Port = 8080,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

Write-Host @"
================================================================================
   🛡️  CloudShield Security Reporting & Managed Services Visibility Platform
   🚀  Yerel Başlatma ve Sağlık Denetim Sistemi (Local Diagnostic Launcher)
================================================================================
"@ -ForegroundColor Cyan

# 1. Python Sürüm Denetimi
Write-Host "[1/5] Python çalışma ortamı kontrol ediliyor..." -ForegroundColor Yellow
try {
    $pythonVer = & python --version 2>&1
    Write-Host "      [OK] $pythonVer bulundu." -ForegroundColor Green
} catch {
    Write-Host "      [HATA] Python bulunamadı! Lütfen Python 3.10+ kurulu ve PATH'e ekli olduğundan emin olun." -ForegroundColor Red
    exit 1
}

# 2. Çalışma Dizini Ayarı
Set-Location -Path $ScriptDir
$env:PYTHONPATH = $ScriptDir

# 3. Port Kullanılabilirlik Denetimi
Write-Host "[2/5] TCP Port $Port durumu kontrol ediliyor..." -ForegroundColor Yellow
$portInUse = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Listen" }
if ($portInUse) {
    Write-Host "      [UYARI] Port $Port halihazırda dinleniyor (PID: $($portInUse.OwningProcess[0]))." -ForegroundColor DarkYellow
    Write-Host "      Mevcut çalışan portala bağlanmayı deneyebilirsiniz: http://localhost:$Port" -ForegroundColor DarkYellow
    if (-not $NoBrowser) {
        Start-Process "http://localhost:$Port"
    }
    Write-Host "      Sunucu zaten çalışıyor. Çıkılıyor." -ForegroundColor Green
    exit 0
}

# 4. Veritabanı ve Şema Başlatma / Migrasyon
Write-Host "[3/5] Veritabanı migrasyonları ve RBAC şeması doğrulanıyor..." -ForegroundColor Yellow
try {
    & python -c "from database.db import init_db; init_db(); from Portal.api.server import _ensure_session_tables; _ensure_session_tables()"
    Write-Host "      [OK] SQLite RBAC ve Session tabloları hazırlandı." -ForegroundColor Green
} catch {
    Write-Host "      [UYARI] Veritabanı ön hazırlığı uyarısı: $_" -ForegroundColor DarkYellow
}

# 5. Sunucu Başlatma
Write-Host "[4/5] CloudShield Portal REST API sunucusu başlatılıyor (Port: $Port)..." -ForegroundColor Yellow
$serverScript = Join-Path $ScriptDir "Portal\api\server.py"

if (-not (Test-Path $serverScript)) {
    Write-Host "      [HATA] Server scripti bulunamadı: $serverScript" -ForegroundColor Red
    exit 1
}

$job = Start-Process -FilePath "python" -ArgumentList "`"$serverScript`" $Port" -PassThru -NoNewWindow

Write-Host "      [OK] Python süreci başlatıldı (PID: $($job.Id))." -ForegroundColor Green

# 6. Sağlık Uç Noktası Doğrulama & Tarayıcı Açma
Write-Host "[5/5] Sağlık kontrolü (Health Check) bekleniyor..." -ForegroundColor Yellow
$healthy = $false
$targetUrl = "http://localhost:$Port"
$healthUrl = "$targetUrl/api/health"

for ($i = 1; $i -le 15; $i++) {
    Start-Sleep -Milliseconds 600
    try {
        $resp = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($resp -and $resp.status -eq "Healthy") {
            $healthy = $true
            break
        }
    } catch {
        # Devam et
    }
}

if ($healthy) {
    Write-Host @"
================================================================================
   ✅  CloudShield Platformu Başarıyla Ayağa Kaldırıldı!
   🌐  Erişim Adresi: $targetUrl
   🔑  Giriş Seçenekleri:
       - Microsoft Entra ID SSO: Caner@cnrctnky.onmicrosoft.com
       - Yerel Yönetici: PORTAL_ADMIN_PASSWORD ortam değişkeni
   🛑  Durdurmak için bu pencerede Ctrl+C tuşlarına basınız.
================================================================================
"@ -ForegroundColor Green

    if (-not $NoBrowser) {
        Start-Process $targetUrl
    }

    try {
        # Süreç kapanana kadar bekle
        $job | Wait-Process
    } catch {
        # Ctrl+C durumunda süreci kapat
        Write-Host "`n[BİLGİ] Sunucu kapatılıyor..." -ForegroundColor Yellow
        Stop-Process -Id $job.Id -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "      [UYARI] Sağlık denetimi 10 saniyede yanıt vermedi. Süreç loglarını inceleyiniz." -ForegroundColor Yellow
    if (-not $NoBrowser) {
        Start-Process $targetUrl
    }
}
