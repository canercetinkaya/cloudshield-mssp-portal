<#
.SYNOPSIS
    KoçSistem Managed Security Operations & Reporting Platform (MSSP Portal)
    Yerel Başlatıcı ve Yönetim Konsolu

.DESCRIPTION
    Bu betik yerel ortamda Python REST API sunucusunu arka planda ayağa kaldırır,
    sağlık durumunu doğrular ve varsayılan web tarayıcısında portali açar.

.EXAMPLE
    .\Start-LocalPortal.ps1
    .\Start-LocalPortal.ps1 -Port 8085
#>

[CmdletBinding()]
param (
    [int]$Port = 8080,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerScript = Join-Path $ScriptDir "Portal\api\server.py"

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  KoçSistem Managed Security Operations & Reporting Platform (MSSP Portal)" -ForegroundColor White
Write-Host "  Yerel Web Arayüzü Başlatılıyor..." -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Python Varlığını Kontrol Et
$pythonExe = $null
$pyCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if ($pyCmd) {
    $pythonExe = $pyCmd.Source
} else {
    $pyCmd = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyCmd) {
        $pythonExe = $pyCmd.Source
    }
}

if (-not $pythonExe) {
    Write-Host "[HATA] Sistemde Python 3 bulunamadı!" -ForegroundColor Red
    Write-Host "Lütfen python.org adresinden Python 3 kurunuz veya PATH'e ekleyiniz." -ForegroundColor DarkYellow
    exit 1
}

$pyVersion = & $pythonExe --version 2>&1
Write-Host "[OK] Python Runtime: $pyVersion" -ForegroundColor Green

# 2. Port Kontrolü ve Sağlık Testi
$portalUrl = "http://localhost:$Port"
$isAlreadyRunning = $false

try {
    $res = Invoke-RestMethod -Uri "$portalUrl/api/health" -TimeoutSec 2 -ErrorAction Stop
    if ($res.status -eq "Healthy") {
        $isAlreadyRunning = $true
        Write-Host "[BİLGİ] Sunucu zaten port $Port üzerinde aktif olarak çalışıyor (Sürüm: $($res.version))." -ForegroundColor Green
    }
}
catch {
    $isAlreadyRunning = $false
}

# 3. Sunucuyu Başlat (Eğer çalışmıyorsa)
if (-not $isAlreadyRunning) {
    Write-Host "[BİLGİ] API Sunucusu arka planda başlatılıyor (Port: $Port)..." -ForegroundColor Cyan
    
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $pythonExe
    $psi.Arguments = "`"$ServerScript`" $Port"
    $psi.WorkingDirectory = $ScriptDir
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    
    # 3 saniye bekle ve sağlık durumunu test et
    Start-Sleep -Seconds 2
    try {
        $res = Invoke-RestMethod -Uri "$portalUrl/api/health" -TimeoutSec 5
        Write-Host "[BAŞARILI] Platform hazır ve sağlıklı! (Status: $($res.status))" -ForegroundColor Green
    }
    catch {
        Write-Host "[UYARI] Sunucu başlatıldı ancak sağlık yanıtı beklenenden yavaş. Tarayıcı açılıyor..." -ForegroundColor Yellow
    }
}

# 4. Tarayıcıda Aç
if (-not $NoBrowser) {
    Write-Host "[BİLGİ] Varsayılan tarayıcıda açılıyor: $portalUrl" -ForegroundColor White
    Start-Process $portalUrl
}

Write-Host ""
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  Portal Adresi    : $portalUrl" -ForegroundColor White
Write-Host "  REST API Test    : $portalUrl/api/tenants" -ForegroundColor White
Write-Host "  Global İstatistik: $portalUrl/api/stats/global" -ForegroundColor White
Write-Host "  Durdurmak İçin   : Görev Yöneticisi'nden 'python.exe' işlemini sonlandırabilirsiniz." -ForegroundColor DarkGray
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host ""
