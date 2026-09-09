# ==============================================================================
# CloudShield MSSP Portal - Otomatik Dosya İzleyici ve GitHub Senkronizasyonu
# Bu betik klasörde herhangi bir değişiklik algıladığında otomatik commit & push yapar.
# Birden fazla proje klasörünü izleyebilir; eksik klasörler için uyarı verir ama
# devam eder — klasör ileride oluşturulduğunda otomatik olarak algılanır.
# ==============================================================================

param(
    [string]$Branch          = "main",
    [int]$DebounceSeconds    = 5,
    [string[]]$ExtraWatchPaths = @()
)

$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# 1. YOL TANIMLARI
# ==============================================================================
$portalDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$baseDir   = Split-Path -Parent $portalDir    # ..\Microsoft Purview Reports

# Ana repo + Eğer varsa yan klasörler
$candidatePaths = @($portalDir) + $ExtraWatchPaths
if (Test-Path $baseDir -PathType Container) {
    Get-ChildItem -Path $baseDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $candidatePaths += $_.FullName
    }
}


Set-Location $portalDir

# ==============================================================================
# 2. BAŞLIK
# ==============================================================================
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  CloudShield MSSP Portal - Otomatik Dosya İzleyici (Auto-Sync)"               -ForegroundColor White
Write-Host "  Git Deposu   : $portalDir"                                                     -ForegroundColor Green
Write-Host "  Hedef Dal    : $Branch (Değişiklik algılandığında otomatik gönderilir)"       -ForegroundColor Yellow
Write-Host "  Durdurmak için Ctrl + C tuşlarına basabilirsiniz."                            -ForegroundColor Gray
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# ==============================================================================
# 3. GIT ÇÖZÜMLE
# ==============================================================================
$gitExe = "C:\Program Files\Git\cmd\git.exe"
if (-not (Test-Path $gitExe)) {
    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
}
if (-not $gitExe) {
    Write-Host "[HATA] Git bulunamadı!" -ForegroundColor Red
    exit 1
}

# ==============================================================================
# 4. KLASÖR KONTROLÜ VE İZLEYİCİ OLUŞTURMA
# ==============================================================================
$watchers = [System.Collections.Generic.List[System.IO.FileSystemWatcher]]::new()

$script:lastChange  = [DateTime]::MinValue
$script:pendingSync = $false

$action = {
    param($source, $event)
    $p = $event.FullPath
    if ($p -like "*.git*" -or $p -like "*Engine\Logs*" -or $p -like "*Engine\Data\temp*" -or
        $p -like "*__pycache__*" -or $p -like "*node_modules*") {
        return
    }
    $script:lastChange  = [DateTime]::Now
    $script:pendingSync = $true
    Write-Host "[~] Değişiklik algılandı: $($event.Name)" -ForegroundColor Gray
}

Write-Host "  Klasör Durumu:" -ForegroundColor Cyan
foreach ($watchPath in ($candidatePaths | Select-Object -Unique)) {
    if ([string]::IsNullOrWhiteSpace($watchPath)) { continue }

    if (Test-Path $watchPath -PathType Container) {
        Write-Host "  [OK] İzleniyor    : $watchPath" -ForegroundColor Green

        $w = New-Object System.IO.FileSystemWatcher
        $w.Path                  = $watchPath
        $w.IncludeSubdirectories = $true
        $w.EnableRaisingEvents   = $true
        $w.NotifyFilter          = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

        Register-ObjectEvent $w 'Changed' -Action $action | Out-Null
        Register-ObjectEvent $w 'Created' -Action $action | Out-Null
        Register-ObjectEvent $w 'Deleted' -Action $action | Out-Null
        Register-ObjectEvent $w 'Renamed' -Action $action | Out-Null

        $watchers.Add($w)
    }
    else {
        Write-Host "  [--] Bulunamadı (atlanıyor): $watchPath" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "[+] İzleyici devrede. Dosyalarınızı kaydedip güncelleyebilirsiniz...`n" -ForegroundColor Green

# ==============================================================================
# 5. ANA DÖNGÜ
# ==============================================================================
try {
    while ($true) {
        Start-Sleep -Seconds 1

        if ($script:pendingSync -and ([DateTime]::Now - $script:lastChange).TotalSeconds -ge $DebounceSeconds) {
            $script:pendingSync = $false

            Set-Location $portalDir   # git komutları her zaman repo kökünden

            & $gitExe add .
            $status = & $gitExe status --porcelain
            if ($status) {
                $nowStr = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "`n[>] Değişiklikler otomatik commit ediliyor ($nowStr)..." -ForegroundColor Cyan
                & $gitExe commit -m "auto: Değişiklikler otomatik eşitlendi ($nowStr)"
                Write-Host "[>] GitHub'a aktarılıyor (git push origin $Branch)..." -ForegroundColor Yellow
                & $gitExe push origin $Branch
                Write-Host "[OK] Başarıyla GitHub ile eşitlendi!`n" -ForegroundColor Green
            }
            else {
                Write-Host "[i] Değişiklik algılandı fakat git'e eklenecek yeni içerik yok." -ForegroundColor DarkGray
            }
        }
    }
}
finally {
    foreach ($w in $watchers) {
        $w.EnableRaisingEvents = $false
        $w.Dispose()
    }
    Get-EventSubscriber -ErrorAction SilentlyContinue | Unregister-Event -ErrorAction SilentlyContinue
    Write-Host "`n[!] İzleyici durduruldu." -ForegroundColor Yellow
}
