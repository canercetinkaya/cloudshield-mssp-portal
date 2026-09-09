# ==============================================================================
# KoçSistem MSSP Portal - Otomatik Dosya İzleyici ve GitHub Senkronizasyonu
# Bu betik klasörde herhangi bir değişiklik algıladığında otomatik commit & push yapar.
# ==============================================================================

param(
    [string]$Branch = "main",
    [int]$DebounceSeconds = 5
)

$portalDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $portalDir

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  KoçSistem MSSP Portal - Otomatik Dosya İzleyici (Auto-Sync)" -ForegroundColor White
Write-Host "  İzlenen Dizin: $portalDir" -ForegroundColor Green
Write-Host "  Hedef Dal: $Branch (Değişiklik algılandığında otomatik gönderilir)" -ForegroundColor Yellow
Write-Host "  Durdurmak için Ctrl + C tuşlarına basabilirsiniz." -ForegroundColor Gray
Write-Host "================================================================================`n" -ForegroundColor Cyan

$gitExe = "C:\Program Files\Git\cmd\git.exe"
if (-not (Test-Path $gitExe)) {
    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
}

# Dosya İzleyici (FileSystemWatcher) Tanımla
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $portalDir
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true
$watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

$script:lastChange = [DateTime]::MinValue
$script:pendingSync = $false

$action = {
    param($source, $event)
    $path = $event.FullPath
    if ($path -like "*.git*" -or $path -like "*Engine\Logs*" -or $path -like "*Engine\Data\temp*") {
        return
    }
    $script:lastChange = [DateTime]::Now
    $script:pendingSync = $true
    Write-Host "[~] Değişiklik algılandı: $($event.Name)" -ForegroundColor Gray
}

Register-ObjectEvent $watcher 'Changed' -Action $action | Out-Null
Register-ObjectEvent $watcher 'Created' -Action $action | Out-Null
Register-ObjectEvent $watcher 'Deleted' -Action $action | Out-Null
Register-ObjectEvent $watcher 'Renamed' -Action $action | Out-Null

Write-Host "[+] İzleyici devrede. Dosyalarınızı kaydedip güncelleyebilirsiniz...`n" -ForegroundColor Green

try {
    while ($true) {
        Start-Sleep -Seconds 1
        if ($script:pendingSync -and ([DateTime]::Now - $script:lastChange).TotalSeconds -ge $DebounceSeconds) {
            $script:pendingSync = $false
            
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
        }
    }
} finally {
    Unregister-Event -SourceIdentifier $watcher.ToString() -ErrorAction SilentlyContinue
    $watcher.Dispose()
    Write-Host "`n[!] İzleyici durduruldu." -ForegroundColor Yellow
}
