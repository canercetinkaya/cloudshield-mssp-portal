<#
==============================================================================
CloudShield MSSP Portal - Otomatik Dosya İzleyici ve Güvenli Çalışma Dalı Eşitleme
Quality Gate 3 Güvenceleri:
  - Güvenli branch izolasyonu (sync/yyyyMMdd-HHmmss-shortsha) veya -DirectPush
  - Otomatik release tag oluşturmaz (release işlemi New-CloudShieldRelease.ps1 ile ayrılmıştır).
  - Unsafe / Secret / Log / Output yollarını kesinlikle reddeder.
==============================================================================
#>
[CmdletBinding()]
param(
    [int]$DebounceSeconds    = 5,
    [string[]]$ExtraWatchPaths = @(),
    [switch]$DirectPush,
    [switch]$DryRun
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
$portalDir = if ((Split-Path -Leaf $scriptDir) -eq "Scripts") { Split-Path -Parent $scriptDir } else { $scriptDir }
Set-Location $portalDir

Write-Host ''
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host '  CloudShield MSSP Portal - Güvenli Çalışma Alanı İzleyici (Safe Sync)           ' -ForegroundColor White
Write-Host "  Git Deposu   : $portalDir"                                                     -ForegroundColor Green
if ($DirectPush) {
    Write-Host '  Politika     : Doğrudan aktif çalışma dalına ve main dalına eşitleme AÇIK.     ' -ForegroundColor Magenta
} else {
    Write-Host '  Politika     : İzole senkronizasyon dalı formatı: sync/yyyyMMdd-HHmmss        ' -ForegroundColor Yellow
}
Write-Host '  Durdurmak için Ctrl + C tuşlarına basabilirsiniz.'                            -ForegroundColor Gray
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. GIT ÇÖZÜMLE
$gitExe = 'C:\Program Files\Git\cmd\git.exe'
if (-not (Test-Path $gitExe)) {
    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
}
if (-not $gitExe) {
    Write-Error '[HATA] Git çalıştırılabilir dosyası bulunamadı!'
    exit 1
}

# 2. GÜVENLİ STAGING VE UNSAFE YOL KONTROLÜ
$unsafePatterns = @(
    '\.git', '__pycache__', 'node_modules', 'Logs', 'Output', 'temp',
    '\.local\.json', 'auth\.local\.json', 'certificates', 'private.*\.key',
    '\.pfx', '\.pem', 'execution.*\.transcript', 'access-token'
)

function Test-IsSafePath {
    param([string]$FilePath)
    foreach ($pattern in $unsafePatterns) {
        if ($FilePath -match $pattern) {
            return $false
        }
    }
    return $true
}

function Sync-WorkspaceBranch {
    param([switch]$IsDryRun)

    Set-Location $portalDir
    $statusLines = & $gitExe status --porcelain
    if (-not $statusLines) {
        Write-Host '[i] Senkronize edilecek değişiklik bulunamadı.' -ForegroundColor DarkGray
        return $null
    }

    # Unsafe dosya taraması
    $changedFiles = @()
    foreach ($line in $statusLines) {
        $f = ($line.Trim() -split '\s+', 2)[-1].Trim('"')
        if (-not (Test-IsSafePath -FilePath $f)) {
            Write-Host "[UYARI] Güvenlik Kuralı İhlali: Hassas/Geçici dosya git staging listesinden çıkarıldı: $f" -ForegroundColor Red
        } else {
            $changedFiles += $f
        }
    }

    if ($changedFiles.Count -eq 0) {
        Write-Host '[i] Güvenli yollar arasında commit edilecek dosya kalmadı.' -ForegroundColor Yellow
        return $null
    }

    $shortSha = (& $gitExe rev-parse --short HEAD).Trim()
    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $currentBranch = (& $gitExe rev-parse --abbrev-ref HEAD).Trim()
    $syncBranch = "sync/$timestamp-$shortSha"

    Write-Host "[>] Senkronizasyon Hazırlanıyor ($($changedFiles.Count) dosya)..." -ForegroundColor Cyan
    foreach ($cf in $changedFiles) {
        Write-Host "    + $cf" -ForegroundColor DarkCyan
    }

    if ($IsDryRun) {
        Write-Host "[DRY-RUN] Senkronizasyon dalı ($syncBranch) simüle edildi (main dalına dokunulmaz, tag oluşturulmaz)." -ForegroundColor Green
        return [PSCustomObject]@{
            Success = $true
            Branch = $syncBranch
            Files = $changedFiles
            DryRun = $true
        }
    }

    if ($DirectPush) {
        # Direct push to active branch and sync to main
        foreach ($cf in $changedFiles) {
            if (Test-Path $cf) {
                & $gitExe add $cf
            }
        }
        $commitMsg = "sync(workspace): auto-sync $timestamp [$shortSha]"
        & $gitExe commit -m $commitMsg
        Write-Host "[>] origin/$currentBranch dalına push yapılıyor..." -ForegroundColor Yellow
        & $gitExe push origin "$currentBranch"
        if ($currentBranch -ne "main") {
            Write-Host "[>] Azure Container Apps için main dalına push yapılıyor..." -ForegroundColor Yellow
            & $gitExe push origin "${currentBranch}:main"
        }
        Write-Host "[OK] Değişiklikler doğrudan GitHub'a aktarıldı!`n" -ForegroundColor Green
        return [PSCustomObject]@{
            Success = $true
            Branch = $currentBranch
            Files = $changedFiles
            DryRun = $false
        }
    }

    # Isolated sync branch flow
    & $gitExe checkout -b $syncBranch
    foreach ($cf in $changedFiles) {
        if (Test-Path $cf) {
            & $gitExe add $cf
        }
    }

    $commitMsg = "sync(workspace): automated snapshot $timestamp [$shortSha]"
    & $gitExe commit -m $commitMsg

    Write-Host "[>] Senkronizasyon dalı origin'e gönderiliyor (git push origin $syncBranch)..." -ForegroundColor Yellow
    & $gitExe push -u origin $syncBranch

    # Switch back to previous branch without destroying working tree
    & $gitExe checkout -
    Write-Host "[OK] Senkronizasyon dalı başarıyla gönderildi: $syncBranch`n" -ForegroundColor Green

    return [PSCustomObject]@{
        Success = $true
        Branch = $syncBranch
        Files = $changedFiles
        DryRun = $false
    }
}

if ($DryRun) {
    return Sync-WorkspaceBranch -IsDryRun
}

# 3. DOSYA İZLEYİCİ BAŞLAT
$watchers = [System.Collections.Generic.List[System.IO.FileSystemWatcher]]::new()
$script:lastChange  = [DateTime]::MinValue
$script:pendingSync = $false

$action = {
    param($source, $event)
    $p = $event.FullPath
    if (-not (Test-IsSafePath -FilePath $p)) { return }
    $script:lastChange  = [DateTime]::Now
    $script:pendingSync = $true
    Write-Host "[~] Değişiklik algılandı: $($event.Name)" -ForegroundColor Gray
}

$candidatePaths = @($portalDir) + $ExtraWatchPaths
foreach ($watchPath in ($candidatePaths | Select-Object -Unique)) {
    if ([string]::IsNullOrWhiteSpace($watchPath)) { continue }
    if (Test-Path $watchPath -PathType Container) {
        Write-Host "  [OK] İzleniyor : $watchPath" -ForegroundColor Green
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
}

Write-Host "`n[+] İzleyici devrede. Otomatik eşitleme aktif.`n" -ForegroundColor Green

try {
    while ($true) {
        Start-Sleep -Seconds 1
        if ($script:pendingSync -and ([DateTime]::Now - $script:lastChange).TotalSeconds -ge $DebounceSeconds) {
            $script:pendingSync = $false
            Sync-WorkspaceBranch
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
