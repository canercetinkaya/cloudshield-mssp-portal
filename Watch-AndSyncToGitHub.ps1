<#
==============================================================================
CloudShield MSSP Portal - Otomatik Dosya ?zleyici ve G?venli ?al??ma Dal? E?itleme
Quality Gate 3 G?venceleri:
  - Asla do?rudan main dal?na push yapmaz.
  - Ba??ms?z senkronizasyon dal? ?retir: sync/yyyyMMdd-HHmmss-shortsha
  - Otomatik release tag olu?turmaz (release i?lemi New-CloudShieldRelease.ps1 ile ayr?lm??t?r).
  - Unsafe / Secret / Log / Output yollar?n? kesinlikle reddeder.
==============================================================================
#>
[CmdletBinding()]
param(
    [int]$DebounceSeconds    = 5,
    [string[]]$ExtraWatchPaths = @(),
    [switch]$DryRun
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$portalDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $portalDir) { $portalDir = (Get-Location).Path }
Set-Location $portalDir

Write-Host ''
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host '  CloudShield MSSP Portal - G?venli ?al??ma Alan? ?zleyici (Safe Sync)           ' -ForegroundColor White
Write-Host "  Git Deposu   : $portalDir"                                                     -ForegroundColor Green
Write-Host '  Politika     : Do?rudan main push YASAKTIR. Dal format?: sync/yyyyMMdd-HHmmss ' -ForegroundColor Yellow
Write-Host '  Durdurmak i?in Ctrl + C tu?lar?na basabilirsiniz.'                            -ForegroundColor Gray
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. GIT ??Z?MLE
$gitExe = 'C:\Program Files\Git\cmd\git.exe'
if (-not (Test-Path $gitExe)) {
    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
}
if (-not $gitExe) {
    Write-Error '[HATA] Git ?al??t?r?labilir dosyas? bulunamad?!'
    exit 1
}

# 2. G?VENL? STAGING VE UNSAFE YOL KONTROL?
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
        Write-Host '[i] Senkronize edilecek de?i?iklik bulunamad?.' -ForegroundColor DarkGray
        return $null
    }

    # Unsafe dosya taramas?
    $changedFiles = @()
    foreach ($line in $statusLines) {
        $f = ($line.Trim() -split '\s+', 2)[-1].Trim('"')
        if (-not (Test-IsSafePath -FilePath $f)) {
            Write-Host "[UYARI] G?venlik Kural? ?hlali: Hassas/Ge?ici dosya git staging listesinden ??kar?ld?: $f" -ForegroundColor Red
        } else {
            $changedFiles += $f
        }
    }

    if ($changedFiles.Count -eq 0) {
        Write-Host '[i] G?venli yollar aras?nda commit edilecek dosya kalmad?.' -ForegroundColor Yellow
        return $null
    }

    $shortSha = (& $gitExe rev-parse --short HEAD).Trim()
    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $syncBranch = "sync/$timestamp-$shortSha"

    Write-Host "[>] ?zole Senkronizasyon Dal? Haz?rlan?yor: $syncBranch" -ForegroundColor Cyan
    Write-Host "[>] Eklenecek G?venli Dosyalar ($($changedFiles.Count)):" -ForegroundColor Gray
    foreach ($cf in $changedFiles) {
        Write-Host "    + $cf" -ForegroundColor DarkCyan
    }

    if ($IsDryRun) {
        Write-Host "[DRY-RUN] Senkronizasyon dal? ($syncBranch) sim?le edildi (main dal?na dokunulmaz, tag olu?turulmaz)." -ForegroundColor Green
        return [PSCustomObject]@{
            Success = $true
            Branch = $syncBranch
            Files = $changedFiles
            DryRun = $true
        }
    }

    # Create and switch to sync branch
    & $gitExe checkout -b $syncBranch
    foreach ($cf in $changedFiles) {
        if (Test-Path $cf) {
            & $gitExe add $cf
        }
    }

    $commitMsg = "sync(workspace): automated snapshot $timestamp [$shortSha]"
    & $gitExe commit -m $commitMsg

    Write-Host "[>] Senkronizasyon dal? origin'e g?nderiliyor (git push origin $syncBranch)..." -ForegroundColor Yellow
    & $gitExe push -u origin $syncBranch

    # Switch back to previous branch without destroying working tree
    & $gitExe checkout -
    Write-Host "[OK] Senkronizasyon dal? ba?ar?yla g?nderildi: $syncBranch (main dal? korundu, tag olu?turulmad?)`n" -ForegroundColor Green

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

# 3. DOSYA ?ZLEY?C? BA?LAT
$watchers = [System.Collections.Generic.List[System.IO.FileSystemWatcher]]::new()
$script:lastChange  = [DateTime]::MinValue
$script:pendingSync = $false

$action = {
    param($source, $event)
    $p = $event.FullPath
    if (-not (Test-IsSafePath -FilePath $p)) { return }
    $script:lastChange  = [DateTime]::Now
    $script:pendingSync = $true
    Write-Host "[~] De?i?iklik alg?land?: $($event.Name)" -ForegroundColor Gray
}

$candidatePaths = @($portalDir) + $ExtraWatchPaths
foreach ($watchPath in ($candidatePaths | Select-Object -Unique)) {
    if ([string]::IsNullOrWhiteSpace($watchPath)) { continue }
    if (Test-Path $watchPath -PathType Container) {
        Write-Host "  [OK] ?zleniyor : $watchPath" -ForegroundColor Green
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

Write-Host "`n[+] ?zleyici devrede. Do?rudan main push engellendi. Dal izolasyonu aktif.`n" -ForegroundColor Green

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
    Write-Host "`n[!] ?zleyici durduruldu." -ForegroundColor Yellow
}
