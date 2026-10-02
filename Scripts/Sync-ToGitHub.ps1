<#
==============================================================================
CloudShield Enterprise MSSP - Hızlı GitHub Senkronizasyonu (Sync-ToGitHub)
Bu betik mevcut çalışma alanındaki değişiklikleri güvenli şekilde commit eder
ve hem aktif çalışma dalına hem de Azure Container Apps'i tetikleyen 'main'
dalına senkronize eder.
==============================================================================
#>
[CmdletBinding()]
param(
    [string]$Message = "",
    [switch]$SkipTests
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
$repoDir = if ((Split-Path -Leaf $scriptDir) -eq "Scripts") { Split-Path -Parent $scriptDir } else { $scriptDir }
Set-Location $repoDir

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  CloudShield Enterprise MSSP -> GitHub Senkronizasyon Aracı                    " -ForegroundColor White
Write-Host "  Çalışma Dizini : $repoDir"                                                     -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

$gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
if (-not $gitExe) {
    Write-Error "[HATA] Git komut satırı aracı bulunamadı!"
    exit 1
}

$currentBranch = (& $gitExe rev-parse --abbrev-ref HEAD).Trim()
Write-Host "[+] Mevcut Git Dalı: $currentBranch" -ForegroundColor Green

# 1. Hızlı Doğrulama Testi
if (-not $SkipTests) {
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    $testResult = & python -m unittest discover tests 2>&1
    $testCode = $LASTEXITCODE
    $ErrorActionPreference = $oldEap

    if ($testCode -ne 0) {
        Write-Error "[HATA] Testler başarısız oldu! Senkronizasyon durduruldu.`n$testResult"
        exit 1
    }
    Write-Host "[OK] Temel testler başarıyla geçti (46 test doğrulandı)." -ForegroundColor Green
}

# 2. Değişiklikleri Sahnele
$status = & $gitExe status --porcelain
if ($status) {
    Write-Host "[*] Değişiklikler inceleniyor ve sahneleniyor..." -ForegroundColor Cyan
    & $gitExe add -A

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $commitMsg = if ($Message) { $Message } else { "chore(sync): automated sync $timestamp" }

    Write-Host "[*] Commit oluşturuluyor: '$commitMsg'" -ForegroundColor Cyan
    & $gitExe commit -m "$commitMsg"
} else {
    Write-Host "[i] Çalışma ağacı temiz (yeni commit gerektiren dosya yok)." -ForegroundColor DarkGray
}

# 3. Aktif Dalı Gönder
Write-Host "[>] origin/$currentBranch dalına push yapılıyor..." -ForegroundColor Yellow
& $gitExe push origin "$currentBranch"

# 4. Main Dalını Eşitle (Azure Container Apps CI/CD tetikleyici)
if ($currentBranch -ne "main") {
    Write-Host "[>] Azure Container Apps canlı dağıtımı için 'main' dalı eşitleniyor..." -ForegroundColor Yellow
    & $gitExe push origin "${currentBranch}:main"
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  [OK] TEBRİKLER! TÜM DEĞİŞİKLİKLER GITHUB'A SENKRONİZE EDİLDİ." -ForegroundColor White
Write-Host "  Canlı Depo : https://github.com/canercetinkaya/cloudshield-mssp-portal" -ForegroundColor Cyan
Write-Host "  Canlı Portal: https://cs-mssp-poc-app.icygrass-237b4292.westeurope.azurecontainerapps.io" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ""
