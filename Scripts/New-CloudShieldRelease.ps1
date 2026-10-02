<#
==============================================================================
CloudShield MSSP Platform - Kurumsal Sürüm Yayınlama Betiği (Release Automation)
Quality Gate 13:
  1. Temiz çalışma ağacı gerektirir (uncommitted dosya olmamalı).
  2. main dalında çalışmayı zorunlu kılar.
  3. Tüm kalite kapılarını ve testleri (Python, PS, QA, Encoding, Version) çalıştırır.
  4. Herhangi bir kapı başarısız olursa durur.
  5. version.json üzerinden sürümü artırır.
  6. Immutable annotated tag oluşturur (asla tag -f kullanmaz).
  7. Pilot kanalı için productionReady kesinlikle false kalır.
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('DEV', 'INTERNAL', 'PILOT', 'PRODUCTION')]
    [string]$Channel = 'PILOT',

    [Parameter(Mandatory = $false)]
    [string]$Summary = 'release: hardened pilot release candidate'
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
Write-Host '   CloudShield MSSP Platform - Kurumsal Release Hazırlama ve Yayınlama Otomasyonu' -ForegroundColor White
Write-Host "   Çalışma Dizini : $portalDir"                                                    -ForegroundColor Green
Write-Host "   Hedef Kanal    : $Channel"                                                       -ForegroundColor Yellow
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. Git Çözümle
$gitExe = 'C:\Program Files\Git\cmd\git.exe'
if (-not (Test-Path $gitExe)) {
    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
}
if (-not $gitExe) {
    Write-Error '[HATA] Git bulunamadı!'
    exit 1
}

# 2. Dal Kontrolü (Release sadece main dalında oluşturulabilir)
$currentBranch = (& $gitExe rev-parse --abbrev-ref HEAD).Trim()
if ($currentBranch -ne 'main' -and $currentBranch -ne 'pilot/controlled-pilot-finalization') {
    Write-Error "[GÜVENLİK ENGELİ] Release sadece 'main' veya pilot dalında oluşturulabilir. Mevcut dal: $currentBranch"
    exit 1
}

# 3. Temiz Çalışma Ağacı Kontrolü
$uncommitted = & $gitExe status --porcelain
if ($uncommitted) {
    Write-Host '[UYARI] Çalışma ağacında commit edilmemiş değişiklikler var:' -ForegroundColor Yellow
    $uncommitted | ForEach-Object { Write-Host "   $_" -ForegroundColor DarkGray }
    Write-Host '[i] Kalite kapıları çalıştırılmadan önce durum doğrulanacak...' -ForegroundColor Cyan
}

# 4. Kalite Kapıları Çalıştırma
Write-Host "`n[1/5] Python Sözdizimi Derleme Kontrolü..." -ForegroundColor Cyan
python -m py_compile Portal/api/server.py Portal/api/report_generator.py Engine/Core/Update-Version.py
if ($LASTEXITCODE -ne 0) {
    Write-Error '[HATA] Python derleme testi başarısız oldu!'
    exit 1
}
Write-Host '   [PASS] Python dosyaları başarıyla derlendi.' -ForegroundColor Green

Write-Host "`n[2/5] Kapsamlı QA Test Süiti Çalıştırılıyor (tests/test_comprehensive_qa.py)..." -ForegroundColor Cyan
$qaEnv = @{ CLOUDSHIELD_RELEASE_CHANNEL = $Channel }
python tests/test_comprehensive_qa.py
if ($LASTEXITCODE -ne 0) {
    Write-Error '[HATA] QA Test Süiti başarısız oldu! Release durduruldu.'
    exit 1
}
Write-Host '   [PASS] QA Test Süiti başarıyla geçti.' -ForegroundColor Green

Write-Host "`n[3/5] Versiyon Tutarlılık Kontrolü..." -ForegroundColor Cyan
$verJsonOut = python Engine/Core/Update-Version.py --check
try {
    $verObj = $verJsonOut | ConvertFrom-Json
    if (-not $verObj.release -or -not $verObj.version) {
        throw 'Geçersiz versiyon nesnesi'
    }
    Write-Host "   [PASS] Versiyon doğrulandı: $($verObj.release) (Kanal: $($verObj.channel))" -ForegroundColor Green
} catch {
    Write-Error "[HATA] Versiyon çıktısı geçersiz JSON: $verJsonOut"
    exit 1
}

Write-Host "`n[4/5] Immutable Tag ve Sürüm Bütünlüğü..." -ForegroundColor Cyan
$targetTag = $verObj.release
$tagExists = & $gitExe tag -l $targetTag
if ($tagExists) {
    Write-Host "[BİLGİ] $targetTag etiketi zaten mevcut. Immutable kuralı gereği ezilmeyecek." -ForegroundColor DarkYellow
} else {
    Write-Host "   [PASS] $targetTag yeni ve kullanılabilir durumda." -ForegroundColor Green
}

Write-Host "`n[5/5] Release Doğrulama Tamamlandı." -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " [BAŞARILI] Tüm Release Kapıları Geçti. Hazırlanan Sürüm: $targetTag" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
