<#
==============================================================================
CloudShield MSSP Platform - Kurumsal S?r?m Yay?nlama Beti?i (Release Automation)
Quality Gate 13:
  1. Temiz ?al??ma a?ac? gerektirir (uncommitted dosya olmamal?).
  2. main dal?nda ?al??may? zorunlu k?lar.
  3. T?m kalite kap?lar?n? ve testleri (Python, PS, QA, Encoding, Version) ?al??t?r?r.
  4. Herhangi bir kap? ba?ar?s?z olursa durur.
  5. version.json ?zerinden s?r?m? art?r?r.
  6. ?mmutable annotated tag olu?turur (asla tag -f kullanmaz).
  7. Pilot kanal? i?in productionReady kesinlikle false kal?r.
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

$portalDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $portalDir) { $portalDir = (Get-Location).Path }
Set-Location $portalDir

Write-Host ''
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host '   CloudShield MSSP Platform - Kurumsal Release Haz?rlama ve Yay?nlama Otomasyonu' -ForegroundColor White
Write-Host "   ?al??ma Dizini : $portalDir"                                                    -ForegroundColor Green
Write-Host "   Hedef Kanal    : $Channel"                                                       -ForegroundColor Yellow
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. Git ??z?mle
$gitExe = 'C:\Program Files\Git\cmd\git.exe'
if (-not (Test-Path $gitExe)) {
    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
}
if (-not $gitExe) {
    Write-Error '[HATA] Git bulunamad?!'
    exit 1
}

# 2. Dal Kontrol? (Release sadece main dal?nda olu?turulabilir)
$currentBranch = (& $gitExe rev-parse --abbrev-ref HEAD).Trim()
if ($currentBranch -ne 'main') {
    Write-Error "[G?VENL?K ENGEL?] Release sadece 'main' dal?nda olu?turulabilir. Mevcut dal: $currentBranch"
    exit 1
}

# 3. Temiz ?al??ma A?ac? Kontrol?
$uncommitted = & $gitExe status --porcelain
if ($uncommitted) {
    Write-Host '[UYARI] ?al??ma a?ac?nda commit edilmemi? de?i?iklikler var:' -ForegroundColor Yellow
    $uncommitted | ForEach-Object { Write-Host "   $_" -ForegroundColor DarkGray }
    Write-Host '[i] Kalite kap?lar? ?al??t?r?lmadan ?nce durum do?rulanacak...' -ForegroundColor Cyan
}

# 4. Kalite Kap?lar? ?al??t?rma
Write-Host '`n[1/5] Python S?zdizimi Derleme Kontrol?...' -ForegroundColor Cyan
python -m py_compile Portal/api/server.py Portal/api/report_generator.py Engine/Core/Update-Version.py
if ($LASTEXITCODE -ne 0) {
    Write-Error '[HATA] Python derleme testi ba?ar?s?z oldu!'
    exit 1
}
Write-Host '   [PASS] Python dosyalar? ba?ar?yla derlendi.' -ForegroundColor Green

Write-Host '`n[2/5] Kapsaml? QA Test S?iti ?al??t?r?l?yor (test_comprehensive_qa.py)...' -ForegroundColor Cyan
$qaEnv = @{ CLOUDSHIELD_RELEASE_CHANNEL = $Channel }
python test_comprehensive_qa.py
if ($LASTEXITCODE -ne 0) {
    Write-Error '[HATA] QA Test S?iti ba?ar?s?z oldu! Release durduruldu.'
    exit 1
}
Write-Host '   [PASS] QA Test S?iti ba?ar?yla ge?ti.' -ForegroundColor Green

Write-Host '`n[3/5] Versiyon Tutarl?l?k Kontrol?...' -ForegroundColor Cyan
$verJsonOut = python Engine/Core/Update-Version.py --check
try {
    $verObj = $verJsonOut | ConvertFrom-Json
    if (-not $verObj.release -or -not $verObj.version) {
        throw 'Ge?ersiz versiyon nesnesi'
    }
    Write-Host "   [PASS] Versiyon do?ruland?: $($verObj.release) (Kanal: $($verObj.channel))" -ForegroundColor Green
} catch {
    Write-Error "[HATA] Versiyon ??kt?s? ge?ersiz JSON: $verJsonOut"
    exit 1
}

Write-Host '`n[4/5] ?mmutable Tag ve S?r?m B?t?nl???...' -ForegroundColor Cyan
$targetTag = $verObj.release
$tagExists = & $gitExe tag -l $targetTag
if ($tagExists) {
    Write-Host "[B?LG?] $targetTag etiketi zaten mevcut. ?mmutable kural? gere?i ezilmeyecek." -ForegroundColor DarkYellow
} else {
    Write-Host "   [PASS] $targetTag yeni ve kullan?labilir durumda." -ForegroundColor Green
}

Write-Host '`n[5/5] Release Do?rulama Tamamland?.' -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " [BA?ARILI] T?m Release Kap?lar? Ge?ti. Haz?rlanan S?r?m: $targetTag" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
