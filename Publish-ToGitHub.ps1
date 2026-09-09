# ==============================================================================
# KoçSistem MSSP Portal - GitHub Yayınlama ve Eşitleme Betiği
# Hedef Depo: https://github.com/canercetinkaya/kocsistem-mssp-portal
# ==============================================================================

[CmdletBinding()]
param(
    [string]$RemoteUrl = "https://github.com/canercetinkaya/kocsistem-mssp-portal.git",
    [string]$Branch = "main",
    [string]$CommitMessage = "feat: KoçSistem MSSP Portal v2.0 - Deploy to Azure ARM, Zero SOC & Automated Dispatch"
)

$ErrorActionPreference = "Stop"
$portalDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  KoçSistem MSSP Portal -> GitHub Dağıtım Aracı" -ForegroundColor White
Write-Host "  Hedef Depo: $RemoteUrl" -ForegroundColor Green
Write-Host "================================================================================`n" -ForegroundColor Cyan

# 1. Git Kurulumu Kontrolü
$gitCmd = Get-Command "git" -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    $commonGitPaths = @(
        "$env:ProgramFiles\Git\cmd\git.exe",
        "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe",
        "$env:ProgramFiles(x86)\Git\cmd\git.exe"
    )
    foreach ($p in $commonGitPaths) {
        if (Test-Path $p) {
            $gitCmd = $p
            break
        }
    }
}

if (-not $gitCmd) {
    Write-Host "[!] 'git' komut satırı aracı sisteminizde bulunamadı." -ForegroundColor Yellow
    Write-Host "[i] Git for Windows kurulu değilse: winget install --id Git.Git -e" -ForegroundColor White
    Write-Host "[i] veya GitHub Desktop / VS Code ile bu klasörü ($portalDir) açarak doğrudan commit ve push yapabilirsiniz." -ForegroundColor White
    Write-Host "`nAlternatif Komutlar:" -ForegroundColor Cyan
    Write-Host "  git init" -ForegroundColor Gray
    Write-Host "  git branch -M main" -ForegroundColor Gray
    Write-Host "  git remote add origin $RemoteUrl" -ForegroundColor Gray
    Write-Host "  git add ." -ForegroundColor Gray
    Write-Host "  git commit -m `"$CommitMessage`"" -ForegroundColor Gray
    Write-Host "  git push -u origin main" -ForegroundColor Gray
    return
}

$gitExe = if ($gitCmd -is [string]) { $gitCmd } else { $gitCmd.Source }
Write-Host "[+] Git Aracı Tespit Edildi: $gitExe" -ForegroundColor Green

Set-Location $portalDir

# 2. Git init
if (-not (Test-Path "$portalDir\.git")) {
    Write-Host "[+] Git deposu başlatılıyor..." -ForegroundColor White
    & $gitExe init
    & $gitExe branch -M $Branch
}

# 3. Remote Ekle / Güncelle
$remotes = & $gitExe remote
if ($remotes -contains "origin") {
    & $gitExe remote set-url origin $RemoteUrl
} else {
    & $gitExe remote add origin $RemoteUrl
}
Write-Host "[+] Remote origin ayarlandı: $RemoteUrl" -ForegroundColor Green

# 4. Dosyaları Ekle
Write-Host "[+] Dosyalar hazırlanıyor (git add)..." -ForegroundColor White
& $gitExe add .

# 5. Commit
$status = & $gitExe status --porcelain
if ($status) {
    Write-Host "[+] Değişiklikler commit ediliyor..." -ForegroundColor White
    & $gitExe commit -m $CommitMessage
} else {
    Write-Host "[i] Yeni bir değişiklik yok, çalışma dizini temiz." -ForegroundColor Yellow
}

# 6. Push
Write-Host "`n[+] GitHub'a gönderiliyor (git push -u origin $Branch)..." -ForegroundColor Cyan
try {
    & $gitExe push -u origin $Branch
    Write-Host "`n[OK] BAŞARILI! Kodlar depoya aktarıldı." -ForegroundColor Green
    Write-Host "     Depo URL: https://github.com/canercetinkaya/kocsistem-mssp-portal" -ForegroundColor Cyan
    Write-Host "     Deploy to Azure Butonu artık aktif ve kullanıma hazır!" -ForegroundColor Green
} catch {
    Write-Host "`n[!] Push işlemi sırasında kimlik doğrulama istendi veya hata oluştu:" -ForegroundColor Yellow
    Write-Host "    $_" -ForegroundColor Red
    Write-Host "    Lütfen 'git push -u origin main' komutunu terminalde çalıştırarak GitHub oturumunuzu onaylayınız." -ForegroundColor White
}
