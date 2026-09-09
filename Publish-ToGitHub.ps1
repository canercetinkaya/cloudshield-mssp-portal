﻿# ==============================================================================
# CloudShield MSSP Portal - GitHub Yayınlama ve Eşitleme Betiği
# Hedef Depo: https://github.com/canercetinkaya/cloudshield-mssp-portal
# ==============================================================================

[CmdletBinding()]
param(
    [string]$RemoteUrl = "https://github.com/canercetinkaya/cloudshield-mssp-portal.git",
    [string]$Branch = "main",
    [string]$CommitMessage = "feat: CloudShield MSSP Portal v2.0 - Deploy to Azure ARM, Zero SOC & Automated Dispatch"
)

$ErrorActionPreference = "Stop"
$portalDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  CloudShield MSSP Portal -> GitHub Dağıtım Aracı" -ForegroundColor White
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
    return
}

$gitExe = if ($gitCmd -is [string]) { $gitCmd } else { $gitCmd.Source }
Write-Host "[+] Git Aracı: $gitExe" -ForegroundColor Green

Set-Location $portalDir

# 2. Git Kimlik Kontrolü
$userName = & $gitExe config user.name
$userEmail = & $gitExe config user.email
if (-not $userName) {
    & $gitExe config user.name "Caner Çetinkaya"
    Write-Host "[+] Git Kullanıcı Adı Ayarlandı: Caner Çetinkaya" -ForegroundColor Green
}
if (-not $userEmail) {
    & $gitExe config user.email "caner.cetinkaya@cloudshield-mssp.com"
    Write-Host "[+] Git E-posta Ayarlandı: caner.cetinkaya@cloudshield-mssp.com" -ForegroundColor Green
}

# 3. Git init
if (-not (Test-Path "$portalDir\.git")) {
    Write-Host "[+] Git deposu başlatılıyor..." -ForegroundColor White
    & $gitExe init
    & $gitExe branch -M $Branch
}

# 4. Remote Ekle / Güncelle
$remotes = & $gitExe remote
if ($remotes -contains "origin") {
    & $gitExe remote set-url origin $RemoteUrl
} else {
    & $gitExe remote add origin $RemoteUrl
}
Write-Host "[+] Remote origin: $RemoteUrl" -ForegroundColor Green

# 5. Dosyaları Ekle
& $gitExe add .

# 6. Commit
$status = & $gitExe status --porcelain
if ($status) {
    Write-Host "[+] Değişiklikler commit ediliyor..." -ForegroundColor White
    & $gitExe commit -m $CommitMessage
} else {
    Write-Host "[i] Çalışma dizini temiz (tüm dosyalar commit edildi)." -ForegroundColor Green
}

# 7. Push
Write-Host "`n[+] GitHub'a gönderiliyor (git push -u origin $Branch)..." -ForegroundColor Cyan
Write-Host "[i] İlk push işleminde tarayıcınızda GitHub oturum açma penceresi açılabilir." -ForegroundColor Yellow
& $gitExe push -u origin $Branch

Write-Host "`n[OK] BAŞARILI! Kodlar GitHub deposuna aktarıldı." -ForegroundColor Green
Write-Host "     Depo URL: https://github.com/canercetinkaya/cloudshield-mssp-portal" -ForegroundColor Cyan
Write-Host "     Deploy to Azure Butonu artık aktif ve kullanıma hazır!" -ForegroundColor Green
