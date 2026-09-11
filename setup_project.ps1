<#
.SYNOPSIS
    CloudShield Enterprise MSSP Platform - Turnkey Environment Setup & Bootstrap (Windows)
.DESCRIPTION
    Verifies Python, pwsh/powershell, Edge/Chrome, initializes database and runs verification tests.
#>
[CmdletBinding()]
param (
    [int]$Port = 8080,
    [switch]$StartPortal
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  CloudShield MSSP Platform - Automated Setup & Verification" -ForegroundColor White
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
Write-Host "[*] Checking Python 3 runtime..." -ForegroundColor Yellow
$pyCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $pyCmd) { $pyCmd = Get-Command py.exe -ErrorAction SilentlyContinue }
if (-not $pyCmd) {
    Write-Host "[!] ERROR: Python 3 was not found in PATH. Install from python.org." -ForegroundColor Red
    exit 1
}
$pyExe = $pyCmd.Source
$pyVersion = & $pyExe --version 2>&1
Write-Host "[+] Python detected: $pyVersion ($pyExe)" -ForegroundColor Green

# 2. Check PowerShell Core / Windows PowerShell
Write-Host "[*] Checking PowerShell environment..." -ForegroundColor Yellow
$pwshCmd = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if ($pwshCmd) {
    Write-Host "[+] PowerShell Core 7+ found: $($pwshCmd.Source)" -ForegroundColor Green
} else {
    Write-Host "[i] Using Windows PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkYellow
}

# 3. Check Edge or Chrome for PDF printing
Write-Host "[*] Checking Edge / Chrome for PDF export..." -ForegroundColor Yellow
$edgePaths = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
)
$browserFound = $false
foreach ($path in $edgePaths) {
    if (Test-Path $path) {
        Write-Host "[+] Headless PDF generator browser found: $path" -ForegroundColor Green
        $browserFound = $true
        break
    }
}
if (-not $browserFound) {
    Write-Host "[i] NOTICE: Edge/Chrome executable not found at default paths. HTML reports work; PDF export requires browser." -ForegroundColor DarkYellow
}

# 4. Environment Configuration
Write-Host "[*] Verifying environment configuration..." -ForegroundColor Yellow
$envFile = Join-Path $ScriptDir ".env"
$envExample = Join-Path $ScriptDir ".env.example"
if (-not (Test-Path $envFile)) {
    if (Test-Path $envExample) {
        Copy-Item $envExample $envFile
        Write-Host "[+] Created .env from .env.example template." -ForegroundColor Green
    }
} else {
    Write-Host "[+] Existing .env file found." -ForegroundColor Green
}

# 5. Initialize SQLite Database & Seed Data
Write-Host "[*] Initializing CloudShield SQLite Database & RBAC schema..." -ForegroundColor Yellow
& $pyExe -c "from database.db import init_db; init_db(); print('[+] SQLite Database initialized and seeded successfully.')"

# 6. Run Core Security & Authorization Unit Tests
Write-Host "[*] Executing Core Authorization & Quality Gate Unit Tests..." -ForegroundColor Yellow
& $pyExe -m unittest test_rbac_authorization.py test_post_remediation_independent_gate.py test_report_quality_gate.py

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE - CLOUDSHIELD PLATFORM IS READY" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "To launch the local web portal:" -ForegroundColor White
Write-Host "    .\Start-LocalPortal.ps1 -Port $Port" -ForegroundColor Yellow
Write-Host ""

if ($StartPortal) {
    & "$ScriptDir\Start-LocalPortal.ps1" -Port $Port
}
