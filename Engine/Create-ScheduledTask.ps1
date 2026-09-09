<#
.SYNOPSIS
    CloudShield Microsoft Security Managed Services Reporting Platform - Zamanlanmış Görev Kurucusu
.DESCRIPTION
    Windows Task Scheduler üzerinde aylık, haftalık veya dashboard modunda
    otomatik rapor üretimini ve e-posta iletimini tetikleyen zamanlanmış görevi kaydeder.
.EXAMPLE
    .\Create-ScheduledTask.ps1 -Mode Monthly
    .\Create-ScheduledTask.ps1 -Mode Weekly -Time "07:30"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string] $ConfigPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Monthly', 'Weekly', 'Dashboard')]
    [string] $Mode = 'Monthly',

    [Parameter(Mandatory = $false)]
    [string] $Time = '08:30',

    [Parameter(Mandatory = $false)]
    [string] $TaskName = $null
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $root 'Config\customer.config.json'
}

$safeName = "CloudShield-Security-Reporting-$Mode"
if ($TaskName) { $safeName = $TaskName }

$invokeScript = Join-Path $root 'Invoke-CloudShieldSecurityReporting.ps1'
$pwshExe = (Get-Process -Id $PID).Path
if (-not $pwshExe) { $pwshExe = 'powershell.exe' }

$actionArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$invokeScript`" -ConfigPath `"$ConfigPath`" -Mode $Mode -Pdf -SendMail"

Write-Host "Zamanlanmış Görev Tanımlanıyor: $safeName..." -ForegroundColor Cyan

# Windows Task Scheduler Tanımlaması
try {
    $action = New-ScheduledTaskAction -Execute $pwshExe -Argument $actionArgs -WorkingDirectory $root

    $trigger = switch ($Mode) {
        'Monthly'   { New-ScheduledTaskTrigger -At $Time -DaysOfWeek Sunday -WeeksInterval 4 } # Veya her ayın 1'i
        'Weekly'    { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $Time }
        'Dashboard' { New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 60) }
    }

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Görevi kaydet (Current User ile)
    Register-ScheduledTask -TaskName $safeName `
                           -Action $action `
                           -Trigger $trigger `
                           -Settings $settings `
                           -Description "CloudShield Microsoft Güvenlik ve Purview Yönetilen Hizmetler Otomatik Raporlama Görevi" `
                           -Force | Out-Null

    Write-Host "   [OK] Görev başarıyla oluşturuldu: $safeName" -ForegroundColor Green
    Write-Host "   Çalışma Zamanı : $Time ($Mode)" -ForegroundColor Gray
    Write-Host "   Komut          : $pwshExe $actionArgs" -ForegroundColor DarkGray
}
catch {
    Write-Warning "PowerShell ScheduledTask cmdlet'i ile görev oluşturulamadı ($($_.Exception.Message)). schtasks.exe fallback deneniyor..."
    
    # Fallback schtasks.exe
    $schArgs = "/create /tn `"$safeName`" /tr `"\`"$pwshExe\`" $actionArgs`" /sc monthly /d 1 /st $Time /f"
    Start-Process -FilePath "schtasks.exe" -ArgumentList $schArgs -Wait -NoNewWindow
    Write-Host "   [OK] schtasks.exe ile görev oluşturuldu." -ForegroundColor Green
}
