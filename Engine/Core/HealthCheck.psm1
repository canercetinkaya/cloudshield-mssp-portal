﻿# Core/HealthCheck.psm1 - CloudShield Security Reporting Platform
# Pre-flight environment, network, credential, and engine validation.
[CmdletBinding()]
param()

function Find-EdgeExecutable {
    $candidates = @(
        "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe"
    )

    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    return $null
}

function Test-EndpointConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $HostName,
        [Parameter(Mandatory = $false)]
        [int] $Port = 443
    )

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(3000, $false)
        if (-not $wait) {
            $tcp.Close()
            return $false
        }
        $tcp.EndConnect($connect)
        $tcp.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-PlatformHealthCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig
    )

    $checks = [ordered]@{}
    $allHealthy = $true

    # 1. PowerShell Sürümü
    $psVer = $PSVersionTable.PSVersion.ToString()
    $psOk = ($PSVersionTable.PSVersion.Major -ge 5)
    $checks['PowerShellVersion'] = @{
        Status  = if ($psOk) { 'OK' } else { 'FAIL' }
        Detail  = "Sürüm: $psVer"
    }

    # 2. PDF Motoru (Microsoft Edge / Chrome)
    $edgePath = Find-EdgeExecutable
    if ($edgePath) {
        $checks['PdfEngine'] = @{
            Status  = 'OK'
            Detail  = "Bulundu: $edgePath"
        }
    } else {
        $checks['PdfEngine'] = @{
            Status  = 'WARN'
            Detail  = "Chromium/Edge bulunamadı. Raporlar yalnızca HTML formatında üretilebilir."
        }
    }

    # 3. Ağ Erişimi ve Uç Noktalar
    $endpoints = @('login.microsoftonline.com', 'graph.microsoft.com', 'api.securitycenter.microsoft.com')
    $netFails = @()
    foreach ($ep in $endpoints) {
        if (-not (Test-EndpointConnectivity -HostName $ep)) {
            $netFails += $ep
        }
    }

    if ($netFails.Count -eq 0) {
        $checks['NetworkConnectivity'] = @{
            Status  = 'OK'
            Detail  = "Tüm Microsoft bulut uç noktalarına (Port 443) erişildi."
        }
    } else {
        $allHealthy = $false
        $checks['NetworkConnectivity'] = @{
            Status  = 'FAIL'
            Detail  = "Erişilemeyen uç noktalar: $($netFails -join ', ')"
        }
    }

    # 4. Kimlik Bilgisi ve Süre Bitiş Kontrolü
    $cust = $PlatformConfig.CustomerConfig
    $coreAuth = $cust.Authentication.CoreApp

    if ($coreAuth.CredentialExpiry) {
        try {
            $expDate = [DateTime]::Parse($coreAuth.CredentialExpiry)
            $daysLeft = [int]($expDate - (Get-Date)).TotalDays

            if ($daysLeft -lt 0) {
                $allHealthy = $false
                $checks['CredentialLifetime'] = @{
                    Status  = 'FAIL'
                    Detail  = "Kimlik bilgisinin süresi dolmuş! ($($expDate.ToString('yyyy-MM-dd')))"
                }
            }
            elseif ($daysLeft -le 30) {
                $checks['CredentialLifetime'] = @{
                    Status  = 'WARN'
                    Detail  = "DİKKAT: Kimlik bilgisinin süresi $daysLeft gün sonra doluyor! ($($expDate.ToString('yyyy-MM-dd')))"
                }
            }
            else {
                $checks['CredentialLifetime'] = @{
                    Status  = 'OK'
                    Detail  = "Geçerlilik süresi: $daysLeft gün ($($expDate.ToString('yyyy-MM-dd')))"
                }
            }
        }
        catch {
            $checks['CredentialLifetime'] = @{ Status = 'WARN'; Detail = "Tarih formatı çözülemedi." }
        }
    }

    return [PSCustomObject]@{
        Healthy = $allHealthy
        Checks  = $checks
    }
}

Export-ModuleMember -Function Find-EdgeExecutable, Test-EndpointConnectivity, Invoke-PlatformHealthCheck
