﻿# Core/TrendEngine.psm1 - CloudShield Security Reporting Platform
# Historical KPI snapshotting, MoM (Month-over-Month) trend calculations, and delta badges.
[CmdletBinding()]
param()

$Script:RootPath = Split-Path -Parent $PSScriptRoot

function Save-KpiSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $CustomerName,
        [Parameter(Mandatory = $true)]
        [string] $PeriodTag,
        [Parameter(Mandatory = $true)]
        $KpiMap
    )

    $dataDir = Join-Path $Script:RootPath 'Data'
    if (-not (Test-Path $dataDir)) {
        New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    }

    $safeCustomer = ($CustomerName -replace '[^A-Za-z0-9_-]', '_')
    $filePath = Join-Path $dataDir "KPI_${safeCustomer}_${PeriodTag}.json"

    $json = ConvertTo-Json $KpiMap -Depth 15
    Set-Content -Path $filePath -Value $json -Encoding UTF8 -Force
}

function Get-PreviousKpiSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $CustomerName,
        [Parameter(Mandatory = $true)]
        [datetime] $CurrentStartDate
    )

    $dataDir = Join-Path $Script:RootPath 'Data'
    if (-not (Test-Path $dataDir)) { return $null }

    # Bir önceki ayın etiketi (örn: 2026-07)
    $prevDate = $CurrentStartDate.AddMonths(-1)
    $prevTag = $prevDate.ToString('yyyy-MM')
    $safeCustomer = ($CustomerName -replace '[^A-Za-z0-9_-]', '_')
    $filePath = Join-Path $dataDir "KPI_${safeCustomer}_${prevTag}.json"

    if (Test-Path $filePath) {
        try {
            $raw = Get-Content -Path $filePath -Raw -Encoding UTF8
            return ConvertFrom-Json $raw
        }
        catch {
            return $null
        }
    }
    return $null
}

function Calculate-MetricTrend {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $CurrentValue,
        [Parameter(Mandatory = $false)]
        $PreviousValue,
        [Parameter(Mandatory = $false)]
        [switch] $HigherIsBetter
    )

    if ($null -eq $PreviousValue -or $PreviousValue -eq 0) {
        return [PSCustomObject]@{
            Current        = $CurrentValue
            Previous       = $PreviousValue
            Delta          = 0
            PercentChange  = 0
            Direction      = 'Neutral'
            StatusClass    = 'neutral'
            BadgeHtml      = "<span class='badge neutral'>-</span>"
        }
    }

    $cur = [double]$CurrentValue
    $prev = [double]$PreviousValue
    $delta = $cur - $prev
    $pct = [math]::Round(($delta / $prev) * 100, 1)

    $direction = if ($delta -gt 0) { 'Up' } elseif ($delta -lt 0) { 'Down' } else { 'Stable' }

    # Renk sınıfı belirleme: Tehditlerde azalış (Down) yeşilken, uyumda artış (Up) yeşildir.
    $statusClass = 'neutral'
    if ($HigherIsBetter) {
        $statusClass = if ($delta -gt 0) { 'positive' } elseif ($delta -lt 0) { 'negative' } else { 'neutral' }
    } else {
        $statusClass = if ($delta -gt 0) { 'negative' } elseif ($delta -lt 0) { 'positive' } else { 'neutral' }
    }

    $arrow = if ($delta -gt 0) { '▲' } elseif ($delta -lt 0) { '▼' } else { '●' }
    $sign = if ($delta -gt 0) { '+' } else { '' }
    $badge = "<span class='badge $statusClass'>$arrow $sign$pct%</span>"

    return [PSCustomObject]@{
        Current       = $cur
        Previous      = $prev
        Delta         = $delta
        PercentChange = $pct
        Direction     = $direction
        StatusClass   = $statusClass
        BadgeHtml     = $badge
    }
}

Export-ModuleMember -Function Save-KpiSnapshot, Get-PreviousKpiSnapshot, Calculate-MetricTrend
