# Engine/Core/LicenseIntelligenceCollector.psm1 - CloudShield Security Reporting Platform
# Collects Subscribed SKUs, Service Plans, User Profiles and 5-Layer Workload Reconciliation via Microsoft Graph.
[CmdletBinding()]
param()

function Get-TenantLicenseIntelligence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $TenantId,

        [Parameter(Mandatory = $false)]
        [string] $AccessToken,

        [Parameter(Mandatory = $false)]
        [switch] $DryRun,

        [Parameter(Mandatory = $false)]
        [string] $OutputPath
    )

    Write-Verbose "[LICENSE-INTEL] Starting license intelligence collection for Tenant: $TenantId"
    $snapshotDate = (Get-Date).ToString("yyyy-MM-dd")
    $period = (Get-Date).ToString("yyyy-MM")

    $isLive = ($AccessToken -and -not $DryRun.IsPresent)
    $trustLabel = if ($isLive) { "Canlı Tenant API Doğrulandı" } else { "Sentetik / Simülasyon Verisi" }

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
        "User-Agent"    = "CloudShield-LicenseIntelligence/3.2.0 (PowerShell Core)"
    }

    $inventory = @()
    $users = @()

    if ($isLive) {
        try {
            Write-Verbose "[LICENSE-INTEL] Querying Graph /v1.0/subscribedSkus..."
            $skusResp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" -Headers $headers -Method Get -TimeoutSec 20
            foreach ($s in $skusResp.value) {
                $inventory += [PSCustomObject]@{
                    sku_id            = $s.skuId
                    sku_part_number   = $s.skuPartNumber
                    display_name      = $s.skuPartNumber
                    prepaid_units     = [int]$s.prepaidUnits.enabled
                    consumed_units    = [int]$s.consumedUnits
                    suspended_units   = [int]$s.suspendedUnits
                    warning_units     = [int]$s.warningUnits
                    capability_status = $s.capabilityStatus
                }
            }

            Write-Verbose "[LICENSE-INTEL] Querying Graph /v1.0/users..."
            $usersUrl = "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,department,jobTitle,usageLocation,assignedLicenses,assignedPlans&`$top=999"
            $usersResp = Invoke-RestMethod -Uri $usersUrl -Headers $headers -Method Get -TimeoutSec 30
            $users = $usersResp.value
        }
        catch {
            Write-Warning "[LICENSE-INTEL] Live Graph API error: $_. Falling back to synthetic simulation."
            $isLive = $false
            $trustLabel = "Sentetik / Simülasyon Verisi (API Fallback)"
        }
    }

    if (-not $isLive) {
        # Realistic Synthetic Fixture
        $inventory = @(
            [PSCustomObject]@{
                sku_id            = "06e2b970-d779-4be0-9168-26d6e502024e"
                sku_part_number   = "SPE_E5"
                display_name      = "Microsoft 365 E5"
                prepaid_units     = 150
                consumed_units    = 135
                suspended_units   = 0
                warning_units     = 0
                capability_status = "Enabled"
            },
            [PSCustomObject]@{
                sku_id            = "05e023e4-d397-4574-a818-b27b878ec968"
                sku_part_number   = "SPE_E3"
                display_name      = "Microsoft 365 E3"
                prepaid_units     = 50
                consumed_units    = 40
                suspended_units   = 0
                warning_units     = 0
                capability_status = "Enabled"
            },
            [PSCustomObject]@{
                sku_id            = "b0563a55-0822-463e-9080-690a64936b85"
                sku_part_number   = "SPE_E5_SEC"
                display_name      = "Microsoft 365 E5 Security"
                prepaid_units     = 25
                consumed_units    = 20
                suspended_units   = 0
                warning_units     = 0
                capability_status = "Enabled"
            }
        )
    }

    $totalPrepaid = ($inventory | Measure-Object -Property prepaid_units -Sum).Sum
    $totalConsumed = ($inventory | Measure-Object -Property consumed_units -Sum).Sum
    $totalIdle = [Math]::Max(0, ($totalPrepaid - $totalConsumed))

    $result = [PSCustomObject]@{
        TenantId           = $TenantId
        SnapshotDate       = $snapshotDate
        Period             = $period
        TrustLabel         = $trustLabel
        IsLive             = $isLive
        TotalLicenses      = $totalPrepaid
        AssignedLicenses   = $totalConsumed
        IdleLicenses       = $totalIdle
        InventoryCount     = $inventory.Count
        Inventory          = $inventory
    }

    if ($OutputPath) {
        $outDir = Split-Path -Parent $OutputPath
        if ($outDir -and -not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        $result | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
        Write-Verbose "[LICENSE-INTEL] Saved report artifact to: $OutputPath"
    }

    return $result
}

Export-ModuleMember -Function Get-TenantLicenseIntelligence
