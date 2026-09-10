<#
.SYNOPSIS
    CloudShield MSSP Platform - KQL Syntax & Security Validator
.DESCRIPTION
    KQL sorgularini sozluk ve guvenlik denetiminden gecirir:
    - Yasakli degistirme/silme operatorleri (.drop, .alter, .delete, externaldata)
    - Tablo adlarinin gecerliligi (Microsoft Defender XDR Advanced Hunting semasi)
    - Kayan zaman penceresi kontrolu (Timestamp / ago)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string] $QueryCatalogPath = "$PSScriptRoot\..\query-catalog"
)

$AllowedTables = @(
    'DeviceInfo', 'DeviceEvents', 'DeviceFileEvents', 'DeviceNetworkEvents',
    'DeviceProcessEvents', 'DeviceLogonEvents', 'DeviceRegistryEvents',
    'DeviceFileCertificateInfo', 'DeviceImageLoadEvents', 'DeviceTvmSoftwareVulnerabilities',
    'EmailEvents', 'EmailAttachmentInfo', 'EmailUrlInfo', 'EmailPostDeliveryEvents',
    'IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents',
    'CloudAppEvents', 'AlertInfo', 'AlertEvidence', 'AADSignInEventsBeta'
)

$ProhibitedPatterns = @(
    '\.drop', '\.alter', '\.delete', '\.create', '\.set',
    'externaldata', 'evaluate\s+fork', 'evaluate\s+python', 'evaluate\s+r'
)

$kqlFiles = Get-ChildItem -Path $QueryCatalogPath -Filter "*.kql" -Recurse

Write-Host "Found $($kqlFiles.Count) KQL query files. Validating..." -ForegroundColor Cyan

$passed = 0
$failed = 0

foreach ($file in $kqlFiles) {
    $content = Get-Content $file.FullName -Raw
    $relPath = $file.FullName.Substring($QueryCatalogPath.Length)
    $hasError = $false

    # 1. Yasakli Komut Kontrolu
    foreach ($p in $ProhibitedPatterns) {
        if ($content -match $p) {
            Write-Error ("SECURITY VIOLATION in " + $relPath + " - Contains prohibited operator matching: " + $p)
            $hasError = $true
        }
    }

    # 2. Tablo Varligi Kontrolu
    $foundTable = $false
    foreach ($tbl in $AllowedTables) {
        if ($content -match "\b$tbl\b") {
            $foundTable = $true
            break
        }
    }
    if (-not $foundTable) {
        Write-Warning ("SCHEMA WARNING in " + $relPath + " - No standard Defender XDR table recognized.")
    }

    # 3. Zaman Penceresi Kontrolu
    if (-not ($content -match 'Timestamp' -or $content -match 'ago\(')) {
        Write-Warning ("PERFORMANCE WARNING in " + $relPath + " - Query does not filter by Timestamp or ago().")
    }

    if (-not $hasError) {
        $passed++
    } else {
        $failed++
    }
}

Write-Host "`nValidation Summary: $passed PASSED, $failed FAILED." -ForegroundColor (if ($failed -eq 0) { 'Green' } else { 'Red' })
if ($failed -gt 0) {
    exit 1
} else {
    exit 0
}
