﻿# Core/PrivacyEngine.psm1 - CloudShield Security Reporting Platform
# Differential privacy, k-anonymity (k=5), salted SHA256 hashing, and sensitive data masking.
[CmdletBinding()]
param()

$Script:SaltCache = @{}

function Get-TenantSalt {
    param([string] $TenantId)
    if (-not $Script:SaltCache.ContainsKey($TenantId)) {
        # Tenant bazlı deterministik fakat tahmin edilemez bir salt türet
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("$TenantId-CloudShield-Security-Privacy-Salt-2026")
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($bytes)
        $Script:SaltCache[$TenantId] = [Convert]::ToBase64String($hash)
    }
    return $Script:SaltCache[$TenantId]
}

function Protect-EmailAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $EmailAddress,
        [Parameter(Mandatory = $false)]
        [switch] $MaskDomain
    )

    if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
        return 'bilinmeyen@kurum.com'
    }

    $clean = $EmailAddress.Trim()

    # Sistem ve servis hesaplarını olduğu gibi bırak
    if ($clean -match '(?i)(system|sharepoint|app@sharepoint|automated|defender)') {
        return $clean
    }

    if (-not ($clean -match '^([^@]+)@(.+)$')) {
        if ($clean.Length -le 3) { return "$($clean[0])***" }
        return "$($clean.Substring(0, 2))***"
    }

    $localPart = $Matches[1]
    $domainPart = $Matches[2]

    # Yerel parçayı noktalara, alt çizgilere veya tirelere göre maskele (örn: ahmet.yilmaz -> a***.y***)
    $delimiters = @('.', '_', '-')
    $usedDelimiter = $null
    foreach ($d in $delimiters) {
        if ($localPart.Contains($d)) {
            $usedDelimiter = $d
            break
        }
    }

    $maskedLocal = ''
    if ($usedDelimiter) {
        $segments = $localPart.Split($usedDelimiter)
        $maskedSegments = foreach ($seg in $segments) {
            if ([string]::IsNullOrWhiteSpace($seg)) {
                '***'
            } elseif ($seg.Length -eq 1) {
                "$seg***"
            } else {
                "$($seg[0])***"
            }
        }
        $maskedLocal = $maskedSegments -join $usedDelimiter
    } else {
        if ($localPart.Length -le 2) {
            $maskedLocal = "$($localPart[0])***"
        } else {
            $maskedLocal = "$($localPart[0])***$($localPart[-1])"
        }
    }

    $maskedDomain = if ($MaskDomain) {
        $domParts = $domainPart.Split('.')
        if ($domParts.Count -ge 2) {
            "$($domParts[0][0])***." + ($domParts[1..($domParts.Count - 1)] -join '.')
        } else {
            "***.$domainPart"
        }
    } else {
        $domainPart
    }

    return "$maskedLocal@$maskedDomain"
}

function Protect-FileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath,
        [Parameter(Mandatory = $false)]
        [int] $PreserveTokens = 2
    )

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return 'Dosya_***.dat'
    }

    # Klasör yolunu temizle (Kullanıcı adı veya sunucu yolu sızıntısını önler: C:\Users\ayilmaz\...)
    $fileName = [System.IO.Path]::GetFileName($FilePath.Trim())
    if ([string]::IsNullOrWhiteSpace($fileName)) {
        $fileName = $FilePath.Trim()
    }

    $ext = [System.IO.Path]::GetExtension($fileName)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)

    if ([string]::IsNullOrWhiteSpace($baseName)) {
        return "***$ext"
    }

    # Kelime ayracı tespiti (_ veya - veya boşluk)
    $delim = if ($baseName.Contains('_')) { '_' }
             elseif ($baseName.Contains('-')) { '-' }
             elseif ($baseName.Contains(' ')) { ' ' }
             else { $null }

    if ($delim) {
        $tokens = $baseName.Split($delim) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($tokens.Count -gt $PreserveTokens) {
            $preserved = ($tokens[0..($PreserveTokens - 1)] -join $delim)
            return "$preserved$delim***$ext"
        } elseif ($tokens.Count -eq 2) {
            return "$($tokens[0])$delim***$ext"
        } else {
            return "$($tokens[0])$delim***$ext"
        }
    } else {
        if ($baseName.Length -gt 4) {
            return "$($baseName.Substring(0, 4))***$ext"
        } else {
            return "$($baseName.Substring(0, 1))***$ext"
        }
    }
}

function Protect-UserIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $UserPrincipalName,
        [Parameter(Mandatory = $false)]
        [string] $TenantId = 'Default',
        [Parameter(Mandatory = $false)]
        [switch] $MaskDomain,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Hash', 'Mask')]
        [string] $Mode = 'Hash'
    )

    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        return 'Bilinmeyen Kullanıcı'
    }

    # Sistem ve servis hesaplarını olduğu gibi bırak
    if ($UserPrincipalName -match '(?i)(system|sharepoint|app@sharepoint|automated|defender)') {
        return $UserPrincipalName
    }

    # E-posta maskeleme modu (örn: a***.y***@sirket.com)
    if ($Mode -eq 'Mask') {
        return Protect-EmailAddress -EmailAddress $UserPrincipalName -MaskDomain:$MaskDomain
    }

    # Deterministik tuzlu SHA-256 hash modu (User_8F9A4C1E)
    $salt = Get-TenantSalt -TenantId $TenantId
    $combined = "$($UserPrincipalName):$salt"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($combined)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash($bytes)
    $hex = -join ($hashBytes[0..3] | ForEach-Object { $_.ToString("X2") })

    $domain = if ($UserPrincipalName -contains '@') { $UserPrincipalName.Split('@')[1] } else { '' }
    if ($MaskDomain -or [string]::IsNullOrWhiteSpace($domain)) {
        return "User_$hex"
    } else {
        return "User_${hex}@$domain"
    }
}

function Apply-KAnonymity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable] $Items,
        [Parameter(Mandatory = $true)]
        [string] $GroupByProperty,
        [Parameter(Mandatory = $false)]
        [int] $Threshold = 5,
        [Parameter(Mandatory = $false)]
        [string] $AggregationLabel = 'Diğer Kullanıcılar (k-Anonymity)'
    )

    $grouped = $Items | Group-Object -Property $GroupByProperty
    $result = @()
    $suppressedCount = 0
    $suppressedItems = @()

    foreach ($g in $grouped) {
        if ($g.Count -ge $Threshold) {
            $result += [PSCustomObject]@{
                Key   = $g.Name
                Count = $g.Count
                Group = $g.Group
            }
        }
        else {
            $suppressedCount += $g.Count
            $suppressedItems += $g.Group
        }
    }

    if ($suppressedCount -gt 0) {
        $result += [PSCustomObject]@{
            Key   = $AggregationLabel
            Count = $suppressedCount
            Group = $suppressedItems
        }
    }

    return $result | Sort-Object Count -Descending
}

function Scrub-SensitiveText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

    $scrubbed = $Text

    # 1. Bearer / JWT Token Maskeleme
    $scrubbed = [regex]::Replace($scrubbed, "Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", "Bearer [REDACTED_JWT]")
    $scrubbed = [regex]::Replace($scrubbed, "ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "[REDACTED_JWT]")

    # 2. Private Key / Secret / Password Maskeleme
    $scrubbed = [regex]::Replace($scrubbed, "client_secret=[^&\s]+", "client_secret=[REDACTED_SECRET]")
    $scrubbed = [regex]::Replace($scrubbed, "password=[^&\s]+", "password=[REDACTED_SECRET]")

    # 3. Kredi kartı numarası benzeri 13-16 haneli blokları maskele
    $scrubbed = [regex]::Replace($scrubbed, '\b(?:\d[ -]*?){13,16}\b', '****-****-****-****')

    # 4. TC Kimlik No benzeri 11 haneli sayıları maskele
    $scrubbed = [regex]::Replace($scrubbed, '\b[1-9]\d{10}\b', '***********')

    # 5. IBAN Numaraları (TR ile başlayan 26 karakter)
    $scrubbed = [regex]::Replace($scrubbed, 'TR[0-9]{2}[0-9A-Z]{5}[0-9]{17}', 'TR**-****-****-****-****-**')

    return $scrubbed
}

Export-ModuleMember -Function Protect-UserIdentity, Protect-EmailAddress, Protect-FileName, Apply-KAnonymity, Scrub-SensitiveText
