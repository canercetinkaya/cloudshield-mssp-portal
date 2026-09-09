# Core/Authentication.psm1 - CloudShield Security Reporting Platform
# RFC 7523 Certificate-Based Authentication (JWT Assertion), Client Secret, Token Caching, and Resilient REST Invoker.
[CmdletBinding()]
param()

$Script:TokenCache = @{}

function ConvertTo-Base64UrlString {
    param([byte[]] $Bytes)
    $b64 = [Convert]::ToBase64String($Bytes)
    return $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-AvailableCertificates {
    [CmdletBinding()]
    param()

    $certs = @()
    $locations = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')

    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            $found = Get-ChildItem -Path $loc -ErrorAction SilentlyContinue | Where-Object {
                $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date)
            }
            foreach ($c in $found) {
                $certs += [PSCustomObject]@{
                    Subject      = $c.Subject
                    FriendlyName = $c.FriendlyName
                    Thumbprint   = $c.Thumbprint
                    NotAfter     = $c.NotAfter
                    DaysLeft     = [int]($c.NotAfter - (Get-Date)).TotalDays
                    Location     = $loc
                    Certificate  = $c
                }
            }
        }
    }
    return $certs
}

function New-ClientAssertionJwt {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ClientId,
        [Parameter(Mandatory = $true)]
        [string] $TenantId,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $now = [DateTimeOffset]::UtcNow
    $nbf = $now.ToUnixTimeSeconds()
    $exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    $jti = [Guid]::NewGuid().ToString()
    $aud = "https://login.microsoftonline.com/$TenantId/v2.0"

    $header = @{
        alg = "RS256"
        typ = "JWT"
        x5t = (ConvertTo-Base64UrlString $Certificate.GetCertHash())
    }

    $payload = @{
        aud = $aud
        exp = $exp
        iss = $ClientId
        jti = $jti
        nbf = $nbf
        sub = $ClientId
    }

    $headerJson = ConvertTo-Json $header -Compress
    $payloadJson = ConvertTo-Json $payload -Compress

    $headerB64 = ConvertTo-Base64UrlString ([System.Text.Encoding]::UTF8.GetBytes($headerJson))
    $payloadB64 = ConvertTo-Base64UrlString ([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
    $unsignedToken = "$headerB64.$payloadB64"

    # RSA Private Key ile İmzalama (Saf .NET BCL)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) {
        throw "Sertifikanın RSA özel anahtarı (private key) okunamadı veya erişim izni yok."
    }

    $dataToSign = [System.Text.Encoding]::UTF8.GetBytes($unsignedToken)
    $signature = $rsa.SignData(
        $dataToSign,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    $sigB64 = ConvertTo-Base64UrlString $signature
    return "$unsignedToken.$sigB64"
}

function Get-AzureManagedIdentityToken {
    [CmdletBinding()]
    param(
        [string] $Resource = 'https://vault.azure.net'
    )

    # 1. Container Apps / App Service Managed Identity (IDENTITY_ENDPOINT & IDENTITY_HEADER)
    if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
        try {
            $uri = "$($env:IDENTITY_ENDPOINT)?resource=$Resource&api-version=2019-08-01"
            $headers = @{ "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER }
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -TimeoutSec 10 -ErrorAction Stop
            if ($resp.access_token) { return $resp.access_token }
        }
        catch {}
    }

    # 2. Azure IMDS Endpoint (Azure VM / Default Azure Instance Metadata Service)
    try {
        $imdsUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$Resource"
        $headers = @{ "Metadata" = "true" }
        $resp = Invoke-RestMethod -Uri $imdsUri -Headers $headers -Method GET -TimeoutSec 5 -ErrorAction Stop
        if ($resp.access_token) { return $resp.access_token }
    }
    catch {}

    # 3. Azure CLI Token Fallback (Yerel geliştirme veya Azure Cloud Shell ortamı)
    $azCmd = Get-Command az.cmd -ErrorAction SilentlyContinue
    if (-not $azCmd) { $azCmd = Get-Command az -ErrorAction SilentlyContinue }
    if ($azCmd) {
        try {
            $token = az account get-access-token --resource $Resource --query accessToken -o tsv 2>$null
            if ($token) { return $token.Trim() }
        }
        catch {}
    }

    return $null
}

function Get-PlatformKeyVaultSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $SecretName,
        [Parameter(Mandatory = $false)]
        [string] $VaultUrl = $env:AZURE_KEYVAULT_URL
    )

    if (-not $VaultUrl) {
        throw "Azure Key Vault URL tanımlanmamış (AZURE_KEYVAULT_URL ortam değişkeni boş)."
    }

    $cleanVaultUrl = $VaultUrl.TrimEnd('/')
    $token = Get-AzureManagedIdentityToken -Resource 'https://vault.azure.net'
    if (-not $token) {
        throw "Azure Key Vault erişimi için Managed Identity token alınamadı. Container App Managed Identity yetkilerini kontrol ediniz."
    }

    $secretUri = "$cleanVaultUrl/secrets/$SecretName`?api-version=7.4"
    $headers = @{
        "Authorization" = "Bearer $token"
        "Accept"        = "application/json"
    }

    try {
        $resp = Invoke-RestMethod -Uri $secretUri -Headers $headers -Method GET -ErrorAction Stop
        return $resp.value
    }
    catch {
        throw "Azure Key Vault sırrı ($SecretName) okunamadı: $($_.Exception.Message)"
    }
}

function Get-PlatformKeyVaultCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $CertificateName,
        [Parameter(Mandatory = $false)]
        [string] $VaultUrl = $env:AZURE_KEYVAULT_URL
    )

    if (-not $VaultUrl) {
        throw "Azure Key Vault URL tanımlanmamış (AZURE_KEYVAULT_URL ortam değişkeni boş)."
    }

    $cleanVaultUrl = $VaultUrl.TrimEnd('/')
    $token = Get-AzureManagedIdentityToken -Resource 'https://vault.azure.net'
    if (-not $token) {
        throw "Azure Key Vault erişimi için Managed Identity token alınamadı. Container App Managed Identity yetkilerini kontrol ediniz."
    }

    # Azure Key Vault'ta sertifikanın özel anahtarlı hali (PFX/PKCS12) secrets uç noktasından Base64 olarak çekilir
    $secretUri = "$cleanVaultUrl/secrets/$CertificateName`?api-version=7.4"
    $headers = @{
        "Authorization" = "Bearer $token"
        "Accept"        = "application/json"
    }

    try {
        $resp = Invoke-RestMethod -Uri $secretUri -Headers $headers -Method GET -ErrorAction Stop
        $pfxBytes = [Convert]::FromBase64String($resp.value)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $pfxBytes,
            "",
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )
        return $cert
    }
    catch {
        throw "Azure Key Vault sertifikası ($CertificateName) okunamadı: $($_.Exception.Message)"
    }
}

function Get-ServiceToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Graph', 'MDE', 'MDCA', 'Exchange')]
        [string] $TargetResource = 'Graph',
        [Parameter(Mandatory = $false)]
        [ValidateSet('CoreSecurityReporting', 'PurviewReporting', 'SensitiveComplianceReporting', 'ReportMailSender')]
        [string] $AppProfile = 'CoreSecurityReporting',
        [Parameter(Mandatory = $false)]
        [switch] $UseIsolatedApp
    )

    $cust = $PlatformConfig.CustomerConfig
    $tenantId = $cust.Customer.TenantId

    # İlgili uygulama ayarlarını seç (SensitiveComplianceReporting veya IsolatedApp talebi)
    $appConfig = if (($UseIsolatedApp -or $AppProfile -eq 'SensitiveComplianceReporting') -and $cust.Authentication.IsolatedApp.Enabled) {
        $cust.Authentication.IsolatedApp
    } else {
        $cust.Authentication.CoreApp
    }

    $clientId = $appConfig.ClientId
    $authMethod = if ($appConfig.AuthMethod) { $appConfig.AuthMethod } else { 'ClientSecret' }

    # Hedef scope belirleme
    $scope = switch ($TargetResource) {
        'MDE'      { "https://api.securitycenter.microsoft.com/.default" }
        'MDCA'     { "05a65629-4c1b-48c1-a78b-804c4abdd4c0/.default" }
        'Exchange' { "https://outlook.office365.com/.default" }
        default    { "https://graph.microsoft.com/.default" }
    }

    $cacheKey = "$tenantId|$clientId|$TargetResource|$AppProfile"

    # Önbellek kontrolü (Süresi bitmeye 5 dakika kalana kadar geçerli)
    if ($Script:TokenCache.ContainsKey($cacheKey)) {
        $cached = $Script:TokenCache[$cacheKey]
        if ($cached.ExpiresAt -gt (Get-Date).AddMinutes(5)) {
            return $cached.AccessToken
        }
    }

    $tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $body = @{
        client_id  = $clientId
        grant_type = "client_credentials"
        scope      = $scope
    }

    if ($authMethod -eq 'Certificate') {
        $cert = $null
        if ($appConfig.CertificateThumbprint) {
            $thumb = $appConfig.CertificateThumbprint.Replace(" ", "").Trim()
            $locations = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
            foreach ($loc in $locations) {
                if (Test-Path "$loc\$thumb") {
                    $cert = Get-Item "$loc\$thumb"
                    break
                }
            }
        }
        elseif ($appConfig.CertificateFilePath -and (Test-Path $appConfig.CertificateFilePath)) {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($appConfig.CertificateFilePath)
        }
        elseif ($appConfig.KeyVaultCertificateName -or ($env:AZURE_KEYVAULT_URL -and $appConfig.KeyVaultSecretName)) {
            $certName = if ($appConfig.KeyVaultCertificateName) { $appConfig.KeyVaultCertificateName } else { $appConfig.KeyVaultSecretName }
            $cert = Get-PlatformKeyVaultCertificate -CertificateName $certName
        }

        if (-not $cert) {
            throw "Belirtilen sertifika bulunamadı (Thumbprint: $($appConfig.CertificateThumbprint), Key Vault: $($appConfig.KeyVaultCertificateName))"
        }

        $assertion = New-ClientAssertionJwt -ClientId $clientId -TenantId $tenantId -Certificate $cert
        $body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        $body['client_assertion'] = $assertion
    }
    else {
        # Secret Çözme (Doğrudan ClientSecret, Azure Key Vault Managed Identity veya yerel Windows DPAPI)
        $plainSecret = $null
        if ($appConfig.ClientSecret) {
            $plainSecret = $appConfig.ClientSecret
        }
        elseif ($appConfig.KeyVaultSecretName) {
            $vaultUrl = if ($env:AZURE_KEYVAULT_URL) { $env:AZURE_KEYVAULT_URL } else { 'https://cs-kv-qwy6we.vault.azure.net' }
            try {
                $plainSecret = Get-PlatformKeyVaultSecret -SecretName $appConfig.KeyVaultSecretName -VaultUrl $vaultUrl
            }
            catch {
                Write-Verbose "Key Vault secret okunamadı ($($appConfig.KeyVaultSecretName)): $($_.Exception.Message)"
            }
        }
        elseif ($appConfig.SecretEncrypted) {
            $secretScope = if ($appConfig.DataProtectionScope) { $appConfig.DataProtectionScope } else { 'CurrentUser' }
            $plainSecret = Unprotect-PlatformSecret -EncryptedBase64 $appConfig.SecretEncrypted -Scope $secretScope
        }

        if (-not $plainSecret) {
            # Local dev fallback: Check untracked tenants.local.json or env variable
            if ($env:MSSP_CLIENT_SECRET) {
                $plainSecret = $env:MSSP_CLIENT_SECRET
            }
            else {
                $localTenantsPath = Join-Path $Script:RootPath '..\..\Data\tenants.local.json'
                if (Test-Path $localTenantsPath) {
                    try {
                        $locData = Get-Content $localTenantsPath -Raw -Encoding UTF8 | ConvertFrom-Json
                        $matchT = $locData | Where-Object { $_.TenantId -eq $tenantId -or $_.Auth.ClientId -eq $clientId }
                        if ($matchT.Auth.ClientSecret) {
                            $plainSecret = $matchT.Auth.ClientSecret
                        }
                    } catch {}
                }
            }
        }

        if (-not $plainSecret) {
            throw "İstemci secret anahtarı çözülemedi (ClientSecret boş veya Key Vault erişilemedi: $($appConfig.KeyVaultSecretName))."
        }
        $body['client_secret'] = $plainSecret
    }

    try {
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        $token = $response.access_token
        $expiresIn = if ($response.expires_in) { [int]$response.expires_in } else { 3599 }

        $Script:TokenCache[$cacheKey] = @{
            AccessToken = $token
            ExpiresAt   = (Get-Date).AddSeconds($expiresIn)
            Profile     = $AppProfile
            Resource    = $TargetResource
        }

        return $token
    }
    catch {
        $errDetail = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $errDetail = $reader.ReadToEnd()
            } catch {}
        }
        throw "Token alımı başarısız oldu ($TargetResource - $AppProfile): $errDetail"
    }
}

function Invalidate-ServiceToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $TenantId,
        [Parameter(Mandatory = $false)]
        [string] $ClientId = '',
        [Parameter(Mandatory = $false)]
        [string] $TargetResource = 'Graph',
        [Parameter(Mandatory = $false)]
        [string] $AppProfile = 'CoreSecurityReporting'
    )

    $keysToRemove = @()
    foreach ($k in $Script:TokenCache.Keys) {
        if ($k.StartsWith("$TenantId|")) {
            $keysToRemove += $k
        }
    }
    foreach ($k in $keysToRemove) {
        $Script:TokenCache.Remove($k)
    }
}

function Clear-RunTokenCache {
    [CmdletBinding()]
    param()

    $Script:TokenCache.Clear()
    [GC]::Collect()
}

function Invoke-PlatformRestApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Uri,
        [Parameter(Mandatory = $true)]
        [string] $AccessToken,
        [Parameter(Mandatory = $false)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string] $Method = 'GET',
        [Parameter(Mandatory = $false)]
        $Body = $null,
        [Parameter(Mandatory = $false)]
        [int] $MaxRetries = 3
    )

    $headers = @{
        Authorization = "Bearer $AccessToken"
        Accept        = "application/json"
    }

    if ($Body -and $Method -in @('POST', 'PATCH')) {
        $headers['Content-Type'] = 'application/json'
    }

    $retries = 0
    while ($retries -lt $MaxRetries) {
        try {
            $params = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $headers
                ErrorAction = 'Stop'
            }

            if ($Body) {
                $params['Body'] = if ($Body -is [string]) { $Body } else { ConvertTo-Json $Body -Depth 10 }
            }

            $response = Invoke-RestMethod @params
            return $response
        }
        catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            # HTTP 429 (Throttled) veya 503 (Service Unavailable) durumunda bekleme
            if ($statusCode -in @(429, 503)) {
                $retries++
                $retryAfter = 5
                if ($_.Exception.Response.Headers['Retry-After']) {
                    $retryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                }
                Start-Sleep -Seconds ($retryAfter + 1)
                continue
            }

            # HTTP 403 Forbidden tanılaması
            if ($statusCode -eq 403) {
                $errBody = ''
                try {
                    $stream = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $errBody = $reader.ReadToEnd()
                } catch {}
                throw "HTTP 403 Forbidden (PermissionMissing / NotConsented): $errBody ($Uri)"
            }

            throw $_
        }
    }
    throw "API isteği maksimum deneme sayısına ulaştı: $Uri"
}

Export-ModuleMember -Function Get-AvailableCertificates, Get-ServiceToken, Invalidate-ServiceToken, Clear-RunTokenCache, `
                              Invoke-PlatformRestApi, New-ClientAssertionJwt, Get-AzureManagedIdentityToken, `
                              Get-PlatformKeyVaultSecret, Get-PlatformKeyVaultCertificate

