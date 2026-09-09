# Core/Logging.psm1 - CloudShield Security Reporting Platform
# Structured JSONL logging, SIEM compatibility, and colored CLI output.
[CmdletBinding()]
param()

$Script:LogFile = $null
$Script:AuditLogFile = $null
$Script:CorrelationId = $null
$Script:LogInitialized = $false

function Get-SanitizedLogMessage {
    param([string] $Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return '' }
    $clean = $Message
    $clean = [regex]::Replace($clean, "Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", "Bearer [REDACTED_JWT]")
    $clean = [regex]::Replace($clean, "ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "[REDACTED_JWT]")
    $clean = [regex]::Replace($clean, "client_secret=[^&\s]+", "client_secret=[REDACTED_SECRET]")
    $clean = [regex]::Replace($clean, "password=[^&\s]+", "password=[REDACTED_SECRET]")
    $clean = [regex]::Replace($clean, '\b(?:\d[ -]*?){13,16}\b', '****-****-****-****')
    $clean = [regex]::Replace($clean, '\b[1-9]\d{10}\b', '***********')
    $clean = [regex]::Replace($clean, 'TR[0-9]{2}[0-9A-Z]{5}[0-9]{17}', 'TR**-****-****-****-****-**')
    return $clean
}

function Initialize-LogContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $LogsDirectory,
        [Parameter(Mandatory = $false)]
        [string] $CustomerName = 'System'
    )

    $root = Split-Path -Parent $PSScriptRoot
    if (-not $LogsDirectory) {
        $LogsDirectory = Join-Path $root 'Logs'
    }

    if (-not (Test-Path $LogsDirectory)) {
        New-Item -ItemType Directory -Path $LogsDirectory -Force | Out-Null
    }

    $monthStamp = (Get-Date).ToString('yyyy-MM')
    $safeCustomer = ($CustomerName -replace '[^A-Za-z0-9_-]', '_')
    $logFileName = "CloudShieldSecurityReporting_${safeCustomer}_${monthStamp}.jsonl"
    $auditFileName = "Audit_PurviewReporting_${safeCustomer}_${monthStamp}.jsonl"

    $Script:LogFile = Join-Path $LogsDirectory $logFileName
    $Script:AuditLogFile = Join-Path $LogsDirectory $auditFileName
    $Script:CorrelationId = [guid]::NewGuid().ToString()
    $Script:LogInitialized = $true

    Write-PlatformLog -Level 'INFO' -Message "Günlükleme başlatıldı. Log dosyası: $Script:LogFile" -Component 'Core.Logging'
    Write-PlatformLog -Level 'INFO' -Message "KVKK/GDPR Denetim İzi (Audit Log) dosyası: $Script:AuditLogFile" -Component 'Core.Logging'
}

function Write-PlatformLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'STEP', 'DEBUG')]
        [string] $Level = 'INFO',
        [Parameter(Mandatory = $false)]
        [string] $Component = 'General',
        [Parameter(Mandatory = $false)]
        [hashtable] $Properties = @{}
    )

    $sanitizedMessage = Get-SanitizedLogMessage -Message $Message
    $isoTimestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

    # Renkli konsol çıktısı
    switch ($Level) {
        'OK'    { Write-Host "   [OK]   $sanitizedMessage" -ForegroundColor Green }
        'STEP'  { Write-Host "   [->]   $sanitizedMessage" -ForegroundColor Cyan }
        'WARN'  { Write-Host "   [WARN] $sanitizedMessage" -ForegroundColor Yellow }
        'ERROR' { Write-Host "   [FAIL] $sanitizedMessage" -ForegroundColor Red }
        'DEBUG' { Write-Host "   [DBG]  $sanitizedMessage" -ForegroundColor DarkGray }
        default { Write-Host "   [INFO] $sanitizedMessage" -ForegroundColor White }
    }

    # Yapılandırılmış JSONL dosyasına yazma
    if ($Script:LogFile) {
        $logEntry = [ordered]@{
            timestamp     = $isoTimestamp
            level         = $Level
            correlationId = $Script:CorrelationId
            component     = $Component
            message       = $sanitizedMessage
            properties    = $Properties
        }

        try {
            $jsonLine = ConvertTo-Json $logEntry -Compress -Depth 5
            Add-Content -Path $Script:LogFile -Value $jsonLine -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch {
            # Log yazma hatası ana süreci asla durdurmamalı
        }
    }
}

function Write-PlatformAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Action,
        [Parameter(Mandatory = $true)]
        [string] $CustomerName,
        [Parameter(Mandatory = $false)]
        [string] $TenantId = 'Unknown',
        [Parameter(Mandatory = $false)]
        [string] $ReportPeriod = '',
        [Parameter(Mandatory = $false)]
        [string[]] $ActiveServices = @(),
        [Parameter(Mandatory = $false)]
        [hashtable] $AuditProperties = @{}
    )

    $isoTimestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $localTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $auditId = [guid]::NewGuid().ToString()

    $auditEntry = [ordered]@{
        auditEventId         = $auditId
        timestampUtc         = $isoTimestamp
        timestampLocal       = $localTimestamp
        action               = $Action
        customerName         = $CustomerName
        tenantId             = $TenantId
        operator             = "$env:USERDOMAIN\$env:USERNAME"
        machineName          = $env:COMPUTERNAME
        processId            = $PID
        correlationId        = $Script:CorrelationId
        reportPeriod         = $ReportPeriod
        activeServices       = $ActiveServices
        regulatoryFrameworks = @('KVKK_Kanunu_md4_md12', 'GDPR_Art5_Art25_Art32', 'ISO27001_A8.15_A8.16', 'BDDK_Bilgi_Sistemleri_md20')
        privacyGuarantees    = @{
            PseudonymizationSaltedSHA256 = $true
            KAnonymityThreshold          = 5
            FileNameMasking              = $true
            EmailMasking                 = $true
            IsolatedAppForPurviewRisk    = $true
        }
        details              = $AuditProperties
    }

    if ($Script:AuditLogFile) {
        try {
            $jsonLine = ConvertTo-Json $auditEntry -Compress -Depth 6
            Add-Content -Path $Script:AuditLogFile -Value $jsonLine -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch {}
    }

    Write-PlatformLog -Level 'INFO' -Message "KVKK/GDPR Denetim İzi Kaydedildi: [$Action] - Olay: $auditId" -Component 'Audit'
}

function Get-PlatformLogPath {
    return $Script:LogFile
}

function Get-AuditLogPath {
    return $Script:AuditLogFile
}

function Get-LogCorrelationId {
    return $Script:CorrelationId
}

Export-ModuleMember -Function Initialize-LogContext, Write-PlatformLog, Write-PlatformAuditLog, Get-PlatformLogPath, Get-AuditLogPath, Get-LogCorrelationId, Get-SanitizedLogMessage
