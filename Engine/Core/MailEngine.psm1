﻿# Core/MailEngine.psm1 - CloudShield Security Reporting Platform
# Multi-protocol report delivery: Microsoft Graph API (Mail.Send) and Modern SMTP with attachment handling.
[CmdletBinding()]
param()

function Send-PlatformReportMail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        [string] $Subject,
        [Parameter(Mandatory = $true)]
        [string] $HtmlBody,
        [Parameter(Mandatory = $false)]
        [string] $AttachmentPath,
        [Parameter(Mandatory = $false)]
        [string] $ServiceCode = $null
    )

    $delivery = $PlatformConfig.CustomerConfig.Delivery
    $method = if ($delivery.Method) { $delivery.Method } else { 'Graph' }
    $from = $delivery.From

    # Servise özel alıcı var mı?
    $to = @($delivery.To)
    $cc = @($delivery.Cc)

    if ($ServiceCode -and $delivery.ServiceSpecificRouting -and $delivery.ServiceSpecificRouting.PSObject.Properties[$ServiceCode]) {
        $svcRoute = $delivery.ServiceSpecificRouting.$ServiceCode
        if ($svcRoute.To -and $svcRoute.To.Count -gt 0) {
            $to = @($svcRoute.To)
        }
        if ($svcRoute.Cc -and $svcRoute.Cc.Count -gt 0) {
            $cc = @($svcRoute.Cc)
        }
    }

    if ($to.Count -eq 0) {
        Write-Warning "E-posta alıcısı belirtilmedi. Gönderim atlandı."
        return $false
    }

    if ($method -eq 'Graph') {
        # Graph API ile gönderim
        $graphToken = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph'
        $sendEndpoint = "https://graph.microsoft.com/v1.0/users/$from/sendMail"

        $attachments = @()
        if ($AttachmentPath -and (Test-Path $AttachmentPath)) {
            $fileBytes = [System.IO.File]::ReadAllBytes($AttachmentPath)
            $b64 = [Convert]::ToBase64String($fileBytes)
            $fileName = [System.IO.Path]::GetFileName($AttachmentPath)

            $attachments += @{
                "@odata.type" = "#microsoft.graph.fileAttachment"
                name          = $fileName
                contentType   = "application/pdf"
                contentBytes  = $b64
            }
        }

        $message = @{
            subject      = $Subject
            body         = @{
                contentType = "HTML"
                content     = $HtmlBody
            }
            toRecipients = @($to | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
            ccRecipients = @($cc | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
        }

        if ($attachments.Count -gt 0) {
            $message['attachments'] = $attachments
        }

        $payload = @{
            message         = $message
            saveToSentItems = "true"
        }

        Invoke-PlatformRestApi -Uri $sendEndpoint -AccessToken $graphToken -Method POST -Body $payload
        return $true
    }
    else {
        # SMTP ile gönderim
        $smtpConfig = $PlatformConfig.CustomerConfig.Smtp
        $smtp = New-Object System.Net.Mail.SmtpClient($smtpConfig.Server, $smtpConfig.Port)
        $smtp.EnableSsl = [bool]$smtpConfig.UseSsl

        if ($smtpConfig.User -and $smtpConfig.PasswordEncrypted) {
            $plainPass = Unprotect-PlatformSecret -EncryptedBase64 $smtpConfig.PasswordEncrypted
            $smtp.Credentials = New-Object System.Net.NetworkCredential($smtpConfig.User, $plainPass)
        }

        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($from)
        foreach ($t in $to) { $mail.To.Add($t) }
        foreach ($c in $cc) { $mail.CC.Add($c) }
        $mail.Subject = $Subject
        $mail.Body = $HtmlBody
        $mail.IsBodyHtml = $true

        if ($AttachmentPath -and (Test-Path $AttachmentPath)) {
            $att = New-Object System.Net.Mail.Attachment($AttachmentPath)
            $mail.Attachments.Add($att)
        }

        $smtp.Send($mail)
        $mail.Dispose()
        $smtp.Dispose()
        return $true
    }
}

Export-ModuleMember -Function Send-PlatformReportMail
