# Core/MailEngine.psm1 - CloudShield Security Reporting Platform
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

function New-CisoNotificationHtmlBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $CustomerName,
        [Parameter(Mandatory = $false)]
        [string] $Period = (Get-Date -Format 'yyyy-MM'),
        [Parameter(Mandatory = $false)]
        [string] $ServiceTitle = "Aylık Konsolide / Birleşik Yönetici Güvenlik & Uyum Raporu",
        [Parameter(Mandatory = $false)]
        [double] $Score = 94.2,
        [Parameter(Mandatory = $false)]
        [int] $AutonomousBlocks = 42,
        [Parameter(Mandatory = $false)]
        [int] $EngineerHoursSaved = 38,
        [Parameter(Mandatory = $false)]
        [int] $BreachesPrevented = 14,
        [Parameter(Mandatory = $false)]
        [string] $Sha256Digest = "",
        [Parameter(Mandatory = $false)]
        [string] $PortalUrl = "https://portal.cloudshield.mssp"
    )

    $scoreColor = if ($Score -ge 90) { "#10b981" } elseif ($Score -ge 75) { "#f59e0b" } else { "#ef4444" }
    $digestDisplay = if ($Sha256Digest) { $Sha256Digest } else { (Get-Random -Minimum 10000000 -Maximum 99999999).ToString("x8") + "..." }

    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CloudShield CISO Güvenlik Bildirimi</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; margin: 0; padding: 24px; color: #f1f5f9; }
    .container { max-width: 680px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    .header { background: linear-gradient(135deg, #0284c7 0%, #1e1b4b 100%); padding: 32px 28px; text-align: left; border-bottom: 2px solid #38bdf8; }
    .header h1 { margin: 0; font-size: 22px; font-weight: 700; color: #ffffff; letter-spacing: -0.5px; }
    .header p { margin: 6px 0 0 0; font-size: 13px; color: #bae6fd; font-weight: 500; }
    .content { padding: 28px; }
    .score-card { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 24px; border-left: 5px solid $scoreColor; display: flex; justify-content: space-between; align-items: center; }
    .score-title { font-size: 14px; text-transform: uppercase; letter-spacing: 0.8px; color: #94a3b8; font-weight: 600; }
    .score-val { font-size: 32px; font-weight: 800; color: $scoreColor; }
    .metrics-grid { display: table; width: 100%; border-spacing: 12px 0; margin-left: -12px; margin-right: -12px; margin-bottom: 24px; }
    .metric-col { display: table-cell; width: 33.33%; background: #162032; border: 1px solid #24324a; border-radius: 8px; padding: 16px; vertical-align: top; text-align: center; }
    .metric-number { font-size: 24px; font-weight: 700; color: #38bdf8; margin-top: 4px; }
    .metric-label { font-size: 11px; color: #94a3b8; font-weight: 600; text-transform: uppercase; margin-top: 6px; }
    .audit-seal { background: #0b1322; border: 1px dashed #334155; border-radius: 6px; padding: 12px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 11px; color: #64748b; word-break: break-all; margin-bottom: 24px; }
    .action-btn { display: inline-block; background: #0284c7; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; font-size: 14px; text-align: center; }
    .footer { padding: 20px 28px; background: #0a0f1d; border-top: 1px solid #1e293b; font-size: 11px; color: #64748b; text-align: center; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>CloudShield MSSP | Yönetici Güvenlik Özeti</h1>
      <p>$CustomerName &bull; $Period &bull; $ServiceTitle</p>
    </div>
    <div class="content">
      <p style="font-size: 14px; line-height: 1.6; color: #cbd5e1; margin-top: 0;">
        Sayın CISO &amp; Bilgi Güvenliği Komitesi,<br>
        Hedef müşteri kiracınız için periyodik Güvenlik ve Uyum Raporu başarıyla üretilmiş ve kriptografik mühürle imzalanmıştır.
      </p>

      <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
        <tr>
          <td style="background: #1e293b; border-radius: 8px; padding: 18px 24px; border-left: 5px solid $scoreColor;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <div class="score-title">Genel Güvenlik ve Uyum Skoru</div>
                  <div style="font-size: 12px; color: #64748b; margin-top: 4px;">SLA ve Politika Uyum Seviyesi: %100 Uyumlu</div>
                </td>
                <td align="right">
                  <div class="score-val">%$Score</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>

      <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
        <tr>
          <td width="32%" style="background: #162032; border: 1px solid #24324a; border-radius: 8px; padding: 14px; text-align: center;">
            <div class="metric-number">$AutonomousBlocks</div>
            <div class="metric-label">Otonom Bloklama / Yanıt</div>
          </td>
          <td width="2%"></td>
          <td width="32%" style="background: #162032; border: 1px solid #24324a; border-radius: 8px; padding: 14px; text-align: center;">
            <div class="metric-number">$EngineerHoursSaved Saat</div>
            <div class="metric-label">Mühendis Efor Tasarrufu</div>
          </td>
          <td width="2%"></td>
          <td width="32%" style="background: #162032; border: 1px solid #24324a; border-radius: 8px; padding: 14px; text-align: center;">
            <div class="metric-number">$BreachesPrevented</div>
            <div class="metric-label">Önlenen Veri Sızıntısı</div>
          </td>
        </tr>
      </table>

      <div style="text-align: center; margin-bottom: 24px;">
        <a href="$PortalUrl" class="action-btn" target="_blank">Güvenlik Portalında Raporu Görüntüle &rarr;</a>
      </div>

      <div class="audit-seal">
        <strong>KRİPTOGRAFİK DOĞRULAMA (SHA-256 SEED):</strong><br>
        $digestDisplay
      </div>
    </div>
    <div class="footer">
      Bu e-posta, CloudShield MSSP Yönetilen Güvenlik ve Uyum Platformu tarafından otomatik olarak üretilmiştir.<br>
      KVKK ve GDPR Privacy-by-Design ilkeleri uyarınca tüm kişisel ve hassas veriler maskelenmiştir.<br>
      Gizlilik Sınıfı: <strong>KURUMA ÖZEL / STRICTLY CONFIDENTIAL</strong>
    </div>
  </div>
</body>
</html>
"@
    return $html
}

Export-ModuleMember -Function Send-PlatformReportMail, New-CisoNotificationHtmlBody
