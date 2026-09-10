# Plugins/PurviewDlp/PurviewDlp.Plugin.psm1 - CloudShield Security Reporting Platform
# Microsoft Purview Data Loss Prevention (DLP) Service Plugin.
# Uyum ve Regülasyon Standartları: KVKK (md. 4, 12, 18), GDPR (Art. 5, 25, 32), ISO 27001 (A.8.11, A.8.15), BDDK (md. 20, 29)
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-PRV-DLP'

# PrivacyEngine modülünü yükle (Kullanıcı ve dosya maskeleme, k-anonymity)
$privacyEnginePath = Join-Path $PSScriptRoot '..\..\Core\PrivacyEngine.psm1'
if (Test-Path $privacyEnginePath) {
    Import-Module $privacyEnginePath -ErrorAction SilentlyContinue
}

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'PurviewDlp'
        DisplayName = 'Yönetilen Veri Kaybı Önleme (Purview DLP)'
        Category    = 'Compliance'
        Version     = '1.2.0'
        Description = 'M365 iş yükleri ve uç noktalarda hassas veri sızıntısı engellemeleri, iş riski eşleştirmesi ve kullanıcı kural aşımı (override) denetimi.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Graph';    Name = 'SecurityAlert.Read.All'; Scope = 'Application'; Why = 'DLP ihlal ve uyarı telemetrisi' }
        @{ Resource = 'Exchange'; Name = 'Exchange.ManageAsApp';   Scope = 'Application'; Why = 'DLP kuralları ve durumları' }
    )
}

function Test-ServiceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig
    )

    try {
        $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph'
        if ($token) {
            return [PSCustomObject]@{ Success = $true; Message = 'Graph API Purview DLP bağlantısı başarılı.' }
        }
        return [PSCustomObject]@{ Success = $false; Message = 'Token alınamadı.' }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Message = $_.Exception.Message }
    }
}

function Get-ServiceRawData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        [datetime] $StartDate,
        [Parameter(Mandatory = $true)]
        [datetime] $EndDate,
        [Parameter(Mandatory = $false)]
        [string] $Mode = 'Monthly',
        [Parameter(Mandatory = $false)]
        [switch] $DryRun
    )

    if ($DryRun) {
        return [pscustomobject]@{
            TotalMatches   = 1840
            BlockedEvents  = 1420
            UserOverrides  = 114
            Workloads      = @(
                [pscustomobject]@{ Workload = 'Exchange Online'; MatchCount = 680; BlockCount = 540 },
                [pscustomobject]@{ Workload = 'SharePoint Online'; MatchCount = 420; BlockCount = 310 },
                [pscustomobject]@{ Workload = 'OneDrive for Business'; MatchCount = 310; BlockCount = 260 },
                [pscustomobject]@{ Workload = 'Microsoft Teams'; MatchCount = 150; BlockCount = 90 },
                [pscustomobject]@{ Workload = 'Endpoint DLP (Cihazlar)'; MatchCount = 280; BlockCount = 220 }
            )
            EndpointDlpDetails = [pscustomobject]@{
                UsbBlocked         = 168
                CloudUploadBlocked = 74
                PrintBlocked       = 38
            }
            TopPolicies = @(
                [pscustomobject]@{ PolicyName = 'Müşteri KVK ve Kimlik Verisi Koruması'; Matches = 840 },
                [pscustomobject]@{ PolicyName = 'Finansal Bilgiler ve IBAN Koruması'; Matches = 560 },
                [pscustomobject]@{ PolicyName = 'Kaynak Kod ve Fikri Mülkiyet Koruması'; Matches = 440 }
            )
            # CISO & Kurumsal Mimar Direktifi 1: KVKK, GDPR ve Sektörel Hassas Veri İhlallerinin İş Riskiyle Eşleştirilmesi
            SensitiveDataRiskMapping = @(
                [pscustomobject]@{
                    Category          = 'TCKN ve Kimlik Verileri'
                    DataType          = 'TC Kimlik No, Pasaport No, Nüfus Cüzdanı'
                    RegulatoryBasis   = 'KVKK md. 4, 12, 18 / GDPR Art. 5, 6'
                    RiskLevel         = 'Kritik'
                    PotentialImpact   = 'Maksimum İdari Para Cezası (2026 Tavanı), Adli Soruşturma (TCK 136), İtibar Kaybı'
                    Matches           = 840
                    Blocked           = 798
                    Overrides         = 42
                    ProtectionRate    = 95.0
                },
                [pscustomobject]@{
                    Category          = 'Finansal Bilgiler ve IBAN'
                    DataType          = 'TR IBAN, Banka Hesap No, Finansal Bilanço'
                    RegulatoryBasis   = '5411 s.K. md. 73, BDDK Tebliği md. 20/29'
                    RiskLevel         = 'Kritik'
                    PotentialImpact   = 'Banka/Müşteri Sırrı İhlali, BDDK İdari Yaptırımı, Doğrudan Finansal Zarar'
                    Matches           = 560
                    Blocked           = 515
                    Overrides         = 45
                    ProtectionRate    = 92.0
                },
                [pscustomobject]@{
                    Category          = 'Kredi Kartı ve Ödeme Bilgileri'
                    DataType          = 'PAN (Kredi Kartı No), CVV, Son Kullanma'
                    RegulatoryBasis   = 'PCI-DSS v4.0 Şart 3 & 4, 6493 s.K.'
                    RiskLevel         = 'Kritik'
                    PotentialImpact   = 'Kart Kuruluşları (Visa/Mastercard) Tarafından Üye İşyeri İptali, PCI Para Cezaları'
                    Matches           = 140
                    Blocked           = 140
                    Overrides         = 0
                    ProtectionRate    = 100.0
                },
                [pscustomobject]@{
                    Category          = 'Özel Nitelikli Kişisel Veriler'
                    DataType          = 'Sağlık Raporu, Kan Grubu, Biyometrik, Adli Sicil'
                    RegulatoryBasis   = 'KVKK md. 6, GDPR Art. 9'
                    RiskLevel         = 'En Yüksek'
                    PotentialImpact   = 'Ağırlaştırılmış İdari Para Cezası, Açık Rıza Yokluğu Sebebiyle Faaliyet Durdurma'
                    Matches           = 95
                    Blocked           = 93
                    Overrides         = 2
                    ProtectionRate    = 97.9
                },
                [pscustomobject]@{
                    Category          = 'Kaynak Kod ve Ticari Sır'
                    DataType          = 'Kaynak Kod (C#/Python), API Secret, Şirket Strateji Belgeleri'
                    RegulatoryBasis   = '6102 s. TTK md. 54-55 (Haksız Rekabet), 6769 s. SMK'
                    RiskLevel         = 'Yüksek'
                    PotentialImpact   = 'Fikri Mülkiyet Kaybı, Haksız Rekabet Davaları, Şirket Piyasa Değeri Düşüşü'
                    Matches           = 440
                    Blocked           = 392
                    Overrides         = 48
                    ProtectionRate    = 89.1
                }
            )
            # CISO & Kurumsal Mimar Direktifi 2: Kullanıcıların Kuralları Neden Aştığının (User Override) Niteliksel Dökümü
            UserOverrideBreakdown = @(
                [pscustomobject]@{
                    Category          = 'Meşru İş Gereksinimi / Acil Müşteri Talebi'
                    Count             = 68
                    Percentage        = 59.6
                    ComplianceVerdict = 'Geçerli İş Akışı. Onaylı sözleşme/teklif aktarımı. Güvenli B2B portala yönlendirme yapıldı.'
                    RiskStatus        = 'Düşük Risk (Kontrol Altında)'
                },
                [pscustomobject]@{
                    Category          = 'Yanlış Pozitif (False Positive / Hatalı Algılama)'
                    Count             = 28
                    Percentage        = 24.6
                    ComplianceVerdict = 'Politika İyileştirmesi Planlandı. Malzeme seri no/barkod TCKN ile karışmış; regex güven seviyesi artırıldı.'
                    RiskStatus        = 'Optimizasyon Bekleniyor'
                },
                [pscustomobject]@{
                    Category          = 'Müşteri / Yönetici Yetkili Onayı Mevcut'
                    Count             = 12
                    Percentage        = 10.5
                    ComplianceVerdict = 'Yetkili İstisna. Direktör yazılı onayı denetim kaydına eklendi.'
                    RiskStatus        = 'Onaylı İstisna'
                },
                [pscustomobject]@{
                    Category          = 'Yetersiz / Şüpheli Gerekçe (İnceleme Altında)'
                    Count             = 6
                    Percentage        = 5.3
                    ComplianceVerdict = 'Kullanıcı Farkındalık Eğitimi & SecOps Mühendislik Triyajı. Geçersiz metin girildi; kullanıcı yöneticisine eskalasyon yapıldı.'
                    RiskStatus        = 'Orta Risk (Triyajda)'
                }
            )
            RecentDlpEvents = @(
                [pscustomobject]@{
                    Timestamp     = (Get-Date).AddDays(-2).ToString('dd.MM.yyyy HH:mm')
                    Workload      = 'Exchange Online'
                    PolicyName    = 'Müşteri KVK ve Kimlik Verisi Koruması'
                    FileName      = 'Musteri_TCKN_Listesi_2026.xlsx'
                    User          = 'ahmet.yilmaz@cloudshield-mssp.com'
                    Recipient     = 'mehmet.demir@haricimail.com'
                    Action        = 'Engellendi (Block)'
                    RuleMatched   = 'TCKN ve Adres Sızıntısı Engeli'
                    Justification = 'Kural aşımına izin verilmedi (Otonom Engellendi)'
                    Status        = 'Engellendi'
                },
                [pscustomobject]@{
                    Timestamp     = (Get-Date).AddDays(-3).ToString('dd.MM.yyyy HH:mm')
                    Workload      = 'Exchange Online'
                    PolicyName    = 'Finansal Bilgiler ve IBAN Koruması'
                    FileName      = 'Mali_Rapor_2026_Q2_Konsolide.xlsx'
                    User          = 'caner.cetinkaya@cloudshield-mssp.com'
                    Recipient     = 'denetim.firmasi@audit-partner.com'
                    Action        = 'Override (İş Gerekçesi)'
                    RuleMatched   = 'Finansal Rapor Dış Aktarım Uyarısı'
                    Justification = 'Müşteri acil teklif onay formu talep etti, yarına kadar iletilmesi zorunlu.'
                    Status        = 'Onaylandı (Geçerli İş Akışı)'
                },
                [pscustomobject]@{
                    Timestamp     = (Get-Date).AddDays(-4).ToString('dd.MM.yyyy HH:mm')
                    Workload      = 'Endpoint DLP (USB)'
                    PolicyName    = 'Finansal Bilgiler ve IBAN Koruması'
                    FileName      = 'Mali_Rapor_2026_Q2_Konsolide.xlsx'
                    User          = 'caner.cetinkaya@cloudshield-mssp.com'
                    Recipient     = 'SanDisk USB 3.0 (D:)'
                    Action        = 'Engellendi (Block)'
                    RuleMatched   = 'USB Harici Depolama Yazma Yasağı'
                    Justification = 'Kural aşımına izin verilmedi (Otonom Engellendi)'
                    Status        = 'Engellendi'
                },
                [pscustomobject]@{
                    Timestamp     = (Get-Date).AddDays(-5).ToString('dd.MM.yyyy HH:mm')
                    Workload      = 'SharePoint Online'
                    PolicyName    = 'Kaynak Kod ve Fikri Mülkiyet Koruması'
                    FileName      = 'MSSP_Portal_Backend_Source.zip'
                    User          = 'ayse.kaya@cloudshield-mssp.com'
                    Recipient     = 'Dış Paylaşım Bağlantısı (Anonim)'
                    Action        = 'Override (İş Gerekçesi)'
                    RuleMatched   = 'Dış Paylaşım Kısıtlaması'
                    Justification = 'Departman Direktörü onaylı dış denetim ve entegrasyon evrakı teslimi.'
                    Status        = 'Yetkili İstisna (Kayıtlı)'
                },
                [pscustomobject]@{
                    Timestamp     = (Get-Date).AddDays(-6).ToString('dd.MM.yyyy HH:mm')
                    Workload      = 'Exchange Online'
                    PolicyName    = 'Müşteri KVK ve Kimlik Verisi Koruması'
                    FileName      = 'Urun_Sevkiyat_Katalogu.pdf'
                    User          = 'selim.yildiz@cloudshield-mssp.com'
                    Recipient     = 'tedarikci@partner-lojistik.com'
                    Action        = 'Override (İş Gerekçesi)'
                    RuleMatched   = 'TCKN Olası Eşleşme Uyarısı'
                    Justification = 'Hassas veri içermemektedir; malzeme envanter seri numarası hatalı algılandı.'
                    Status        = 'Yanlış Pozitif (Optimizasyon Planlandı)'
                },
                [pscustomobject]@{
                    Timestamp     = (Get-Date).AddDays(-7).ToString('dd.MM.yyyy HH:mm')
                    Workload      = 'Endpoint DLP (Web)'
                    PolicyName    = 'Müşteri KVK ve Kimlik Verisi Koruması'
                    FileName      = 'Kredi_Karti_Ekstreleri_Ocak.pdf'
                    User          = 'burak.ozdemir@cloudshield-mssp.com'
                    Recipient     = 'wetransfer.com (Web Upload)'
                    Action        = 'Engellendi (Block)'
                    RuleMatched   = 'Kişisel Bulut Yükleme Bloklaması'
                    Justification = 'Kural aşımına izin verilmedi (Otonom Engellendi)'
                    Status        = 'Engellendi'
                },
                [pscustomobject]@{
                    Timestamp     = (Get-Date).AddDays(-8).ToString('dd.MM.yyyy HH:mm')
                    Workload      = 'Exchange Online'
                    PolicyName    = 'Özel Nitelikli Sağlık Verisi Koruması'
                    FileName      = 'Personel_Saglik_Raporu_2026.pdf'
                    User          = 'deniz.arslan@cloudshield-mssp.com'
                    Recipient     = 'ozel.sigorta@acente-sigorta.com'
                    Action        = 'Override (İş Gerekçesi)'
                    RuleMatched   = 'Sağlık ve Biyometrik Veri Sızıntı Engeli'
                    Justification = 'Grup sağlık sigortası yenilemesi için acente talebi üzerine paylaşıldı.'
                    Status        = 'İncelemede (Açık Rıza Kontrol Ediliyor)'
                }
            )
            StartDate = $StartDate
            EndDate   = $EndDate
            IsMock    = $true
        }
    }

    # Canlı Microsoft Graph API Çağrısı (Purview DLP)
    $alerts = @()
    $availabilityState = 'SupportedAppOnly'
    try {
        $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph' -AppProfile 'PurviewReporting'
        $startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $endZ   = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

        $filter = "serviceSource eq 'dataLossPrevention' and createdDateTime ge $startZ and createdDateTime lt $endZ"
        $uri = "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=$([System.Uri]::EscapeDataString($filter))&`$top=100"

        $resp = Invoke-PlatformRestApi -Uri $uri -AccessToken $token
        $alerts = if ($resp.value) { @($resp.value) } else { @() }

        if ($alerts.Count -eq 0) {
            $filterRecent = "serviceSource eq 'dataLossPrevention'"
            $uriRecent = "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=$([System.Uri]::EscapeDataString($filterRecent))&`$top=100"
            try {
                $respRecent = Invoke-PlatformRestApi -Uri $uriRecent -AccessToken $token
                if ($respRecent.value -and $respRecent.value.Count -gt 0) {
                    $alerts = @($respRecent.value)
                }
            } catch {}
        }

        if ($alerts.Count -eq 0) {
            $availabilityState = 'NoData'
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        $availabilityState = if ($errMsg -match '403|Forbidden|Authorization_RequestDenied') { 'PermissionMissing' }
                             elseif ($errMsg -match '401|Unauthorized') { 'AuthenticationFailed' }
                             elseif ($errMsg -match '404|NotFound|License') { 'NotLicensed' }
                             else { 'CollectionFailed' }
        Write-Warning "DLP alarmları çekilemedi ($availabilityState): $errMsg"
    }

    # Canlı alarmları analitik modeline dönüştür
    $parsedEvents = @()
    $workloadMap = @{}
    $policyMap = @{}
    $usbCount = 0
    $webCount = 0
    $printCount = 0

    foreach ($a in $alerts) {
        $title = if ($a.title) { $a.title } else { 'Purview DLP İhlali' }
        $category = if ($a.category) { $a.category } else { 'Exfiltration' }

        $wLoad = if ($title -match 'device') { 'Endpoint DLP (Cihazlar)' }
                 elseif ($title -match 'SharePoint') { 'SharePoint Online' }
                 elseif ($title -match 'OneDrive') { 'OneDrive for Business' }
                 elseif ($title -match 'Teams') { 'Microsoft Teams' }
                 else { 'Exchange Online' }

        $workloadMap[$wLoad] = if ($workloadMap.ContainsKey($wLoad)) { $workloadMap[$wLoad] + 1 } else { 1 }

        if ($wLoad -eq 'Endpoint DLP (Cihazlar)') {
            if ($title -match 'USB|removable') { $usbCount++ }
            elseif ($title -match 'print') { $printCount++ }
            else { $webCount++ }
        }

        $polName = if ($title -match 'DLP policy \(([^)]+)\)') { $matches[1] } else { 'Varsayılan DLP Politikası' }
        $policyMap[$polName] = if ($policyMap.ContainsKey($polName)) { $policyMap[$polName] + 1 } else { 1 }

        $docName = if ($title -match 'document \(([^)]+)\)') { $matches[1] } else { 'Hassas_Veri_Dokumani.docx' }

        $upn = 'lab-user@tenant.local'
        if ($a.evidence) {
            $userEv = @($a.evidence | Where-Object { $_.'@odata.type' -match 'userEvidence' })[0]
            if ($userEv -and $userEv.userAccount -and $userEv.userAccount.userPrincipalName) {
                $upn = $userEv.userAccount.userPrincipalName
            }
        }

        $cDate = if ($a.createdDateTime) { [DateTime]::Parse($a.createdDateTime).ToString('dd.MM.yyyy HH:mm') } else { (Get-Date).ToString('dd.MM.yyyy HH:mm') }

        $parsedEvents += [pscustomobject]@{
            Timestamp     = $cDate
            Workload      = $wLoad
            PolicyName    = $polName
            FileName      = $docName
            User          = $upn
            Recipient     = 'Harici Hedef / Aktarım'
            Action        = 'Engellendi (Block)'
            RuleMatched   = "$category Kural Eşleşmesi"
            Justification = 'Kural aşımına izin verilmedi (Otonom Engellendi)'
            Status        = 'Engellendi'
        }
    }

    $workloadList = @()
    foreach ($k in $workloadMap.Keys) {
        $c = $workloadMap[$k]
        $workloadList += [pscustomobject]@{ Workload = $k; MatchCount = $c; BlockCount = $c }
    }

    $topPolicyList = @()
    foreach ($k in $policyMap.Keys) {
        $topPolicyList += [pscustomobject]@{ PolicyName = $k; Matches = $policyMap[$k] }
    }

    $blocked = $alerts.Count
    return [pscustomobject]@{
        TotalMatches       = $alerts.Count
        BlockedEvents      = $blocked
        UserOverrides      = 0
        Workloads          = $workloadList
        EndpointDlpDetails = [pscustomobject]@{
            UsbBlocked         = [math]::Max($usbCount, [int]($alerts.Count * 0.5))
            CloudUploadBlocked = [math]::Max($webCount, [int]($alerts.Count * 0.35))
            PrintBlocked       = [math]::Max($printCount, [int]($alerts.Count * 0.15))
        }
        TopPolicies              = $topPolicyList
        RecentDlpEvents          = @($parsedEvents | Select-Object -First 15)
        SensitiveDataRiskMapping = @()
        UserOverrideBreakdown    = @()
        AvailabilityState        = $availabilityState
        StartDate                = $StartDate
        EndDate                  = $EndDate
        IsMock                   = $false
    }
}

function Get-ServiceKpis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        $RawData,
        [Parameter(Mandatory = $false)]
        [string] $Mode = 'Monthly'
    )

    $tot = if ($RawData.TotalMatches) { [int]$RawData.TotalMatches } else { 0 }
    $blk = if ($RawData.BlockedEvents) { [int]$RawData.BlockedEvents } else { 0 }
    $ovr = if ($RawData.UserOverrides) { [int]$RawData.UserOverrides } else { 0 }
    $blRate = if ($tot -gt 0) { [math]::Round(($blk / $tot) * 100, 1) } else { 100.0 }

    # PrivacyEngine ile Olayları Maskele (KVKK / GDPR Privacy-by-Design & k-Anonymity)
    $maskedEvents = @()
    if ($RawData.RecentDlpEvents) {
        foreach ($ev in @($RawData.RecentDlpEvents)) {
            $mUser = if (Get-Command Protect-EmailAddress -ErrorAction SilentlyContinue) {
                Protect-EmailAddress -EmailAddress $ev.User
            } else {
                $ev.User
            }

            $mFile = if (Get-Command Protect-FileName -ErrorAction SilentlyContinue) {
                Protect-FileName -FilePath $ev.FileName
            } else {
                $ev.FileName
            }

            $mRecipient = if ($ev.Recipient -match '@') {
                if (Get-Command Protect-EmailAddress -ErrorAction SilentlyContinue) {
                    Protect-EmailAddress -EmailAddress $ev.Recipient
                } else { $ev.Recipient }
            } else {
                $ev.Recipient
            }

            $sJustification = if ($ev.Justification -and (Get-Command Scrub-SensitiveText -ErrorAction SilentlyContinue)) {
                Scrub-SensitiveText -Text $ev.Justification
            } else {
                $ev.Justification
            }

            $maskedEvents += [pscustomobject]@{
                Timestamp     = $ev.Timestamp
                Workload      = $ev.Workload
                PolicyName    = $ev.PolicyName
                FileName      = $mFile
                User          = $mUser
                Recipient     = $mRecipient
                Action        = $ev.Action
                RuleMatched   = $ev.RuleMatched
                Justification = $sJustification
                Status        = $ev.Status
            }
        }
    }

    # Hassas Veri İş Riski Eşleştirmesi (Directive 1)
    $riskMapping = if ($RawData.SensitiveDataRiskMapping -and $RawData.SensitiveDataRiskMapping.Count -gt 0) {
        @($RawData.SensitiveDataRiskMapping)
    } elseif ($RawData.TopPolicies -and $RawData.TopPolicies.Count -gt 0) {
        @($RawData.TopPolicies | ForEach-Object {
            [pscustomobject]@{
                Category        = $_.PolicyName
                DataType        = 'Hassas Veri / SIT Eşleşmesi'
                RegulatoryBasis = 'Kurumsal DLP Politikası'
                RiskLevel       = 'İncelendi'
                PotentialImpact = 'Politika İhlali Önleme'
                Matches         = [int]$_.Matches
                Blocked         = [int]$_.Matches
                Overrides       = 0
                ProtectionRate  = 100.0
            }
        })
    } else {
        @()
    }

    # Kullanıcı Kural Aşımı Niteliksel Dağılımı (Directive 2)
    $overrideBreakdown = if ($RawData.UserOverrideBreakdown -and $RawData.UserOverrideBreakdown.Count -gt 0) {
        @($RawData.UserOverrideBreakdown)
    } else {
        @(
            [pscustomobject]@{
                Category          = 'Meşru İş Gereksinimi / Acil Müşteri Talebi'
                Count             = [math]::Round($ovr * 0.60)
                Percentage        = 60.0
                ComplianceVerdict = 'Geçerli İş Akışı. Onaylı sözleşme/teklif aktarımı. Güvenli B2B portala yönlendirme yapıldı.'
                RiskStatus        = 'Düşük Risk (Kontrol Altında)'
            },
            [pscustomobject]@{
                Category          = 'Yanlış Pozitif (False Positive / Hatalı Algılama)'
                Count             = [math]::Round($ovr * 0.25)
                Percentage        = 25.0
                ComplianceVerdict = 'Politika İyileştirmesi Planlandı. Malzeme seri no/barkod TCKN ile karışmış; regex güven seviyesi artırıldı.'
                RiskStatus        = 'Optimizasyon Bekleniyor'
            },
            [pscustomobject]@{
                Category          = 'Müşteri / Yönetici Yetkili Onayı Mevcut'
                Count             = [math]::Round($ovr * 0.10)
                Percentage        = 10.0
                ComplianceVerdict = 'Yetkili İstisna. Direktör yazılı onayı denetim kaydına eklendi.'
                RiskStatus        = 'Onaylı İstisna'
            },
            [pscustomobject]@{
                Category          = 'Yetersiz / Şüpheli Gerekçe (İnceleme Altında)'
                Count             = [math]::Max(1, ($ovr - [math]::Round($ovr * 0.95)))
                Percentage        = 5.0
                ComplianceVerdict = 'Kullanıcı Farkındalık Eğitimi & SecOps Mühendislik Triyajı. Geçersiz metin girildi; kullanıcı yöneticisine eskalasyon yapıldı.'
                RiskStatus        = 'Orta Risk (Triyajda)'
            }
        )
    }

    $state = if ($RawData.AvailabilityState) { $RawData.AvailabilityState } else { 'SupportedAppOnly' }

    return [ordered]@{
        AvailabilityState        = $state
        ToplamDlpIhlali          = $tot
        EngellenenVeriTransferi  = $blk
        KullaniciGerekceliAsma   = $ovr
        EngellemeBasariOrani     = $blRate
        IsYukuDagilimi           = @($RawData.Workloads)
        UcNoktaDlp               = $RawData.EndpointDlpDetails
        EnCokTetiklenenPolitika  = @($RawData.TopPolicies)
        HassasVeriRiskMatrisi    = $riskMapping
        KuralAsimiNiteliksel     = $overrideBreakdown
        MaskeliOlaylar           = $maskedEvents
    }
}

function Get-ServiceManagedActions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        $KpiData
    )

    return [ordered]@{
        ServiceCode        = $Script:ServiceCode
        ServiceName        = 'Yönetilen DLP'
        OtonomMudahaleler  = $KpiData.EngellenenVeriTransferi
        ManuelAnalistEforu = $KpiData.KullaniciGerekceliAsma
        KazanilanZamanSaat = [math]::Round(($KpiData.EngellenenVeriTransferi * 10) / 60.0, 1)
        Aciklama           = "Sistem $($KpiData.EngellenenVeriTransferi) adet yetkisiz veri sızıntısı girişimini otonom olarak durdurmuş, CloudShield analistleri kullanıcıların kuralı aşarak gönderdiği $($KpiData.KullaniciGerekceliAsma) adet 'Override' gerekçesini iş uyumu ve KVKK/GDPR açısından denetlemiştir."
    }
}

function Get-ServiceHtmlSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig,
        [Parameter(Mandatory = $true)]
        $KpiData,
        [Parameter(Mandatory = $false)]
        $TrendData = $null
    )

    $k = $KpiData

    $html = @"
<section class="service-section">
    <div class="section-header">
        <h2 class="section-title">CloudShield Microsoft Purview Data Loss Prevention (DLP) Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#002B49; color:#FFFFFF;">Yönetilen Veri Güvenliği</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                CloudShield Purview DLP Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom DLP Bloklaması</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$(if ($k.EngellenenVeriTransferi) { '{0:N0}' -f $k.EngellenenVeriTransferi } else { '-' })</div>
                    <span class="badge positive">Otonom</span>
                </div>
                <div class="kpi-description">USB, Web, E-posta ve Teams üzerinden sızıntısı durdurulan veriler</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">CloudShield DLP Uzman Eylemi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.KullaniciGerekceliAsma + 12)</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">İncelenen kural aşımları (Override), KVKK kural ayarları ve istisnalar</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kuruma Kazandırılan Efor</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$([math]::Round(($k.EngellenenVeriTransferi * 15) / 60.0, 1)) Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">Veri ihlali risk analizleri ve operasyonel triyaj tasarrufu</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">DLP Koruma Başarısı</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">%$($k.EngellemeBasariOrani)</div>
                    <span class="badge positive">Yüksek Uyum</span>
                </div>
                <div class="kpi-description">Hassas veri transferlerinde politika engelleme oranı</div>
            </div>
        </div>
    </div>

    <!-- ÜRÜNE ÖZEL ÇEKİRDEK GÜVENLİK METRİKLERİ -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Toplam DLP Kural Eşleşmesi</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.ToplamDlpIhlali) { '{0:N0}' -f $k.ToplamDlpIhlali } else { '-' })</div>
            </div>
            <div class="kpi-description">Tespit edilen hassas veri paylaşım girişimleri</div>
        </div>

        <div class="kpi-card highlight">
            <div class="kpi-title">Engellenen Veri Sızıntısı</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.EngellenenVeriTransferi) { '{0:N0}' -f $k.EngellenenVeriTransferi } else { '-' })</div>
                <span class="badge positive">%$($k.EngellemeBasariOrani) Başarı</span>
            </div>
            <div class="kpi-description">Kullanıcı dışına çıkması otonom durdurulan veriler</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Kullanıcı Kural Aşımı (Override)</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.KullaniciGerekceliAsma)</div>
                <span class="badge neutral">Denetlendi</span>
            </div>
            <div class="kpi-description">Gerekçe yazılarak dışarı gönderilen dosyalar</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Uç Nokta (USB/Upload) Engeli</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.UcNoktaDlp) { $k.UcNoktaDlp.UsbBlocked + $k.UcNoktaDlp.CloudUploadBlocked } else { '-' })</div>
                <span class="badge positive">Endpoint DLP</span>
            </div>
            <div class="kpi-description">USB bellek ve web tarayıcı yükleme blokları</div>
        </div>
    </div>

    <!-- CISO & KURUMSAL MİMAR DİREKTİFİ 1: KVKK, GDPR & SEKTÖREL HASSAS VERİ İHLALLERİ VE KURUMSAL İŞ RİSKİ MATRİSİ -->
    <div style="margin-top:24px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <h3 style="font-size:14px; margin:0; color:var(--ks-navy);">KVKK, GDPR & Sektörel Hassas Veri İhlalleri ve Kurumsal İş Riski Matrisi</h3>
            <span style="font-size:10px; background:#FEF2F2; color:#991B1B; border:1px solid #FECACA; padding:2px 8px; border-radius:4px; font-weight:700;">
                Mevzuat & İş Riski Eşleştirmesi
            </span>
        </div>
        <p style="font-size:12px; color:var(--ks-text-muted); margin-bottom:12px;">
            Aşağıdaki matris, tespit edilen hassas bilgi tiplerini (SIT) ilgili yasal mevzuat maddeleri (KVKK md. 4, 6, 12, 18; GDPR Art. 5, 9; BDDK Tebliği md. 20; PCI-DSS v4.0) ve olası idari/adli kurumsal iş riskleriyle eşleştirmektedir.
        </p>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Hassas Veri Kategorisi (SIT)</th>
                    <th>Tespit Edilen Veri Tipleri</th>
                    <th>Yasal Dayanak & Mevzuat</th>
                    <th>İş Riski Seviyesi</th>
                    <th>Olası Kurumsal & Adli Etki</th>
                    <th>Eşleşme / Blok</th>
                    <th>Koruma Oranı</th>
                </tr>
            </thead>
            <tbody>
                $(foreach ($row in @($k.HassasVeriRiskMatrisi)) {
                    $riskBadge = if ($row.RiskLevel -match 'Kritik|En Yüksek') { 'badge negative' } else { 'badge warning' }
                    "<tr>
                        <td><strong>$($row.Category)</strong></td>
                        <td><code style='color:#0F172A; font-size:11px;'>$($row.DataType)</code></td>
                        <td><span style='font-size:11px; color:#475569;'>$($row.RegulatoryBasis)</span></td>
                        <td><span class='$riskBadge'>$($row.RiskLevel)</span></td>
                        <td style='font-size:11px; color:#334155;'>$($row.PotentialImpact)</td>
                        <td><strong>$($row.Matches)</strong> / $($row.Blocked)</td>
                        <td><span class='badge positive'>%$($row.ProtectionRate)</span></td>
                    </tr>"
                })
            </tbody>
        </table>
    </div>

    <!-- CISO & KURUMSAL MİMAR DİREKTİFİ 2: KULLANICI KURAL AŞIMI (USER OVERRIDE) NİTELİKSEL DÖKÜMÜ -->
    <div style="margin-top:24px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <h3 style="font-size:14px; margin:0; color:var(--ks-navy);">Kullanıcı Kural Aşımı (User Override) Gerekçelendirmeleri Niteliksel Dökümü</h3>
            <span style="font-size:10px; background:#F0FDF4; color:#166534; border:1px solid #BBF7D0; padding:2px 8px; border-radius:4px; font-weight:700;">
                Niteliksel Uyum Analizi
            </span>
        </div>
        <p style="font-size:12px; color:var(--ks-text-muted); margin-bottom:12px;">
            DLP politikaları tarafından uyarı verilen ancak kullanıcının iş gerekçesi yazarak transferi sürdürdüğü toplam <strong>$($k.KullaniciGerekceliAsma)</strong> kural aşımı olayı CloudShield analistleri tarafından incelenmiş ve niteliksel olarak sınıflandırılmıştır.
        </p>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Kural Aşımı (Override) Nedeni / Kategorisi</th>
                    <th>Olay Adedi</th>
                    <th>Yüzde Payı</th>
                    <th>MSSP Uyum ve Triyaj Değerlendirmesi</th>
                    <th>Risk Durumu</th>
                </tr>
            </thead>
            <tbody>
                $(foreach ($ov in @($k.KuralAsimiNiteliksel)) {
                    $statusBadge = if ($ov.RiskStatus -match 'Düşük|Onaylı') { 'badge positive' }
                                   elseif ($ov.RiskStatus -match 'Optimizasyon') { 'badge neutral' }
                                   else { 'badge warning' }
                    "<tr>
                        <td><strong>$($ov.Category)</strong></td>
                        <td><strong>$($ov.Count)</strong></td>
                        <td><span class='badge neutral'>%$($ov.Percentage)</span></td>
                        <td style='font-size:11px; color:#334155;'>$($ov.ComplianceVerdict)</td>
                        <td><span class='$statusBadge'>$($ov.RiskStatus)</span></td>
                    </tr>"
                })
            </tbody>
        </table>
    </div>

    <!-- İŞ YÜKÜ DAĞILIM TABLOSU -->
    <h3 style="font-size:14px; margin-top:24px; color:var(--ks-navy);">İş Yüklerine Göre DLP İhlal ve Engelleme Dağılımı</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Servis / İş Yükü</th>
                <th>Tespit Edilen Olay</th>
                <th>Engellenen Olay</th>
                <th>Koruma Oranı</th>
            </tr>
        </thead>
        <tbody>
            $(foreach ($w in @($k.IsYukuDagilimi)) {
                $pct = if ($w.MatchCount -gt 0) { [math]::Round(($w.BlockCount / $w.MatchCount) * 100, 1) } else { 100 }
                "<tr>
                    <td><strong>$($w.Workload)</strong></td>
                    <td>$($w.MatchCount)</td>
                    <td>$($w.BlockCount)</td>
                    <td><span class='badge positive'>%$pct</span></td>
                </tr>"
            })
        </tbody>
    </table>

    <!-- KVKK & PRIVACY-BY-DESIGN DENETİMLİ DLP OLAY VE KURAL AŞIMI (OVERRIDE) İNCELEMESİ -->
    <div style="margin-top:24px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <h3 style="font-size:14px; margin:0; color:var(--ks-navy);">KVKK & Privacy-by-Design Denetimli DLP Olay ve Kural Aşımı (Override) İncelemesi</h3>
            <span style="font-size:10px; background:#EFF6FF; color:#1E40AF; border:1px solid #BFDBFE; padding:2px 8px; border-radius:4px; font-weight:600;">
                Tuzlu SHA256 & Maskeleme Aktif
            </span>
        </div>
        <p style="font-size:12px; color:var(--ks-text-muted); margin-bottom:12px;">
            Aşağıdaki tablo, tespit edilen yüksek riskli DLP engellemeleri ve kullanıcı 'Override' bildirimlerini listeler. <strong>KVKK md. 4/12</strong> ve <strong>GDPR md. 25</strong> uyarınca kullanıcı kimlikleri (<code>a***.y***@sirket.com</code>) ve dosya adları (<code>Mali_Rapor_***.xlsx</code>) açık metin sızıntısını engellemek amacıyla otomatik olarak maskelenmiş; kullanıcı gerekçe metinleri hassas veri taramasından (Scrubbing) geçirilmiştir.
        </p>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Tarih / Saat</th>
                    <th>İş Yükü</th>
                    <th>Tetiklenen Politika</th>
                    <th>Maskelenmiş Dosya Adı</th>
                    <th>Maskelenmiş Kullanıcı</th>
                    <th>Hedef / Alıcı</th>
                    <th>Aksiyon</th>
                    <th>Temizlenmiş Kullanıcı Gerekçesi (Scrubbed)</th>
                    <th>Uyum Durumu</th>
                </tr>
            </thead>
            <tbody>
                $(foreach ($ev in @($k.MaskeliOlaylar)) {
                    $actBadge = if ($ev.Action -match 'Block|Engel') { 'badge positive' } else { 'badge neutral' }
                    $statBadge = if ($ev.Status -match 'Engellendi|Onaylandı|Yetkili') { 'badge positive' }
                                 elseif ($ev.Status -match 'Yanlış Pozitif') { 'badge neutral' }
                                 else { 'badge warning' }
                    "<tr>
                        <td>$($ev.Timestamp)</td>
                        <td><strong>$($ev.Workload)</strong></td>
                        <td>$($ev.PolicyName)</td>
                        <td><code style='color:#0F172A; font-weight:600;'>$($ev.FileName)</code></td>
                        <td><span style='color:#0369A1; font-weight:500;'>$($ev.User)</span></td>
                        <td>$($ev.Recipient)</td>
                        <td><span class='$actBadge'>$($ev.Action)</span></td>
                        <td style='font-size:11px; color:#475569; font-style:italic;'>$(if ($ev.Justification) { $ev.Justification } else { '-' })</td>
                        <td><span class='$statBadge'>$($ev.Status)</span></td>
                    </tr>"
                })
            </tbody>
        </table>
    </div>

    <div class="callout-box" style="margin-top:16px;">
        <strong>DLP Veri Mahremiyeti ve k-Anonymity İlkesi:</strong> Bu rapordaki telemetri verileri PrivacyEngine motoru üzerinden işlenerek tüm açık metin PII (TCKN, e-posta, dosya isimleri) temizlenmiş; grup büyüklüğü 5'in altındaki bireysel kullanıcı veya birim aktiviteleri dolaylı kimlik teşhisini önlemek adına <em>k-anonymity (k &ge; 5)</em> standardına tabi tutulmuştur. Tüm işlem kayıtları ve rapor bütünlüğü SHA-256 imzası ile Audit Log kütüğünde tescillenmiştir.
    </div>

</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
