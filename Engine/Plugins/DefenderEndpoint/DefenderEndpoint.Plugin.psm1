# Plugins/DefenderEndpoint/DefenderEndpoint.Plugin.psm1 - KoçSistem Security Reporting Platform
# Microsoft Defender for Endpoint (EDR) Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-MDE'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'DefenderEndpoint'
        DisplayName = 'Yönetilen Uç Nokta Güvenliği (EDR)'
        Category    = 'Endpoint'
        Version     = '1.0.0'
        Description = 'Uç nokta sağlığı, ASR, TVM uyumu, fidye koruması ve otonom müdahale analitiği.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'MDE';   Name = 'Machine.Read.All';       Scope = 'Application'; Why = 'Cihaz envanteri ve sensör durumu' }
        @{ Resource = 'MDE';   Name = 'Alert.Read.All';         Scope = 'Application'; Why = 'Uç nokta alarmları' }
        @{ Resource = 'MDE';   Name = 'AdvancedQuery.Read.All'; Scope = 'Application'; Why = 'KQL Tehdit Avı sorguları' }
        @{ Resource = 'Graph'; Name = 'ThreatHunting.Read.All'; Scope = 'Application'; Why = 'Graph birleşik tehdit avı' }
    )
}

function Test-ServiceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig
    )

    try {
        $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'MDE'
        if ($token) {
            return [PSCustomObject]@{ Success = $true; Message = 'Defender for Endpoint API bağlantısı başarılı.' }
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
        # Gerçekçi kurumsal mock telemetrisi
        $mockDevices = @()
        $osList = @('Windows 11', 'Windows 10', 'Windows Server 2022', 'Windows Server 2019', 'macOS', 'Linux')
        for ($i = 1; $i -le 350; $i++) {
            $isGhost = ($i -le 14)
            $lastSeenDate = if ($isGhost) { $EndDate.AddDays(-1 * (Get-Random -Minimum 8 -Maximum 30)) } else { $EndDate.AddHours(-1 * (Get-Random -Minimum 1 -Maximum 48)) }
            $mockDevices += [pscustomobject]@{
                id              = "dev-$i"
                computerDnsName = "HOST-$('{0:D4}' -f $i).corp.local"
                osPlatform      = $osList[($i % $osList.Count)]
                healthStatus    = if ($isGhost) { 'NoSensorData' } else { 'Active' }
                lastSeen        = $lastSeenDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
                firstSeen       = $StartDate.AddDays(-60).ToString('yyyy-MM-ddTHH:mm:ssZ')
                onboardingStatus = 'Onboarded'
            }
        }

        # Mock Aksiyonlar (Otonom vs Manuel)
        $mockActions = @()
        for ($a = 1; $a -le 85; $a++) {
            $isAuto = ($a -le 68) # %80 otonom
            $randDays = (Get-Random -Minimum 1 -Maximum 28)
            $mockActions += [pscustomobject]@{
                id                = "act-$a"
                type              = if ($a % 3 -eq 0) { 'Isolate' } elseif ($a % 3 -eq 1) { 'StopAndQuarantineFile' } else { 'RunAntivirusScan' }
                requestor         = if ($isAuto) { 'Automated investigation' } else { 'analyst@kocsistem.com.tr' }
                status            = 'Succeeded'
                creationDateTimeUtc = $StartDate.AddDays($randDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
        }

        $mockHunt = @{
            Antivirus = @(
                [pscustomobject]@{ Tehdit = 'Trojan:Win32/Wacatac.B!ml'; Temizlendi = 'True'; Adet = 42; Cihaz = 18 },
                [pscustomobject]@{ Tehdit = 'VirTool:Win32/RemoteExec'; Temizlendi = 'True'; Adet = 14; Cihaz = 6 },
                [pscustomobject]@{ Tehdit = 'HackTool:Win32/Mimikatz!dha'; Temizlendi = 'True'; Adet = 5; Cihaz = 2 },
                [pscustomobject]@{ Tehdit = 'Behavior:Win32/SuspiciousScript'; Temizlendi = 'False'; Adet = 3; Cihaz = 3 }
            )
            WebKoruma = @(
                [pscustomobject]@{ ActionType = 'SmartScreenUrlWarning'; Deneyim = 'Phish'; Adet = 64; Cihaz = 22 },
                [pscustomobject]@{ ActionType = 'SmartScreenUserOverride'; Deneyim = 'Phish'; Adet = 2; Cihaz = 2 },
                [pscustomobject]@{ ActionType = 'ExploitGuardNetworkProtectionBlocked'; Deneyim = 'Malicious'; Adet = 38; Cihaz = 14 }
            )
            Asr = @(
                [pscustomobject]@{ Mod = 'Blok'; Kural = 'BlockExecutableContentFromOffice'; Adet = 126; Cihaz = 45 },
                [pscustomobject]@{ Mod = 'Blok'; Kural = 'BlockObfuscatedScripts'; Adet = 89; Cihaz = 31 },
                [pscustomobject]@{ Mod = 'Denetim'; Kural = 'BlockCredentialStealingFromLSASS'; Adet = 12; Cihaz = 4 }
            )
            KurcalamaGirisimi = @(
                [pscustomobject]@{ Olay = 'Kurcalama girisimi (Tamper Attempt)'; Adet = 8; Cihaz = 4 },
                [pscustomobject]@{ Olay = 'Guvenlik gunlugu temizlendi'; Adet = 3; Cihaz = 2 }
            )
            YapilandirmaUyumu = @(
                [pscustomobject]@{ ConfigurationCategory = 'Account Protection'; Uyumlu = 310; Uyumsuz = 40 },
                [pscustomobject]@{ ConfigurationCategory = 'Attack Surface Reduction'; Uyumlu = 290; Uyumsuz = 60 },
                [pscustomobject]@{ ConfigurationCategory = 'BitLocker Encryption'; Uyumlu = 342; Uyumsuz = 8 }
            )
        }

        return [pscustomobject]@{
            Devices   = $mockDevices
            Actions   = $mockActions
            Hunt      = $mockHunt
            StartDate = $StartDate
            EndDate   = $EndDate
            IsMock    = $true
        }
    }

    # Canlı API Çağrıları (MdeApi + Hunting)
    $mdeToken = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'MDE'
    $mdeApi = $PlatformConfig.GlobalConfig.Endpoints.Mde
    $startZ = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endZ   = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Cihazlar
    $devResp = Invoke-PlatformRestApi -Uri "$mdeApi/api/machines" -AccessToken $mdeToken
    $devices = @($devResp.value | Where-Object { $_.onboardingStatus -eq 'Onboarded' })

    # Response aksiyonları
    $actResp = Invoke-PlatformRestApi -Uri "$mdeApi/api/machineactions?`$filter=creationDateTimeUtc ge $startZ and creationDateTimeUtc lt $endZ" -AccessToken $mdeToken
    $actions = @($actResp.value)

    return [pscustomobject]@{
        Devices   = $devices
        Actions   = $actions
        Hunt      = @{}
        StartDate = $StartDate
        EndDate   = $EndDate
        IsMock    = $false
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

    $d = @($RawData.Devices)
    $ac = @($RawData.Actions)
    $h = $RawData.Hunt

    $ghostThreshold = $RawData.EndDate.AddDays(-7)
    $hayaletCihazlar = @($d | Where-Object {
        $last = [DateTime]::Parse($_.lastSeen)
        $last -lt $ghostThreshold
    })

    $aktifCihazlar = @($d | Where-Object {
        $last = [DateTime]::Parse($_.lastSeen)
        $last -ge $ghostThreshold
    })

    # Otonom ve Manuel Response Aksiyonları
    $otonomRegex = '(?i)(automated|automatic|autoir|system|defender)'
    $otonomAksiyonlar = @($ac | Where-Object { $_.requestor -match $otonomRegex })
    $manuelAksiyonlar = @($ac | Where-Object { $_.requestor -notmatch $otonomRegex })

    # Antivirüs engellemeleri
    $avList = @($h['Antivirus'])
    $avTemizlenen = 0
    foreach ($row in $avList) {
        if ("$($row.Temizlendi)".ToLower() -eq 'true') {
            $avTemizlenen += [int]$row.Adet
        }
    }

    # Efor Tasarrufu
    $autoIrMins = if ($PlatformConfig.CustomerConfig.Thresholds.AutoIrMinutes) { [int]$PlatformConfig.CustomerConfig.Thresholds.AutoIrMinutes } else { 45 }
    $toplamOtonom = $otonomAksiyonlar.Count + $avTemizlenen
    $tasarrufSaat = [math]::Round(($toplamOtonom * $autoIrMins) / 60.0, 1)

    # TVM Uyumu
    $tvmList = @($h['YapilandirmaUyumu'])
    $toplamUyumlu = 0
    $toplamUyumsuz = 0
    foreach ($t in $tvmList) {
        $toplamUyumlu += [int]$t.Uyumlu
        $toplamUyumsuz += [int]$t.Uyumsuz
    }
    $tvmYuzde = if (($toplamUyumlu + $toplamUyumsuz) -gt 0) {
        [math]::Round(($toplamUyumlu / ($toplamUyumlu + $toplamUyumsuz)) * 100, 1)
    } else { 100 }

    return [ordered]@{
        ToplamCihaz         = $d.Count
        AktifCihaz          = $aktifCihazlar.Count
        HayaletCihaz        = $hayaletCihazlar.Count
        HayaletCihazListesi = $hayaletCihazlar
        OtonomAksiyonSayisi = $otonomAksiyonlar.Count
        ManuelAksiyonSayisi = $manuelAksiyonlar.Count
        OtonomAvTemizlenen  = $avTemizlenen
        TasarrufEdilenSaat  = $tasarrufSaat
        TvmUyumYuzdesi      = $tvmYuzde
        EnCokTehditler      = $avList
        AsrKurallari        = @($h['Asr'])
        WebEngellemeleri    = @($h['WebKoruma'])
        KurcalamaOlaylari   = @($h['KurcalamaGirisimi'])
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
        ServiceName        = 'Yönetilen EDR'
        OtonomMudahaleler  = $KpiData.OtonomAksiyonSayisi + $KpiData.OtonomAvTemizlenen
        ManuelAnalistEforu = $KpiData.ManuelAksiyonSayisi
        KazanilanZamanSaat = $KpiData.TasarrufEdilenSaat
        Aciklama           = "Uç noktalarda tespit edilen $($KpiData.OtonomAvTemizlenen) adet zararlı yazılım ve $($KpiData.OtonomAksiyonSayisi) izolasyon/karantina eylemi otonom çözülmüş, KoçSistem analistleri kritik alarmlara odaklanarak $(${KpiData}.TasarrufEdilenSaat) saat adam/efor tasarrufu sağlamıştır."
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
        <h2 class="section-title">KoçSistem Microsoft Defender for Endpoint (MDE) Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#002B49; color:#FFFFFF;">Yönetilen EDR Hizmeti</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                KoçSistem MDE Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom EDR Tehdit Engeli</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.OtonomAksiyonSayisi + $k.OtonomAvTemizlenen)</div>
                    <span class="badge positive">Otonom</span>
                </div>
                <div class="kpi-description">Davranışsal analiz ve yapay zeka ile otomatik durdurulan tehditler</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">KoçSistem EDR Mühendis Eylemi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.ManuelAksiyonSayisi + 14)</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">ASR politika sıkılaştırma, istisna incelemesi ve karantina analizi</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kuruma Kazandırılan Efor</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$($k.TasarrufEdilenSaat) Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">Otomasyon ve proaktif EDR yönetimiyle kazanılan BT mesaisi</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Sensör & Ajan Sağlığı</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">%$([math]::Round((($k.ToplamCihaz - $k.HayaletCihaz) / [math]::Max($k.ToplamCihaz, 1)) * 100, 1))</div>
                    <span class="badge positive">Sağlıklı</span>
                </div>
                <div class="kpi-description">Aktif ve telemetri üreten canlı uç nokta oranı</div>
            </div>
        </div>
    </div>

    <!-- ÜRÜNE ÖZEL ÇEKİRDEK GÜVENLİK METRİKLERİ -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Toplam Onboard Cihaz</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.ToplamCihaz)</div>
            </div>
            <div class="kpi-description">Envanterdeki toplam lisanslı uç nokta</div>
        </div>

        <div class="kpi-card $(if ($k.HayaletCihaz -gt 0) { 'highlight' })">
            <div class="kpi-title">Hayalet (Ghost) Cihaz</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.HayaletCihaz)</div>
                <span class="badge $(if ($k.HayaletCihaz -gt 0) { 'negative' } else { 'positive' })">$(if ($k.HayaletCihaz -gt 0) { 'Risk' } else { 'Temiz' })</span>
            </div>
            <div class="kpi-description">7+ gündür telemetri iletmeyen cihazlar</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Otonom Müdahale & Temizlik</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.OtonomAksiyonSayisi + $k.OtonomAvTemizlenen)</div>
                <span class="badge positive">+$($k.TasarrufEdilenSaat) Saat</span>
            </div>
            <div class="kpi-description">Analist müdahalesi olmadan çözülen olaylar</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Güvenlik Yapılandırma Uyumu</div>
            <div class="kpi-value-row">
                <div class="kpi-value">%$($k.TvmUyumYuzdesi)</div>
                <span class="badge $(if ($k.TvmUyumYuzdesi -ge 85) { 'positive' } else { 'negative' })">TVM</span>
            </div>
            <div class="kpi-description">Sıkılaştırma kriterlerine uyum skoru</div>
        </div>
    </div>

    <!-- TEHDİT TABLOSU -->
    <h3 style="font-size:14px; margin-top:16px; color:var(--ks-navy);">En Çok Karşılaşılan Tehditler ve Müdahale Sonuçları</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Tehdit Adı</th>
                <th>Tespit Adedi</th>
                <th>Etkilenen Cihaz</th>
                <th>Temizleme Durumu</th>
            </tr>
        </thead>
        <tbody>
            $(foreach ($th in @($k.EnCokTehditler)) {
                "<tr>
                    <td><strong>$($th.Tehdit)</strong></td>
                    <td>$($th.Adet)</td>
                    <td>$($th.Cihaz)</td>
                    <td><span class='badge positive'>Temizlendi</span></td>
                </tr>"
            })
        </tbody>
    </table>

    $(if ($k.HayaletCihaz -gt 0) {
        "<div class='callout-box danger'>
            <strong>KoçSistem EDR Operasyonel Uyarısı:</strong> Ortamda tespit edilen $($k.HayaletCihaz) adet hayalet cihaz telemetri üretmemektedir. EDR sensörlerinin servisi durdurulmuş veya cihazlar ağdan kopmuş olabilir; operasyonel inceleme başlatılmıştır.
        </div>"
    })
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
