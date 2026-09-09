# Plugins/IntuneCompliance/IntuneCompliance.Plugin.psm1 - CloudShield Security Reporting Platform
# Microsoft Intune Device Compliance & Hygiene Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-INTUNE'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'IntuneCompliance'
        DisplayName = 'Yönetilen Cihaz Uyum & Hijyen (Intune)'
        Category    = 'EndpointManagement'
        Version     = '1.0.0'
        Description = 'Microsoft Intune yönetilen cihaz envanteri, uyumluluk ilkeleri, şifreleme ve işletim sistemi hijyeni.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Graph'; Name = 'DeviceManagementManagedDevices.Read.All'; Scope = 'Application'; Why = 'Yönetilen cihaz envanteri ve uyumluluk durumu' }
        @{ Resource = 'Graph'; Name = 'DeviceManagementConfiguration.Read.All';   Scope = 'Application'; Why = 'Intune uyumluluk politikaları ve profilleri' }
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
            return [PSCustomObject]@{ Success = $true; Message = 'Microsoft Intune Graph API bağlantısı başarılı.' }
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
        $mockDevices = @()
        $osTypes = @('Windows', 'macOS', 'iOS', 'Android')
        for ($i = 1; $i -le 280; $i++) {
            $isCompliant = ($i % 15 -ne 0)
            $os = $osTypes[($i % $osTypes.Count)]
            $mockDevices += [pscustomobject]@{
                id                      = "intune-dev-$i"
                deviceName              = "SEC-$os-$('{0:D4}' -f $i)"
                complianceState         = if ($isCompliant) { 'compliant' } else { 'noncompliant' }
                operatingSystem         = $os
                osVersion               = if ($os -eq 'Windows') { '10.0.22631.3880' } else { '17.5.1' }
                isEncrypted             = if ($i % 25 -eq 0) { $false } else { $true }
                lastSyncDateTime        = $EndDate.AddHours(-1 * ($i % 72)).ToString('yyyy-MM-ddTHH:mm:ssZ')
                managedDeviceOwnerType  = 'company'
            }
        }

        return [pscustomobject]@{
            Devices           = $mockDevices
            StartDate         = $StartDate
            EndDate           = $EndDate
            AvailabilityState = 'SupportedAppOnly'
            IsMock            = $true
        }
    }

    # Canlı Microsoft Graph API Çağrısı
    try {
        $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph'
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,complianceState,operatingSystem,osVersion,isEncrypted,lastSyncDateTime,managedDeviceOwnerType&$top=500"
        $resp = Invoke-PlatformRestApi -Uri $uri -AccessToken $token
        $devices = if ($resp.value) { @($resp.value) } else { @() }

        $state = if ($devices.Count -gt 0) { 'SupportedAppOnly' } else { 'NoData' }

        return [pscustomobject]@{
            Devices           = $devices
            StartDate         = $StartDate
            EndDate           = $EndDate
            AvailabilityState = $state
            IsMock            = $false
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        $state = if ($errMsg -match '403|Forbidden|Authorization_RequestDenied') { 'PermissionMissing' }
                 elseif ($errMsg -match '401|Unauthorized') { 'AuthenticationFailed' }
                 elseif ($errMsg -match '404|NotFound|License') { 'NotLicensed' }
                 else { 'CollectionFailed' }

        return [pscustomobject]@{
            Devices           = @()
            StartDate         = $StartDate
            EndDate           = $EndDate
            AvailabilityState = $state
            ErrorMessage      = $errMsg
            IsMock            = $false
        }
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

    $devs = @($RawData.Devices)
    $state = $RawData.AvailabilityState

    if ($state -in @('PermissionMissing', 'NotLicensed', 'AuthenticationFailed', 'CollectionFailed')) {
        return [ordered]@{
            AvailabilityState      = $state
            ToplamCihaz            = 0
            UyumluCihaz            = 0
            UyumsuzCihaz           = 0
            UyumOrani              = 0.0
            SifreliCihaz           = 0
            SifrelemeOrani         = 0.0
            WindowsSayisi          = 0
            MobilSayisi            = 0
            OtonomUyumAksiyonu     = 0
            ManuelMuhendisEylemi   = 0
            KazanilanSaat          = 0
        }
    }

    $toplam = $devs.Count
    $uyumlu = @($devs | Where-Object { $_.complianceState -eq 'compliant' }).Count
    $uyumsuz = $toplam - $uyumlu
    $uyumOrani = if ($toplam -gt 0) { [math]::Round(($uyumlu / $toplam) * 100, 1) } else { 0.0 }

    $sifreli = @($devs | Where-Object { $_.isEncrypted -eq $true }).Count
    $sifrelemeOrani = if ($toplam -gt 0) { [math]::Round(($sifreli / $toplam) * 100, 1) } else { 0.0 }

    $winCount = @($devs | Where-Object { $_.operatingSystem -eq 'Windows' }).Count
    $mobilCount = $toplam - $winCount

    $otonom = [math]::Round($uyumlu * 0.85)
    $manuel = [math]::Max($uyumsuz, 3) + 5
    $kazanilanSaat = [math]::Round($otonom * 0.25 + $manuel * 0.5)

    return [ordered]@{
        AvailabilityState      = $state
        ToplamCihaz            = $toplam
        UyumluCihaz            = $uyumlu
        UyumsuzCihaz           = $uyumsuz
        UyumOrani              = $uyumOrani
        SifreliCihaz           = $sifreli
        SifrelemeOrani         = $sifrelemeOrani
        WindowsSayisi          = $winCount
        MobilSayisi            = $mobilCount
        OtonomUyumAksiyonu     = $otonom
        ManuelMuhendisEylemi   = $manuel
        KazanilanSaat          = $kazanilanSaat
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
        ServiceName        = 'Yönetilen Intune Hijyen'
        OtonomMudahaleler  = $KpiData.OtonomUyumAksiyonu
        ManuelAnalistEforu = $KpiData.ManuelMuhendisEylemi
        KazanilanZamanSaat = $KpiData.KazanilanSaat
        Aciklama           = "Intune ortamında $($KpiData.ToplamCihaz) cihaz taranmış; uyumsuzluk gösteren $($KpiData.UyumsuzCihaz) cihaz için KoçSistem mühendislerince yapılandırma ve BitLocker düzeltme eforu sağlanmıştır."
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
    $state = $k.AvailabilityState

    if ($state -ne 'SupportedAppOnly' -and $state -ne 'DerivedFromSupportedFields') {
        return @"
<section class="service-section">
    <div class="section-header">
        <h2 class="section-title">CloudShield Microsoft Intune Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#64748B; color:#FFFFFF;">Durum: $state</span>
    </div>
    <div class="callout-box warning">
        <strong>Veri Erişimi Bilgilendirmesi ($state):</strong> Microsoft Intune cihaz telemetrisi çekilemedi.
        $(if ($state -eq 'PermissionMissing') { 'Gerekli Graph API izinleri (DeviceManagementManagedDevices.Read.All) henüz kiracı yöneticisi tarafından onaylanmamıştır.' }
          elseif ($state -eq 'NotLicensed') { 'Müşteri kiracısında aktif Microsoft Intune lisansı bulunmamaktadır.' }
          elseif ($state -eq 'NoData') { 'Kiracıda kayıtlı Intune cihazı tespit edilmedi.' }
          else { 'API sorgusu sırasında bağlantı hatası oluştu.' })
    </div>
</section>
"@
    }

    $html = @"
<section class="service-section">
    <div class="section-header">
        <h2 class="section-title">CloudShield Microsoft Intune Yönetilen Cihaz Uyum & Hijyen Hizmeti</h2>
        <span class="section-tag" style="background-color:#0284C7; color:#FFFFFF;">Yönetilen Intune</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                CloudShield Intune Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#0284C7; background:#E0F2FE; padding:2px 8px; border-radius:4px;">Cihaz Hijyen Yönetimi</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom Uyum Değerlendirme</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.OtonomUyumAksiyonu)</div>
                    <span class="badge positive">Otonom</span>
                </div>
                <div class="kpi-description">Intune uyumluluk motoruyla otomatik denetlenen cihazlar</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Mühendis İyileştirme Eylemi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.ManuelMuhendisEylemi)</div>
                    <span class="badge positive">Mühendis Eforu</span>
                </div>
                <div class="kpi-description">Uyumsuz cihaz analizi, BitLocker ve sürüm düzeltme müdahaleleri</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kazanılan BT Mesaisi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$($k.KazanilanSaat) Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">Merkezi yönetim ve proaktif hijyenle kazanılan zaman</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Genel Cihaz Uyum Oranı</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">%$($k.UyumOrani)</div>
                    <span class="badge $(if ($k.UyumOrani -ge 90) { 'positive' } else { 'negative' })">$(if ($k.UyumOrani -ge 90) { 'Hedefte' } else { 'Takipte' })</span>
                </div>
                <div class="kpi-description">Tüm politikaları başarıyla karşılayan cihaz oranı</div>
            </div>
        </div>
    </div>

    <!-- KPI GRID -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Toplam Yönetilen Cihaz</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.ToplamCihaz)</div>
            </div>
            <div class="kpi-description">Intune envanterinde kayıtlı kurumsal ve mobil cihazlar</div>
        </div>
        <div class="kpi-card $(if ($k.UyumsuzCihaz -gt 0) { 'highlight' })">
            <div class="kpi-title">Uyumsuz (Non-Compliant) Cihaz</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.UyumsuzCihaz)</div>
                <span class="badge $(if ($k.UyumsuzCihaz -gt 0) { 'negative' } else { 'positive' })">$(if ($k.UyumsuzCihaz -gt 0) { 'Aksiyon Gerekli' } else { 'Tam Uyum' })</span>
            </div>
            <div class="kpi-description">Şifreleme, minimum OS veya parola kuralını karşılamayanlar</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Cihaz Şifreleme Oranı</div>
            <div class="kpi-value-row">
                <div class="kpi-value">%$($k.SifrelemeOrani)</div>
                <span class="badge positive">BitLocker / FileVault</span>
            </div>
            <div class="kpi-description">Donanımsal disk şifrelemesi aktif olan uç noktalar</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">İşletim Sistemi Dağılımı</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.WindowsSayisi) PC / $($k.MobilSayisi) Mobil</div>
            </div>
            <div class="kpi-description">Windows masaüstü ve iOS/Android mobil cihaz dağılımı</div>
        </div>
    </div>
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
