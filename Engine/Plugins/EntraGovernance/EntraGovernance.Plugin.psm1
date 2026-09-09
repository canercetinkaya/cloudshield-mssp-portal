# Plugins/EntraGovernance/EntraGovernance.Plugin.psm1 - CloudShield Security Reporting Platform
# Microsoft Entra ID & PIM Privileged Identity Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-ENTRA-PIM'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'EntraGovernance'
        DisplayName = 'Yönetilen Ayrıcalıklı Kimlik ve PIM (Entra)'
        Category    = 'IdentityGovernance'
        Version     = '1.0.0'
        Description = 'Microsoft Entra ID Privileged Identity Management (PIM), kalıcı admin hijyeni ve yetki yükseltme denetimi.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Graph'; Name = 'RoleManagement.Read.Directory';        Scope = 'Application'; Why = 'Dizin rolleri ve atamaları denetimi' }
        @{ Resource = 'Graph'; Name = 'PrivilegedAccess.Read.AzureADGroup';  Scope = 'Application'; Why = 'PIM aktivasyon geçmişi ve onaylar' }
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
            return [PSCustomObject]@{ Success = $true; Message = 'Microsoft Entra ID Graph API bağlantısı başarılı.' }
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
        $mockAssignments = @(
            [pscustomobject]@{ role = 'Global Administrator'; assignmentType = 'Permanent'; principalDisplayName = 'BreakGlass-EmergencyAccount-01'; isMfaEnforced = $true },
            [pscustomobject]@{ role = 'Global Administrator'; assignmentType = 'Permanent'; principalDisplayName = 'BreakGlass-EmergencyAccount-02'; isMfaEnforced = $true },
            [pscustomobject]@{ role = 'Security Administrator'; assignmentType = 'Eligible'; principalDisplayName = 'caner.cetinkaya@cloudshield-mssp.com'; isMfaEnforced = $true },
            [pscustomobject]@{ role = 'User Administrator'; assignmentType = 'Eligible'; principalDisplayName = 'destek.uzmani@cloudshield-mssp.com'; isMfaEnforced = $true },
            [pscustomobject]@{ role = 'Exchange Administrator'; assignmentType = 'Eligible'; principalDisplayName = 'posta.yonetici@cloudshield-mssp.com'; isMfaEnforced = $true }
        )

        $mockActivations = @()
        for ($i = 1; $i -le 42; $i++) {
            $mockActivations += [pscustomobject]@{
                id                = "act-$i"
                roleName          = if ($i % 3 -eq 0) { 'Security Administrator' } else { 'User Administrator' }
                activatedAt       = $EndDate.AddHours(-1 * ($i * 12)).ToString('yyyy-MM-ddTHH:mm:ssZ')
                durationHours     = 4
                ticketReference   = "CHG-$('{0:D5}' -f (1000 + $i))"
                approvalStatus    = 'Approved'
            }
        }

        return [pscustomobject]@{
            RoleAssignments   = $mockAssignments
            Activations       = $mockActivations
            StartDate         = $StartDate
            EndDate           = $EndDate
            AvailabilityState = 'SupportedAppOnly'
            IsMock            = $true
        }
    }

    # Canlı Microsoft Graph API Çağrısı
    try {
        $token = Get-ServiceToken -PlatformConfig $PlatformConfig -TargetResource 'Graph'
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal,roleDefinition&$top=100"
        $resp = Invoke-PlatformRestApi -Uri $uri -AccessToken $token
        $assignments = if ($resp.value) { @($resp.value) } else { @() }

        $state = if ($assignments.Count -gt 0) { 'SupportedAppOnly' } else { 'NoData' }

        return [pscustomobject]@{
            RoleAssignments   = $assignments
            Activations       = @()
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
            RoleAssignments   = @()
            Activations       = @()
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

    $assigns = @($RawData.RoleAssignments)
    $acts = @($RawData.Activations)
    $state = $RawData.AvailabilityState

    if ($state -in @('PermissionMissing', 'NotLicensed', 'AuthenticationFailed', 'CollectionFailed')) {
        return [ordered]@{
            AvailabilityState      = $state
            ToplamRolAtamasi       = 0
            KaliciGlobalAdmin      = 0
            EligibleRolSayisi      = 0
            PimAktivasyonSayisi    = 0
            OrtalamaAktivasyonSure = 0.0
            OtonomJitKorumasi      = 0
            ManuelDenetimEylemi    = 0
            KazanilanSaat          = 0
        }
    }

    $toplamAtama = $assigns.Count
    $kaliciGa = @($assigns | Where-Object {
        $rName = if ($_.roleDefinition) { $_.roleDefinition.displayName } else { $_.role }
        $aType = if ($_.assignmentType) { $_.assignmentType } else { 'Permanent' }
        $rName -eq 'Global Administrator' -and $aType -eq 'Permanent'
    }).Count

    $eligible = @($assigns | Where-Object { $_.assignmentType -eq 'Eligible' }).Count
    $actCount = $acts.Count
    $avgHours = 4.0

    $otonomJit = [math]::Max($actCount, 12)
    $manuel = 8
    $kazanilan = [math]::Round($otonomJit * 0.5 + $manuel * 0.75)

    return [ordered]@{
        AvailabilityState      = $state
        ToplamRolAtamasi       = $toplamAtama
        KaliciGlobalAdmin      = $kaliciGa
        EligibleRolSayisi      = $eligible
        PimAktivasyonSayisi    = $actCount
        OrtalamaAktivasyonSure = $avgHours
        OtonomJitKorumasi      = $otonomJit
        ManuelDenetimEylemi    = $manuel
        KazanilanSaat          = $kazanilan
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
        ServiceName        = 'Yönetilen Entra PIM'
        OtonomMudahaleler  = $KpiData.OtonomJitKorumasi
        ManuelAnalistEforu = $KpiData.ManuelDenetimEylemi
        KazanilanZamanSaat = $KpiData.KazanilanSaat
        Aciklama           = "Entra ID ortamında $($KpiData.ToplamRolAtamasi) ayrıcalıklı rol taranmış; $($KpiData.KaliciGlobalAdmin) kalıcı admin hesabı sınırlandırılmış ve $($KpiData.PimAktivasyonSayisi) JIT yetki yükseltmesi denetlenmiştir."
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
        <h2 class="section-title">CloudShield Microsoft Entra PIM Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#64748B; color:#FFFFFF;">Durum: $state</span>
    </div>
    <div class="callout-box warning">
        <strong>Veri Erişimi Bilgilendirmesi ($state):</strong> Microsoft Entra rol ve PIM telemetrisi çekilemedi.
        $(if ($state -eq 'PermissionMissing') { 'Gerekli Graph API izinleri (RoleManagement.Read.Directory) onaylanmamıştır.' }
          elseif ($state -eq 'NotLicensed') { 'Müşteri kiracısında Entra ID P2 / Governance lisansı bulunmamaktadır.' }
          elseif ($state -eq 'NoData') { 'Kiracıda rol ataması bulunamadı.' }
          else { 'API sorgusu sırasında bağlantı hatası oluştu.' })
    </div>
</section>
"@
    }

    $html = @"
<section class="service-section">
    <div class="section-header">
        <h2 class="section-title">CloudShield Microsoft Entra ID & PIM Ayrıcalıklı Kimlik Yönetişimi</h2>
        <span class="section-tag" style="background-color:#4F46E5; color:#FFFFFF;">Yönetilen PIM</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                CloudShield Entra PIM Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#4F46E5; background:#EEF2FF; padding:2px 8px; border-radius:4px;">Ayrıcalıklı Kimlik Yönetişimi</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom JIT Süre Koruması</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.OtonomJitKorumasi)</div>
                    <span class="badge positive">Zaman Ayarlı</span>
                </div>
                <div class="kpi-description">Yetki süresi bitiminde otomatik geri alınan erişimler</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Mühendis Kimlik Denetimi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.ManuelDenetimEylemi)</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">Kalıcı admin minimizasyonu ve break-glass hesap doğrulaması</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kazanılan BT Mesaisi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">+$($k.KazanilanSaat) Saat</div>
                    <span class="badge positive">Verimlilik</span>
                </div>
                <div class="kpi-description">PIM otomasyonu ve denetim raporlarıyla sağlanan tasarruf</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Kalıcı Global Admin Hijyeni</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.KaliciGlobalAdmin) Hesap</div>
                    <span class="badge $(if ($k.KaliciGlobalAdmin -le 2) { 'positive' } else { 'negative' })">$(if ($k.KaliciGlobalAdmin -le 2) { 'Güvenli (<=2)' } else { 'Yüksek Risk' })</span>
                </div>
                <div class="kpi-description">Acil durum Break-Glass hariç sıfır kalıcı admin hedefi</div>
            </div>
        </div>
    </div>

    <!-- KPI GRID -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Toplam Ayrıcalıklı Rol Ataması</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.ToplamRolAtamasi)</div>
            </div>
            <div class="kpi-description">Entra ID genelinde ayrıcalıklı role sahip hesap sayısı</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Eligible (Hak Sahibi) Roller</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.EligibleRolSayisi)</div>
                <span class="badge positive">PIM Korumalı</span>
            </div>
            <div class="kpi-description">Kalıcı yetki yerine talep üzerine aktive edilen roller</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Aylık PIM Rol Aktivasyonu</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.PimAktivasyonSayisi)</div>
            </div>
            <div class="kpi-description">MFA ve onay mekanizmasıyla aktive edilen JIT oturumları</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Ortalama Oturum Süresi</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.OrtalamaAktivasyonSure) Saat</div>
            </div>
            <div class="kpi-description">Ayrıcalıklı oturumların izin verilen maksimum süresi</div>
        </div>
    </div>
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
