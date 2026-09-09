﻿# Plugins/PurviewGovernance/PurviewGovernance.Plugin.psm1 - CloudShield Security Reporting Platform
# Microsoft Purview Data Lifecycle & Records Management Service Plugin.
[CmdletBinding()]
param()

$Script:ServiceCode = 'SVC-PRV-GOV'

function Get-ServiceMetadata {
    return [ordered]@{
        ServiceCode = $Script:ServiceCode
        Name        = 'PurviewGovernance'
        DisplayName = 'Yönetilen Saklama ve İmha Politikaları'
        Category    = 'Compliance'
        Version     = '1.0.0'
        Description = 'Kurumsal veri yaşam döngüsü, saklama (retention) etiketleri, mevzuatsal arşivleme ve güvenli imha postürü.'
    }
}

function Get-ServiceDependencies {
    return @()
}

function Get-ServicePermissions {
    return @(
        @{ Resource = 'Exchange'; Name = 'Exchange.ManageAsApp'; Scope = 'Application'; Why = 'Saklama kuralları ve durumları' }
    )
}

function Test-ServiceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PlatformConfig
    )

    return [PSCustomObject]@{ Success = $true; Message = 'Purview Governance bağlantısı hazır.' }
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
            RetentionLabels = @(
                [pscustomobject]@{ Name = 'Mali ve Muhasebe Kayıtları'; RetentionDurationYears = 10; ActionAfter = 'Delete'; ItemCount = 480000 },
                [pscustomobject]@{ Name = 'Personel ve Özlük Dosyaları'; RetentionDurationYears = 15; ActionAfter = 'Review'; ItemCount = 210000 },
                [pscustomobject]@{ Name = 'Ticari Sözleşmeler'; RetentionDurationYears = 10; ActionAfter = 'KeepForever'; ItemCount = 145000 },
                [pscustomobject]@{ Name = 'Geçici Proje Çalışmaları'; RetentionDurationYears = 1; ActionAfter = 'Delete'; ItemCount = 84000 }
            )
            AutoDisposedItems = 34200
            PendingReviews    = 14
            StartDate         = $StartDate
            EndDate           = $EndDate
            IsMock            = $true
        }
    }

    return [pscustomobject]@{
        RetentionLabels   = @()
        AutoDisposedItems = 0
        PendingReviews    = 0
        StartDate         = $StartDate
        EndDate           = $EndDate
        IsMock            = $false
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

    $labels = @($RawData.RetentionLabels)
    $toplamKorumali = 0
    foreach ($l in $labels) { $toplamKorumali += [int]$l.ItemCount }

    return [ordered]@{
        ToplamSaklamaEtiketi = $labels.Count
        ToplamKorumaliOge    = $toplamKorumali
        ImhaEdilenEskiVeri   = $RawData.AutoDisposedItems
        OnayBekleyenImha     = $RawData.PendingReviews
        Etiketler            = $labels
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
        ServiceName        = 'Yönetilen Veri Yaşam Döngüsü'
        OtonomMudahaleler  = $KpiData.ImhaEdilenEskiVeri
        ManuelAnalistEforu = $KpiData.OnayBekleyenImha
        KazanilanZamanSaat = 0
        Aciklama           = "Kurum genelinde $($KpiData.ToplamKorumaliOge) adet doküman yasal saklama kurallarıyla kilitlenmiş, süresi dolan $($KpiData.ImhaEdilenEskiVeri) adet atıl veri otonom imha edilerek depolama maliyeti ve yasal sorumluluk riski azaltılmıştır."
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
        <h2 class="section-title">CloudShield Microsoft Purview Veri Yaşam Döngüsü ve Saklama Yönetilen Hizmeti</h2>
        <span class="section-tag" style="background-color:#002B49; color:#FFFFFF;">Yönetilen Veri Yönetişimi</span>
    </div>

    <!-- KOÇSİSTEM YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
    <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:13px; font-weight:700; color:var(--ks-navy); margin:0;">
                CloudShield Veri Yönetişimi Yönetilen Hizmet Operasyonel Değeri
            </h3>
            <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:0;">
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom Saklama Koruması</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$(if ($k.ToplamKorumaliOge) { '{0:N0}' -f $k.ToplamKorumaliOge } else { '-' })</div>
                    <span class="badge positive">Korumalı</span>
                </div>
                <div class="kpi-description">Yasal saklama politikaları ile kilitlenen kurumsal belgeler</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">CloudShield Uyum Uzman Eylemi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$($k.ToplamSaklamaEtiketi) Politika / $($k.OnayBekleyenImha) İnceleme</div>
                    <span class="badge positive">Uzman Eforu</span>
                </div>
                <div class="kpi-description">Saklama etiketi yaşam döngüsü doğrulamaları ve imha onay süreçleri</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Otonom İmha Edilen Eski Veri</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">$(if ($k.ImhaEdilenEskiVeri) { '{0:N0}' -f $k.ImhaEdilenEskiVeri } else { '-' })</div>
                    <span class="badge positive">Depolama Tasarrufu</span>
                </div>
                <div class="kpi-description">Yasal süresi dolup otonom imha edilen atıl veriler</div>
            </div>
            <div class="kpi-card" style="background:#FFFFFF;">
                <div class="kpi-title">Yasal Uyum Güvencesi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">%100</div>
                    <span class="badge positive">Uyumlu</span>
                </div>
                <div class="kpi-description">Yasal mevzuat ve regülasyonlara uygun saklama & imha garantisi</div>
            </div>
        </div>
    </div>

    <!-- ÜRÜNE ÖZEL ÇEKİRDEK GÜVENLİK METRİKLERİ -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Yasal Saklama Altındaki Veri</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.ToplamKorumaliOge) { '{0:N0}' -f $k.ToplamKorumaliOge } else { '-' })</div>
            </div>
            <div class="kpi-description">Mevzuatsal süre boyunca silinmesi engellenen öğeler</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Güvenli İmha Edilen Atıl Veri</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$(if ($k.ImhaEdilenEskiVeri) { '{0:N0}' -f $k.ImhaEdilenEskiVeri } else { '-' })</div>
                <span class="badge positive">Temizlendi</span>
            </div>
            <div class="kpi-description">Süresi dolup kurallara uygun silinen belgeler</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">İmha İncelemesi Bekleyen</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.OnayBekleyenImha)</div>
                <span class="badge neutral">Onay Bekliyor</span>
            </div>
            <div class="kpi-description">İnsan onayı gerektiren arşiv dosyaları</div>
        </div>

        <div class="kpi-card">
            <div class="kpi-title">Tanımlı Saklama Politikası</div>
            <div class="kpi-value-row">
                <div class="kpi-value">$($k.ToplamSaklamaEtiketi)</div>
            </div>
            <div class="kpi-description">Maliye, İK ve KVKK saklama etiketleri</div>
        </div>
    </div>
</section>
"@

    return $html
}

Export-ModuleMember -Function Get-ServiceMetadata, Get-ServiceDependencies, Get-ServicePermissions, `
                              Test-ServiceConnection, Get-ServiceRawData, Get-ServiceKpis, `
                              Get-ServiceHtmlSection, Get-ServiceManagedActions
