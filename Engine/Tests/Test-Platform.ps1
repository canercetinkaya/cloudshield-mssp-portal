<#
.SYNOPSIS
    CloudShield Microsoft Security Managed Services Reporting Platform - Kapsamlı Test Süiti
.DESCRIPTION
    Tüm çekirdek modüller, servis eklentileri (plugins), DPAPI şifreleme, gizlilik motoru,
    HTML ve vektörel PDF üretimini birim ve entegrasyon testleriyle doğrular.
.EXAMPLE
    .\Tests\Test-Platform.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

Write-Host "=================================================================================" -ForegroundColor Cyan
Write-Host "       CloudShield Microsoft Security Reporting Platform - Test Süiti              " -ForegroundColor White
Write-Host "=================================================================================" -ForegroundColor Cyan
Write-Host ""

$testResults = @()

function Assert-Test {
    param(
        [string] $TestName,
        [scriptblock] $Assertion
    )

    try {
        $res = & $Assertion
        if ($res -eq $true -or $null -eq $res) {
            Write-Host "   [PASS] $TestName" -ForegroundColor Green
            $script:testResults += [PSCustomObject]@{ Test = $TestName; Status = 'PASS'; Error = '' }
        } else {
            Write-Host "   [FAIL] $TestName (Assertion returned false)" -ForegroundColor Red
            $script:testResults += [PSCustomObject]@{ Test = $TestName; Status = 'FAIL'; Error = 'Returned False' }
        }
    }
    catch {
        Write-Host "   [FAIL] $TestName - $($_.Exception.Message)" -ForegroundColor Red
        $script:testResults += [PSCustomObject]@{ Test = $TestName; Status = 'FAIL'; Error = $_.Exception.Message }
    }
}

# 1. ÇEKİRDEK MODÜL YÜKLEME TESTLERİ
Write-Host "1. Çekirdek Modül (Core) Sözdizimi ve Yükleme Testleri:" -ForegroundColor Yellow
$coreFiles = Get-ChildItem -Path (Join-Path $root 'Core\*.psm1')
foreach ($cf in $coreFiles) {
    Assert-Test "Core Modül Yükleme: $($cf.Name)" {
        $mod = Import-Module $cf.FullName -PassThru -Force -ErrorAction Stop
        $mod.ExportedFunctions.Count -gt 0
    }
}

# 2. YAPILANDIRMA VE ŞEMA TESTLERİ
Write-Host "`n2. Yapılandırma ve Şema Doğrulama Testleri:" -ForegroundColor Yellow
Assert-Test "Servis Kataloğu (service-catalog.json) Geçerliliği" {
    $catPath = Join-Path $root 'Config\service-catalog.json'
    (Test-Path $catPath) -and (@((Get-Content $catPath -Raw | ConvertFrom-Json).Services.PSObject.Properties).Count -ge 10)
}

Assert-Test "Global Yapılandırma Şablonu Geçerliliği" {
    $globPath = Join-Path $root 'Config\global.config.template.json'
    (Test-Path $globPath) -and ((Get-Content $globPath -Raw -Encoding UTF8 | ConvertFrom-Json).Provider.ShortName -match 'Ko.Sistem|CloudShield')
}

Assert-Test "Müşteri Yapılandırma Şablonu Geçerliliği" {
    $custPath = Join-Path $root 'Config\customer.config.template.json'
    (Test-Path $custPath) -and (@((Get-Content $custPath -Raw | ConvertFrom-Json).Subscriptions.ActiveServices).Count -ge 3)
}

# 3. DPAPI ŞİFRELEME ROUND-TRIP TESTİ
Write-Host "`n3. DPAPI Şifreleme ve Gizlilik Motoru Testleri:" -ForegroundColor Yellow
Assert-Test "DPAPI Secret Şifreleme ve Çözme Döngüsü (Round-Trip)" {
    Import-Module (Join-Path $root 'Core\Configuration.psm1') -Force
    $plain = "CloudShield-Super-Secret-2026!#%"
    $enc = Protect-PlatformSecret -PlainText $plain -Scope 'CurrentUser'
    $dec = Unprotect-PlatformSecret -EncryptedBase64 $enc -Scope 'CurrentUser'
    $plain -eq $dec
}

Assert-Test "PrivacyEngine: k-Anonymity (k=5) Eşik Doğrulaması" {
    Import-Module (Join-Path $root 'Core\PrivacyEngine.psm1') -Force
    $data = @(
        [pscustomobject]@{ User = 'Alice'; Action = 'DLPDrop' },
        [pscustomobject]@{ User = 'Alice'; Action = 'DLPDrop' },
        [pscustomobject]@{ User = 'Alice'; Action = 'DLPDrop' },
        [pscustomobject]@{ User = 'Alice'; Action = 'DLPDrop' },
        [pscustomobject]@{ User = 'Alice'; Action = 'DLPDrop' },
        [pscustomobject]@{ User = 'Bob';   Action = 'DLPDrop' },
        [pscustomobject]@{ User = 'Bob';   Action = 'DLPDrop' }
    )
    $res = Apply-KAnonymity -Items $data -GroupByProperty 'User' -Threshold 5
    (@($res | Where-Object { $_.Key -eq 'Alice' }).Count -eq 1) -and
    (@($res | Where-Object { $_.Key -match 'k-Anonymity' }).Count -eq 1)
}

Assert-Test "PrivacyEngine: Deterministik Tuzlu SHA256 Maskeleme" {
    Import-Module (Join-Path $root 'Core\PrivacyEngine.psm1') -Force
    $m1 = Protect-UserIdentity -UserPrincipalName 'caner.cetinkaya@cloudshield-mssp.com' -TenantId 'Tenant-A'
    $m2 = Protect-UserIdentity -UserPrincipalName 'caner.cetinkaya@cloudshield-mssp.com' -TenantId 'Tenant-A'
    $m3 = Protect-UserIdentity -UserPrincipalName 'caner.cetinkaya@cloudshield-mssp.com' -TenantId 'Tenant-B'
    ($m1 -eq $m2) -and ($m1 -ne $m3) # Aynı tenant'ta aynı hash, farklı tenant'ta farklı hash
}

Assert-Test "PrivacyEngine: E-posta Maskeleme (a***.y***@sirket.com)" {
    Import-Module (Join-Path $root 'Core\PrivacyEngine.psm1') -Force
    $m = Protect-EmailAddress 'ahmet.yilmaz@sirket.com'
    $m -eq 'a***.y***@sirket.com'
}

Assert-Test "PrivacyEngine: Dosya Adı Maskeleme (Mali_Rapor_***.xlsx)" {
    Import-Module (Join-Path $root 'Core\PrivacyEngine.psm1') -Force
    $m1 = Protect-FileName 'Mali_Rapor_2026_Q2.xlsx'
    $m2 = Protect-FileName 'C:\Users\caner\Documents\Musteri_TCKN_Listesi.xlsx'
    ($m1 -eq 'Mali_Rapor_***.xlsx') -and ($m2 -eq 'Musteri_TCKN_***.xlsx')
}

Assert-Test "Logging: KVKK ve GDPR Kriptografik Denetim İzi (Audit Log)" {
    Import-Module (Join-Path $root 'Core\Logging.psm1') -Force
    Initialize-LogContext -CustomerName 'TestCustomer'
    Write-PlatformAuditLog -Action 'TestAudit' -CustomerName 'TestCustomer' -TenantId 'test-tenant-123'
    $auditPath = Get-AuditLogPath
    (Test-Path $auditPath) -and ((Get-Content $auditPath | Select-Object -Last 1) -match 'KVKK_Kanunu_md4_md12')
}

# 4. SERVİS EKLENTİSİ (PLUGIN) SÖZLEŞME VE İZİN TESTLERİ
Write-Host "`n4. Servis Eklentileri (Plugins) Standart Arayüz Sözleşme Testleri:" -ForegroundColor Yellow
$pluginFolders = Get-ChildItem -Path (Join-Path $root 'Plugins') -Directory
$mandatoryMethods = @(
    'Get-ServiceMetadata', 'Get-ServiceDependencies', 'Get-ServicePermissions',
    'Test-ServiceConnection', 'Get-ServiceRawData', 'Get-ServiceKpis',
    'Get-ServiceHtmlSection', 'Get-ServiceManagedActions'
)

foreach ($pFolder in $pluginFolders) {
    Assert-Test "Eklenti Standart Sözleşmesi: $($pFolder.Name)" {
        $pScript = Join-Path $pFolder.FullName "$($pFolder.Name).Plugin.psm1"
        if (-not (Test-Path $pScript)) { return $false }

        $mod = Import-Module $pScript -PassThru -Force -ErrorAction Stop
        foreach ($fn in $mandatoryMethods) {
            if (-not $mod.ExportedFunctions.ContainsKey($fn)) { return $false }
        }
        $meta = & $mod.ExportedFunctions['Get-ServiceMetadata'].ScriptBlock
        $meta.ServiceCode -match '^SVC-'
    }
}

# 5. UÇTAN UCA ENTEGRASYON VE RAPOR ÜRETİM TESTİ
Write-Host "`n5. Uçtan Uca Entegrasyon ve Rapor Üretim Testi (DryRun & PDF):" -ForegroundColor Yellow
Assert-Test "Invoke-CloudShieldSecurityReporting (DryRun + PDF)" {
    $invokeScript = Join-Path $root 'Invoke-CloudShieldSecurityReporting.ps1'
    $res = & $invokeScript -DryRun -Pdf
    $res.Success -eq $true -and (Test-Path $res.HtmlPath) -and (Test-Path $res.PdfPath) -and ((Get-Item $res.PdfPath).Length -gt 1000)
}

Assert-Test "Invoke-CloudShieldSecurityReporting Standalone Mod (Tekil MDO Servisi)" {
    $invokeScript = Join-Path $root 'Invoke-CloudShieldSecurityReporting.ps1'
    $res = & $invokeScript -ServiceCode 'SVC-MDO' -DryRun
    $res.Success -eq $true -and ($res.ServicesRun.Count -eq 1)
}

Write-Host ""
Write-Host "=================================================================================" -ForegroundColor Cyan
$passed = ($testResults | Where-Object { $_.Status -eq 'PASS' }).Count
$total = $testResults.Count
Write-Host "                 Test Tamamlandı: $passed / $total Test Başarılı                  " -ForegroundColor Green
Write-Host "=================================================================================" -ForegroundColor Cyan
