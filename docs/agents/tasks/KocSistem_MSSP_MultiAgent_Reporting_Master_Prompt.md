# KoçSistem Microsoft Security Managed Services Reporting Platform

## Multi-Agent Uygulama ve Doğrulama Ana Promptu

## 1. Ana Görev

Mevcut PowerShell tabanlı **MDE Monthly Reporting** çözümünü temel alarak, KoçSistem MSSP müşterilerinin satın aldığı Microsoft güvenlik hizmetlerine göre seçilebilir, modüler, en az ayrıcalıklı ve otomatik çalışan bir **KoçSistem Microsoft Security Managed Services Reporting Platform** tasarla, geliştir, test et ve üretime hazır hale getir.

Çalışma tek bir agent tarafından yürütülmemelidir. Sistemde bulunan aşağıdaki uzman agentları aktif olarak görevlendir:

1. Principal Security Architect
2. Customer Enterprise Architect
3. MSSP Operations Architect
4. Microsoft Purview & Regulatory Compliance Lead
5. Azure Solutions & DevOps Architect
6. QA Automation Engineer
7. Customer CISO & Board Executive

Her agent kendi uzmanlık alanında bağımsız analiz yapmalı, somut artifact üretmeli, kararlarını ve risklerini kayıt altına almalı ve ilgili diğer agentların çıktılarını eleştirel olarak kontrol etmelidir.

Agentların çalışmış görünmesi yeterli değildir. Her agent için üretilen artifact, alınan karar, kullanılan kanıt, tespit edilen risk ve onay durumu görünür olmalıdır.

---

## 2. Platform Hedefleri

Platform aşağıdaki işlevleri sağlamalıdır:

- Müşteri bilgilerini interaktif PowerShell sihirbazıyla almak
- Müşterinin aldığı yönetilen hizmetleri seçtirmek
- Seçilen her hizmet için hizmet seviyesini belirlemek
- Servis bağımlılıklarını otomatik çözmek
- Yalnızca seçilen servislerin KPI kataloğunu etkinleştirmek
- Yalnızca seçilen servisler için gereken minimum read-only izinleri hesaplamak
- App Registration ve sertifika kurulumunu yönlendirmek veya uygunsa otomatikleştirmek
- API, PowerShell, Advanced Hunting ve Management Activity API collector modüllerini çalıştırmak
- Hizmete özel KPI ve trendleri üretmek
- Microsoft teknolojilerinin otomatik koruma aksiyonları ile KoçSistem operasyon faaliyetlerini ayırmak
- Executive PDF, Technical PDF, HTML, CSV ve JSON çıktıları üretmek
- Test modunda anlık rapor göndermek
- Üretim modunda aylık Task Scheduler görevi oluşturmak
- Yinelenen çalışma ve yinelenen e-posta gönderimini engellemek
- Veri gizliliği, anonimleştirme ve minimum group size kontrollerini uygulamak
- Her KPI için veri kaynağı, sorgu, minimum izin, lisans, gizlilik ve destek durumunu belgelemek

---

## 3. Desteklenecek Bağımsız Hizmetler

### SVC-MDE
Yönetilen Uç Nokta Güvenliği, EDR, Microsoft Defender for Endpoint

### SVC-MDO
Yönetilen E-Posta Güvenliği, Microsoft Defender for Office 365 ve Exchange Online Protection

### SVC-MDI
Yönetilen Kimlik Tehdit Koruması, Microsoft Defender for Identity

### SVC-MDCA
Yönetilen Bulut Uygulama Güvenliği, Microsoft Defender for Cloud Apps

### SVC-XDR
Yönetilen XDR Olay Yönetimi ve MTTR, Microsoft Defender XDR

### SVC-INTUNE
Yönetilen Cihaz Uyum ve Hijyen, Microsoft Intune

### SVC-ENTRA-PIM
Yönetilen Ayrıcalıklı Kimlik ve PIM, Microsoft Entra ID ve Privileged Identity Management

### SVC-PRV-DLP
Yönetilen Veri Kaybı Önleme, Microsoft Purview DLP ve Endpoint DLP

### SVC-PRV-CLASS
Yönetilen Veri Envanteri ve Sınıflandırma, Information Protection, Sensitivity Labels, Sensitive Information Types ve Data Classification

### SVC-PRV-GOV
Yönetilen Saklama ve İmha Politikaları, Data Lifecycle Management ve Records Management

### SVC-PRV-RISK
Yönetilen İç Tehdit ve İletişim Uyumu, Insider Risk Management, Adaptive Protection ve Communication Compliance

### SVC-AI-SECURITY
Yönetilen Yapay Zekâ ve Copilot Güvenliği, DSPM, DSPM for AI, Copilot audit, DLP ve ilgili AI güvenlik sinyalleri

Seçilmeyen bir servis için collector çalışmamalı, permission istenmemeli, lisans kontrolü yapılmamalı ve rapor bölümü oluşturulmamalıdır.

---

## 4. Agent Orkestrasyonu

### Aşama 1: Keşif ve kapsam

Paralel çalışacak agentlar:

- Principal Security Architect
- Customer Enterprise Architect
- MSSP Operations Architect
- Microsoft Purview & Regulatory Compliance Lead

### Aşama 2: Ortak tasarım

- Principal Security Architect
- Azure Solutions & DevOps Architect
- MSSP Operations Architect
- Microsoft Purview & Regulatory Compliance Lead

### Aşama 3: Geliştirme

- Azure Solutions & DevOps Architect
- Principal Security Architect

İlgili servis için MSSP Operations Architect ve Microsoft Purview & Regulatory Compliance Lead alan denetçisi olarak sürece katılmalıdır.

### Aşama 4: Test ve güvenlik doğrulama

- QA Automation Engineer
- Principal Security Architect
- Azure Solutions & DevOps Architect

### Aşama 5: Yönetici raporu ve hizmet değeri kontrolü

- Customer CISO & Board Executive
- Customer Enterprise Architect
- MSSP Operations Architect

### Aşama 6: Nihai serbest bırakma kararı

Bir servis modülü aşağıdaki onaylar olmadan `ProductionReady` olamaz:

- Principal Security Architect: `SecurityApproved`
- MSSP Operations Architect: `OperationallyApproved`
- Purview modüllerinde Microsoft Purview & Regulatory Compliance Lead: `ComplianceApproved`
- Azure Solutions & DevOps Architect: `DeploymentApproved`
- QA Automation Engineer: `QualityApproved`
- Customer Enterprise Architect: `CustomerFitApproved`
- Customer CISO & Board Executive: `ExecutiveReportApproved`

Bir agent onay vermezse red nedeni, etkilenen artifact, blocking durumu, düzeltme ve retest sonucu kayıt altına alınmalıdır. Güvenlik veya uyumluluk engelleri çoğunluk oyuyla aşılamaz.

---

## 5. Agent Sorumlulukları

### 5.1 Principal Security Architect

Sorumluluklar:

- Mevcut MDE çözümünü incelemek
- Yeniden kullanılabilir authentication, configuration, logging, KPI, renderer, mail ve scheduler bileşenlerini belirlemek
- Hedef plug-in mimarisini tasarlamak
- Threat model oluşturmak
- Shared ve isolated App Registration karar ağacını oluşturmak
- Minimum permission ve read-only modelini doğrulamak
- Tenant izolasyonunu değerlendirmek
- Sertifika yaşam döngüsü ve güvenli saklama modelini oluşturmak
- Delegated erişimi istisna haline getirmek
- Raporlama uygulamasına remediation veya ReadWrite izni verilmesini engellemek
- Hassas verinin rapora, cache'e veya loga düşmesini engellemek
- Her permission'ı kullanılan endpoint veya cmdlet ile eşleştirmek
- Supply chain, dependency pinning ve code signing modelini oluşturmak

Artifactlar:

- `Architecture.md`
- `SecurityArchitecture.md`
- `ThreatModel.md`
- `AuthenticationDesign.md`
- `AuthorizationDesign.md`
- `AppRegistrationDecisionTree.md`
- `TenantIsolationModel.md`
- `SecurityAcceptanceCriteria.md`
- `SecurityReviewReport.md`

### 5.2 Customer Enterprise Architect

Sorumluluklar:

- Farklı müşteri tenantlarında standart kurulabilirliği değerlendirmek
- Network, proxy, DNS, firewall, certificate store ve outbound gereksinimlerini çıkarmak
- Müşteri rollerini ve sorumluluklarını tanımlamak
- GDAP kullanılan ve kullanılmayan senaryoları değerlendirmek
- Müşteri tenantında ve KoçSistem merkezinde çalışacak bileşenleri ayırmak
- Lisans ve özellik farklılıklarını yönetmek
- Tenant onboarding ve offboarding süreçlerini tasarlamak
- Customer readiness assessment oluşturmak
- Müşterinin almadığı hizmet için veri toplanmadığını doğrulamak

Artifactlar:

- `CustomerDeploymentModel.md`
- `CustomerReadinessChecklist.md`
- `NetworkRequirements.md`
- `TenantOnboardingGuide.md`
- `TenantOffboardingGuide.md`
- `CustomerResponsibilityMatrix.md`
- `LicensingValidationModel.md`
- `CustomerArchitectureReview.md`

### 5.3 MSSP Operations Architect

Sorumluluklar:

- Hizmet kodu ve hizmet seviyesi modelini oluşturmak
- Monitoring, Reporting, Managed, Managed and Response ve Advisory seviyelerini ayırmak
- Microsoft otomatik aksiyonlarıyla KoçSistem operasyonlarını ayırmak
- SLA, MTTA, MTTT ve MTTR tanımlarını ve formüllerini oluşturmak
- Alert, event, incident ve action çift sayımını engellemek
- Ticket, change, incident ve remediation korelasyonunu tasarlamak
- Manuel hizmet aktivitesi şemasını oluşturmak
- Operasyon kanıtı bulunmayan faaliyetin rapora girmesini engellemek
- Müşteri aksiyonlarıyla KoçSistem aksiyonlarını ayırmak
- Her KPI'ı hizmet sözleşmesi ve hizmet seviyesiyle eşleştirmek

Artifactlar:

- `ServiceCatalog.md`
- `ServiceLevelModel.md`
- `ManagedServiceKpiCatalog.md`
- `IncidentLifecycle.md`
- `SlaCalculationRules.md`
- `OperationalEvidenceModel.md`
- `TicketCorrelationModel.md`
- `ManualServiceActivitySchema.json`
- `OperationsAcceptanceCriteria.md`
- `MonthlyServiceReviewTemplate.md`

### 5.4 Microsoft Purview & Regulatory Compliance Lead

Sorumluluklar:

- DLP, Endpoint DLP, Information Protection ve Data Classification KPI'larını doğrulamak
- SIT, EDM, trainable classifier ve sensitivity label verilerini doğrulamak
- Insider Risk, Adaptive Protection ve Communication Compliance veri erişimini doğrulamak
- Retention ve Records Management KPI'larını doğrulamak
- DSPM, DSPM for AI ve Copilot audit erişimlerini doğrulamak
- Portal, API, PowerShell, Advanced Hunting ve manuel export kabiliyetlerini ayırmak
- App-only desteklenmeyen veri kaynaklarını işaretlemek
- KVKK, veri minimizasyonu ve amaçla sınırlılık kontrolü yapmak
- Anonimleştirme, pseudonymization ve minimum group size standardı oluşturmak
- Mesaj içeriği, matched content, prompt, response, kullanıcı risk skoru ve Content Explorer preview verisinin rapora alınmasını engellemek

Artifactlar:

- `PurviewCapabilityMatrix.md`
- `PurviewKpiCatalog.md`
- `PurviewPermissionMatrix.md`
- `PurviewQueryCatalog.md`
- `PrivacyImpactAssessment.md`
- `DataMinimizationRules.md`
- `AnonymizationStandard.md`
- `RetentionAndDeletionStandard.md`
- `RegulatoryControlMapping.md`
- `PurviewLimitations.md`
- `ComplianceAcceptanceCriteria.md`

### 5.5 Azure Solutions & DevOps Architect

Sorumluluklar:

- Mevcut MDE PowerShell kodunu analiz etmek ve platform standardına taşımak
- Core ve plug-in collector mimarisini geliştirmek
- Dynamic permission planner geliştirmek
- App Registration ve certificate-assisted setup geliştirmek
- Task Scheduler, test, manual, validate, dry-run ve scheduled modlarını geliştirmek
- Pagination, throttling, Retry-After, exponential backoff ve jitter uygulamak
- Structured JSON logging, state ve idempotency geliştirmek
- HTML, PDF, CSV ve JSON renderer geliştirmek
- Mail provider'ı veri collector uygulamasından ayırmak
- CI/CD, versioning, update ve rollback mekanizmasını oluşturmak
- Config schema validation, dependency pinning ve code signing uygulamak

Artifactlar:

- `DeploymentArchitecture.md`
- `RepositoryStructure.md`
- `ModuleInterface.md`
- `ConfigurationSchema.json`
- `ServiceCatalog.json`
- `PermissionCatalog.json`
- `KpiCatalog.json`
- `QueryCatalog.json`
- `BuildPipeline.yml`
- `ReleasePipeline.yml`
- `DeploymentGuide.md`
- `RollbackGuide.md`
- `OperationsRunbook.md`

### 5.6 QA Automation Engineer

Sorumluluklar:

- Requirement traceability matrix oluşturmak
- KPI, veri kaynağı, permission ve test senaryolarını birbirine bağlamak
- Seçilmeyen servisin collector ve permission'ının devre dışı olduğunu test etmek
- App-only authentication ve certificate testleri yazmak
- 401, 403, 404, 409, 429 ve 5xx testlerini yazmak
- Pagination, throttling ve retry testleri yazmak
- NoData ve CollectionFailed durumlarını ayırmak
- KPI formülü, zero denominator ve previous-period testlerini yazmak
- Duplicate, deduplication ve incident korelasyonunu test etmek
- Anonimleştirme ve minimum group size kontrollerini test etmek
- Test recipient izolasyonu ve duplicate mail engellemesini test etmek
- Task Scheduler idempotency ve concurrent run kontrolünü test etmek
- API contract ve schema-change testleri geliştirmek
- PDF, HTML, CSV ve JSON tutarlılığını test etmek
- Hassas verinin loglara düşmediğini kanıtlamak

Artifactlar:

- `TestStrategy.md`
- `RequirementsTraceabilityMatrix.md`
- `UnitTestPlan.md`
- `IntegrationTestPlan.md`
- `SecurityTestPlan.md`
- `PrivacyTestPlan.md`
- `PerformanceTestPlan.md`
- `RegressionTestPlan.md`
- `PesterTestResults.xml`
- `TestEvidence.md`
- `DefectRegister.md`
- `QualityGateReport.md`

### 5.7 Customer CISO & Board Executive

Sorumluluklar:

- Executive raporun anlaşılabilirliğini ve karar desteğini kontrol etmek
- Yönetici özetini en fazla beş doğrulanmış bulguyla sınırlandırmak
- Koruma, risk, KoçSistem aksiyonu ve müşteri aksiyonunu ayırmak
- Microsoft otomatik koruma aksiyonlarıyla KoçSistem hizmet değerini ayırmak
- Kanıtlanmayan başarı, tam koruma veya nedensellik ifadelerini reddetmek
- Çalışan sıralaması ve kişi bazlı risk değerlendirmesini reddetmek
- Teknik sınırlamaların açıkça sunulmasını sağlamak
- Raporu hizmet sözleşmesiyle karşılaştırmak

Artifactlar:

- `ExecutiveReportStandard.md`
- `BoardReportingGuidelines.md`
- `ExecutiveKpiSelection.md`
- `ExecutiveLanguageRules.md`
- `CustomerValueNarrative.md`
- `ExecutiveReportReview.md`
- `ExecutiveAcceptanceCriteria.md`

---

## 6. Kimlik Doğrulama ve App Registration Kararı

Varsayılan model:

- Her müşteri tenantında ayrı App Registration
- Certificate-based client credentials
- Export edilemeyen private key
- LocalMachine certificate store veya onaylı güvenli sertifika deposu
- Task Scheduler için tercihen gMSA
- Secret kullanımı varsayılan olarak kapalı
- Seçilen servislerin yalnızca doğrulanmış read-only izinleri
- Mail gönderiminin ayrı `ReportMailSender` uygulamasıyla yapılması

Application profilleri:

1. `CoreSecurityReporting`
   - Defender, XDR, Intune ve Entra read-only raporlama

2. `PurviewReporting`
   - DLP, classification, retention ve audit raporlama

3. `SensitiveComplianceReporting`
   - Insider Risk ve Communication Compliance

4. `ReportMailSender`
   - Yalnızca tanımlı gönderen posta kutusuyla sınırlı mail gönderimi

Hassas servislerde varsayılan olarak isolated App Registration kullanılmalıdır:

- Insider Risk Management
- Communication Compliance
- Investigator verileri
- Kullanıcı risk detayına ulaşabilen kaynaklar

Tüm servislere ait izinler tek uygulamaya önceden verilmemelidir. Permission planı hizmet seçimine göre dinamik üretilmelidir.

---

## 7. Veri Kaynağı ve Minimum Yetki Araştırma Standardı

Her KPI için güncel resmi Microsoft dokümantasyonundan aşağıdakileri doğrula:

- Ürün ve servis
- Veri kaynağı
- API ailesi
- Endpoint veya cmdlet
- API sürümü
- Beklenen response alanları
- Application permission
- Delegated permission
- Minimum application permission
- App-only desteği
- Required Entra role
- Defender Unified RBAC permission
- Purview role group
- Exchange RBAC role
- Intune RBAC role
- Lisans gereksinimi
- Admin consent gereksinimi
- Pagination yöntemi
- Rate limit ve throttling
- Maximum lookback
- Veri gecikmesi
- Deprecation durumu
- Preview durumu
- Son doğrulama tarihi

Veri kaynağı önceliği:

1. Microsoft Graph v1.0
2. Microsoft Defender XDR API
3. Belgelenmiş product-specific application-context API
4. Security & Compliance PowerShell app-only
5. Exchange Online PowerShell app-only
6. Office 365 Management Activity API
7. Advanced Hunting API
8. Microsoft Graph beta, yalnızca feature flag ile
9. Delegated API veya PowerShell, yalnızca zorunlu istisna olarak
10. Manuel CSV export
11. Portal-only

Hiçbir endpoint, cmdlet, permission veya response field tahmin edilmemelidir.

KPI destek durumları:

- `SupportedAppOnly`
- `SupportedPowerShellAppOnly`
- `SupportedManagementActivityAPI`
- `SupportedAdvancedHunting`
- `SupportedDelegated`
- `DerivedFromSupportedFields`
- `ManualExportOnly`
- `PortalOnly`
- `Preview`
- `Unsupported`
- `RequiresValidation`

Üretim collector'ına yalnızca app-only veya açıkça kabul edilmiş güvenli otomasyon yöntemiyle doğrulanan KPI'lar eklenmelidir.

---

## 8. Ortak KPI Veri Modeli

Her KPI aşağıdaki alanlarla tanımlanmalıdır:

- KpiId
- ServiceCode
- KpiNameTR
- KpiNameEN
- KpiGroup
- ExecutiveDescription
- TechnicalDefinition
- Formula
- Numerator
- Denominator
- Unit
- DataSource
- ApiEndpointOrCmdlet
- QueryTemplate
- RequiredFields
- MinimumPermission
- AuthenticationMode
- LicenseRequirement
- ApiVersion
- MaximumLookback
- DataLatency
- PaginationMethod
- PrivacyClassification
- ContainsUserIdentity
- AnonymizationRequired
- MinimumGroupSize
- PreviousPeriodComparison
- ThresholdType
- WarningThreshold
- CriticalThreshold
- AvailabilityStatus
- ValidationMethod
- OfficialDocumentation
- LastValidatedDate
- KnownLimitations

KPI değeri alınamıyorsa sıfır üretme. Aşağıdaki durumlardan birini döndür:

- NotAvailable
- NotLicensed
- PermissionMissing
- SourceNotSupported
- NoData
- CollectionFailed
- ManualInputRequired

---

## 9. Servis Bazlı KPI Kataloğu

### 9.1 SVC-MDE

- Onboarded, active ve inactive device sayıları
- Son 7, 15 ve 30 gündür görünmeyen cihazlar
- OS ve device group dağılımı
- Sensor health, communication ve version durumu
- EDR in block mode ve Tamper Protection kapsamı, doğrulanabiliyorsa
- Alert, incident, severity, status ve category dağılımı
- MITRE tactic ve technique dağılımı
- Malware, ransomware, exploit, credential theft ve lateral movement tespitleri
- Exposure Score ve Secure Score for Devices
- Açık security recommendation ve CVE sayıları
- Kritik, exploit mevcut ve internet-facing risk göstergeleri
- Automated Investigation ve remediation sonuçları
- Isolation, scan ve quarantine aksiyonları
- KoçSistem tarafından incelenen, eskale edilen ve müşteri aksiyonu bekleyen olaylar

Öncelikli kaynaklar:

- Defender for Endpoint API
- Defender XDR incident API
- Microsoft Graph Security API
- Defender Advanced Hunting API
- Machine, vulnerability, recommendation ve score API'leri

### 9.2 SVC-MDO

- Toplam gelen ve dış kaynaklı e-posta
- Clean, spam, high confidence spam, phishing, high confidence phishing, malware ve bulk dağılımı
- Spoof, user impersonation ve domain impersonation
- Safe Links ve Safe Attachments tespitleri
- Detonation sonuçları
- ZAP tarafından kaldırılan e-postalar
- Karantina ve post-delivery remediation
- Kullanıcı tarafından raporlanan phishing
- False positive ve false negative bildirimleri
- Kampanya, tehdit türü ve anonim hedef grubu dağılımı
- Anti-phishing, Safe Links, Safe Attachments, anti-malware ve anti-spam policy kapsamı
- Preset Security Policy kullanımı
- AIR investigation ve remediation durumları
- KoçSistem inceleme, eskalasyon, tuning ve allow/block değişiklikleri

Öncelikli kaynaklar:

- Defender XDR incident ve alert API
- Microsoft Graph Security API
- Advanced Hunting email tabloları, şema doğrulanırsa
- Exchange Online PowerShell rapor cmdlet'leri
- Belgelenmiş message trace ve threat protection export yolları

### 9.3 SVC-MDI

- Sensor envanteri, health, service status ve version
- Güncel olmayan veya iletişim sorunu bulunan sensorler
- Domain controller, AD FS ve AD CS kapsamı, uygulanıyorsa
- Identity alert ve incident sayıları
- Severity, status ve MITRE dağılımı
- Reconnaissance, credential access, lateral movement, persistence ve domain dominance tespitleri
- Password spray, pass-the-hash, pass-the-ticket ve DCSync tespitleri
- Identity Secure Score ve posture recommendation
- Confirmed compromise, escalation ve kanıtlı response aksiyonları

Programatik sensor inventory doğrulanamıyorsa KPI `PortalOnly` veya `ManualExportOnly` olmalıdır.

### 9.4 SVC-MDCA

- Discovered, sanctioned, unsanctioned ve risky application sayıları
- Application risk score ve category dağılımı
- Shadow IT ve generative AI application görünürlüğü
- MDCA alert, severity, status ve resolution dağılımı
- Activity, file, anomaly, OAuth, session ve access policy eşleşmeleri
- Engellenen, protected, step-up authentication uygulanan aktiviteler
- Governance actions
- OAuth revoke, quarantine ve remove sharing aksiyonları
- Connected app ve connector health
- Veri gecikmesi ve son başarılı sync zamanı

Öncelikli kaynaklar:

- Defender for Cloud Apps application-context API
- Alerts API
- Activities API
- Defender XDR API
- Advanced Hunting CloudAppEvents, şema doğrulanırsa

### 9.5 SVC-XDR

- Oluşturulan, aktif, in-progress ve resolved incident sayıları
- Severity, classification, determination ve product source dağılımı
- MITRE tactic ve technique dağılımı
- Incident başına alert ve entity sayısı
- High severity ratio ve backlog age
- MTTA, MTTT, MTTC, MTTR, median ve P90 resolution time
- Severity ve product bazında MTTR
- SLA içinde ele alınan incident oranı
- Automated ve manual response actions
- Device, account, file, mail ve cloud app containment
- True positive, benign positive ve false positive oranları
- KoçSistem atama, inceleme, eskalasyon ve closure faaliyetleri

Zaman KPI'ları yalnızca güvenilir timestamp veya operasyon kanıtı varsa hesaplanmalıdır.

### 9.6 SVC-INTUNE

- Managed, corporate ve personal device envanteri
- Platform, ownership ve enrollment type dağılımı
- Son check-in, stale, duplicate, jailbroken/rooted ve encryption durumu
- Compliant, noncompliant, unknown ve grace period cihazlar
- Platform ve policy bazında compliance oranı
- En çok başarısız olan compliance settings
- Configuration profile success, error, conflict ve pending dağılımı
- Security baseline, BitLocker, Firewall, Antivirus, ASR ve update kapsamı
- Application installation başarı ve hata oranları
- Required application ve MAM coverage
- Enrollment failure, certificate expiration ve configuration drift
- KoçSistem policy değişiklikleri ve çözülen compliance sorunları

Öncelikli kaynaklar:

- Microsoft Graph Intune v1.0
- managedDevices
- deviceCompliancePolicies
- deviceConfiguration
- reports/exportJobs
- Intune audit events

Her Intune veri ailesi için gerekli read permission ayrı hesaplanmalıdır.

### 9.7 SVC-ENTRA-PIM

- Active, eligible, permanent ve expiring role assignment sayıları
- Kritik rollerin ve service principal assignment'larının dağılımı
- PIM activation, approval, rejection ve cancellation sayıları
- Activation duration, after-hours activation, MFA, justification ve ticket kullanımı
- Role policy hygiene
- MFA, approval veya justification istemeyen kritik roller
- PIM security alerts, destekleniyorsa
- Directory audit içindeki role ve policy değişiklikleri
- Privileged sign-in, failed sign-in, risky sign-in ve legacy authentication
- Conditional Access başarısızlıkları

Öncelikli kaynaklar:

- Microsoft Graph PIM v3
- roleAssignmentScheduleInstances
- roleEligibilityScheduleInstances
- roleAssignmentScheduleRequests
- roleManagementPolicies
- directoryAudits
- signIns

Deprecated privilegedAccess endpoint'leri kullanılmamalıdır.

### 9.8 SVC-PRV-DLP

- DLP policy ve rule inventory
- Enforcement, test ve simulation mode dağılımı
- Workload ve location kapsamı
- Policy, rule, scope ve exception değişiklikleri
- DLP rule match, event, alert ve incident sayıları
- Severity, status, policy, rule, workload ve SIT dağılımı
- Audit, warn, block ve block-with-override dağılımı
- User override ve false positive bildirimleri
- Block Rate
- Override Rate
- High Severity Alert Ratio
- Repeat Event Ratio
- Policy Concentration Index
- Policy Noise Indicator
- USB, network share, RDP, clipboard, print, Bluetooth, browser paste, cloud upload, restricted app ve screen capture aktiviteleri
- Endpoint reporting health ve policy coverage

DLP event, alert ve incident ayrı varlıklar olarak ele alınmalıdır.

Öncelikli kaynaklar:

- Export-ActivityExplorerData
- Security & Compliance PowerShell
- Office 365 Management Activity API
- Unified Audit Log
- Defender XDR incidents ve alerts
- Belgelenmiş DLP Advanced Hunting tabloları

### 9.9 SVC-PRV-CLASS

- Sensitivity label ve label policy inventory
- Published label kapsamı
- Manual, auto ve recommended label uygulamaları
- Recommendation acceptance ve rejection
- Label upgrade, downgrade, removal ve change aktiviteleri
- Protection added ve removed
- Label ve workload bazında kullanım
- Label Downgrade Rate
- Label Removal Rate
- Auto-label Adoption Rate
- Built-in, custom, EDM ve trainable classifier tespitleri
- Confidence level ve SIT count dağılımı
- Workload bazında SIT dağılımı
- Yeni, değiştirilmiş ve silinmiş SIT'ler
- En çok DLP olayı üreten SIT
- Etiketli Exchange, SharePoint, OneDrive ve endpoint öğeleri
- Classification coverage, yalnızca güvenilir denominator varsa

Öncelikli kaynaklar:

- Export-ActivityExplorerData
- Get-Label
- Get-LabelPolicy
- SIT ve classifier cmdlet'leri
- Security & Compliance PowerShell
- Management Activity API
- Unified Audit Log

Content Explorer önizlemesi ve ham içerik rapora alınmamalıdır.

### 9.10 SVC-PRV-GOV

- Retention policy, rule ve label envanteri
- Static ve adaptive policy dağılımı
- Published ve auto-apply retention label policy
- Event-based, record ve regulatory record label dağılımı
- Retain-only, delete-only ve retain-then-delete dağılımı
- Workload coverage
- Applied, changed ve removed retention label aktiviteleri
- Declared record aktiviteleri
- Policy ve label değişiklikleri
- Disposition review backlog, karar ve yaş bilgileri, destekleniyorsa
- Policy deployment error ve conflict göstergeleri
- Kapsanmayan kritik workload
- Yetim veya yayınlanmamış label göstergeleri

Öncelikli kaynaklar:

- Get-RetentionCompliancePolicy
- Get-RetentionComplianceRule
- Get-ComplianceTag
- Resmi V2 veya alternatif cmdlet'ler
- Unified Audit Log
- Belgelenmiş disposition export yöntemi

### 9.11 SVC-PRV-RISK

Insider Risk KPI'ları:

- Policy bazında aggregate alert sayısı
- Severity ve status dağılımı
- Case'e yükseltilen alert ve case sayıları
- Alert-to-case conversion rate
- Alert closure rate
- Exfiltration indicator trendleri
- Removable media, cloud upload, printing ve SharePoint download trendleri
- Policy health ve policy coverage
- Adaptive Protection risk level dağılımı, yalnızca aggregate
- DLP ile korele IRM alertleri
- MTTA ve MTTR, timestamp varsa

Communication Compliance KPI'ları:

- Policy inventory
- Policy bazında match
- Review bekleyen, incelenen, resolved ve escalated item sayıları
- Review aging
- Exchange, Teams, Viva Engage ve Copilot workload dağılımı, destekleniyorsa
- Classifier dağılımı
- Confirmed violation ve false positive oranları, destekleniyorsa
- Reviewer workload, yalnızca aggregate
- Policy modification history ve health

Öncelikli kaynaklar:

- Office 365 Management Activity API
- Defender XDR ile paylaşılan IRM alertleri
- Insider Risk export yöntemleri
- Communication Compliance detailed CSV export
- Unified Audit Log

Mesaj içeriği, kullanıcı risk skoru ve kişi bazlı sıralama rapora eklenmemelidir.

### 9.12 SVC-AI-SECURITY

- Copilot interaction sayısı
- Application host ve workload dağılımı
- Enterprise AI app, Entra-registered AI app ve agent inventory, resmi kaynak varsa
- Sanctioned, unsanctioned ve shadow AI usage
- AI application upload ve paste aktiviteleri
- Hassas veri içeren AI interaction
- AI ile ilişkili DLP match, warn, block ve override
- Third-party AI upload riskleri
- AI ile ilişkili Insider Risk ve Communication Compliance sinyalleri
- DSPM recommendation ve policy coverage, programatik erişim doğrulanırsa
- AI audit, DLP, collection policy ve compliance policy status
- Human-to-agent, agent-to-human, agent-to-tool ve agent-to-agent aktiviteleri, resmi şema varsa
- Agent sensitive data access ve DLP matches

Öncelikli kaynaklar:

- Unified Audit Log CopilotInteraction kayıtları
- Export-ActivityExplorerData
- Office 365 Management Activity API
- Defender for Cloud Apps Cloud Discovery ve activity
- Purview DLP activity
- Belgelenmiş Graph veya Advanced Hunting AI tabloları

DSPM portal dashboard erişimi programatik olarak doğrulanamazsa `PortalOnly` olmalıdır.

---

## 10. KoçSistem Yönetilen Hizmet KPI'ları

Her servis raporunda Microsoft telemetrisi ve KoçSistem operasyonu ayrı gösterilmelidir.

### Microsoft teknolojileri tarafından sağlanan koruma

- Tespit edilen tehdit veya politika olayı
- Engellenen aktivite
- Karantinaya alınan öğe
- Önlenen veri aktarımı
- Otomatik investigation
- Otomatik remediation
- Policy enforcement
- Koruma kapsamındaki cihaz, kullanıcı, uygulama veya veri

### KoçSistem tarafından sağlanan yönetilen hizmet

- İncelenen alert
- Triaged alert
- Müşteriye eskale edilen alert
- Yönetilen incident
- Müdahale edilen incident
- Gerçekleştirilen containment
- Gerçekleştirilen remediation
- Uygulanan policy change
- Uygulanan tuning
- Azaltılan false positive
- Yapılan health check
- Açılan ve kapatılan servis talebi
- SLA içinde ele alınan olay oranı
- KoçSistem MTTA ve MTTR
- Müşteri onayı bekleyen aksiyonlar
- Tamamlanan iyileştirmeler
- Sonraki dönem planı

KoçSistem faaliyeti aşağıdaki kaynaklardan en az biriyle kanıtlanmalıdır:

- Incident audit history
- API action history
- Defender Action Center
- Onaylı ticket kaydı
- Onaylı manual service activity kaydı
- Change request
- Müşteri onayı

Microsoft tarafından otomatik engellenen bir olay KoçSistem müdahalesi olarak sayılmamalıdır.

---

## 11. Manuel Hizmet Aktivitesi Şeması

API ile alınamayan operasyon kayıtları için kontrollü CSV veya JSON girişi oluştur:

- ActivityId
- CustomerId
- ServiceCode
- TicketId
- ChangeId
- IncidentId
- ActivityType
- Description
- PerformedByTeam
- PerformedAtUtc
- Status
- CustomerApproval
- EvidenceReference
- DataSource
- ApprovedBy
- ApprovedAtUtc

Manuel veri, Microsoft API verisinden açıkça ayrılmalıdır. Serbest metin rapora eklenmeden önce sanitize edilmelidir.

---

## 12. Rapor Çıktıları

Her seçilen servis için:

- Executive PDF
- Technical PDF
- HTML email summary
- KPI CSV
- Normalized JSON
- Collection health JSON
- Permission validation report
- Data source limitation report

Rapor yapısı:

1. Kapak
2. Hizmet adı ve kodu
3. Raporlama dönemi
4. Yönetici özeti
5. Microsoft teknolojilerinin sağladığı koruma
6. KoçSistem yönetilen hizmet faaliyetleri
7. Temel KPI kartları
8. Aylık trend
9. Önceki ay karşılaştırması
10. Açık riskler
11. Tamamlanan aksiyonlar
12. Müşteri aksiyonu bekleyen konular
13. İyileştirme önerileri
14. Veri kaynakları
15. Veri tamlık durumu
16. İzin ve lisans durumu
17. Bilinen sınırlamalar
18. KPI sözlüğü
19. Teknik ek

Yönetici özeti en fazla beş doğrulanmış bulgu içermelidir. Kanıtlanmayan nedensellik veya tam koruma iddiası kullanılmamalıdır.

---

## 13. PowerShell Çalışma Modları

Ana script aşağıdaki modları desteklemelidir:

- Interactive
- Scheduled
- Manual
- Test
- Validate
- DryRun
- PermissionCheck
- HealthCheck
- GenerateOnly
- SendExistingReport

Örnek test komutu:

```powershell
.\Invoke-KocSistemSecurityReport.ps1 `
  -Mode Test `
  -CustomerId "CUSTOMER01" `
  -Services DefenderForEndpoint,PurviewDlp `
  -TestRecipient "test@kocsistem.com.tr" `
  -LookbackHours 24 `
  -SendMail `
  -Verbose
```

Test modu:

- Yalnızca test alıcısına göndermeli
- Üretim alıcılarını kullanmamalı
- Konuya `[TEST]` eklemeli
- Gerçek kaynak verisini kullanmalı
- NoData ile CollectionFailed durumlarını ayırmalı
- Task Scheduler oluşturmamalı
- Üretim state kaydı yazmamalı

---

## 14. Collector ve KPI Provider Sözleşmesi

Her collector:

- Get-ServiceMetadata
- Get-ServiceDependencies
- Get-ServiceDataSources
- Get-ServicePermissions
- Get-ServiceLicensingRequirements
- Test-ServiceAuthentication
- Test-ServiceAuthorization
- Test-ServiceConnection
- Get-ServiceRawData
- ConvertTo-ServiceNormalizedData
- Get-ServiceCollectionHealth
- Get-ServiceLimitations

Her KPI Provider:

- Get-KpiMetadata
- Test-KpiPrerequisites
- Get-KpiValue
- Get-KpiTrend
- Get-KpiDataQuality
- Get-KpiLimitations

fonksiyonlarını uygulamalıdır.

Yeni servis eklemek için Core kodun değiştirilmesi gerekmemelidir.

---

## 15. Agent Çıktı Sözleşmesi

Her agent aşağıdaki JSON yapısında sonuç üretmelidir:

```json
{
  "Agent": "",
  "Phase": "",
  "ReviewedInputs": [],
  "ProducedArtifacts": [],
  "Decisions": [
    {
      "DecisionId": "",
      "Decision": "",
      "Reason": "",
      "Evidence": [],
      "AlternativesRejected": [],
      "Impact": "",
      "Status": ""
    }
  ],
  "Risks": [
    {
      "RiskId": "",
      "Description": "",
      "Severity": "",
      "Likelihood": "",
      "Mitigation": "",
      "Owner": "",
      "Blocking": true
    }
  ],
  "OpenItems": [],
  "Dependencies": [],
  "ApprovalStatus": "",
  "ApprovalNotes": ""
}
```

ApprovalStatus:

- NotStarted
- InReview
- ChangesRequired
- ConditionallyApproved
- Approved
- Rejected

---

## 16. Çatışma Çözümü

1. Security veya privacy riski varsa Principal Security Architect kararı önceliklidir.
2. Purview, kişisel veri veya düzenleyici konu varsa Microsoft Purview & Regulatory Compliance Lead onayı zorunludur.
3. Operasyon KPI'sı veya hizmet kanıtı konusunda MSSP Operations Architect kararı zorunludur.
4. Dağıtım uygulanabilirliğinde Azure Solutions & DevOps Architect kararı zorunludur.
5. Test kanıtı olmadan QA Automation Engineer onay veremez.
6. Müşteri ortamı uyumsuzsa Customer Enterprise Architect yayını bloke edebilir.
7. Yönetici raporu yanıltıcıysa Customer CISO & Board Executive rapor yayınını bloke edebilir.

Tüm uyuşmazlıklar `DecisionLog.md` içinde kayıt altına alınmalıdır.

---

## 17. Quality Gate

Her faz sonunda aşağıdaki alanlarla kalite kapısı oluştur:

- GateId
- Requirement
- ResponsibleAgent
- Evidence
- Result
- Blocking
- DefectId
- Remediation
- RetestResult
- FinalApproval

Result:

- Pass
- Fail
- Warning
- NotApplicable
- NotTested

Blocking Fail bulunan faz sonraki aşamaya ProductionReady olarak geçemez.

Bir servis için aşağıdakiler başarısızsa ProductionReady verilmemelidir:

- Authentication test
- Authorization test
- Minimum permission negative test
- Data collection test
- Pagination test
- Throttling test
- Privacy test
- Sensitive logging test
- KPI formula test
- Empty data test
- Partial failure test
- Test recipient isolation
- Scheduled task idempotency
- Duplicate report prevention
- PDF, HTML, CSV ve JSON consistency

---

## 18. Fazlar

### Faz 0: Mevcut MDE çözüm analizi

Sorumlular:

- Principal Security Architect
- Azure Solutions & DevOps Architect
- QA Automation Engineer

Çıktılar:

- Yeniden kullanılabilir bileşenler
- Teknik borç
- Güvenlik açıkları
- Test coverage analizi
- Migration planı

### Faz 1: Servis, KPI ve veri kaynağı araştırması

Sorumlular:

- Principal Security Architect
- MSSP Operations Architect
- Microsoft Purview & Regulatory Compliance Lead
- Customer Enterprise Architect

Çıktılar:

- `ServiceCapabilityMatrix.md`
- `KpiCatalog.md`
- `PermissionMatrix.md`
- `DataSourceMatrix.md`
- `QueryCatalogDesign.md`
- `UnsupportedAndPortalOnlyMetrics.md`

### Faz 2: Mimari ve App Registration tasarımı

Çıktılar:

- `Architecture.md`
- `AppRegistrationProfiles.md`
- `PermissionResolverDesign.md`
- `TenantIsolationModel.md`
- `DeploymentModel.md`

### Faz 3: Core platform

Çıktılar:

- Configuration
- Authentication
- Authorization
- Logging
- State management
- Scheduler
- Mail provider
- Report renderer
- Privacy engine
- Test framework

### Faz 4: Defender, Intune ve Entra modülleri

- SVC-MDE
- SVC-MDO
- SVC-MDI
- SVC-MDCA
- SVC-XDR
- SVC-INTUNE
- SVC-ENTRA-PIM

### Faz 5: Purview ve AI modülleri

- SVC-PRV-DLP
- SVC-PRV-CLASS
- SVC-PRV-GOV
- SVC-PRV-RISK
- SVC-AI-SECURITY

### Faz 6: MSSP operasyon katmanı

- Ticket correlation
- Incident action evidence
- SLA engine
- MTTA ve MTTR engine
- Manual activity ingestion
- Customer action tracking

### Faz 7: Executive reporting

- Executive summary
- Service value summary
- Protection summary
- Risk summary
- Customer action summary
- KoçSistem action summary
- Technical limitation statement

### Faz 8: Nihai test ve release

Tüm agentların role uygun onayı alınmalıdır.

---

## 19. İlk Çalıştırmada Yapılacaklar

İlk çalıştırmada kod yazmaya başlama.

Önce yedi agentı görevlendir ve aşağıdaki çıktıları üret:

1. Her agentın bağımsız ön değerlendirmesi
2. Mevcut MDE çözümünden yeniden kullanılabilir bileşenler
3. Her agentın belirlediği riskler
4. On iki servis için KPI araştırma planı
5. Veri kaynağı doğrulama planı
6. Minimum permission araştırma planı
7. Shared ve isolated App Registration karar modeli
8. Agentlar arası çalışma bağımlılıkları
9. Fazlandırılmış geliştirme planı
10. Faz 0 ve Faz 1 kabul kriterleri
11. Blocking açık konular
12. Decision log
13. Üretilecek artifact dizin ağacı

İlk çıktı sonunda yalnızca aşağıdaki durumlardan birini ver:

- READY_FOR_RESEARCH
- CHANGES_REQUIRED
- BLOCKED_BY_MISSING_INPUT
- BLOCKED_BY_SECURITY_RISK

`READY_FOR_RESEARCH` için en az aşağıdaki agentların onayı zorunludur:

- Principal Security Architect
- MSSP Operations Architect
- Microsoft Purview & Regulatory Compliance Lead
- Customer Enterprise Architect

Kod geliştirmeye yalnızca Faz 1 tamamlandıktan, minimum permission matrisi doğrulandıktan ve QA Automation Engineer test yaklaşımını onayladıktan sonra başlanmalıdır.

---

## 20. Son Kurallar

Aşağıdaki durumları başarı olarak raporlama:

- Agent çağrıldı fakat artifact üretmedi
- Doküman bulundu fakat endpoint doğrulanmadı
- Portal verisi görüldü fakat API veya PowerShell erişimi doğrulanmadı
- Permission adı bulundu fakat endpoint ile eşleştirilmedi
- Kod üretildi fakat çalıştırılmadı
- Test geçti fakat privacy testi yapılmadı
- Rapor üretildi fakat KPI formülü doğrulanmadı
- Mail gönderildi fakat test ve üretim alıcıları ayrıştırılmadı
- Task oluşturuldu fakat duplicate çalışma kontrolü test edilmedi
- KoçSistem faaliyeti yazıldı fakat operasyon kanıtı bulunmadı
- KPI alınamadı ve sessizce sıfır üretildi
- Beta API production-ready olarak işaretlendi
- Delegated access gerekmesine rağmen unattended task güvenli kabul edildi

Her agent kendi uzmanlığı dışında kesin karar vermemeli ve ilgili uzman agentın değerlendirmesini istemelidir.

Amaç çok sayıda dosya veya agent aktivitesi göstermek değil, doğrulanmış, minimum yetkili, güvenli, işletilebilir, denetlenebilir ve müşteriye somut hizmet değeri sunan bir MSSP raporlama platformu oluşturmaktır.

---

# Orkestratörü Çalıştırma Komutu

Aşağıdaki komutu, bu Markdown dosyasını kabul eden agent orkestratörüne ver:

```text
KocSistem_MSSP_MultiAgent_Reporting_Master_Prompt.md dosyasını ana görev tanımı olarak kullan.

Dosyada tanımlanan yedi uzman agentı görevlendir ve yalnızca Faz 0 ile Faz 1'i çalıştır.
İlk çalıştırmada production kodu üretme.

Öncelikle mevcut MDE raporlama çözümünü analiz et. Ardından 12 bağımsız servis için:

1. ServiceCapabilityMatrix.md
2. KpiCatalog.md
3. PermissionMatrix.md
4. DataSourceMatrix.md
5. QueryCatalogDesign.md
6. AppRegistrationProfiles.md
7. PrivacyClassification.md
8. UnsupportedAndPortalOnlyMetrics.md
9. DecisionLog.md
10. QualityGateReport.md

artifactlarını oluştur.

Her KPI için resmi Microsoft kaynağı, API veya cmdlet, API sürümü, minimum read-only permission, authentication mode, app-only desteği, lisans, lookback, pagination, veri gecikmesi, privacy sınıfı ve destek durumu bulunmadan KPI'ı Supported olarak işaretleme.

Her agent kendi artifact, karar, risk ve ApprovalStatus çıktısını versin. Blocking riskleri gizleme. Agent faaliyeti tamamlanmış görünse bile kanıtı ve artifactı yoksa tamamlanmış sayma.

Çalışma sonunda yalnızca aşağıdaki sonuçlardan birini üret:
READY_FOR_RESEARCH
CHANGES_REQUIRED
BLOCKED_BY_MISSING_INPUT
BLOCKED_BY_SECURITY_RISK

READY_FOR_RESEARCH için Principal Security Architect, MSSP Operations Architect, Microsoft Purview & Regulatory Compliance Lead ve Customer Enterprise Architect onayı zorunludur.
```

## Faz 1 Sonrası Devam Komutu

Faz 0 ve Faz 1 onaylandıktan sonra:

```text
Önceki çalışmada üretilen ve onaylanan Faz 0 ve Faz 1 artifactlarını girdi olarak kullan.

KocSistem_MSSP_MultiAgent_Reporting_Master_Prompt.md içindeki Faz 2 ve Faz 3'ü çalıştır.
Yalnızca doğrulanmış veri kaynakları ve minimum permission matrisiyle ilerle.
RequiresValidation, PortalOnly, ManualExportOnly, Preview veya Unsupported KPI'lar için production collector üretme.

Core platformu, interaktif kurulum sihirbazını, dynamic permission resolver'ı, authentication katmanını, privacy engine'i, structured logging'i, state ve idempotency katmanını, mail provider'ı, report renderer'ı ve Pester test altyapısını geliştir.

Her dosyayı çalıştır, test kanıtını kaydet ve quality gate sonucu üret.
Blocking Fail varsa sonraki faza geçme.
```
