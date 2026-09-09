# CloudShield MSSP Service Capability Matrix

This document defines the 12 core Microsoft Security & Purview services supported by the CloudShield MSSP reporting platform, their service levels, authentication profiles, collector dependencies, and implementation readiness.

| Service Code | Turkish Display Name | English Display Name | Product Family | Compatible Service Levels | Auth Profile | Data Sensitivity | Isolation Req |
|:---|:---|:---|:---|:---|:---|:---|:---:|
| **SVC-MDE** | Yönetilen Uç Nokta Güvenliği (EDR) | Managed Endpoint Security (EDR) | Microsoft Defender for Endpoint | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | CoreSecurityReporting | Medium | No |
| **SVC-MDO** | Yönetilen E-Posta Güvenliği (MDO + EOP) | Managed Email Security (MDO + EOP) | Microsoft Defender for Office 365 | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | CoreSecurityReporting | Medium | No |
| **SVC-MDI** | Yönetilen Kimlik Tehdit Koruması (MDI) | Managed Identity Threat Protection | Microsoft Defender for Identity | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | CoreSecurityReporting | High | No |
| **SVC-MDCA** | Yönetilen Bulut Uygulama Güvenliği (CASB) | Managed Cloud App Security (CASB) | Microsoft Defender for Cloud Apps | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | CoreSecurityReporting | Medium | No |
| **SVC-XDR** | Yönetilen XDR Olay Yönetimi & MTTR | Managed XDR Incident Management & MTTR | Microsoft Defender XDR | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | CoreSecurityReporting | Medium | No |
| **SVC-INTUNE** | Yönetilen Cihaz Uyum & Hijyen (Intune) | Managed Device Compliance & Hygiene | Microsoft Intune | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | CoreSecurityReporting | Low | No |
| **SVC-ENTRA-PIM** | Yönetilen Ayrıcalıklı Kimlik ve PIM | Managed Privileged Identity & PIM | Microsoft Entra ID | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | CoreSecurityReporting | High | No |
| **SVC-PRV-DLP** | Yönetilen Veri Kaybı Önleme (Purview DLP) | Managed Data Loss Prevention (Purview DLP) | Microsoft Purview | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | PurviewReporting | High | No |
| **SVC-PRV-CLASS** | Yönetilen Veri Envanteri ve Sınıflandırma | Managed Data Classification & Labels | Microsoft Purview | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | PurviewReporting | Medium | No |
| **SVC-PRV-GOV** | Yönetilen Saklama ve İmha Politikaları | Managed Data Lifecycle & Records | Microsoft Purview | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | PurviewReporting | Medium | No |
| **SVC-PRV-RISK** | Yönetilen İç Tehdit ve İletişim Uyumu | Managed Insider Risk & Compliance | Microsoft Purview (Sensitive) | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | SensitiveComplianceReporting | CriticalSensitive | **Yes** |
| **SVC-AI-SECURITY** | Yönetilen Yapay Zekâ & Copilot Güvenliği | Managed AI & Copilot Security (DSPM) | Microsoft Purview AI Security | MonitoringOnly, MonitoringAndReporting, Managed, ManagedAndResponse, Advisory | PurviewReporting | High | No |

## Service Levels Definition
- **MonitoringOnly**: Visualizes posture, active sensors, and automated protection without presenting managed operational remediation.
- **MonitoringAndReporting**: Automated collection, posture analysis, trend tracking, and monthly executive/technical report dispatch.
- **Managed**: Proactive policy hygiene, false-positive tuning, configuration enhancement, and operational engineering hours.
- **ManagedAndResponse**: Full managed operations including response tracking, incident correlation, and SLA/MTTR accountability.
- **Advisory**: Posture assessment, quarterly roadmap alignment, and compliance architecture guidance.
