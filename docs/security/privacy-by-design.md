# CloudShield MSSP Platform - Privacy-by-Design & Anonymization Standard

**Document Version:** 2.0.0  
**Classification:** Regulatory Compliance Architecture (KVKK / GDPR)  

---

## 1. Dynamic k-Anonymity & Masking Rules

Under KVKK md. 4 & 12 and GDPR Art. 25 & 32, personal identifiable information (PII) must be masked prior to report compilation:

| Entity Type | Raw Input Example | Anonymized Output Example | Masking Mechanism |
| :--- | :--- | :--- | :--- |
| **Turkish ID (TCKN)** | `12345678901` | `*********01` | Salted regex masking (retain last 2 digits) |
| **User Principal Name (UPN)**| `ahmet.yilmaz@sirket.com` | `a***.y***@sirket.com` | First character + asterisks |
| **External Recipient Email** | `ali@partner.com` | `a***@p***.com` | Mask mailbox and external domain |
| **Credit Card Number** | `5421 1234 5678 9012` | `**** **** **** 9012` | Retain last 4 digits only |
| **Confidential File Name** | `Mali_Rapor_2026.xlsx` | `Mali_Rapor_***.xlsx` | Suffix obfuscation |

---

## 2. Cryptographic Integrity Footers

Reports carry build metadata and SHA-256 file hashes affirming technical file integrity without asserting unqualified legal non-repudiation:
> *"Bu rapor, toplanan telemetri verilerinin anlık durumunu yansıtmakta olup teknik dosya bütünlüğü SHA-256 özeti ile korunmaktadır."*
