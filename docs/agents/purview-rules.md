# Purview Compliance & Privacy-by-Design Rules

## 1. Regulatory Governance (KVKK & GDPR)
- **KVKK md. 4, 12, 18:** Personal data processing principles, data security obligations, and administrative sanctions.
- **GDPR Art. 5, 25, 32:** Privacy-by-Design, default encryption, and security of processing.

## 2. PrivacyEngine Cryptographic Masking
- Cleartext user principal names (UPNs) and file names must **never** appear in unmasked reports or logs.
- Salted SHA-256 hashing and k-Anonymity (`k >= 5`) must be enforced:
  - Example: `m***.o***@customer.com`
  - Example: `Mali_Rapor_***.xlsx`
- Content Inspection Boundary: Purview DLP plugins only inspect SIT metadata (match types, rule names, counts), **never** raw file payloads.
