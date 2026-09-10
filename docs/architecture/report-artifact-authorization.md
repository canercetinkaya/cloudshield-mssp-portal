# CloudShield MSSP Platform - Report Artifact Authorization Architecture

## 1. Overview
Public client-supplied path query parameters (/api/reports/download?file=...) present path traversal risks and unconstrained file access vulnerabilities. In v2.5.11-PILOT, report downloads are strictly mediated through opaque, server-side registered reportId UUIDs (GET /api/reports/{reportId}/download).

## 2. Server-Side Report Registry (Data/report_registry.json)
Every generated report is registered with cryptographic and operational metadata including reportId, tenantId, customerId, period, serviceCodes, artifactType, storageKey, createdAtUtc, reportStatus, integrityHash, sizeBytes, expiresAtUtc, and version.

## 3. Defense-in-Depth Authorization Flow
1. Authentication: User session token verified.
2. Tenant Scoping: User AssignedTenants must match record.tenantId or contain ALL. Unauthorized requests return 403 Forbidden.
3. Storage Boundary Enforcement: Resolves physical file within Engine/Output. Traversal attempts return 400 Bad Request or 403 Forbidden.
4. Expiration Enforcement: Reports older than expiresAtUtc return 410 Gone.
5. Safe RFC 5987 Header Encoding: Filenames with Turkish characters are safely encoded using ASCII fallback with UTF-8 filename parameters.
