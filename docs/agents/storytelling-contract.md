# Report Storytelling Contract & Insight Governance

## 1. The Core Principle: Answer "SO WHAT?"
Every visible metric, chart, and scorecard item in a CloudShield report must answer the executive question:
**"SO WHAT? WHY DOES THIS MATTER TO MY BUSINESS?"**

1. If a KPI cannot produce a meaningful insight, **do not display that KPI**.
2. If an insight cannot produce a concrete risk or action, **do not display that insight**.
3. If an action has no identifiable owner, **do not display that action**.

---

## 2. The Four-Stage Storytelling Chain
Every technical observation must follow the immutable progression:
$$\text{Evidence} \longrightarrow \text{Meaning} \longrightarrow \text{Risk} \longrightarrow \text{Action}$$

### Stage 1: Evidence (Kanıt)
- Grounded in validated Microsoft Defender / Purview / Graph API / KQL hunting telemetry.
- Must cite the specific data source (e.g., `DeviceEvents`, `EmailEvents`, `Audit.General`, `DlpEvents`).
- Zero synthetic numbers. If telemetry count is 0, state verified zero-incident posture.

### Stage 2: Meaning (Anlam ve Bağlam)
- What does this evidence indicate in the enterprise environment?
- Distinguish between background environmental noise and active adversary reconnaissance.
- Benchmarked against industry baselines and Microsoft Digital Defense Report indicators.

### Stage 3: Risk (Etki ve Risk)
- What is the operational, regulatory, financial, or reputational consequence if unaddressed?
- Expressed in clear business impact (e.g., ransomware lateral movement, KVKK md. 12 data breach liability, token replay session hijacking).

### Stage 4: Action (Aksiyon ve Sorumlu)
- Concrete remediation runbook (e.g., `RB-MDE-GHOST-REMEDIATION`, `RB-DLP-ENDPOINT-BLOCK`).
- Assigned RACI team (e.g., Intune Uç Nokta Yönetimi, SecOps & MDE Mühendisliği, İK & İç Denetim).
- Strict SLA commitment (e.g., 24 Saat, 48 Saat, 7 Gün).
