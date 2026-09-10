# CloudShield MSSP Platform - Safe Sync & Git Governance

**Document Version:** 2.0.0  
**Classification:** DevSecOps Release Policy  

---

## 1. Branch Protection & Safe Sync Protocol

1. **Direct Push to Main Prohibited:** All production changes require an isolated synchronization branch (`sync/release-v...`) and pull request review.
2. **Automated Pre-Commit Checks:**
   - Secret scanning via Gitleaks and TruffleHog.
   - Static analysis via CodeQL.
   - Comprehensive QA execution (`test_comprehensive_qa.py`).
3. **Artifact Hygiene:** Temporary config files (`*.local.json`), execution transcripts (`.jsonl`), and customer PDFs are strictly barred from version control.
