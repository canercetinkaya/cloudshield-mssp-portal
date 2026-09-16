# Turkish Language & UTF-8 Compliance Report

**Scope:** Repository-wide Turkish-language (UTF-8) rendering integrity.
**Basis:** Findings from the completed investigation only (no further validation performed after this point).
**Document status:** Final summary of confirmed issues and implemented fixes.

---

## 1. Confirmed UTF-8 Issues

### Issue 1 — Lossy ASCII transliteration in the pure-Python PDF fallback
- **Location:** `Portal/api/report_generator.py` — the `to_ascii_safe()` helper and the ASCII fallback branch of `create_executive_pdf()`.
- **Symptom:** When no embeddable Unicode font was located, the fallback PDF silently transliterated Turkish diacritics into ASCII lookalikes (e.g. `İ→I`, `ı→i`, `ç→c`, `ş→s`, `ğ→g`, `ö→o`, `ü→u`), yielding a document that is incorrect and unreadable to a Turkish reader.
- **Classification:** **Customer Visible** (the rendered PDF is delivered to customers).

### Issue 2 — Mojibake in captured PowerShell output feeding the QA results artifact
- **Location:** `test_comprehensive_qa.py` — PowerShell subprocess invocations using `text=True` without an explicit `encoding="utf-8"`.
- **Symptom:** Turkish test names were decoded with the Windows locale codec, producing double-encoded mojibake (e.g. `ModÃ¼l`, `MÃ¼ÅŸteri`, `GÃ¼venliÄŸi`) that was then embedded into the generated `qa_test_results.json`.
- **Classification:** **Internal Only** (test/QA artifact; not shipped to customers).

### Issue 3 — ASCII-stripped Turkish corpus in the encoding quality gate
- **Location:** `test_comprehensive_qa.py` — Gate 4 (`UTF-8 Encoding Round-Trip & Mojibake Absence`) `turkish_corpus`.
- **Symptom:** The corpus consisted entirely of ASCII-stripped strings (e.g. `CloudShield`, `Ic Tehdit`, `Siniflandirma`), so the gate could not detect any loss of Turkish diacritics — a false sense of compliance.
- **Classification:** **Internal Only** (test coverage defect; no customer output, but it masked the customer-visible risk).

### Issue 4 — PowerShell host code page not forced to UTF-8 on entry scripts
- **Location:** `Start-LocalPortal.ps1` (and the pattern is expected across other `.ps1` entry points that launch Python).
- **Symptom:** Without `[Console]::OutputEncoding`/`$OutputEncoding` and a UTF-8 child-process environment, console output from the launched Python server could be rendered as mojibake on legacy Windows code pages.
- **Classification:** **Internal Only** (operator console/log output; does not change stored content).

### Issue 5 — Stale mojibake content in the generated QA artifact
- **Location:** `qa_test_results.json` (git-ignored, generated).
- **Symptom:** The artifact contained replacement characters and double-encoded Turkish (`ModÃ¼l`, etc.) produced by Issue 2 before the fix.
- **Classification:** **Internal Only** (generated, untracked artifact).

### Issue 6 — Structured engine-test JSON not emitted by the test script
- **Location:** `Engine/Tests/Test-Platform.ps1`.
- **Symptom:** The script did not write `Engine/Output/platform-test-results.json`, forcing the harness onto the fragile, mojibake-prone console-parsing fallback path (the root enabler of Issue 2).
- **Classification:** **Internal Only** (test infrastructure).

---

## 2. Confirmed Fixes Implemented

### Fix 1 — Removal of lossy transliteration + fail-closed behavior
- **File:** `Portal/api/report_generator.py`
- Removed the `to_ascii_safe()` function entirely.
- Removed the ASCII fallback branch of `create_executive_pdf()`.
- Added `Utf8ComplianceError(RuntimeError)` and made the no-font path **fail closed** by raising it (with an actionable Turkish-language message), instead of silently degrading output.
- The existing Unicode path (Type0 / Identity-H composite font embedding via a dependency-free TrueType parser covering Turkish code points) is preserved so Turkish diacritics round-trip verbatim when an embeddable font is available.
- Removed the now-dead `_pdf_lit()` helper; updated the `create_executive_pdf` docstring to state fail-closed semantics.
- **Addresses:** Issue 1.

### Fix 2 — UTF-8 decoding of PowerShell subprocess output
- **File:** `test_comprehensive_qa.py`
- Added `encoding="utf-8"` (with `errors="replace"`) to the engine-test, version-check, and sync subprocess invocations.
- **Addresses:** Issue 2.

### Fix 3 — Real Turkish corpus + diacritic coverage assertion in Gate 4
- **File:** `test_comprehensive_qa.py`
- Replaced the ASCII-stripped corpus with genuine Turkish strings covering every Turkish-specific diacritic (`İ ı ç ş ğ ö ü Ç Ş Ğ Ö Ü â`, including uppercase forms via `GÜVENLİK` / `ÇIĞLIK`).
- Added a `required_turkish_chars` coverage assertion and a byte-stability check on the serialized JSON.
- Extended the gate's reported detail with `TurkishDiacriticsCovered` and `ByteStable` flags.
- **Addresses:** Issue 3.

### Fix 4 — UTF-8 console + child-process environment in the launcher
- **File:** `Start-LocalPortal.ps1`
- Added `[Console]::OutputEncoding` / `$OutputEncoding` UTF-8 setup, an optional `chcp 65001`, and exported `PYTHONUTF8=1` / `PYTHONIOENCODING=utf-8` for the launched Python server.
- **Addresses:** Issue 4.

### Fix 5 — UTF-8 console streams in the API server
- **File:** `Portal/api/server.py`
- Added a Windows-guarded `sys.stdout` / `sys.stderr` reconfigure to UTF-8 (`errors="backslashreplace"`) so startup and request logging never mojibake.
- **Note:** The existing RFC 5987 `Content-Disposition` handling (ASCII fallback + `filename*=UTF-8''…`) for file downloads was reviewed and found compliant; it was left unchanged.
- **Addresses:** Issue 4 (server-side).

### Fix 6 — Structured UTF-8 engine-test JSON emission
- **File:** `Engine/Tests/Test-Platform.ps1`
- Added emission of `Engine/Output/platform-test-results.json` as **BOM-less UTF-8**, including per-test name/status/duration, aggregate counts, and exit code, so the harness parses structured data instead of mojibake-prone console text.
- **Addresses:** Issues 2 and 6.

### Fix 7 — Source-tree UTF-8 verification
- All scanned source artifacts (`.py`, `.ps1`, `.md`, `.json`, `.html`, `.css`, `.txt`) were confirmed to decode as valid UTF-8.
- **Addresses:** Cross-cutting verification of the above.

---

## 3. Findings by Classification

### Customer Visible
- **Issue 1** — Lossy ASCII transliteration in the fallback PDF (Turkish characters corrupted in a delivered document). Fixed (Fix 1).

### Internal Only
- **Issue 2** — Mojibake in captured PowerShell output. Fixed (Fix 2).
- **Issue 3** — ASCII-stripped test corpus. Fixed (Fix 3).
- **Issue 4** — PowerShell console code page not forced to UTF-8. Fixed (Fixes 4, 5).
- **Issue 5** — Stale mojibake in generated `qa_test_results.json`. Resolved by Fix 2 (artifact is git-ignored and regenerates cleanly).
- **Issue 6** — Structured engine JSON not emitted. Fixed (Fix 6).

---

## 4. Remaining Work

1. **Regenerate generated artifacts.** Re-run the QA harness and any report generation so that the git-ignored `qa_test_results.json` and any locally produced reports reflect the corrected UTF-8 code paths (no action on the code required; the fix is in place).
2. **Roll out the console/environment pattern to remaining entry scripts.** Apply the same UTF-8 console + `PYTHONUTF8`/`PYTHONIOENCODING` block to the other `.ps1` entry points that launch Python and do not yet set it (e.g. `setup_project.ps1`, `Publish-ToGitHub.ps1`, `New-CloudShieldRelease.ps1`, `Engine/Create-ScheduledTask.ps1`, `Engine/Install-CloudShieldSecurityReporting.ps1`, `Azure/Deploy-ToAzure.ps1`, `Engine/KQL/query-validation/Test-KqlSyntax.ps1`).
3. **Operational precondition for the PDF fallback.** Ensure a Turkish-capable Unicode TrueType font is present wherever the pure-Python PDF fallback runs; otherwise, by design, report generation now fails closed with `Utf8ComplianceError`. Headless Chromium/Edge remains the preferred engine.
4. **Caller handling of `Utf8ComplianceError`.** Confirm all callers of `create_executive_pdf()` surface the fail-closed error to the operator explicitly rather than swallowing it.
5. **End-to-end regression run.** Execute the full QA suite once the environment/font preconditions are met and archive the clean results as evidence.

---

## 5. Customer-Facing UTF-8 Compliance Statement

**The repository is customer-facing UTF-8 compliant for the primary report path, with one explicit, fail-closed dependency.**

- The only confirmed **customer-visible** defect (lossy ASCII transliteration of Turkish characters in the pure-Python PDF fallback) has been **eliminated**. There is no longer any code path that silently emits degraded Turkish text.
- The default/primary rendering path (headless Chromium/Edge over UTF-8 HTML) preserves Turkish characters, and the fallback PDF path now embeds a Unicode font and renders Turkish verbatim when such a font is available.
- If no suitable font is present, generation **fails closed** (raises `Utf8ComplianceError`) rather than producing a non-compliant document — an intentional safety guarantee.

**Conditional caveat:** Customer-facing compliance is contingent on either (a) the headless Chromium/Edge engine being available, or (b) a Turkish-capable Unicode TrueType font being installed for the pure-Python fallback. Under a misconfigured deployment lacking both, reports will not be produced at all (fail-closed) — which is compliant behavior but an operational blocker. This dependency is captured in Remaining Work items 2–5 and must be satisfied and verified before the guarantee is treated as unconditional in production.
">