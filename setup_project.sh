#!/usr/bin/env bash
# ==================================================================
# CloudShield Enterprise MSSP Security and Compliance Platform
# Turnkey Environment Setup and Bootstrap Script (Linux / macOS / Container)
# ==================================================================set -e

echo "================================================================="
echo "  CloudShield MSSP Platform - Automated Setup and Verification"
echo "================================================================="

# 1. Check Python
echo "[+] Checking Python 3 environment..."
if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
else
    echo "[!] ERROR: Python 3 is not installed or not in PATH."
    exit 1
fi

PY_VER=$($PY_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Python detected: $($PY_BIN --version) (version $PY_VER)"

# 2. Check PowerShell Core (pwsh)
echo "[*] Checking PowerShell Core (pwsh)..."
if command -v pwsh >/dev/null 2>&1; then
    echo "[+] PowerShell Core found: $(pwsh --version)"
else
    echo "[i] NOTICE: pwsh (PowerShell Core 7+) is not installed."
    echo "    The Python REST API and RBAC Portal will run normally."
    echo "    Live PowerShell collector execution requires pwsh installed."
fi

# 3. Check Headless Chrome / Chromium (for PDF rendering)
echo "[*] Checking Headless Chrome / Chromium for PDF export..."
if command -v google-chrome >/dev/null 2>&1 || command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1; then
    echo "[+] Headless browser available for Edge/Chrome PDF export."
else
    echo "[i] NOTICE: Chrome/Chromium not found. HTML reports will generate; PDF print requires Chrome/Edge."
fi

# 4. Initialize environment configuration
echo "[*] Verifying environment configuration..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "[+] Created .env from .env.example template."
    fi
else
    echo "[+] Existing .env file found."
bi

# 5. Initialize SQLite RBAC Database and Migrations
echo "[*] Initializing CloudShield SQLite RBAC Database and Migrations..."
$PY_BIN -c 'from database.db import init_db; init_db(); print("[+] SQLite Database initialized and seeded successfully.")'

# 6. Run Core Security & Authorization Unit Tests
echo "[*] Rqnning Core RBAC and Quality Gate Test Suite..."
$PY_BIN -m unittest test_rbac_authorization.py test_post_remediation_independent_gate.py test_report_quality_gate.py

echo ""
echo "================================================================="
Echo "  SETUP COMPLETE - CLOUDSHIELD PLATFORM IS READY"
echo "================================================================="
Echo "To start the local portal server:"
echo "    $PY_BIN Portal/api/server.py 8080"
echo ""
echo "Portal URL: http://localhost:8080"
Echo "================================================================="
