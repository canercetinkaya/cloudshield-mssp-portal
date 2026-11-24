#!/usr/bin/env bash
# ==============================================================================
# CloudShield MSSP Portal - Docker Entrypoint Script
# ==============================================================================

set -e

PORT=${PORT:-8080}
VERSION=$(python3 -c "import json, os; p='/app/version.json'; print(json.load(open(p))['release']) if os.path.exists(p) else 'v3.0.0-ENTERPRISE'" 2>/dev/null || echo "v3.0.0-ENTERPRISE")

echo "================================================================================"
echo "  CloudShield Security Reporting & Managed Services Visibility Platform"
echo "  Sürüm: ${VERSION} | Ortam: ${ENVIRONMENT:-Production}"
echo "  Port : ${PORT}"
echo "================================================================================"

# Verify PowerShell 7.4 runtime
echo -n "[INFO] PowerShell Runtime: "
pwsh -v || echo "[WARN] pwsh not in path"

# Verify Python 3 runtime
echo -n "[INFO] Python Runtime: "
python3 --version || echo "[WARN] python3 not in path"

# Verify Chrome/Chromium for PDF export
if command -v google-chrome &> /dev/null; then
    echo "[INFO] Headless PDF Engine: $(google-chrome --version 2>/dev/null || echo 'Google Chrome ready')"
elif command -v chromium-browser &> /dev/null; then
    echo "[INFO] Headless PDF Engine: $(chromium-browser --version 2>/dev/null || echo 'Chromium ready')"
elif command -v chromium &> /dev/null; then
    echo "[INFO] Headless PDF Engine: $(chromium --version 2>/dev/null || echo 'Chromium ready')"
else
    echo "[WARN] Chrome/Chromium not found; PDF generation will fallback to HTML report output."
fi

# Persist report artifacts inside the mounted /app/Data volume so restarts/revisions never wipe PDFs/HTMLs
mkdir -p /app/Data/Reports
if [ -d "/app/Engine/Output" ] && [ ! -L "/app/Engine/Output" ]; then
    cp -rn /app/Engine/Output/. /app/Data/Reports/ 2>/dev/null || true
    rm -rf /app/Engine/Output
fi
if [ ! -e "/app/Engine/Output" ]; then
    ln -s /app/Data/Reports /app/Engine/Output
fi

echo "[INFO] Starting REST API and Web Portal on 0.0.0.0:${PORT}..."
exec python3 /app/Portal/api/server.py "${PORT}"
