#!/usr/bin/env bash
# ==============================================================================
# CloudShield MSSP Portal - Docker Entrypoint Script
# ==============================================================================

set -e

PORT=${PORT:-8080}
VERSION=$(python3 -c "import json, os; p='/app/version.json'; print(json.load(open(p))['release']) if os.path.exists(p) else 'v2.5.13-PILOT'" 2>/dev/null || echo "v2.5.13-PILOT")

echo "================================================================================"
echo "  CloudShield Enterprise MSSP Security & Compliance Platform (MSSP Portal)"
echo "  Sürüm: ${VERSION} | Ortam: ${ENVIRONMENT:-Production}"
echo "  Port : ${PORT}"
echo "================================================================================"

# Verify PowerShell 7.4 runtime
echo -n "[INFO] PowerShell Runtime: "
pwsh -v || echo "[WARN] pwsh not in path"

# Verify Python 3 runtime
echo -n "[INFO] Python Runtime: "
python3 --version || echo "[WARN] python3 not in path"

# Verify Chromium for PDF export
if command -v chromium-browser &> /dev/null; then
    echo "[INFO] Headless PDF Engine: $(chromium-browser --version 2>/dev/null || echo 'Chromium ready')"
elif command -v chromium &> /dev/null; then
    echo "[INFO] Headless PDF Engine: $(chromium --version 2>/dev/null || echo 'Chromium ready')"
else
    echo "[WARN] Chromium not found; PDF generation will fallback to HTML report output."
fi

# Ensure Output and Data directories exist
mkdir -p /app/Engine/Output
mkdir -p /app/Data

echo "[INFO] Starting REST API and Web Portal on 0.0.0.0:${PORT}..."
exec python3 /app/Portal/api/server.py "${PORT}"
