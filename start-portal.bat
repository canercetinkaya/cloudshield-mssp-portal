@echo off
REM CloudShield Enterprise Security Reporting Platform - Windows Quick Launcher
TITLE CloudShield MSSP Security Reporting Platform
chcp 65001 >nul

echo ================================================================================
echo    CloudShield Security Reporting & Managed Services Visibility Platform
echo    Yerel Baslatici (Local Launcher)
echo ================================================================================

cd /d "%~dp0"

echo [1/3] Python kontrol ediliyor...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Python bulunamadi! Lutfen Python 3.10+ kurulu ve PATH'e ekli oldugundan emin olun.
    pause
    exit /b 1
)

echo [2/3] Veritabani ve sema hazirlaniyor...
python -c "from database.db import init_db; init_db(); from Portal.api.server import _ensure_session_tables; _ensure_session_tables()" >nul 2>&1

echo [3/3] Tarayici aciliyor ve sunucu baslatiliyor: http://localhost:8080 ...
start http://localhost:8080

python Portal\api\server.py 8080

pause
