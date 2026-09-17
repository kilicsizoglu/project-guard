@echo off
setlocal
cd /d "%~dp0\.."
echo [Project Guard] Chrome Web Shield Eklentisi Paketleniyor...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0package_extension.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo [HATA] Paketleme basarisiz oldu!
    pause
    exit /b %ERRORLEVEL%
)
echo [BASARILI] Eklenti paketlendi.
pause
