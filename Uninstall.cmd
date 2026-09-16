@echo off
setlocal EnableDelayedExpansion
title Project Guard Uninstall

:: Check for Administrative Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ==============================================================
    echo  [!] Yonetici Yetkisi Gerekiyor / Administrator Privileges Required
    echo  UAC Yonetici onayi isteniyor, lutfen acilan pencereye 'Evet' deyiniz...
    echo ==============================================================
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: Locate script
set "UNINSTALL_SCRIPT=%~dp0scripts\uninstall.ps1"
if not exist "%UNINSTALL_SCRIPT%" (
    set "UNINSTALL_SCRIPT=%~dp0uninstall.ps1"
)

:: Run PowerShell uninstall script with bypass policy
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%UNINSTALL_SCRIPT%"

if %errorLevel% neq 0 (
    echo.
    echo [!] Kaldirma sirasinda bir hata olustu.
    pause
    exit /b %errorLevel%
)

exit /b 0
