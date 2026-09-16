@echo off
setlocal EnableDelayedExpansion
title Project Guard Setup

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

:: Run PowerShell setup script with bypass policy
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup.ps1"

if %errorLevel% neq 0 (
    echo.
    echo [!] Kurulum sirasinda bir hata olustu. Hata Kodu: %errorLevel%
    pause
    exit /b %errorLevel%
)

exit /b 0
