<#
.SYNOPSIS
    Project Guard Windows Service Uninstaller Script
.DESCRIPTION
    Safely stops and removes the Project Guard Windows Service from SCM.
    Requires Administrator privileges.
#>

Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host "      PROJECT GUARD - WINDOWS SERVICE KALDIRMA            " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Yellow

# 1. Administrator check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] HATA: Bu komut dosyasi Yonetici yetkileriyle calistirilmalidir!"
    Write-Host "Lutfen PowerShell'i 'Yonetici Olarak Calistir' secenegiyle acin." -ForegroundColor Yellow
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$releaseExe = Join-Path $projectRoot "target\release\project-guard.exe"
$debugExe = Join-Path $projectRoot "target\debug\project-guard.exe"

$exePath = if (Test-Path $releaseExe) { $releaseExe } elseif (Test-Path $debugExe) { $debugExe } else { "project-guard" }

Write-Host "[*] Hizmet durduruluyor ve sistemden kaldiriliyor..." -ForegroundColor Cyan
if (Test-Path $exePath) {
    & "$exePath" service uninstall
} else {
    sc.exe stop ProjectGuard
    Start-Sleep -Seconds 1
    sc.exe delete ProjectGuard
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " [OK] Project Guard Hizmeti Basariyla Kaldirildi." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
