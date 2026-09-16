<#
.SYNOPSIS
    Project Guard Windows Service Installer & Setup Script
.DESCRIPTION
    Installs, configures, and starts the Project Guard 24/7 background EDR service.
    Requires Administrator privileges.
#>

[CmdletBinding()]
param(
    [string]$CustomExePath = ""
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       PROJECT GUARD - WINDOWS SERVICE SETUP              " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Administrator check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] HATA: Bu komut dosyasi Yonetici yetkileriyle calistirilmalidir!"
    Write-Host "Lutfen PowerShell'i 'Yonetici Olarak Calistir' secenegiyle acin." -ForegroundColor Yellow
    exit 1
}

# 2. Locate binary
$exePath = $CustomExePath
if ([string]::IsNullOrWhiteSpace($exePath)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $projectRoot = Split-Path -Parent $scriptDir

    $releaseExe = Join-Path $projectRoot "target\release\project-guard.exe"
    $debugExe = Join-Path $projectRoot "target\debug\project-guard.exe"

    if (Test-Path $releaseExe) {
        $exePath = $releaseExe
    } elseif (Test-Path $debugExe) {
        $exePath = $debugExe
    } else {
        Write-Host "[*] project-guard.exe bulunamadi. Proje derleniyor (cargo build --release)..." -ForegroundColor Yellow
        Push-Location $projectRoot
        cargo build --release
        Pop-Location

        if (Test-Path $releaseExe) {
            $exePath = $releaseExe
        } else {
            Write-Error "[!] HATA: project-guard.exe derlenemedi veya bulunamadi."
            exit 1
        }
    }
}

Write-Host "[+] Calistirilabilir dosya: $exePath" -ForegroundColor Green

# 3. Register service
Write-Host "`n[*] 1/3: Windows Hizmeti kaydediliyor (SCM)..." -ForegroundColor Cyan
& "$exePath" service install

# 4. Start service
Write-Host "`n[*] 2/3: Windows Hizmeti baslatiliyor..." -ForegroundColor Cyan
& "$exePath" service start

# 5. Check status
Write-Host "`n[*] 3/3: Hizmet durumu dogrulaniyor..." -ForegroundColor Cyan
& "$exePath" service status

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " [OK] Project Guard Hizmeti Basariyla Kuruldu ve Calisiyor!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "• Gunluk Log Dosyasi : .project_guard\service.log" -ForegroundColor White
Write-Host "• Web Kontrol Merkezi: project-guard ui --port 7890" -ForegroundColor White
Write-Host "• Hizmeti Durdurmak  : .\scripts\uninstall-service.ps1" -ForegroundColor White
