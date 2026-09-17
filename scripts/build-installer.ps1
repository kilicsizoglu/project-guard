<#
.SYNOPSIS
    Project Guard - Windows Standalone Installer (.exe) & Dağıtım Paketi Oluşturucu
.DESCRIPTION
    1. Release ikilisini kontrol eder (gerekirse cargo build --release çalıştırır).
    2. Temp alanında (OneDrive kilitlemelerinden uzak) güvenli bir staging dizini oluşturur.
    3. dist\ProjectGuard-v1.1.0-Windows-x64.zip taşınabilir arşivini üretir.
    4. C# (.NET Framework 4.5+) csc.exe derleyicisi ile yerleşik grafiksel ProjectGuard-Setup-v1.1.0.exe kurulum dosyasını üretir.
    5. Varsa Inno Setup ISCC ile alternatif ISS paketini de derler.
#>

[CmdletBinding()]
param(
    [string]$Version = "1.1.0",
    [switch]$SkipCargoBuild
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "     PROJECT GUARD - WINDOWS STANDALONE INSTALLER BUILDER v$Version     " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Release Binary Check / Build
$releaseExe = Join-Path $projectRoot "target\release\project-guard.exe"
if (-not (Test-Path $releaseExe) -or -not $SkipCargoBuild) {
    Write-Host "[1/4] Release ikilisi derleniyor / guncelleniyor (cargo build --release)..." -ForegroundColor Yellow
    Push-Location $projectRoot
    cargo build --release
    Pop-Location
} else {
    Write-Host "[1/4] Mevcut release ikilisi kullaniliyor: $releaseExe" -ForegroundColor Green
}

# 2. Prepare isolated staging directory in TEMP (avoid OneDrive file locks)
Write-Host "[2/4] Paketleme dosyalari hazirlaniyor..." -ForegroundColor Cyan
$distDir = Join-Path $projectRoot "dist"
if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
}

$stagingId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
$tempStaging = Join-Path $env:TEMP "pg_staging_$stagingId"
if (Test-Path $tempStaging) { Remove-Item -Path $tempStaging -Recurse -Force }
New-Item -ItemType Directory -Path $tempStaging -Force | Out-Null

$destAssets = Join-Path $tempStaging "assets"
$destScripts = Join-Path $tempStaging "scripts"
New-Item -ItemType Directory -Path $destAssets -Force | Out-Null
New-Item -ItemType Directory -Path $destScripts -Force | Out-Null

# Copy Files to Temp Staging
Copy-Item -Path $releaseExe -Destination (Join-Path $tempStaging "project-guard.exe") -Force
Copy-Item -Path (Join-Path $projectRoot "Setup.cmd") -Destination (Join-Path $tempStaging "Setup.cmd") -Force
Copy-Item -Path (Join-Path $projectRoot "Uninstall.cmd") -Destination (Join-Path $tempStaging "Uninstall.cmd") -Force
Copy-Item -Path (Join-Path $projectRoot "assets\*") -Destination $destAssets -Recurse -Force
Copy-Item -Path (Join-Path $projectRoot "scripts\*") -Destination $destScripts -Recurse -Force

$docs = @("README.md", "README_TR.md", "README_EN.md", "QUICKSTART.md", "ARCHITECTURE.md", "LICENSE", "SECURITY.md")
foreach ($doc in $docs) {
    $src = Join-Path $projectRoot $doc
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $tempStaging -Force
    }
}

# Chrome Eklentisini Paketle ve Kopyala
Write-Host "  -> Chrome Web Shield eklentisi paketleniyor..." -ForegroundColor Cyan
& (Join-Path $scriptDir "package_extension.ps1")
$destExtensions = Join-Path $tempStaging "extensions"
New-Item -ItemType Directory -Path $destExtensions -Force | Out-Null
Copy-Item -Path (Join-Path $projectRoot "extensions\*") -Destination $destExtensions -Recurse -Force

# 3. Create Payload Zip
Write-Host "[3/4] Tasinabilir paket arşivi derleniyor..." -ForegroundColor Cyan
Add-Type -AssemblyName "System.IO.Compression.FileSystem"

$tempZip = Join-Path $env:TEMP "pg_payload_$stagingId.zip"
if (Test-Path $tempZip) { Remove-Item -Path $tempZip -Force }

[System.IO.Compression.ZipFile]::CreateFromDirectory($tempStaging, $tempZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)

$distZip = Join-Path $distDir "ProjectGuard-v$Version-Windows-x64.zip"
Copy-Item -Path $tempZip -Destination $distZip -Force
$zipSize = (Get-Item $distZip).Length / 1MB
Write-Host "  -> [OK] ZIP Paketi: $distZip ($('{0:N2}' -f $zipSize) MB)" -ForegroundColor Green

# 4. Compile Standalone GUI Installer Executable (.exe) via csc.exe
Write-Host "[4/4] Bagimsiz Windows Kurulum Dosyasi (.exe) derleniyor..." -ForegroundColor Cyan

$cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $cscPath)) {
    $cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}

$installerExe = Join-Path $distDir "ProjectGuard-Setup-v$Version.exe"
$wizardSource = Join-Path $projectRoot "installer\SetupWizard.cs"
$iconPath = Join-Path $projectRoot "assets\icon.ico"

if ((Test-Path $cscPath) -and (Test-Path $wizardSource)) {
    $cscArgs = @(
        "/nologo",
        "/target:winexe",
        "/optimize+",
        "/win32icon:$iconPath",
        "/resource:$tempZip,Payload",
        "/r:System.dll",
        "/r:System.Windows.Forms.dll",
        "/r:System.Drawing.dll",
        "/r:System.IO.Compression.dll",
        "/r:System.IO.Compression.FileSystem.dll",
        "/out:$installerExe",
        "$wizardSource"
    )

    Write-Host "  -> C# Native Derleyici Calistiriliyor..." -ForegroundColor Gray
    $proc = Start-Process -FilePath $cscPath -ArgumentList $cscArgs -Wait -PassThru -NoNewWindow
    
    if ($proc.ExitCode -eq 0 -and (Test-Path $installerExe)) {
        $exeSize = (Get-Item $installerExe).Length / 1MB
        $sha = (Get-FileHash -Path $installerExe -Algorithm SHA256).Hash
        Write-Host "  -> [OK] Standalone Kurulum Exe'si Uretildi!" -ForegroundColor Green
        Write-Host "     Dosya  : $installerExe" -ForegroundColor White
        Write-Host "     Boyut  : $('{0:N2}' -f $exeSize) MB" -ForegroundColor White
        Write-Host "     SHA-256: $sha" -ForegroundColor White
    } else {
        Write-Warning "C# derleme basarisiz oldu. Hata Kodu: $($proc.ExitCode)"
    }
} else {
    Write-Warning "csc.exe bulunamadi. Inno Setup veya ZIP modu aktif."
}

# Cleanup Temp
Remove-Item -Path $tempStaging -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue

# 5. Check Inno Setup ISCC if available as optional secondary builder
$iscc = Get-Command iscc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $iscc) {
    $possibleIscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    if (Test-Path $possibleIscc) { $iscc = $possibleIscc }
}
if ($iscc) {
    Write-Host "[*] Inno Setup bulundu ($iscc), opsiyonel ISCC paketi derleniyor..." -ForegroundColor Cyan
    & $iscc "$projectRoot\installer\project-guard.iss"
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "               [OK] KURULUM PAKETLERI HAZIRLANDI!                " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "Uretilen Kurulum Paketleri:" -ForegroundColor White
if (Test-Path $installerExe) {
    Write-Host " 1. Setup Wizard (.exe) : $installerExe" -ForegroundColor Cyan
}
if (Test-Path $distZip) {
    Write-Host " 2. Portable Archive    : $distZip" -ForegroundColor Cyan
}
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""
