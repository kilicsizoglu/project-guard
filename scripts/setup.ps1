<#
.SYNOPSIS
    Project Guard - Kurumsal Windows Kurulum ve Yapılandırma Sihirbazı (Setup)
.DESCRIPTION
    Project Guard'ı sisteme (C:\Program Files\ProjectGuard) kurar,
    Masaüstü ve Başlat Menüsü kısayollarını oluşturur,
    Sistem PATH ortam değişkenine ekler ve 7/24 Windows Hizmetini kaydeder.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\ProjectGuard",
    [switch]$SkipService = $false,
    [switch]$Silent = $false
)

$Host.UI.RawUI.WindowTitle = "Project Guard Setup v1.1.0"

function Write-Header {
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "         PROJECT GUARD - WINDOWS KURULUM SIHIRBAZI (SETUP)       " -ForegroundColor Cyan
    Write-Host "      Next-Gen Open-Source Antivirus & EDR Platform v1.1.0       " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""
}

Write-Header

# 1. Administrator Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] HATA: Kurulum Yonetici yetkileri gerektirmektedir!"
    Write-Host "Lutfen 'Setup.cmd' dosyasina sag tiklayip 'Yonetici Olarak Calistir' seciniz." -ForegroundColor Yellow
    if (-not $Silent) { Read-Host "Cikmak icin Enter'a basiniz..." }
    exit 1
}

# 2. Locate project root & binary
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

$releaseExe = Join-Path $projectRoot "target\release\project-guard.exe"
$debugExe = Join-Path $projectRoot "target\debug\project-guard.exe"

$sourceExe = ""
if (Test-Path $releaseExe) {
    $sourceExe = $releaseExe
} elseif (Test-Path $debugExe) {
    $sourceExe = $debugExe
} else {
    Write-Host "[*] project-guard.exe bulunamadi. Optimized Release ikilisi derleniyor..." -ForegroundColor Yellow
    Push-Location $projectRoot
    cargo build --release
    Pop-Location
    if (Test-Path $releaseExe) {
        $sourceExe = $releaseExe
    } else {
        Write-Error "[!] HATA: Proje derlenemedi. Rust kurulumunuzu kontrol ediniz."
        exit 1
    }
}

Write-Host "[+] Kaynak Ikili Dosya: $sourceExe" -ForegroundColor Green
Write-Host "[+] Hedef Kurulum Yolu : $InstallDir" -ForegroundColor Green
Write-Host ""

# 3. Create Installation Directory
Write-Host "[1/6] Kurulum dizini olusturuluyor..." -ForegroundColor Cyan
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$destAssets = Join-Path $InstallDir "assets"
if (-not (Test-Path $destAssets)) {
    New-Item -ItemType Directory -Path $destAssets -Force | Out-Null
}

# 4. Copy Executable & Assets
Write-Host "[2/6] Dosyalar kopyalaniyor..." -ForegroundColor Cyan

# Terminate running process if updating existing install
Get-Process -Name "project-guard" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$destExe = Join-Path $InstallDir "project-guard.exe"
Copy-Item -Path $sourceExe -Destination $destExe -Force
Write-Host "  -> project-guard.exe kopyalandi." -ForegroundColor Gray

# Copy assets (icon, banner)
$sourceAssets = Join-Path $projectRoot "assets"
if (Test-Path $sourceAssets) {
    Copy-Item -Path "$sourceAssets\*" -Destination $destAssets -Recurse -Force
    Write-Host "  -> assets (simgeler ve logolar) kopyalandi." -ForegroundColor Gray
}

# Copy documentation & uninstaller
$docs = @("README.md", "QUICKSTART.md", "ARCHITECTURE.md", "LICENSE", "Uninstall.cmd")
foreach ($doc in $docs) {
    $docPath = Join-Path $projectRoot $doc
    if (Test-Path $docPath) {
        Copy-Item -Path $docPath -Destination $InstallDir -Force
    }
}

$destScripts = Join-Path $InstallDir "scripts"
if (-not (Test-Path $destScripts)) {
    New-Item -ItemType Directory -Path $destScripts -Force | Out-Null
}
Copy-Item -Path "$scriptDir\*" -Destination $destScripts -Recurse -Force
Write-Host "  -> Kaldirma ve yonetim scriptleri kopyalandi." -ForegroundColor Gray

# 5. Create Desktop Shortcut with Icon
Write-Host "[3/6] Masaustu kisayolu olusturuluyor..." -ForegroundColor Cyan
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonDesktopDirectory)
    $shortcutPath = Join-Path $desktopPath "Project Guard.lnk"
    
    $iconPath = Join-Path $destAssets "icon.ico"
    if (-not (Test-Path $iconPath)) { $iconPath = $destExe }

    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = $destExe
    $Shortcut.Arguments = "gui"
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.IconLocation = "$iconPath, 0"
    $Shortcut.Description = "Project Guard Autonomous EDR & Antivirus"
    $Shortcut.Save()
    Write-Host "  -> Masaustu Kisayolu: $shortcutPath [OK]" -ForegroundColor Green
} catch {
    Write-Warning "Masaustu kisayolu olusturulamadi: $_"
}

# 6. Create Start Menu Shortcut
Write-Host "[4/6] Baslat Menusu kisayolu olusturuluyor..." -ForegroundColor Cyan
try {
    $startMenuPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonPrograms)
    $startMenuGroup = Join-Path $startMenuPath "Project Guard"
    if (-not (Test-Path $startMenuGroup)) {
        New-Item -ItemType Directory -Path $startMenuGroup -Force | Out-Null
    }

    $appShortcut = $WshShell.CreateShortcut((Join-Path $startMenuGroup "Project Guard.lnk"))
    $appShortcut.TargetPath = $destExe
    $appShortcut.Arguments = "gui"
    $appShortcut.WorkingDirectory = $InstallDir
    $appShortcut.IconLocation = "$iconPath, 0"
    $appShortcut.Description = "Project Guard Autonomous EDR & Antivirus"
    $appShortcut.Save()

    $webShortcut = $WshShell.CreateShortcut((Join-Path $startMenuGroup "Project Guard Web SOC.lnk"))
    $webShortcut.TargetPath = "http://127.0.0.1:7890"
    $webShortcut.Description = "Project Guard Web SOC Dashboard"
    $webShortcut.Save()

    $uninstShortcut = $WshShell.CreateShortcut((Join-Path $startMenuGroup "Uninstall Project Guard.lnk"))
    $uninstShortcut.TargetPath = (Join-Path $InstallDir "Uninstall.cmd")
    $uninstShortcut.WorkingDirectory = $InstallDir
    $uninstShortcut.IconLocation = "$iconPath, 0"
    $uninstShortcut.Description = "Project Guard Sistemden Kaldir"
    $uninstShortcut.Save()

    Write-Host "  -> Baslat Menusu: $startMenuGroup [OK]" -ForegroundColor Green
} catch {
    Write-Warning "Baslat menusu kisayolu olusturulamadi: $_"
}

# 7. Add to Windows Add/Remove Programs (Registry)
try {
    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ProjectGuard"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "Project Guard EDR & Antivirus"
    Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value "1.1.0"
    Set-ItemProperty -Path $regPath -Name "Publisher" -Value "Project Guard Team"
    Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value "$InstallDir"
    Set-ItemProperty -Path $regPath -Name "DisplayIcon" -Value "$iconPath"
    Set-ItemProperty -Path $regPath -Name "UninstallString" -Value "`"$InstallDir\Uninstall.cmd`""
    Set-ItemProperty -Path $regPath -Name "NoModify" -Value 1 -Type DWord
    Set-ItemProperty -Path $regPath -Name "NoRepair" -Value 1 -Type DWord
    Write-Host "  -> Windows Denetim Masasi Program Ekle/Kaldir kaydi yapildi. [OK]" -ForegroundColor Gray
} catch {
    Write-Warning "Kayit defteri eklenemedi: $_"
}

# 8. Add to System PATH Environment Variable
Write-Host "[5/6] Sistem PATH ortami yapilandiriliyor..." -ForegroundColor Cyan
try {
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    if ($machinePath -notlike "*$InstallDir*") {
        $newPath = "$machinePath;$InstallDir"
        [System.Environment]::SetEnvironmentVariable("Path", $newPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Host "  -> '$InstallDir' sistem PATH ortam degiskenine eklendi. [OK]" -ForegroundColor Green
    } else {
        Write-Host "  -> PATH ortam degiskeninde zaten kayitli. [OK]" -ForegroundColor Gray
    }
} catch {
    Write-Warning "PATH ayarlanamadi: $_"
}

# 8. Register 24/7 Windows Service
if (-not $SkipService) {
    Write-Host "[6/6] 7/24 Windows Arka Plan Hizmeti kaydediliyor..." -ForegroundColor Cyan
    try {
        & "$destExe" service install
        & "$destExe" service start
        Write-Host "  -> ProjectGuard Windows Hizmeti basariyla baslatildi. [OK]" -ForegroundColor Green
    } catch {
        Write-Warning "Windows Hizmeti kaydedilemedi: $_"
    }
} else {
    Write-Host "[6/6] Hizmet kurulumu atlandi (--SkipService)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "          [OK] KURULUM BASARIYLA TAMAMLANDI!                     " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "• Kurulum Yolu     : $destExe" -ForegroundColor White
Write-Host "• Masaustu Simgesi : 'Project Guard' cift tiklayarak baslatilabilir." -ForegroundColor White
Write-Host "• Web Kontrol Paneli: http://127.0.0.1:7890" -ForegroundColor White
Write-Host "• Komut Satiri     : 'project-guard --help' veya 'project-guard gui'" -ForegroundColor White
Write-Host "• Kaldirma         : $InstallDir\scripts\uninstall.ps1 veya Uninstall.cmd" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""

# Optional: Launch GUI
if (-not $Silent) {
    $launch = Read-Host "Project Guard simdi baslatilsin mi? (E/H) [Varsayilan: E]"
    if ($launch -ne "H" -and $launch -ne "h") {
        Write-Host "[*] Project Guard baslatiliyor..." -ForegroundColor Cyan
        Start-Process -FilePath $destExe -ArgumentList "gui"
    }
}
