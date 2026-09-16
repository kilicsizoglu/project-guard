<#
.SYNOPSIS
    Project Guard - Kurumsal Windows Kaldirma Sihirbazi (Uninstall)
.DESCRIPTION
    Project Guard Windows Hizmetini durdurur ve siler,
    Masaustu ve Baslat Menusu kisayollarini kaldirir,
    Sistem PATH ortami degiskenini temizler ve dosyalari siler.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\ProjectGuard",
    [switch]$KeepData = $false,
    [switch]$Silent = $false
)

$Host.UI.RawUI.WindowTitle = "Project Guard Uninstall"

function Write-Header {
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "       PROJECT GUARD - WINDOWS KALDIRMA SIHIRBAZI (UNINSTALL)    " -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host ""
}

Write-Header

# 1. Administrator Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] HATA: Kaldirma islemi Yonetici yetkileri gerektirmektedir!"
    Write-Host "Lutfen 'Uninstall.cmd' dosyasina sag tiklayip 'Yonetici Olarak Calistir' seciniz." -ForegroundColor Yellow
    if (-not $Silent) { Read-Host "Cikmak icin Enter'a basiniz..." }
    exit 1
}

if (-not $Silent) {
    $confirm = Read-Host "Project Guard sisteminizden tamamen kaldirilsin mi? (E/H) [Varsayilan: E]"
    if ($confirm -eq "H" -or $confirm -eq "h") {
        Write-Host "Kaldirma islemi kullanici tarafindan iptal edildi." -ForegroundColor Cyan
        exit 0
    }
}

# 2. Stop running processes
Write-Host "[1/5] Calisan Project Guard surecleri sonlandiriliyor..." -ForegroundColor Cyan
try {
    $procs = Get-Process -Name "project-guard" -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "  -> Surecler durduruldu. [OK]" -ForegroundColor Green
    } else {
        Write-Host "  -> Calisan surec bulunmuyor. [OK]" -ForegroundColor Gray
    }
} catch {
    Write-Warning "Surecler sonlandirilirken uyari: $_"
}

# 3. Stop and Uninstall Windows Service
Write-Host "[2/5] 7/24 Windows Arka Plan Hizmeti kaldiriliyor..." -ForegroundColor Cyan
try {
    $installedExe = Join-Path $InstallDir "project-guard.exe"
    if (Test-Path $installedExe) {
        & "$installedExe" service stop 2>$null | Out-Null
        & "$installedExe" service uninstall 2>$null | Out-Null
    }
    
    # Fallback to SCM sc.exe
    $svc = Get-Service -Name "ProjectGuard" -ErrorAction SilentlyContinue
    if ($svc) {
        sc.exe stop ProjectGuard 2>$null | Out-Null
        Start-Sleep -Seconds 1
        sc.exe delete ProjectGuard 2>$null | Out-Null
    }
    Write-Host "  -> ProjectGuard Windows Hizmeti silindi. [OK]" -ForegroundColor Green
} catch {
    Write-Warning "Hizmet silinirken hata: $_"
}

# 4. Remove Shortcuts
Write-Host "[3/5] Masaustu ve Baslat Menusu kisayollari temizleniyor..." -ForegroundColor Cyan
try {
    $desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonDesktopDirectory)
    $desktopShortcut = Join-Path $desktopPath "Project Guard.lnk"
    if (Test-Path $desktopShortcut) {
        Remove-Item -Path $desktopShortcut -Force -ErrorAction SilentlyContinue
        Write-Host "  -> Masaustu kisayolu silindi. [OK]" -ForegroundColor Green
    }

    # User Desktop shortcut check as well
    $userDesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
    $userDesktopShortcut = Join-Path $userDesktopPath "Project Guard.lnk"
    if (Test-Path $userDesktopShortcut) {
        Remove-Item -Path $userDesktopShortcut -Force -ErrorAction SilentlyContinue
    }

    $startMenuPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonPrograms)
    $startMenuGroup = Join-Path $startMenuPath "Project Guard"
    if (Test-Path $startMenuGroup) {
        Remove-Item -Path $startMenuGroup -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  -> Baslat Menusu grubu silindi. [OK]" -ForegroundColor Green
    }
} catch {
    Write-Warning "Kisayollar silinirken hata: $_"
}

# 5. Clean System PATH
Write-Host "[4/5] Sistem PATH ortami temizleniyor..." -ForegroundColor Cyan
try {
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    if ($machinePath -like "*$InstallDir*") {
        $parts = $machinePath.Split(';') | Where-Object { $_ -ne $InstallDir -and $_ -ne "$InstallDir\" -and $_ -ne "" }
        $newPath = $parts -join ';'
        [System.Environment]::SetEnvironmentVariable("Path", $newPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Host "  -> '$InstallDir' sistem PATH ortamindan cikarildi. [OK]" -ForegroundColor Green
    } else {
        Write-Host "  -> PATH listesinde kayit bulunmuyor. [OK]" -ForegroundColor Gray
    }
} catch {
    Write-Warning "PATH ortami temizlenirken hata: $_"
}

# 6. Remove Windows Registry Uninstall Entry
try {
    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ProjectGuard"
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  -> Windows Denetim Masasi Program Ekle/Kaldir kaydi silindi. [OK]" -ForegroundColor Gray
    }
} catch {
    Write-Warning "Kayit defteri silinirken hata: $_"
}

# 6. Remove Program Files Directory
Write-Host "[5/5] Kurulum dosyalari temizleniyor..." -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    try {
        # If currently running from inside the install dir, schedule cleanup or remove files except executing script
        $items = Get-ChildItem -Path $InstallDir -Exclude "uninstall.ps1", "Uninstall.cmd"
        foreach ($item in $items) {
            Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host "  -> Program dosyalari kaldirildi. [OK]" -ForegroundColor Green
    } catch {
        Write-Warning "Bazi dosyalar silinemedi: $_"
    }
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "     [OK] PROJECT GUARD SISTEMINIZDEN BASARIYLA KALDIRILDI       " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""
if (-not $Silent) {
    Read-Host "Kapatmak icin Enter'a basiniz..."
}
