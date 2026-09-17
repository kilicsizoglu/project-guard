<#
.SYNOPSIS
    Project Guard Web Shield - Chrome Eklentisi (.zip) Otomatik Paketleyici
.DESCRIPTION
    Manifest V3 standartlarındaki Chrome eklentisini doğrular, gerekli dosyaları
    ayıklar ve dağıtıma hazır .zip paketleri üretir (dist, Output, extensions).
#>

[CmdletBinding()]
param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$chromeDir = Join-Path $projectRoot "extensions\chrome"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "     PROJECT GUARD - CHROME WEB SHIELD EKLENTİSİ PAKETLEYİCİ     " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Klasör ve Manifest Doğrulaması
if (-not (Test-Path $chromeDir)) {
    Write-Error "Chrome eklenti klasörü bulunamadı: $chromeDir"
    exit 1
}

$manifestPath = Join-Path $chromeDir "manifest.json"
if (-not (Test-Path $manifestPath)) {
    Write-Error "manifest.json bulunamadı: $manifestPath"
    exit 1
}

$manifestContent = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
if (-not $Version) {
    $Version = $manifestContent.version
}
if (-not $Version) {
    $Version = "1.0.0"
}

Write-Host "[1/4] Eklenti Doğrulanıyor..." -ForegroundColor Cyan
Write-Host "  -> İsim        : $($manifestContent.name)" -ForegroundColor White
Write-Host "  -> Versiyon    : v$Version" -ForegroundColor Yellow
Write-Host "  -> Manifest    : V$($manifestContent.manifest_version)" -ForegroundColor Green

# İkon kontrolü
$iconSizes = @("16", "48", "128")
foreach ($sz in $iconSizes) {
    $icoFile = Join-Path $chromeDir "icons\icon-$sz.png"
    if (-not (Test-Path $icoFile)) {
        Write-Error "Gerekli ikon eksik: $icoFile"
        exit 1
    }
}
Write-Host "  -> İkonlar     : 16x16, 48x48, 128x128 [OK]" -ForegroundColor Green

# 2. Geçici Paketleme Staging Alanı Oluştur
Write-Host "[2/4] Paketleme Dosyaları Hazırlanıyor..." -ForegroundColor Cyan
$stagingId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
$tempDir = Join-Path $env:TEMP "pg_chrome_pack_$stagingId"
if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force }
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$tempIconsDir = Join-Path $tempDir "icons"
New-Item -ItemType Directory -Path $tempIconsDir -Force | Out-Null

# Eklenti dosyalarını kopyala (Gereksiz / geçici dosyaları filtrele)
$filesToCopy = @(
    "manifest.json",
    "background.js",
    "content.js",
    "popup.html",
    "popup.js",
    "popup.css",
    "README.md"
)

foreach ($f in $filesToCopy) {
    $src = Join-Path $chromeDir $f
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $tempDir $f) -Force
    }
}

Copy-Item -Path (Join-Path $chromeDir "icons\*.png") -Destination $tempIconsDir -Force

# 3. ZIP Dosyalarını Oluştur
Write-Host "[3/4] .ZIP Dağıtım Paketleri Oluşturuluyor..." -ForegroundColor Cyan
Add-Type -AssemblyName "System.IO.Compression.FileSystem"

$tempZip = Join-Path $env:TEMP "pg_chrome_$stagingId.zip"
if (Test-Path $tempZip) { Remove-Item -Path $tempZip -Force }

[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $tempDir,
    $tempZip,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false
)

# Hedef dizinler
$distDir = Join-Path $projectRoot "dist"
$outputDir = Join-Path $projectRoot "Output"

if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir -Force | Out-Null }
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

$destZip1 = Join-Path $distDir "project-guard-web-shield-v$Version.zip"
$destZip2 = Join-Path $distDir "project-guard-web-shield.zip"
$destZip3 = Join-Path $outputDir "project-guard-web-shield.zip"
$destZip4 = Join-Path $chromeDir "project-guard-web-shield.zip"

Copy-Item -Path $tempZip -Destination $destZip1 -Force
Copy-Item -Path $tempZip -Destination $destZip2 -Force
Copy-Item -Path $tempZip -Destination $destZip3 -Force
Copy-Item -Path $tempZip -Destination $destZip4 -Force

# Temizlik
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue

# 4. Doğrulama ve Checksum
Write-Host "[4/4] Bütünlük Doğrulaması (SHA-256):" -ForegroundColor Cyan
$hashObj = Get-FileHash -Path $destZip1 -Algorithm SHA256
$sizeBytes = (Get-Item $destZip1).Length
$sizeKb = [math]::Round($sizeBytes / 1024, 2)

Write-Host "  -> Dosya Boyutu: $sizeKb KB ($sizeBytes bayt)" -ForegroundColor White
Write-Host "  -> SHA256      : $($hashObj.Hash)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Paketleme Başarıyla Tamamlandı! Üretilen Dosyalar:" -ForegroundColor Green
Write-Host "  1. $destZip1" -ForegroundColor Green
Write-Host "  2. $destZip2" -ForegroundColor Green
Write-Host "  3. $destZip3" -ForegroundColor Green
Write-Host "  4. $destZip4" -ForegroundColor Green
Write-Host ""
Write-Host "Google Chrome Kurulum Adımları:" -ForegroundColor Cyan
Write-Host "  1. Chrome tarayıcınızda 'chrome://extensions/' sayfasına gidin."
Write-Host "  2. Sağ üstten 'Geliştirici modu' seçeneğini aktif edin."
Write-Host "  3. 'Paketlenmemiş öğe yükle' butonu ile 'extensions\chrome' klasörünü seçin,"
Write-Host "     veya .zip dosyasını dışa aktarıp klasörü yükleyin."
Write-Host "=================================================================" -ForegroundColor Cyan
