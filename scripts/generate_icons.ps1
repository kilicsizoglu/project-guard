param(
    [string]$OutputDir = "extensions/chrome/icons"
)

if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Add-Type -AssemblyName System.Drawing

function Create-ShieldIcon([int]$size, [string]$filename) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    # Background circle (Dark slate)
    $bgBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 15, 23, 42))
    $g.FillEllipse($bgBrush, 0, 0, $size - 1, $size - 1)

    # Shield border (Cyan/Emerald)
    $penWidth = [Math]::Max(1.0, [float]$size / 14.0)
    $penColor = [System.Drawing.Color]::FromArgb(255, 16, 185, 129)
    $pen = New-Object System.Drawing.Pen $penColor, $penWidth

    # Shield polygon
    $w = [float]$size
    $h = [float]$size
    $pad = [Math]::Max(2.0, [float]($size * 0.18))
    $pts = @(
        (New-Object System.Drawing.PointF ($w / 2.0), $pad),
        (New-Object System.Drawing.PointF ($w - $pad), ($pad * 1.5)),
        (New-Object System.Drawing.PointF ($w - $pad), ($h * 0.6)),
        (New-Object System.Drawing.PointF ($w / 2.0), ($h - $pad)),
        (New-Object System.Drawing.PointF $pad, ($h * 0.6)),
        (New-Object System.Drawing.PointF $pad, ($pad * 1.5))
    )
    $fillBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(200, 6, 95, 70))
    $g.FillPolygon($fillBrush, $pts)
    $g.DrawPolygon($pen, $pts)

    $g.Dispose()
    $targetPath = Join-Path $OutputDir $filename
    $bmp.Save($targetPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated icon: $targetPath ($size x $size)"
}

Create-ShieldIcon 16 "icon-16.png"
Create-ShieldIcon 48 "icon-48.png"
Create-ShieldIcon 128 "icon-128.png"
