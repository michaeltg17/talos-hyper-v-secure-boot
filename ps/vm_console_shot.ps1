<#
    Grab the vmconnect console of a Hyper-V VM as a PNG (Talos installer TUI reader).
    See README.md, step 5. The vmconnect window must be reachable on the primary
    monitor for the screen path; an off-screen window uses the PrintWindow path.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$VMName,
    [string]$OutFile = (Join-Path $env:TEMP ("vm_console_" + $VMName + ".png"))
)

$ErrorActionPreference = 'Stop'
$png = $OutFile
$vmc = 'C:\Windows\System32\vmconnect.exe'

$p = Get-Process -Name vmconnect -ErrorAction SilentlyContinue | Select-Object -First 1
if ((-not $p) -or ($p.MainWindowHandle -eq 0)) {
    if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Start-Sleep 2 }
    Start-Process -FilePath $vmc -ArgumentList 'localhost', $VMName
    "relaunched vmconnect; polling for main window (max 40 s)..."
    for ($i = 1; $i -le 20; $i++) {
        Start-Sleep -Seconds 2
        $p = Get-Process -Name vmconnect -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p -and $p.MainWindowHandle -ne 0) { break }
    }
}
if (-not $p -or $p.MainWindowHandle -eq 0) { "no vmconnect window"; exit 3 }
$h = $p.MainWindowHandle
"title: '$($p.MainWindowTitle)'"

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Win32d {
public class W {
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
}
}
'@
[void][Win32d.W]::ShowWindow($h, 9)
Start-Sleep -Milliseconds 500
[void][Win32d.W]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 700

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$r = New-Object Win32d.W+RECT
[void][Win32d.W]::GetWindowRect($h, [ref]$r)
$ww = $r.Right - $r.Left; $wh = $r.Bottom - $r.Top

$primary = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$captured = $false

for ($a = 1; $a -le 3 -and -not $captured; $a++) {
    try {
        $x1 = [Math]::Max($r.Left, $primary.Left); $y1 = [Math]::Max($r.Top, $primary.Top)
        $x2 = [Math]::Min($r.Right, $primary.Left + $primary.Width); $y2 = [Math]::Min($r.Bottom, $primary.Top + $primary.Height)
        $w = $x2 - $x1; $hh = $y2 - $y1
        if ($w -lt 100 -or $hh -lt 100) { "attempt $a - intersection too small"; Start-Sleep 1; continue }
        $bmp = New-Object System.Drawing.Bitmap $w, $hh
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($x1, $y1, 0, 0, $bmp.Size)
        $g.Dispose()
        $bmp.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)
        "SAVED: $png  ($w x $hh)"
        $bmp.Dispose()
        $captured = $true
    } catch {
        "attempt $a failed: $($_.Exception.Message)"
        Start-Sleep 1
    }
}

if (-not $captured) {
    if ($ww -lt 100 -or $wh -lt 100) { $ww = 512; $wh = 400 }
    "fallback: PrintWindow ${ww}x${wh}"
    $bmp = New-Object System.Drawing.Bitmap $ww, $wh
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdcBlt = $g.GetHdc()
    $ok = [Win32d.W]::PrintWindow($h, $hdcBlt, 2)
    $g.ReleaseHdc()
    "PrintWindow ok=$ok"
    if ($ok) {
        $bmp.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)
        "SAVED (PrintWindow): $png"
    }
    $g.Dispose()
    $bmp.Dispose()
}
if (-not $captured) { "FAILED to capture"; exit 4 }
