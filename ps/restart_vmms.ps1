<#
.SYNOPSIS
    Restart the vmms service (flushes its in-memory NVRAM cache) with a .vmgs integrity check.

.DESCRIPTION
    VMMS caches the VM's NVRAM (.vmgs) in memory: a file-level .vmgs edit only
    reaches the firmware after `Restart-Service vmms`. All VMs must be Off
    while you edit their .vmgs and restart the service.

    This script:
      1. verifies the target VM is Off,
      2. lists all VM states,
      3. records the .vmgs sha256,
      4. restarts vmms,
      5. verifies the .vmgs on disk was NOT modified by the restart.

.PARAMETER VMName
    Name of the VM whose .vmgs was edited.

.EXAMPLE
    .\restart_vmms.ps1 -VMName Talos
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$VMName
)

$ErrorActionPreference = 'Stop'

$v = Get-VM -Name $VMName
if ($v.State -ne 'Off') {
    "ERROR: VM '$VMName' is $($v.State) - it must be Off while restarting vmms"
    exit 6
}
$vmgs = Join-Path $v.Path ($v.VMId.ToString() + '.vmgs')
if (-not (Test-Path $vmgs)) {
    "ERROR: .vmgs not found at $vmgs"
    exit 6
}
$hBefore = (Get-FileHash -Algorithm SHA256 -Path $vmgs).Hash
"vmgs sha256 before restart = $hBefore"
""
"=== VM states (must all be Off) ==="
Get-VM | ForEach-Object { "  " + $_.Name + "  " + $_.State }
""
"=== Restart-Service vmms (flushes the in-memory NVRAM cache) ==="
Restart-Service vmms -PassThru | Out-Null
"vmms restarted at " + (Get-Date -Format HH:mm:ss)
Start-Sleep -Seconds 8
""
$hAfter = (Get-FileHash -Algorithm SHA256 -Path $vmgs).Hash
"vmgs sha256 after restart  = $hAfter"
if ($hBefore -eq $hAfter) {
    "VMGS UNCHANGED by the service restart (edits intact on disk)"
} else {
    "VMGS CHANGED by the service restart - inspect before booting!"
    exit 7
}
""
$fw = Get-VMFirmware -VMName $VMName
"SecureBoot=" + $fw.SecureBoot + "  Template=" + $fw.SecureBootTemplate
