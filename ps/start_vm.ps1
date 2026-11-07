<#
.SYNOPSIS
    Boot a Hyper-V VM with a .vmgs hash audit (Talos Secure Boot workflow).

.DESCRIPTION
    Prints a pre-boot snapshot (VM state, NIC, disks), records the VM's .vmgs
    sha256, starts the VM, polls its state for up to 90 s, then checks whether
    the firmware/VMMS rewrote the .vmgs during boot (the firmware rewrites it
    on every stop and failed boot - if it changed, rebuild from BASE before
    the next boot).

    The .vmgs path is derived automatically: <VM folder>\<VM id>.vmgs

.PARAMETER VMName
    Name of the Hyper-V VM.

.EXAMPLE
    .\start_vm.ps1 -VMName Talos
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$VMName
)

$ErrorActionPreference = 'Stop'

$v = Get-VM -Name $VMName
$vmgs = Join-Path $v.Path ($v.VMId.ToString() + '.vmgs')
if (-not (Test-Path $vmgs)) {
    "ERROR: .vmgs not found at $vmgs"
    exit 6
}
$h = (Get-FileHash -Algorithm SHA256 -Path $vmgs).Hash

"=== pre-boot snapshot ==="
"State: " + $v.State
$nic = Get-VMNetworkAdapter -VMName $VMName
"NIC: Mac=" + $nic.MacAddress + "  Switch=" + $nic.SwitchName + "  (VMSwitch: " + $nic.VMSwitch + ")"
"Disks:"
Get-VMHardDiskDrive -VMName $VMName | ForEach-Object {
    "  Ctrl=$($_.ControllerNumber) Loc=$($_.ControllerLocation) " + $_.Path
}
Get-VMDvdDrive -VMName $VMName | ForEach-Object {
    "  DVD Ctrl=$($_.ControllerNumber) Loc=$($_.ControllerLocation) " + $_.Path
}
""
"vmgs sha256 at boot: $h"

"=== Start-VM $VMName ==="
Start-VM -VMName $VMName
"Start-VM issued at " + (Get-Date -Format HH:mm:ss)
""
"=== polling state (max 90 s) ==="
for ($i = 1; $i -le 18; $i++) {
    Start-Sleep -Seconds 5
    $v = Get-VM -Name $VMName
    "t+{0,3}s  State={1}  Status={2}" -f ($i * 5), $v.State, $v.Status
    if ($v.State -ne 'Off') { break }
}
""
"=== post-boot vmgs check (did the firmware rewrite it?) ==="
$h2 = (Get-FileHash -Algorithm SHA256 -Path $vmgs).Hash
"vmgs sha256 after:   $h2"
if ($h -eq $h2) {
    "vmgs UNCHANGED since boot start"
} else {
    "vmgs CHANGED (firmware rewrite during boot - expected after a failed boot; rebuild from BASE before the next boot)"
}
