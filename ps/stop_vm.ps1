<#
.SYNOPSIS
    Force-stop a Hyper-V VM and wait for the firmware to release the .vmgs lock.

.DESCRIPTION
    The firmware keeps the .vmgs file open while the VM is on (and briefly
    after a stop), so a file-level .vmgs edit must wait for the lock to
    release. Every Stop-VM and every failed boot rewrites .vmgs, so after a
    stop the on-disk file is the canonical state again: rebuild your
    db-injection from BASE before the next boot.

.PARAMETER VMName
    Name of the Hyper-V VM.

.EXAMPLE
    .\stop_vm.ps1 -VMName Talos
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$VMName
)

$ErrorActionPreference = 'Stop'

$v = Get-VM -Name $VMName
$vmgs = Join-Path $v.Path ($v.VMId.ToString() + '.vmgs')

"=== stopping $VMName (was: $($v.State)) ==="
Stop-VM -VMName $VMName -Force
"stop issued at " + (Get-Date -Format HH:mm:ss)
"waiting for the .vmgs lock to release (max 90 s)..."
$ok = $false
for ($i = 1; $i -le 45; $i++) {
    Start-Sleep -Seconds 2
    try {
        $h = (Get-FileHash -Algorithm SHA256 -Path $vmgs).Hash
        "READABLE at t+{0}s  sha256={1}" -f ($i * 2), $h
        $ok = $true
        break
    } catch {
        "t+{0,3}s: still locked by VMMS" -f ($i * 2)
    }
}
if (-not $ok) {
    "TIMED OUT waiting for the .vmgs lock"
    exit 5
}
$v = Get-VM -Name $VMName
"final state: " + $v.State
"NOTE: the firmware rewrote .vmgs during shutdown - file-level edits are gone. Rebuild from BASE before the next boot."
