<#
.SYNOPSIS
    Poll a Hyper-V VM's state and NIC IP while it boots (Talos installer).

.DESCRIPTION
    Watches the VM state and any DHCP address reported on its network adapter
    for up to -Seconds seconds, then pings the IP once it appears.

    Note: on bridged (External switch) NICs Get-VMNetworkAdapter often reports
    NO IP even when the guest has one - treat an empty IP list as "unknown",
    not "no IP". Read the installer TUI instead (vm_console_shot.ps1) or
    ping-scan the LAN.

.PARAMETER VMName
    Name of the Hyper-V VM.
.PARAMETER Seconds
    How long to poll (default 180).

.EXAMPLE
    .\monitor_boot.ps1 -VMName Talos
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$VMName,
    [int]$Seconds = 180
)

$ErrorActionPreference = 'Continue'
"=== $VMName boot monitor (waiting for the guest IP, max $Seconds s) ==="
$lastLine = $null
$found = $null
$steps = [int]($Seconds / 5)
for ($i = 1; $i -le $steps; $i++) {
    Start-Sleep -Seconds 5
    $v = Get-VM -Name $VMName
    $nic = Get-VMNetworkAdapter -VMName $VMName
    $ip = ($nic.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ','
    $line = "t+{0,3}s  State={1,-10} IP={2}" -f ($i * 5), $v.State, ([string]$ip)
    if ($line -ne $lastLine) { $line; $lastLine = $line }
    if ($ip) {
        ""
        "=== got an IP, testing reachability ==="
        try {
            $ping = Test-Connection -ComputerName $ip -Count 2 -Quiet -ErrorAction Stop
            "Ping $ip -> $ping"
        } catch {
            "Ping failed: " + $_.Exception.Message
        }
        $found = $ip
        break
    }
}
""
"=== final ==="
$v = Get-VM -Name $VMName
$nic = Get-VMNetworkAdapter -VMName $VMName
"State=" + $v.State + "  IP=" + (($nic.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ',')
"VM status: " + $v.Status
if (-not $found) {
    "no IP reported by the hypervisor (normal for bridged NICs) - check the console (vm_console_shot.ps1) or ping-scan the LAN"
}
