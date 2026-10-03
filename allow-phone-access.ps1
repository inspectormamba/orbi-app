# Lets phones on your home network reach Orbi Control. Needs administrator approval.
#  1. Marks the home network (the one whose gateway is the Orbi) as Private. Windows had
#     it as Public, where it auto-created rules blocking Python, and block rules always
#     win over allow rules.
#  2. Opens TCP 8470 for devices on the local subnet and for phones connected through the
#     Orbi's own VPN (192.168.2.x), on Private networks only (so the port stays closed if
#     this PC is ever on a public network).
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
$ErrorActionPreference = "Stop"
$settings = Get-Content "$env:LOCALAPPDATA\OrbiControl\settings.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
$router = if ($settings.router_host) { $settings.router_host } else { "192.168.1.1" }

$homeNets = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway.NextHop -eq $router -and $_.NetAdapter.Status -eq "Up" }
foreach ($n in $homeNets) {
    Set-NetConnectionProfile -InterfaceIndex $n.InterfaceIndex -NetworkCategory Private
    Write-Host "Network '$($n.NetProfile.Name)' on $($n.InterfaceAlias) is now Private."
}
if (-not $homeNets) { Write-Host "Couldn't find the connection to $router; leaving network categories unchanged." }

Remove-NetFirewallRule -DisplayName "Orbi Control (home network)" -ErrorAction SilentlyContinue
$vpnSubnet = "192.168.2.0/24"  # the Orbi's OpenVPN client subnet
New-NetFirewallRule -DisplayName "Orbi Control (home network)" -Direction Inbound -Protocol TCP -LocalPort 8470 `
    -RemoteAddress @("LocalSubnet", $vpnSubnet) -Action Allow -Profile Private | Out-Null
Write-Host "Done. Phones on your Wi-Fi or connected through the Orbi VPN can now open Orbi Control. You can close this window."
Start-Sleep -Seconds 6
