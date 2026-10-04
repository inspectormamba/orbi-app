# Lets phones on your home network reach Orbi Control. Needs administrator approval.
#  1. Marks the home network (the one whose gateway is the Orbi) as Private. Windows had
#     it as Public, where it auto-created rules blocking Python, and block rules always
#     win over allow rules. The previous category is saved so uninstall.ps1 can restore it.
#  2. Opens TCP 8470 for the Python that runs Orbi Control only, for devices on the local
#     subnet and phones connected through the Orbi's own VPN (192.168.2.x), on Private
#     networks only (so the port stays closed if this PC is ever on a public network).
# Set your app PIN (open http://localhost:8470 on this PC) BEFORE running this.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
$ErrorActionPreference = "Stop"
$dataDir = "$env:LOCALAPPDATA\OrbiControl"
$settings = Get-Content "$dataDir\settings.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
if (-not $settings.pin_hash) {
    Write-Host "Set your app PIN first: open http://localhost:8470 on this PC, then run this again."
    Start-Sleep -Seconds 8
    exit 1
}
$router = if ($settings.router_host) { $settings.router_host } else { "192.168.1.1" }

$stateFile = "$dataDir\phone-access.json"
$saved = @()
if (Test-Path $stateFile) { $saved = @(Get-Content $stateFile -Raw | ConvertFrom-Json) }
$homeNets = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway.NextHop -eq $router -and $_.NetAdapter.Status -eq "Up" }
foreach ($n in $homeNets) {
    $netProfile = Get-NetConnectionProfile -InterfaceIndex $n.InterfaceIndex
    if (-not ($saved | Where-Object { $_.Name -eq $netProfile.Name })) {
        $saved += [pscustomobject]@{ Name = $netProfile.Name; Category = "$($netProfile.NetworkCategory)" }
    }
    Set-NetConnectionProfile -InterfaceIndex $n.InterfaceIndex -NetworkCategory Private
    Write-Host "Network '$($netProfile.Name)' on $($n.InterfaceAlias) is now Private (was $($netProfile.NetworkCategory))."
}
if (-not $homeNets) { Write-Host "Couldn't find the connection to $router; leaving network categories unchanged." }
ConvertTo-Json @($saved) | Set-Content $stateFile -Encoding utf8

# The venv's pythonw.exe is a launcher; the process that listens is the base interpreter it points to.
$cfg = Get-Content (Join-Path $PSScriptRoot ".venv\pyvenv.cfg") | Where-Object { $_ -match "^home\s*=" }
$python = Join-Path (($cfg -split "=", 2)[1].Trim()) "pythonw.exe"

Remove-NetFirewallRule -DisplayName "Orbi Control (home network)" -ErrorAction SilentlyContinue
$vpnSubnet = "192.168.2.0/24"  # the Orbi's OpenVPN client subnet
New-NetFirewallRule -DisplayName "Orbi Control (home network)" -Direction Inbound -Protocol TCP -LocalPort 8470 `
    -Program $python -RemoteAddress @("LocalSubnet", $vpnSubnet) -Action Allow -Profile Private | Out-Null
Write-Host "Done. Phones on your Wi-Fi or connected through the Orbi VPN can now open Orbi Control. You can close this window."
Start-Sleep -Seconds 6
