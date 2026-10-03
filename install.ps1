# Installs Orbi Control for the current Windows user: Python environment, auto-start at
# logon (restarted within 5 minutes if it ever crashes), then starts it. No admin needed.
# Phone access additionally needs allow-phone-access.ps1 (one admin prompt).
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$venv = Join-Path $root ".venv"

if (-not (Test-Path (Join-Path $venv "Scripts\pythonw.exe"))) {
    Write-Host "Creating Python environment..."
    py -3 -m venv $venv
}
& (Join-Path $venv "Scripts\python.exe") -m pip install --quiet --upgrade pip
& (Join-Path $venv "Scripts\python.exe") -m pip install --quiet -r (Join-Path $root "requirements.txt")

$action = New-ScheduledTaskAction -Execute (Join-Path $venv "Scripts\pythonw.exe") -Argument "-m orbi --background" -WorkingDirectory $root
# Start at logon, plus a watchdog every 5 minutes: if Orbi Control isn't running (crash,
# killed, etc.) it starts again; if it is, the scheduler ignores the extra trigger.
$triggers = @(
    (New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName "Orbi Control" -Action $action -Trigger $triggers -Settings $settings -Principal $principal `
    -Description "Monitors and controls the Netgear Orbi (dashboard at http://localhost:8470)" -Force | Out-Null

Start-ScheduledTask -TaskName "Orbi Control"
Write-Host "Orbi Control is installed and running. Open http://localhost:8470"
Write-Host "For phone access, run allow-phone-access.ps1 (it will ask for admin approval once)."
