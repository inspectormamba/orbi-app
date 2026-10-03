# Stops Orbi Control and removes auto-start. Your data stays in %LOCALAPPDATA%\OrbiControl
# (delete that folder too for a clean removal). Run allow-phone-access's rule removal as admin:
#   Remove-NetFirewallRule -DisplayName "Orbi Control (home network)"
Stop-ScheduledTask -TaskName "Orbi Control" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Orbi Control" -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name = 'pythonw.exe'" | Where-Object { $_.CommandLine -like "*-m orbi*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Write-Host "Orbi Control stopped and removed from startup."
