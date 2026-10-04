# Stops Orbi Control and removes auto-start. If allow-phone-access.ps1 was run, it also removes
# that firewall rule and restores the network categories it changed (asks for admin approval).
# Your data stays in %LOCALAPPDATA%\OrbiControl (delete that folder too for a clean removal).
$dataDir = "$env:LOCALAPPDATA\OrbiControl"
$stateFile = "$dataDir\phone-access.json"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$hasRule = [bool](Get-NetFirewallRule -DisplayName "Orbi Control (home network)" -ErrorAction SilentlyContinue)
if (-not $isAdmin -and ($hasRule -or (Test-Path $stateFile))) {
    Start-Process powershell -Verb RunAs -Wait -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -PhoneAccessOnly -DataDir `"$dataDir`""
}
if ($args -contains "-PhoneAccessOnly") {
    $dataDir = $args[[array]::IndexOf($args, "-DataDir") + 1]
    $stateFile = "$dataDir\phone-access.json"
    Remove-NetFirewallRule -DisplayName "Orbi Control (home network)" -ErrorAction SilentlyContinue
    if (Test-Path $stateFile) {
        foreach ($s in @(Get-Content $stateFile -Raw | ConvertFrom-Json)) {
            $p = Get-NetConnectionProfile -Name $s.Name -ErrorAction SilentlyContinue
            if ($p -and $s.Category -in @("Public", "Private")) {
                Set-NetConnectionProfile -Name $s.Name -NetworkCategory $s.Category
                Write-Host "Network '$($s.Name)' set back to $($s.Category)."
            }
        }
        Remove-Item $stateFile
    }
    Write-Host "Phone access removed."
    Start-Sleep -Seconds 3
    exit
}
if ($isAdmin -and ($hasRule -or (Test-Path $stateFile))) {
    & $PSCommandPath -PhoneAccessOnly -DataDir $dataDir
}
Stop-ScheduledTask -TaskName "Orbi Control" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Orbi Control" -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name = 'pythonw.exe'" | Where-Object { $_.CommandLine -like "*-m orbi*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Write-Host "Orbi Control stopped and removed from startup."
