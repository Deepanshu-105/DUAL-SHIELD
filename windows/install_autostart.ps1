# Start Dual-Shield automatically at boot and restart it if it stops (Windows Task Scheduler, runs as SYSTEM).
#   windows\install_autostart.ps1 -Role target      (or -Role peer)
#   windows\install_autostart.ps1 -Remove
param([ValidateSet('target','peer')][string]$Role = 'target', [switch]$Remove)
. "$PSScriptRoot\Common.ps1"
Assert-Admin
$name = 'DualShield-' + $Role
if ($Remove) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue; Write-Host "Removed $name"; exit 0 }
$script = Join-Path $PSScriptRoot ("start_" + $Role + ".ps1")
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
# Anyone who is not an Administrator can neither stop nor edit this task (it runs as SYSTEM); the guard comes back after a crash or reboot.
Write-Host "Installed task $name: starts at boot, restarts up to 5 times if it fails." -ForegroundColor Green
