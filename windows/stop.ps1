# Stop the background Dual-Shield processes started by start_target.ps1 / start_peer.ps1, and optionally clear the firewall rules.
#   windows\stop.ps1            stop processes
#   windows\stop.ps1 -Clean     also remove every DualShield firewall rule and restore the default firewall policy
param([switch]$Clean)
. "$PSScriptRoot\Common.ps1"
Assert-Admin
Stop-Dual
if ($Clean) {
  $py = Get-Python; $env:PYTHONPATH = Join-Path $ROOT 'multi'
  & $py -c "import shield_os; shield_os.block_flush(); [shield_os._run(c) for c in shield_os.release_commands(shield_os.quarantine_allow_saved())]; shield_os.mark_quarantine(False)"
  netsh advfirewall firewall delete rule name='DualShield-Agent-8800' 2>$null | Out-Null
  Write-Host 'DualShield firewall rules removed, default policy restored.'
}
Write-Host 'Stopped.'
