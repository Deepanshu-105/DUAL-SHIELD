# Windows laptop as PEER (P). Run from an elevated PowerShell AFTER start_D.sh on laptop D.
. "$PSScriptRoot\Common.ps1"
Assert-Admin; Read-Config; $py = Get-Python
if (($env:AGENT_SECRET_P).Length -lt 16) { Write-Host 'AGENT_SECRET_P missing in multi\config.env (run multi/gen_secrets.sh on D)' -ForegroundColor Red; exit 1 }
Stop-Dual
$env:SHIELD_ROOT = $ROOT; $env:SHIELD_PY = $py; $env:PYTHONPATH = Join-Path $ROOT 'network'
if (-not (Wait-Gateway $py)) { Write-Host "FAIL: cannot reach the Fabric gateway at $($env:D_IP):$($env:GATEWAY_PORT)" -ForegroundColor Red; exit 1 }
& $py (Join-Path $ROOT 'network\chain_setup.py') --register 2
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL: node registration on Fabric' -ForegroundColor Red; exit 1 }
Open-AgentPort
New-Item -ItemType File -Force -Path (Join-Path $LOGDIR 'peer_block.log') | Out-Null
$env:AGENT_SECRET = $env:AGENT_SECRET_P; $env:ROLE = 'peer'
Start-Bg $py @('-u', (Join-Path $ROOT 'multi\agent.py')) 'agent.out' $ROOT | Out-Null
if ($env:PEER_DETECT -eq '1') {   # P also guards its own logons and reports as node 2 (a real second reporter)
  $env:NODE_ID = '2'; $env:COREPORT = '0'; $env:WHITELIST_EXTRA = "$($env:D_IP),$($env:T_IP)"
  Start-Bg $py @('-u', (Join-Path $ROOT 'detector\win_logon_watch.py')) 'win_logon_watch.out' $ROOT | Out-Null
  Start-Bg $py @('-u', (Join-Path $ROOT 'detector\ssh_parser.py')) 'ssh_parser.out' (Join-Path $ROOT 'detector') | Out-Null
  Remove-Item Env:NODE_ID
}
if ([int]($env:BLOCK_TTL + 0) -gt 0) { Start-Bg $py @('-u', (Join-Path $ROOT 'detector\expire_blocks.py'), '--ttl', $env:BLOCK_TTL) 'expire.out' $ROOT | Out-Null }
Write-Host "P (Windows) READY: agent on :8800, blocking confirmed IPs with Windows Firewall rules. Stop with windows\stop.ps1" -ForegroundColor Green
& $py -u (Join-Path $ROOT 'network\listener.py')
