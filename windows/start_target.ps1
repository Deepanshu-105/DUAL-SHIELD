# Windows laptop as TARGET (T). Run from an elevated PowerShell AFTER start_D.sh on laptop D (Linux or WSL).
. "$PSScriptRoot\Common.ps1"
Assert-Admin; Read-Config; $py = Get-Python
if (($env:AGENT_SECRET_T).Length -lt 16) { Write-Host 'AGENT_SECRET_T missing in multi\config.env (run multi/gen_secrets.sh on D)' -ForegroundColor Red; exit 1 }
if ($env:DISCOVERY -eq '1') { Write-Host 'DISCOVERY=1 is not supported on Windows yet: set T_IP and P_IP in multi\config.env.' -ForegroundColor Yellow }
Stop-Dual
$env:SHIELD_ROOT = $ROOT; $env:SHIELD_PY = $py; $env:PYTHONPATH = Join-Path $ROOT 'network'
if (-not (Wait-Gateway $py)) { Write-Host "FAIL: cannot reach the Fabric gateway at $($env:D_IP):$($env:GATEWAY_PORT) (start_D.sh running? firewall on D? same TLS setting?)" -ForegroundColor Red; exit 1 }
& $py (Join-Path $ROOT 'network\chain_setup.py') --register 1
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL: node registration on Fabric' -ForegroundColor Red; exit 1 }
& $py (Join-Path $ROOT 'ransomware\setup_sample.py') | Out-Null
Open-AgentPort
foreach ($f in 'parser_block.log','metrics.log') { New-Item -ItemType File -Force -Path (Join-Path $LOGDIR $f) | Out-Null }
$wl = "$($env:D_IP),$($env:P_IP)"
# Layer 1: event log -> auth.log lines -> parser (blocks with Windows Firewall rules, reports to the chain)
Start-Bg $py @('-u', (Join-Path $ROOT 'detector\win_logon_watch.py')) 'win_logon_watch.out' $ROOT | Out-Null
$env:COREPORT = '1'; $env:WHITELIST_EXTRA = $wl
Start-Bg $py @('-u', (Join-Path $ROOT 'detector\ssh_parser.py')) 'ssh_parser.out' (Join-Path $ROOT 'detector') | Out-Null
if ($env:LOGIN_WATCH -eq '1') { Start-Bg $py @('-u', (Join-Path $ROOT 'detector\login_watch.py')) 'login_watch.out' $ROOT | Out-Null }
if ([int]($env:BLOCK_TTL + 0) -gt 0) { Start-Bg $py @('-u', (Join-Path $ROOT 'detector\expire_blocks.py'), '--ttl', $env:BLOCK_TTL) 'expire.out' $ROOT | Out-Null }
# Layer 2: the agent starts guard.py (vault + kill rule + containment) when the dashboard asks
$env:AGENT_SECRET = $env:AGENT_SECRET_T; $env:ROLE = 'target'
Start-Bg $py @('-u', (Join-Path $ROOT 'multi\agent.py')) 'agent.out' $ROOT | Out-Null
Write-Host "T (Windows) READY: agent on :8800, logon watch + parser running, logs in $LOGDIR. Stop with windows\stop.ps1" -ForegroundColor Green
Get-Content -Path (Join-Path $LOGDIR 'ssh_parser.out') -Wait -ErrorAction SilentlyContinue
