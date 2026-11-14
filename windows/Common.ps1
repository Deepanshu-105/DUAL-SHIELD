# Shared helpers for the Windows scripts (dot-source this file). Run everything from an elevated PowerShell (Run as Administrator).
$ErrorActionPreference = 'Stop'
$ROOT = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$LOGDIR = Join-Path $env:PROGRAMDATA 'DualShield\logs'
New-Item -ItemType Directory -Force -Path $LOGDIR | Out-Null
$PIDFILE = Join-Path $LOGDIR 'pids.txt'

function Assert-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run this from an elevated PowerShell (right-click PowerShell, Run as administrator).' -ForegroundColor Red; exit 1 }
}

function Read-Config {
  # multi\config.env is the same file the Linux laptops use: KEY=VALUE lines, # comments.
  $cfg = Join-Path $ROOT 'multi\config.env'
  if (-not (Test-Path $cfg)) { Write-Host "Missing multi\config.env. Copy multi\config.env.example to multi\config.env and edit it (same file as on Linux)." -ForegroundColor Red; exit 1 }
  Get-Content $cfg | ForEach-Object {
    $l = $_.Trim()
    if ($l -and -not $l.StartsWith('#') -and $l -match '^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
      $v = $Matches[2].Trim().Trim('"').Trim("'")
      Set-Item -Path ("Env:" + $Matches[1]) -Value $v }
  }
  if (-not $env:GATEWAY_PORT) { $env:GATEWAY_PORT = '8600' }
  if ($env:TLS -eq '1') {
    $d = Join-Path $ROOT 'multi\tls\node'
    foreach ($f in 'ca.crt','node.crt','node.key') { if (-not (Test-Path (Join-Path $d $f))) {
      Write-Host "TLS=1 but $d\$f is missing. On D (Linux/WSL) run multi/make_tls.sh, then copy multi/tls/target (or peer) to multi\tls\node here." -ForegroundColor Red; exit 1 } }
    $env:TLS_DIR = $d
  }
}

function Get-Python {
  $venv = Join-Path $ROOT 'blockchain\.venv\Scripts\python.exe'
  if (Test-Path $venv) { return $venv }
  Write-Host 'Python environment missing. Run windows\install_windows.ps1 first.' -ForegroundColor Red; exit 1
}

function Wait-Gateway($py) {
  $env:PYTHONPATH = Join-Path $ROOT 'network'
  for ($i = 0; $i -lt 40; $i++) {
    & $py -c "from chainlib import Chain; Chain().head()" 2>$null
    if ($LASTEXITCODE -eq 0) { return $true }
    Start-Sleep -Seconds 2 }
  return $false
}

function Start-Bg($py, $argsList, $logName, $workdir) {
  $out = Join-Path $LOGDIR $logName
  $p = Start-Process -FilePath $py -ArgumentList $argsList -WorkingDirectory $workdir -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError ($out + '.err')
  Add-Content -Path $PIDFILE -Value $p.Id
  return $p
}

function Stop-Dual {
  if (Test-Path $PIDFILE) {
    Get-Content $PIDFILE | ForEach-Object { try { Stop-Process -Id ([int]$_) -Force -ErrorAction Stop } catch {} }
    Remove-Item $PIDFILE -Force }
}

function Open-AgentPort {
  # the dashboard laptop (D) must reach this laptop's agent on 8800; nobody else
  $name = 'DualShield-Agent-8800'
  netsh advfirewall firewall delete rule name=$name 2>$null | Out-Null
  netsh advfirewall firewall add rule name=$name dir=in action=allow protocol=TCP localport=8800 remoteip=$env:D_IP profile=any | Out-Null
}
