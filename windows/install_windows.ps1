# Windows laptop (target T or peer P): one-time set-up. Run from an elevated PowerShell:  powershell -ExecutionPolicy Bypass -File windows\install_windows.ps1
. "$PSScriptRoot\Common.ps1"
Assert-Admin
function Have($c) { return [bool](Get-Command $c -ErrorAction SilentlyContinue) }
if (-not (Have 'git'))    { Write-Host 'Installing Git ...';    winget install --id Git.Git -e --silent --accept-package-agreements --accept-source-agreements }
if (-not (Have 'python') -and -not (Have 'py')) { Write-Host 'Installing Python 3.12 ...'; winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements }
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
$sys = if (Have 'py') { 'py' } else { 'python' }
$venv = Join-Path $ROOT 'blockchain\.venv'
if (-not (Test-Path "$venv\Scripts\python.exe")) { & $sys -m venv $venv }
& "$venv\Scripts\python.exe" -m pip install -q --upgrade pip
& "$venv\Scripts\python.exe" -m pip install -q watchdog cryptography psutil
$cfg = Join-Path $ROOT 'multi\config.env'
if (-not (Test-Path $cfg)) { Copy-Item (Join-Path $ROOT 'multi\config.env.example') $cfg }
# Optional, for the SSH brute-force demo: Windows OpenSSH Server (its failures are read from the Windows event log)
$ssh = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
if ($ssh.State -ne 'Installed') { Write-Host 'Installing OpenSSH Server ...'; Add-WindowsCapability -Online -Name $ssh.Name | Out-Null }
Set-Service -Name sshd -StartupType Automatic; Start-Service sshd
wevtutil sl OpenSSH/Operational /e:true 2>$null
# Failed and successful logons must be audited (default on most editions)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
Write-Host "Windows laptop is ready. Edit multi\config.env (same file as on Linux), then run windows\start_target.ps1 (T) or windows\start_peer.ps1 (P)." -ForegroundColor Green
