<#
  RemotePower — minimal Windows agent installer.

  Installs the standalone Windows agent (remotepower-agent-win.py), enrolls it,
  and runs it as a SYSTEM scheduled task at boot. Requires Python 3.8+ on PATH
  (https://python.org) — the agent is stdlib-only; psutil is optional but
  recommended for full metrics and is installed if pip is available.

  Run from an elevated PowerShell:
    .\install-windows.ps1 -Server https://rp.example.com -Pin 123456 [-Name MyHost]
#>
param(
  [Parameter(Mandatory = $true)] [string] $Server,
  [string] $Pin,
  [string] $Token,
  [string] $Name = $env:COMPUTERNAME
)

$ErrorActionPreference = 'Stop'
$ErrorMsg = 'Provide -Pin or -Token'
if (-not $Pin -and -not $Token) { throw $ErrorMsg }

$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { throw 'Python 3.8+ not found on PATH. Install from https://python.org and re-run.' }

$installDir = Join-Path $env:ProgramFiles 'RemotePower'
$dataDir    = Join-Path $env:ProgramData 'RemotePower'
New-Item -ItemType Directory -Force -Path $installDir, $dataDir | Out-Null

# Copy the agent next to this script into the install dir.
$src = Join-Path $PSScriptRoot 'remotepower-agent-win.py'
if (-not (Test-Path $src)) { throw "agent not found beside installer: $src" }
$agent = Join-Path $installDir 'remotepower-agent-win.py'
Copy-Item $src $agent -Force

# Best-effort psutil for richer metrics (agent runs without it).
try { & python -m pip install --quiet --disable-pip-version-check psutil } catch {
  Write-Warning 'psutil install failed — agent will report a reduced metric set.'
}

# Enroll.
$enrollArgs = @($agent, '--enroll', '--server', $Server, '--name', $Name)
if ($Pin)   { $enrollArgs += @('--pin', $Pin) }
if ($Token) { $enrollArgs += @('--token', $Token) }
& python @enrollArgs
if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed.' }

# Run at boot as SYSTEM via a scheduled task (simplest reliable supervisor).
$pyw = (Get-Command pythonw -ErrorAction SilentlyContinue)
$exe = if ($pyw) { $pyw.Source } else { (Get-Command python).Source }
$action  = New-ScheduledTaskAction -Execute $exe -Argument "`"$agent`" --run"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'RemotePowerAgent' -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null

# Start it now without waiting for a reboot.
Start-ScheduledTask -TaskName 'RemotePowerAgent'
Write-Host 'RemotePower Windows agent installed, enrolled, and started.' -ForegroundColor Green
