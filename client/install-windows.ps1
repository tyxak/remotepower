<#
  RemotePower — minimal Windows agent installer.

  Installs the standalone Windows agent (remotepower-agent-win.py), enrolls it,
  and runs it as a SYSTEM scheduled task at boot. Requires Python 3.8+ on PATH
  (https://python.org) — the agent is stdlib-only; psutil is optional but
  recommended for full metrics and is installed if pip is available.

  Run from an elevated PowerShell:
    .\install-windows.ps1 -Server https://rp.example.com -Pin 123456 [-Name MyHost]

  Self-signed-CA server (v4.5.0): pass -CaFingerprint (printed by tools/gen-ca.sh)
  so the agent trusts your internal CA. The CA is fetched over HTTP and verified
  against the fingerprint before it is trusted.
    .\install-windows.ps1 -Server https://rp.internal -Pin 123456 -CaFingerprint AA:BB:..
#>
param(
  [Parameter(Mandatory = $true)] [string] $Server,
  [string] $Pin,
  [string] $Token,
  [string] $Name = $env:COMPUTERNAME,
  [string] $CaFingerprint,
  [string] $Ca
)

$ErrorActionPreference = 'Stop'
$ErrorMsg = 'Provide -Pin or -Token'
if (-not $Pin -and -not $Token) { throw $ErrorMsg }

$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { throw 'Python 3.8+ not found on PATH. Install from https://python.org and re-run.' }

$installDir = Join-Path $env:ProgramFiles 'RemotePower'
$dataDir    = Join-Path $env:ProgramData 'RemotePower'
New-Item -ItemType Directory -Force -Path $installDir, $dataDir | Out-Null

# ── Self-signed CA trust (optional) ───────────────────────────────────────────
$caPath = Join-Path $dataDir 'ca.crt'
if ($CaFingerprint -or $Ca) {
  $tmpCa = Join-Path $env:TEMP ('rp-ca-' + [guid]::NewGuid().ToString('N') + '.crt')
  if (-not $Ca) {
    $h = ([uri]$Server).Host
    $Ca = "http://$h/ca.crt"
  }
  Write-Host "Fetching CA from $Ca ..."
  if ($Ca -match '^https?://') {
    Invoke-WebRequest -Uri $Ca -OutFile $tmpCa -UseBasicParsing
  } else {
    Copy-Item $Ca $tmpCa -Force
  }
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $tmpCa
  if ($CaFingerprint) {
    $got  = $cert.GetCertHashString('SHA256').ToUpper()
    $want = ($CaFingerprint -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($got -ne $want) { throw "CA FINGERPRINT MISMATCH — refusing to trust (expected $want, got $got)" }
    Write-Host "CA fingerprint verified ($got)" -ForegroundColor Green
  } else {
    Write-Warning 'No -CaFingerprint — trusting fetched CA WITHOUT verification (TOFU).'
  }
  Copy-Item $tmpCa $caPath -Force
  Remove-Item $tmpCa -Force -ErrorAction SilentlyContinue
  # Machine-scoped env var (the agent also falls back to this exact path).
  [Environment]::SetEnvironmentVariable('RP_CA_BUNDLE', $caPath, 'Machine')
  Write-Host "CA installed -> $caPath" -ForegroundColor Green
}

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
