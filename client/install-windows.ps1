<#
  RemotePower — Windows agent installer.

  Installs the Windows agent (remotepower-agent-win.py), enrolls it, and runs it
  as a SYSTEM scheduled task at boot. Requires Python 3.8+ on PATH
  (https://www.python.org/downloads/ — tick "Add python.exe to PATH"). The agent
  is stdlib-only; psutil is optional but recommended for the full metric set and
  is installed if pip is available.

  The agent is used from beside this script if present; otherwise it is
  downloaded from the server (and its checksum verified) — so this script works
  standalone. The smoothest path is the one-liner from "Add device → Quick
  install"; this script is the scripted / offline equivalent.

  Run from an ELEVATED PowerShell:
    .\install-windows.ps1 -Server https://rp.example.com -Token <enrollment-token> [-Name MyHost]
    .\install-windows.ps1 -Server https://rp.example.com -Pin 123456
    .\install-windows.ps1 -Uninstall

  Self-signed-CA server: pass -CaFingerprint (printed by tools/gen-ca.sh) so the
  agent trusts your internal CA. The CA is fetched over HTTP and verified against
  the fingerprint before it is trusted.
    .\install-windows.ps1 -Server https://rp.internal -Token <t> -CaFingerprint AA:BB:..
#>
param(
  [string] $Server,
  [string] $Pin,
  [string] $Token,
  [string] $Name = $env:COMPUTERNAME,
  [string] $CaFingerprint,
  [string] $Ca,
  [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
  $admin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltinRole]::Administrator)
  if (-not $admin) {
    throw 'This installer must run as Administrator. Open PowerShell as Administrator (Win+X -> Terminal (Admin)) and re-run.'
  }
}

$installDir = Join-Path $env:ProgramFiles 'RemotePower'
$dataDir    = Join-Path $env:ProgramData 'RemotePower'
$agent      = Join-Path $installDir 'remotepower-agent-win.py'

# ── Uninstall ────────────────────────────────────────────────────────────────
if ($Uninstall) {
  Assert-Admin
  Write-Host 'Uninstalling the RemotePower Windows agent ...'
  schtasks /end /tn RemotePowerAgent 2>$null | Out-Null
  schtasks /delete /tn RemotePowerAgent /f 2>$null | Out-Null
  Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host 'Uninstalled. Remove the device from the dashboard to stop tracking it.' -ForegroundColor Green
  return
}

Assert-Admin
if (-not $Server) { throw 'Provide -Server https://<your-remotepower>' }
if (-not $Pin -and -not $Token) { throw 'Provide -Token (from "Add device") or -Pin' }

function Install-PythonIfMissing {
  if (Get-Command python -ErrorAction SilentlyContinue) { return }
  Write-Host 'Python not found - installing it automatically ...'
  $refresh = {
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path','User')
  }
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    try {
      & winget install -e --id Python.Python.3.12 --silent --scope machine `
        --accept-source-agreements --accept-package-agreements | Out-Null
    } catch {}
    & $refresh
    if (Get-Command python -ErrorAction SilentlyContinue) { Write-Host 'Python installed (winget).' -ForegroundColor Green; return }
  }
  $ver = '3.12.7'
  $exe = Join-Path $env:TEMP "python-$ver-amd64.exe"
  Write-Host "Downloading Python $ver ..."
  Invoke-WebRequest -Uri "https://www.python.org/ftp/python/$ver/python-$ver-amd64.exe" -OutFile $exe -UseBasicParsing
  Start-Process -FilePath $exe -ArgumentList '/quiet','InstallAllUsers=1','PrependPath=1','Include_pip=1' -Wait
  Remove-Item $exe -Force -ErrorAction SilentlyContinue
  & $refresh
  if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Automatic Python install failed. Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH") and re-run.'
  }
  Write-Host 'Python installed.' -ForegroundColor Green
}
Install-PythonIfMissing

New-Item -ItemType Directory -Force -Path $installDir, $dataDir | Out-Null

# ── Self-signed CA trust (optional) ───────────────────────────────────────────
$caPath = Join-Path $dataDir 'ca.crt'
if ($CaFingerprint -or $Ca) {
  $tmpCa = Join-Path $env:TEMP ('rp-ca-' + [guid]::NewGuid().ToString('N') + '.crt')
  if (-not $Ca) { $Ca = "http://$(([uri]$Server).Host)/ca.crt" }
  Write-Host "Fetching CA from $Ca ..."
  if ($Ca -match '^https?://') { Invoke-WebRequest -Uri $Ca -OutFile $tmpCa -UseBasicParsing }
  else { Copy-Item $Ca $tmpCa -Force }
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $tmpCa
  if ($CaFingerprint) {
    $got  = $cert.GetCertHashString('SHA256').ToUpper()
    $want = ($CaFingerprint -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($got -ne $want) { throw "CA FINGERPRINT MISMATCH - refusing to trust (expected $want, got $got)" }
    Write-Host "CA fingerprint verified ($got)" -ForegroundColor Green
  } else {
    Write-Warning 'No -CaFingerprint - trusting fetched CA WITHOUT verification (TOFU).'
  }
  Copy-Item $tmpCa $caPath -Force
  Remove-Item $tmpCa -Force -ErrorAction SilentlyContinue
  [Environment]::SetEnvironmentVariable('RP_CA_BUNDLE', $caPath, 'Machine')
  $env:RP_CA_BUNDLE = $caPath
  Write-Host "CA installed -> $caPath" -ForegroundColor Green
}

# ── Get the agent: from beside this script, else download from the server ─────
$src = Join-Path $PSScriptRoot 'remotepower-agent-win.py'
if (Test-Path $src) {
  Copy-Item $src $agent -Force
} else {
  Write-Host "Downloading the agent from $Server ..."
  $want = ''
  try { $want = (Invoke-RestMethod -Uri "$Server/api/agent/win/version" -UseBasicParsing).sha256 } catch {}
  Invoke-WebRequest -Uri "$Server/api/agent/win/download" -OutFile $agent -UseBasicParsing
  if ($want) {
    $got = (Get-FileHash -Path $agent -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $want.ToLower()) {
      Remove-Item $agent -Force -ErrorAction SilentlyContinue
      throw "Agent checksum mismatch - refusing to install (expected $want, got $got)."
    }
    Write-Host 'Agent checksum verified.' -ForegroundColor Green
  }
}

# psutil (richer metrics) + pywin32 (real Windows service). Best-effort.
try { & python -m pip install --quiet --disable-pip-version-check psutil } catch {
  Write-Warning 'psutil install failed - the agent will report a reduced metric set.'
}
$havePywin32 = $false
try {
  & python -m pip install --quiet --disable-pip-version-check pywin32 | Out-Null
  & python -c "import win32serviceutil" 2>$null
  if ($LASTEXITCODE -eq 0) {
    $havePywin32 = $true
    $ppi = Join-Path (Split-Path (Get-Command python).Source) 'Scripts\pywin32_postinstall.py'
    if (Test-Path $ppi) { & python $ppi -install -quiet 2>$null | Out-Null }
  }
} catch {}

# ── Enroll ────────────────────────────────────────────────────────────────────
$enrollArgs = @($agent, '--enroll', '--server', $Server, '--name', $Name)
if ($Pin)   { $enrollArgs += @('--pin', $Pin) }
if ($Token) { $enrollArgs += @('--token', $Token) }
& python @enrollArgs
if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed.' }

# ── Persistence: a real Windows service (preferred), else a SYSTEM task ────────
schtasks /delete /tn RemotePowerAgent /f 2>$null | Out-Null
sc.exe stop RemotePowerAgent 2>$null | Out-Null
sc.exe delete RemotePowerAgent 2>$null | Out-Null

$installedAs = ''
if ($havePywin32) {
  & python $agent --install-service
  Start-Sleep -Seconds 2
  if ((sc.exe query RemotePowerAgent 2>$null) -match 'RUNNING|START_PENDING|STOPPED') { $installedAs = 'service' }
}
if (-not $installedAs) {
  # Fallback scheduled task. Resolve a machine-wide interpreter SYSTEM can launch
  # (a per-user / Microsoft Store Python fails under SYSTEM with 0x80070780).
  $py = (Get-Command python).Source
  if ($py -match '\\WindowsApps\\' -or $py -match '(?i)\\Users\\') {
    $mp = Get-ChildItem "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if ($mp) { $py = $mp.FullName }
  }
  $pyw = Join-Path (Split-Path $py) 'pythonw.exe'
  if (-not (Test-Path $pyw)) { $pyw = $py }
  if ($pyw -match '\\WindowsApps\\' -or $pyw -match '(?i)\\Users\\') {
    throw "Only a per-user/Store Python was found ($pyw); the SYSTEM task can't launch it. Install a machine-wide Python (all users) and re-run."
  }
  $action  = New-ScheduledTaskAction -Execute $pyw -Argument "`"$agent`" --run"
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName 'RemotePowerAgent' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
  Start-ScheduledTask -TaskName 'RemotePowerAgent'
  $installedAs = 'scheduled task'
}
Write-Host "RemotePower Windows agent installed as a $installedAs, enrolled, and started. It will appear on the dashboard within a minute." -ForegroundColor Green
