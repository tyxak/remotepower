#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RemotePower Windows Client Installer
.DESCRIPTION
    Installs the RemotePower agent as a Windows Service using NSSM.
    Requires Python 3.8+ and an internet connection to download NSSM.
.NOTES
    Run as Administrator:
      powershell -ExecutionPolicy Bypass -File install-client.ps1
#>

$ErrorActionPreference = 'Stop'

$InstallDir   = "$env:ProgramFiles\RemotePower"
$DataDir      = "$env:ProgramData\RemotePower"
$ServiceName  = 'RemotePowerAgent'
$NssmVersion  = '2.24'
$NssmZipUrl   = "https://nssm.cc/release/nssm-$NssmVersion.zip"

function Write-Info    { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok      { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn    { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Fail    { param($m) Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "+----------------------------------------------+" -ForegroundColor White
Write-Host "|   RemotePower Client Installer (Windows)      |" -ForegroundColor White
Write-Host "+----------------------------------------------+" -ForegroundColor White
Write-Host ""

# ---- Check Python ----------------------------------------------------------
Write-Info "Checking Python..."
$py = $null
foreach ($candidate in @('python3', 'python', 'py')) {
    try {
        $ver = & $candidate --version 2>&1
        if ($ver -match 'Python 3\.(\d+)') {
            $minor = [int]$Matches[1]
            if ($minor -ge 8) {
                $py = $candidate
                break
            }
        }
    } catch {}
}
if (-not $py) { Write-Fail "Python 3.8+ is required. Install from https://python.org" }
Write-Ok "Found: $(& $py --version 2>&1)"

# ---- Install psutil (optional) --------------------------------------------
Write-Info "Installing psutil (optional, for CPU/RAM/disk metrics)..."
try {
    & $py -m pip install psutil --quiet 2>$null
    Write-Ok "psutil installed"
} catch {
    Write-Warn "psutil not installed - metrics will be unavailable"
}

# ---- Create directories ---------------------------------------------------
Write-Info "Creating directories..."
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir    -Force | Out-Null
Write-Ok "Directories created"

# ---- Copy agent script -----------------------------------------------------
Write-Info "Installing agent..."
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentSrc  = Join-Path $ScriptDir "client\remotepower-agent.py"

if (-not (Test-Path $AgentSrc)) {
    # Try relative to script location
    $AgentSrc = Join-Path $ScriptDir "remotepower-agent.py"
}
if (-not (Test-Path $AgentSrc)) {
    Write-Fail "Cannot find remotepower-agent.py - run this script from the remotepower directory"
}

Copy-Item $AgentSrc "$InstallDir\remotepower-agent.py" -Force
Write-Ok "Agent installed to $InstallDir\remotepower-agent.py"

# ---- Enrollment ------------------------------------------------------------
Write-Info "Starting enrollment wizard..."
Write-Host ""
& $py "$InstallDir\remotepower-agent.py" enroll
if ($LASTEXITCODE -ne 0) { Write-Fail "Enrollment failed" }
Write-Host ""

# ---- Download NSSM ---------------------------------------------------------
Write-Info "Setting up Windows Service..."
$NssmExe = "$InstallDir\nssm.exe"

if (Test-Path $NssmExe) {
    Write-Ok "NSSM already present"
} else {
    Write-Info "Downloading NSSM $NssmVersion..."
    $zipPath = "$env:TEMP\nssm-$NssmVersion.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $NssmZipUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\nssm" -Force
        $arch = if ([Environment]::Is64BitOperatingSystem) { 'win64' } else { 'win32' }
        Copy-Item "$env:TEMP\nssm\nssm-$NssmVersion\$arch\nssm.exe" $NssmExe -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\nssm" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "NSSM installed"
    } catch {
        Write-Warn "Could not download NSSM automatically."
        Write-Warn "Download manually from https://nssm.cc and place nssm.exe in $InstallDir"
        Write-Warn "Then run: nssm install $ServiceName $py $InstallDir\remotepower-agent.py run"
        Write-Warn "The agent will run in the foreground for now."
        Write-Host ""
        Write-Host "  To run manually:  $py $InstallDir\remotepower-agent.py run" -ForegroundColor White
        exit 0
    }
}

# ---- Install service -------------------------------------------------------
# Remove existing service if present
try { & $NssmExe stop $ServiceName 2>$null } catch {}
try { & $NssmExe remove $ServiceName confirm 2>$null } catch {}

$pyPath = (Get-Command $py).Source
& $NssmExe install $ServiceName $pyPath "$InstallDir\remotepower-agent.py run"
& $NssmExe set $ServiceName AppDirectory $InstallDir
& $NssmExe set $ServiceName Description "RemotePower Agent - Remote device management client"
& $NssmExe set $ServiceName Start SERVICE_AUTO_START
& $NssmExe set $ServiceName AppStdout "$DataDir\service_stdout.log"
& $NssmExe set $ServiceName AppStderr "$DataDir\service_stderr.log"
& $NssmExe set $ServiceName AppRotateFiles 1
& $NssmExe set $ServiceName AppRotateBytes 1048576
& $NssmExe set $ServiceName AppRestartDelay 30000

Write-Ok "Service '$ServiceName' installed"

# ---- Start service ---------------------------------------------------------
Write-Info "Starting service..."
& $NssmExe start $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Ok "Service is running"
} else {
    Write-Warn "Service may not have started - check: Get-Service $ServiceName"
}

Write-Host ""
Write-Host "+----------------------------------------------+" -ForegroundColor White
Write-Host "|   Client installed!                           |" -ForegroundColor White
Write-Host "+----------------------------------------------+" -ForegroundColor White
Write-Host ""
Write-Host "  Status:    Get-Service $ServiceName"
Write-Host "  Logs:      Get-Content '$DataDir\agent.log' -Tail 50 -Wait"
Write-Host "  Re-enroll: $py '$InstallDir\remotepower-agent.py' enroll"
Write-Host "  Uninstall: $NssmExe remove $ServiceName confirm"
Write-Host ""
