# deploy-production.ps1 — Windows production deployment for aikey-proxy.
#
# Supports deploying to Windows targets (local or remote via WinRM/PSRemoting).
# Run this script from a Windows build machine (PowerShell 5.1+ or PowerShell 7+).
#
# Usage:
#   # Local Windows deployment
#   .\scripts\deploy-production.ps1 -Config C:\path\to\prod.yaml [-Vault C:\path\to\vault.db]
#
#   # Remote Windows deployment (requires WinRM / PSRemoting enabled on target)
#   .\scripts\deploy-production.ps1 -ComputerName server01 -Config C:\path\to\prod.yaml [-Credential (Get-Credential)]
#
# Prerequisites:
#   - Go >= 1.26.1 installed and in PATH (build machine)
#   - For remote: WinRM enabled on target (Enable-PSRemoting -Force)
#   - NSSM (Non-Sucking Service Manager) on target (optional, recommended)
#     Download: https://nssm.cc  — Apache License 2.0
#     Without NSSM, falls back to native Windows Service (sc.exe + wrapper)

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory = $true)]
    [string]$Config,

    [Parameter(Mandatory = $false)]
    [string]$Vault = "",

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServiceName  = "aikey-proxy"
$InstallDir   = "C:\Program Files\aikey-proxy"
$ConfigDir    = "C:\ProgramData\aikey-proxy"
$LogDir       = "C:\ProgramData\aikey-proxy\logs"
$BackupDir    = "C:\ProgramData\aikey-proxy\backup"
$BinaryName   = "aikey-proxy.exe"

function Write-Info  { param($msg) Write-Host "[INFO]  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg" -ForegroundColor Cyan }
function Write-Warn  { param($msg) Write-Host "[WARN]  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERROR] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg" -ForegroundColor Red; exit 1 }

# --- Validation ---
if (-not (Test-Path $Config)) { Write-Err "Config file not found: $Config" }
if ($Vault -ne "" -and -not (Test-Path $Vault)) { Write-Err "Vault file not found: $Vault" }
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Write-Err "Go is not installed or not in PATH. Install Go >= 1.26.1 from https://go.dev/dl/" }

# --- Confirmation ---
if (-not $Yes) {
    Write-Host ""
    Write-Host "=== PRODUCTION DEPLOYMENT (Windows) ===" -ForegroundColor Magenta
    Write-Host "  Target:  $ComputerName"
    Write-Host "  Config:  $Config"
    Write-Host "  Vault:   $(if ($Vault) { $Vault } else { '<not provided, using existing>' })"
    Write-Host ""
    $confirm = Read-Host "Proceed? [y/N]"
    if ($confirm -notmatch "^[Yy]$") { Write-Info "Aborted."; exit 0 }
}

# --- Locate project root (two levels up from scripts/) ---
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

# --- 1. Run tests ---
Write-Info "Running tests..."
Push-Location $ProjectDir
try {
    & go test -race ./internal/...
    if ($LASTEXITCODE -ne 0) { Write-Err "Tests failed. Aborting." }
} finally { Pop-Location }
Write-Info "All tests passed."

# --- 2. Build Windows release binary ---
$Version = (& git -C $ProjectDir describe --tags --always 2>$null) ?? "dev"
$BinaryPath = Join-Path $ProjectDir "bin\$BinaryName"
Write-Info "Building $BinaryName (version: $Version)..."

Push-Location $ProjectDir
try {
    $env:GOOS   = "windows"
    $env:GOARCH = "amd64"
    & go build -ldflags "-s -w -X main.version=$Version" -o $BinaryPath .\cmd\aikey-proxy
    if ($LASTEXITCODE -ne 0) { Write-Err "Build failed." }
} finally {
    Remove-Item Env:\GOOS   -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}
Write-Info "Binary built: $BinaryPath"

# --- Remote deployment block ---
$deployScript = {
    param(
        $BinaryContent,
        $ConfigContent,
        $VaultContent,
        $ServiceName,
        $InstallDir,
        $ConfigDir,
        $LogDir,
        $BackupDir,
        $BinaryName
    )

    function Write-Info { param($msg) Write-Host "[INFO]  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg" -ForegroundColor Cyan }
    function Write-Warn { param($msg) Write-Host "[WARN]  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg" -ForegroundColor Yellow }

    # Create directories.
    foreach ($dir in @($InstallDir, $ConfigDir, $LogDir, $BackupDir)) {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }

    # Backup existing binary and config (keep last 5).
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $existingBin    = Join-Path $InstallDir $BinaryName
    $existingConfig = Join-Path $ConfigDir "aikey-proxy.yaml"

    if (Test-Path $existingBin) {
        Copy-Item $existingBin (Join-Path $BackupDir "$BinaryName.$ts") -Force
        Write-Info "Backed up binary → $BackupDir\$BinaryName.$ts"
    }
    if (Test-Path $existingConfig) {
        Copy-Item $existingConfig (Join-Path $BackupDir "aikey-proxy.yaml.$ts") -Force
        Write-Info "Backed up config → $BackupDir\aikey-proxy.yaml.$ts"
    }

    # Prune old backups (keep 5).
    @("$BinaryName.*", "aikey-proxy.yaml.*") | ForEach-Object {
        Get-ChildItem (Join-Path $BackupDir $_) -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -Skip 5 |
            Remove-Item -Force
    }

    # Stop service before replacing binary.
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Info "Stopping service $ServiceName..."
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }

    # Install binary.
    [IO.File]::WriteAllBytes($existingBin, $BinaryContent)
    Write-Info "Binary installed: $existingBin"

    # Install config.
    [IO.File]::WriteAllBytes($existingConfig, $ConfigContent)
    Write-Info "Config installed: $existingConfig"

    # Install vault if provided.
    if ($VaultContent) {
        $vaultDest = Join-Path $ConfigDir "vault.db"
        [IO.File]::WriteAllBytes($vaultDest, $VaultContent)

        # Restrict ACL to LocalSystem + Administrators only.
        $acl = Get-Acl $vaultDest
        $acl.SetAccessRuleProtection($true, $false)
        $sysRule   = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "FullControl", "Allow")
        $acl.AddAccessRule($sysRule)
        $acl.AddAccessRule($adminRule)
        Set-Acl -Path $vaultDest -AclObject $acl
        Write-Info "Vault installed: $vaultDest"
    }

    # Create vault password env file if missing.
    $envFile = Join-Path $ConfigDir "env.ps1"
    if (-not (Test-Path $envFile)) {
        @'
# Set the vault password for aikey-proxy.
# This file is loaded by the service wrapper. Keep it protected.
$env:AIKEY_VAULT_PASSWORD = ""
'@ | Set-Content $envFile -Encoding UTF8
        Write-Warn "IMPORTANT: Set AIKEY_VAULT_PASSWORD in $envFile before starting the service."
    }

    # Create a service wrapper script (loads env then starts proxy).
    $wrapperPath = Join-Path $InstallDir "run.ps1"
    @"
# Auto-generated service wrapper for aikey-proxy.
if (Test-Path '$envFile') { . '$envFile' }
& '$existingBin' --config '$existingConfig'
"@ | Set-Content $wrapperPath -Encoding UTF8

    # Install or update Windows Service.
    $nssm = (Get-Command nssm -ErrorAction SilentlyContinue)?.Source

    if ($nssm) {
        # Preferred: NSSM (Apache License 2.0, https://nssm.cc)
        Write-Info "Installing service via NSSM..."
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) {
            & $nssm install $ServiceName (Get-Command powershell).Source `
                "-NoProfile -ExecutionPolicy Bypass -File `"$wrapperPath`""
        } else {
            & $nssm set $ServiceName Application (Get-Command powershell).Source
            & $nssm set $ServiceName AppParameters `
                "-NoProfile -ExecutionPolicy Bypass -File `"$wrapperPath`""
        }
        & $nssm set $ServiceName DisplayName "AiKey Proxy (Production)"
        & $nssm set $ServiceName Description "AiKey local proxy — virtual key to real key forwarding"
        & $nssm set $ServiceName Start SERVICE_AUTO_START
        & $nssm set $ServiceName AppStdout (Join-Path $LogDir "proxy.log")
        & $nssm set $ServiceName AppStderr (Join-Path $LogDir "error.log")
        & $nssm set $ServiceName AppRotateFiles 1
        & $nssm set $ServiceName AppRotateOnline 1
        & $nssm set $ServiceName AppRotateBytes 10485760
    } else {
        # Fallback: native sc.exe
        Write-Warn "NSSM not found. Using sc.exe (no log rotation). Recommend installing NSSM: https://nssm.cc"
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $pwshExe = (Get-Command powershell).Source
        $binPathQuoted = "`"$pwshExe`" -NoProfile -ExecutionPolicy Bypass -File `"$wrapperPath`""

        if (-not $svc) {
            & sc.exe create $ServiceName binPath= $binPathQuoted start= auto obj= "LocalSystem"
            & sc.exe description $ServiceName "AiKey local proxy — virtual key to real key forwarding"
        } else {
            & sc.exe config $ServiceName binPath= $binPathQuoted start= auto
        }
        & sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/10000/restart/30000
    }

    # Start or restart service.
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Info "Restarting $ServiceName..."
        Restart-Service -Name $ServiceName -Force
    } else {
        Write-Info "Starting $ServiceName..."
        Start-Service -Name $ServiceName
    }

    Start-Sleep -Seconds 2

    # Health check — parse port from config YAML.
    $configText = [IO.File]::ReadAllText($existingConfig)
    $portMatch  = [regex]::Match($configText, 'port:\s*(\d+)')
    $hostMatch  = [regex]::Match($configText, 'host:\s*"([^"]+)"')
    $port = if ($portMatch.Success) { $portMatch.Groups[1].Value } else { "27200" }
    $host = if ($hostMatch.Success) { $hostMatch.Groups[1].Value } else { "127.0.0.1" }

    try {
        $resp = Invoke-WebRequest -Uri "http://${host}:${port}/health" -UseBasicParsing -TimeoutSec 5
        if ($resp.StatusCode -eq 200) {
            Write-Info "Health check passed: http://${host}:${port}/health"
        } else {
            Write-Warn "Health check returned HTTP $($resp.StatusCode)"
        }
    } catch {
        Write-Warn "Health check failed! Check logs in $LogDir or run: Get-EventLog -LogName Application -Source aikey-proxy"
    }

    Write-Info "Windows deployment complete."
}

# --- 3. Read file bytes for transfer ---
$binaryBytes = [IO.File]::ReadAllBytes($BinaryPath)
$configBytes  = [IO.File]::ReadAllBytes($Config)
$vaultBytes   = if ($Vault) { [IO.File]::ReadAllBytes($Vault) } else { $null }

# --- 4. Execute (local or remote) ---
if ($ComputerName -eq "localhost" -or $ComputerName -eq $env:COMPUTERNAME) {
    Write-Info "Deploying locally on Windows..."
    & $deployScript $binaryBytes $configBytes $vaultBytes `
        $ServiceName $InstallDir $ConfigDir $LogDir $BackupDir $BinaryName
} else {
    Write-Info "Deploying to remote Windows host: $ComputerName..."
    $sessionParams = @{ ComputerName = $ComputerName }
    if ($Credential) { $sessionParams.Credential = $Credential }

    $session = New-PSSession @sessionParams
    try {
        Invoke-Command -Session $session -ScriptBlock $deployScript `
            -ArgumentList $binaryBytes, $configBytes, $vaultBytes, `
                $ServiceName, $InstallDir, $ConfigDir, $LogDir, $BackupDir, $BinaryName
    } finally {
        Remove-PSSession $session
    }
}

Write-Info "Production deployment finished successfully."
