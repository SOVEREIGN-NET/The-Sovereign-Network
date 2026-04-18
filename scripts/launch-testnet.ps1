#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Launch a local 4-node Sovereign Network testnet with neural mesh enabled.

.DESCRIPTION
    Builds the zhtp node binary and starts 4 validator nodes locally.
    Each node uses a separate config (test-node1..4.toml), data directory,
    and port range. Node 1 is the bootstrap node.

    Neural mesh components (RL Router, Anomaly Sentry, Predictive Prefetcher,
    NeuroCompressor) are started automatically as part of the RuntimeOrchestrator.

    Ports:
      Node 1: mesh=9001, dht=19001, api=9101
      Node 2: mesh=9002, dht=19002, api=9102
      Node 3: mesh=9003, dht=19003, api=9103
      Node 4: mesh=9004, dht=19004, api=9104

.PARAMETER Nodes
    Number of nodes to start (1-4). Default: 4.

.PARAMETER Clean
    Remove data directories before starting. Default: true.

.PARAMETER Release
    Build in release mode. Default: false (debug mode for faster builds).

.PARAMETER LogLevel
    Log level for all nodes. Default: "info".

.EXAMPLE
    .\scripts\launch-testnet.ps1
    .\scripts\launch-testnet.ps1 -Nodes 2 -LogLevel debug
    .\scripts\launch-testnet.ps1 -Release -Clean
#>

param(
    [int]$Nodes = 4,
    [switch]$Clean = $true,
    [switch]$Release = $false,
    [string]$LogLevel = "info"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Sovereign Network — Local Testnet" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Nodes: $Nodes | Log: $LogLevel" -ForegroundColor Gray
Write-Host ""

# --- Build ---
Write-Host "[1/4] Building zhtp node binary..." -ForegroundColor Yellow
$buildArgs = @("build", "-p", "zhtp")
if ($Release) {
    $buildArgs += "--release"
    $binaryPath = Join-Path $projectRoot "target\release\zhtp.exe"
} else {
    $binaryPath = Join-Path $projectRoot "target\debug\zhtp.exe"
}

Push-Location $projectRoot
try {
    & cargo @buildArgs 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BUILD FAILED" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $binaryPath)) {
    Write-Host "ERROR: Binary not found at $binaryPath" -ForegroundColor Red
    exit 1
}
Write-Host "  Binary: $binaryPath" -ForegroundColor Green

# --- Clean data directories ---
if ($Clean) {
    Write-Host "[2/4] Cleaning data directories..." -ForegroundColor Yellow
    for ($i = 1; $i -le $Nodes; $i++) {
        $dataDir = Join-Path $projectRoot "data\test-node$i"
        if (Test-Path $dataDir) {
            Remove-Item -Recurse -Force $dataDir
            Write-Host "  Removed $dataDir" -ForegroundColor DarkGray
        }
    }
}

# --- Start nodes ---
Write-Host "[3/4] Starting $Nodes nodes..." -ForegroundColor Yellow
$jobs = @()
$pids = @()

for ($i = 1; $i -le $Nodes; $i++) {
    $configPath = Join-Path $projectRoot "zhtp\configs\test-node$i.toml"
    $dataDir = Join-Path $projectRoot "data\test-node$i"

    if (-not (Test-Path $configPath)) {
        Write-Host "  WARNING: Config not found: $configPath" -ForegroundColor Red
        continue
    }

    # Ensure data directory exists
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

    $meshPort = 9000 + $i
    $apiPort = 9100 + $i

    Write-Host "  Node $i: mesh=$meshPort api=$apiPort config=$configPath" -ForegroundColor Cyan

    $env:RUST_LOG = $LogLevel
    $nodeArgs = @(
        "--config", $configPath,
        "--data-dir", $dataDir,
        "--mesh-port", $meshPort
    )

    # Start node as background process
    $process = Start-Process -FilePath $binaryPath `
        -ArgumentList $nodeArgs `
        -WorkingDirectory $projectRoot `
        -PassThru `
        -RedirectStandardOutput (Join-Path $dataDir "stdout.log") `
        -RedirectStandardError (Join-Path $dataDir "stderr.log") `
        -WindowStyle Hidden

    $pids += $process.Id
    Write-Host "    PID: $($process.Id)" -ForegroundColor DarkGray

    # Stagger startup: bootstrap node first, then others after a brief delay
    if ($i -eq 1) {
        Write-Host "  Waiting 3s for bootstrap node to initialize..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 3
    } else {
        Start-Sleep -Milliseconds 500
    }
}

# --- Status check ---
Write-Host ""
Write-Host "[4/4] Checking node health..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

$running = 0
for ($idx = 0; $idx -lt $pids.Count; $idx++) {
    $pid = $pids[$idx]
    $nodeNum = $idx + 1
    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
    if ($proc -and -not $proc.HasExited) {
        Write-Host "  Node $nodeNum (PID $pid): RUNNING" -ForegroundColor Green
        $running++
    } else {
        Write-Host "  Node $nodeNum (PID $pid): STOPPED" -ForegroundColor Red
        $stderrLog = Join-Path $projectRoot "data\test-node$nodeNum\stderr.log"
        if (Test-Path $stderrLog) {
            Write-Host "  Last 5 lines of stderr:" -ForegroundColor DarkGray
            Get-Content $stderrLog -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        }
    }
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  $running / $Nodes nodes running" -ForegroundColor $(if ($running -eq $Nodes) { "Green" } else { "Yellow" })
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Logs: data\test-node{1..$Nodes}\{stdout,stderr}.log" -ForegroundColor Gray
Write-Host ""
Write-Host "  API endpoints:" -ForegroundColor Gray
for ($i = 1; $i -le $Nodes; $i++) {
    Write-Host "    Node $i: http://127.0.0.1:$(9100 + $i)/health" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  Stop all: .\scripts\stop-testnet.ps1" -ForegroundColor Gray
Write-Host "  Or: Get-Process -Name zhtp | Stop-Process" -ForegroundColor Gray
Write-Host ""

# Save PIDs for stop script
$pidFile = Join-Path $projectRoot "data\testnet-pids.txt"
$pids | Out-File -FilePath $pidFile -Force
Write-Host "  PIDs saved to $pidFile" -ForegroundColor DarkGray
