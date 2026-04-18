#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Check the status of running Sovereign Network testnet nodes.

.DESCRIPTION
    Shows process status, log tails, and attempts to query API health endpoints.
#>

$ErrorActionPreference = "SilentlyContinue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$pidFile = Join-Path $projectRoot "data\testnet-pids.txt"

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Sovereign Network — Testnet Status" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check PIDs
if (Test-Path $pidFile) {
    $pids = Get-Content $pidFile | Where-Object { $_ -match '^\d+$' }
    $nodeNum = 0
    foreach ($pid in $pids) {
        $nodeNum++
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc -and -not $proc.HasExited) {
            $mem = [math]::Round($proc.WorkingSet64 / 1MB, 1)
            $cpu = $proc.CPU
            Write-Host "  Node $nodeNum (PID $pid): RUNNING  |  Memory: ${mem}MB  |  CPU: ${cpu}s" -ForegroundColor Green
        } else {
            Write-Host "  Node $nodeNum (PID $pid): STOPPED" -ForegroundColor Red
        }

        # Show last 3 lines of stderr
        $stderrLog = Join-Path $projectRoot "data\test-node$nodeNum\stderr.log"
        if (Test-Path $stderrLog) {
            $lines = Get-Content $stderrLog -Tail 3
            if ($lines) {
                $lines | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            }
        }
        Write-Host ""
    }
} else {
    Write-Host "  No testnet-pids.txt found. Run launch-testnet.ps1 first." -ForegroundColor Yellow
}

# Try API health endpoints
Write-Host "  API Health Checks:" -ForegroundColor Yellow
for ($i = 1; $i -le 4; $i++) {
    $url = "http://127.0.0.1:$(9100 + $i)/health"
    try {
        $response = Invoke-WebRequest -Uri $url -TimeoutSec 2 -UseBasicParsing
        Write-Host "    Node $i ($url): $($response.StatusCode) OK" -ForegroundColor Green
    } catch {
        Write-Host "    Node $i ($url): unreachable" -ForegroundColor Red
    }
}

Write-Host ""
