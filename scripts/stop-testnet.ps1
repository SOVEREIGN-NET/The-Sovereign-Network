#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Stop all running Sovereign Network testnet nodes.

.DESCRIPTION
    Reads PIDs from data\testnet-pids.txt and gracefully stops them.
    Falls back to stopping any process named "zhtp".
#>

$ErrorActionPreference = "SilentlyContinue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$pidFile = Join-Path $projectRoot "data\testnet-pids.txt"

Write-Host ""
Write-Host "Stopping Sovereign Network testnet..." -ForegroundColor Yellow

$stopped = 0

if (Test-Path $pidFile) {
    $pids = Get-Content $pidFile | Where-Object { $_ -match '^\d+$' }
    foreach ($pid in $pids) {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $pid -Force
            Write-Host "  Stopped PID $pid" -ForegroundColor Green
            $stopped++
        }
    }
    Remove-Item $pidFile -Force
} else {
    # Fallback: kill any zhtp processes
    $procs = Get-Process -Name "zhtp" -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | ForEach-Object {
            Stop-Process -Id $_.Id -Force
            Write-Host "  Stopped PID $($_.Id)" -ForegroundColor Green
            $stopped++
        }
    }
}

if ($stopped -eq 0) {
    Write-Host "  No running testnet nodes found." -ForegroundColor Gray
} else {
    Write-Host "  $stopped node(s) stopped." -ForegroundColor Green
}
Write-Host ""
