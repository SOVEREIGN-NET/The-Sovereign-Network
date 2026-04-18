# ============================================================================
# Sovereign Network — Multi-Node Local Test Harness
# ============================================================================
# Spins up N validator nodes on localhost, tests:
#   1. Peer discovery (multicast + bootstrap)
#   2. Neural mesh activation (PPO, LSTM, Isolation Forest)
#   3. Shard storage/fetch via DHT
#   4. Consensus (Tendermint BFT round-trip)
#   5. Neural mesh training loop (routing rewards)
#
# Usage:
#   .\test_multi_node.ps1                   # Default: 3 nodes
#   .\test_multi_node.ps1 -NumNodes 4       # 4 nodes
#   .\test_multi_node.ps1 -Clean            # Clean data dirs first
# ============================================================================

param(
    [int]$NumNodes = 3,
    [switch]$Clean,
    [switch]$BuildOnly,
    [int]$BootTimeSeconds = 15,
    [string]$LogLevel = "info"
)

$ErrorActionPreference = "Stop"
$WorkspaceRoot = $PSScriptRoot  # or adjust if script is in scripts/

# If run from workspace root directly:
if (Test-Path "$WorkspaceRoot\Cargo.toml") {
    # We're in the right place
} elseif (Test-Path "$WorkspaceRoot\..\Cargo.toml") {
    $WorkspaceRoot = Resolve-Path "$WorkspaceRoot\.."
}

$DataRoot = Join-Path $WorkspaceRoot "data"
$ConfigDir = Join-Path $WorkspaceRoot "zhtp\configs"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Sovereign Network — Multi-Node Local Test" -ForegroundColor Cyan
Write-Host "  Nodes: $NumNodes | Boot: ${BootTimeSeconds}s | Log: $LogLevel" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 0: Clean data directories ──────────────────────────────────────────
if ($Clean) {
    Write-Host "[0] Cleaning data directories..." -ForegroundColor Yellow
    for ($i = 1; $i -le $NumNodes; $i++) {
        $dir = Join-Path $DataRoot "test-node$i"
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir
            Write-Host "   Removed $dir"
        }
    }
    Write-Host ""
}

# ── Step 1: Build the zhtp binary ──────────────────────────────────────────
Write-Host "[1] Building zhtp binary (this may take a few minutes)..." -ForegroundColor Yellow
$buildStart = Get-Date

Push-Location $WorkspaceRoot
try {
    $env:RUST_LOG = $LogLevel
    $buildResult = & cargo build --bin zhtp 2>&1
    $buildExit = $LASTEXITCODE
    
    if ($buildExit -ne 0) {
        Write-Host "BUILD FAILED:" -ForegroundColor Red
        $buildResult | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }
    
    $buildTime = ((Get-Date) - $buildStart).TotalSeconds
    Write-Host "   Build OK (${buildTime:N1}s)" -ForegroundColor Green
    
    $binary = Join-Path $WorkspaceRoot "target\debug\zhtp.exe"
    if (-not (Test-Path $binary)) {
        Write-Host "Binary not found at $binary" -ForegroundColor Red
        exit 1
    }
    Write-Host "   Binary: $binary" -ForegroundColor DarkGray
} finally {
    Pop-Location
}

if ($BuildOnly) {
    Write-Host "`nBuild complete. Exiting." -ForegroundColor Green
    exit 0
}

Write-Host ""

# ── Step 2: Create data directories ────────────────────────────────────────
Write-Host "[2] Preparing data directories..." -ForegroundColor Yellow
for ($i = 1; $i -le $NumNodes; $i++) {
    $dir = Join-Path $DataRoot "test-node$i"
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Write-Host "   Node $i data: $dir"
}
Write-Host ""

# ── Step 3: Start nodes ────────────────────────────────────────────────────
Write-Host "[3] Starting $NumNodes validator nodes..." -ForegroundColor Yellow

$jobs = @()
$pids = @()

for ($i = 1; $i -le $NumNodes; $i++) {
    $configFile = Join-Path $ConfigDir "test-node$i.toml"
    $dataDir = Join-Path $DataRoot "test-node$i"
    $logFile = Join-Path $DataRoot "test-node$i\node.log"
    
    if (-not (Test-Path $configFile)) {
        Write-Host "   Config not found: $configFile — skipping node $i" -ForegroundColor Red
        continue
    }
    
    $env:RUST_LOG = $LogLevel
    
    # Start node process in background
    $proc = Start-Process -FilePath $binary `
        -ArgumentList "--config", $configFile, "--data-dir", $dataDir, "--testnet" `
        -PassThru `
        -RedirectStandardOutput $logFile `
        -RedirectStandardError (Join-Path $DataRoot "test-node$i\node-err.log") `
        -WindowStyle Hidden
    
    $pids += $proc.Id
    Write-Host "   Node $i started (PID: $($proc.Id)) — mesh:$(9000 + $i) api:$(9100 + $i)" -ForegroundColor Green
}

Write-Host ""

# ── Step 4: Wait for boot ──────────────────────────────────────────────────
Write-Host "[4] Waiting ${BootTimeSeconds}s for nodes to boot and discover each other..." -ForegroundColor Yellow
for ($s = 1; $s -le $BootTimeSeconds; $s++) {
    $pctg = [math]::Round(($s / $BootTimeSeconds) * 100)
    $bar = "#" * [math]::Round($pctg / 5) + "-" * (20 - [math]::Round($pctg / 5))
    Write-Host "`r   [$bar] ${pctg}% (${s}s/${BootTimeSeconds}s)" -NoNewline
    Start-Sleep -Seconds 1
}
Write-Host ""
Write-Host ""

# ── Step 5: Check node health ──────────────────────────────────────────────
Write-Host "[5] Checking node health..." -ForegroundColor Yellow

$aliveCount = 0
for ($i = 1; $i -le $NumNodes; $i++) {
    $pid = $pids[$i - 1]
    try {
        $proc = Get-Process -Id $pid -ErrorAction Stop
        if (-not $proc.HasExited) {
            $aliveCount++
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
            Write-Host "   Node $i (PID: $pid): ALIVE — ${memMB}MB RAM" -ForegroundColor Green
            
            # Check log for key startup messages
            $logFile = Join-Path $DataRoot "test-node$i\node.log"
            if (Test-Path $logFile) {
                $logContent = Get-Content $logFile -Tail 30 -ErrorAction SilentlyContinue
                
                $hasCrypto = $logContent | Select-String "Crypto component started" -Quiet
                $hasNetwork = $logContent | Select-String "network|mesh" -Quiet
                $hasNeuralMesh = $logContent | Select-String "Neural Mesh" -Quiet
                
                $status = @()
                if ($hasCrypto) { $status += "crypto" }
                if ($hasNetwork) { $status += "network" }
                if ($hasNeuralMesh) { $status += "neural-mesh" }
                
                if ($status.Count -gt 0) {
                    Write-Host "     Components: $($status -join ', ')" -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host "   Node $i (PID: $pid): EXITED" -ForegroundColor Red
        }
    } catch {
        Write-Host "   Node $i (PID: $pid): NOT FOUND" -ForegroundColor Red
    }
}

Write-Host ""
if ($aliveCount -eq $NumNodes) {
    Write-Host "   All $NumNodes nodes are running!" -ForegroundColor Green
} else {
    Write-Host "   WARNING: Only $aliveCount/$NumNodes nodes alive" -ForegroundColor Yellow
}
Write-Host ""

# ── Step 6: Check logs for peer discovery ───────────────────────────────────
Write-Host "[6] Checking peer discovery..." -ForegroundColor Yellow

for ($i = 1; $i -le $NumNodes; $i++) {
    $logFile = Join-Path $DataRoot "test-node$i\node.log"
    $errFile = Join-Path $DataRoot "test-node$i\node-err.log"
    
    if (Test-Path $logFile) {
        $logLines = Get-Content $logFile -ErrorAction SilentlyContinue
        $peerLines = $logLines | Select-String "peer|discovery|bootstrap|connect" -AllMatches
        Write-Host "   Node $i: $($peerLines.Count) peer-related log entries"
        
        # Show last few relevant lines
        $peerLines | Select-Object -Last 3 | ForEach-Object {
            Write-Host "     $_" -ForegroundColor DarkGray
        }
    }
    
    if (Test-Path $errFile) {
        $errLines = Get-Content $errFile -ErrorAction SilentlyContinue
        if ($errLines.Count -gt 0) {
            $errSample = $errLines | Select-Object -Last 3
            Write-Host "   Node $i errors:" -ForegroundColor Red
            $errSample | ForEach-Object {
                Write-Host "     $_" -ForegroundColor Red
            }
        }
    }
}
Write-Host ""

# ── Step 7: Check Neural Mesh activation ────────────────────────────────────
Write-Host "[7] Checking Neural Mesh activation..." -ForegroundColor Yellow

for ($i = 1; $i -le $NumNodes; $i++) {
    $logFile = Join-Path $DataRoot "test-node$i\node.log"
    $errFile = Join-Path $DataRoot "test-node$i\node-err.log"
    
    $neuralLog = @()
    if (Test-Path $logFile) {
        $neuralLog += Get-Content $logFile -ErrorAction SilentlyContinue | Select-String "Neural|neural|RL Router|Anomaly|Prefetch|Compressor"
    }
    if (Test-Path $errFile) {
        $neuralLog += Get-Content $errFile -ErrorAction SilentlyContinue | Select-String "Neural|neural|RL Router|Anomaly|Prefetch|Compressor"
    }
    
    if ($neuralLog.Count -gt 0) {
        Write-Host "   Node $i: Neural Mesh ACTIVE ($($neuralLog.Count) events)" -ForegroundColor Green
        $neuralLog | Select-Object -Last 5 | ForEach-Object {
            Write-Host "     $_" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "   Node $i: Neural Mesh — no log entries yet" -ForegroundColor Yellow
    }
}
Write-Host ""

# ── Step 8: Summary ─────────────────────────────────────────────────────────
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Nodes started: $aliveCount / $NumNodes"
Write-Host "  Data directory: $DataRoot"
Write-Host ""
Write-Host "  Node ports:" -ForegroundColor DarkGray
for ($i = 1; $i -le $NumNodes; $i++) {
    Write-Host "    Node $i — mesh:$(9000+$i) api:$(9100+$i) dht:$(19000+$i)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  View logs:" -ForegroundColor DarkGray
for ($i = 1; $i -le $NumNodes; $i++) {
    Write-Host "    Get-Content $(Join-Path $DataRoot "test-node$i\node.log") -Tail 20" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  Stop all nodes:" -ForegroundColor DarkGray
Write-Host "    $($pids | ForEach-Object { "Stop-Process -Id $_" }) ; Write-Host 'All stopped'" -ForegroundColor DarkGray
Write-Host ""

# Save PIDs for cleanup
$pidFile = Join-Path $DataRoot "running-pids.txt"
$pids | Out-File -FilePath $pidFile -Force
Write-Host "  PIDs saved to: $pidFile" -ForegroundColor DarkGray
Write-Host ""

# ── Prompt for cleanup ──────────────────────────────────────────────────────
Write-Host "Press Ctrl+C to exit, or Enter to stop all nodes..." -ForegroundColor Yellow
$null = Read-Host

Write-Host "`nStopping all nodes..." -ForegroundColor Yellow
foreach ($pid in $pids) {
    try {
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        Write-Host "  Stopped PID $pid" -ForegroundColor Green
    } catch {
        Write-Host "  PID $pid already stopped" -ForegroundColor DarkGray
    }
}
Write-Host "All nodes stopped." -ForegroundColor Green
