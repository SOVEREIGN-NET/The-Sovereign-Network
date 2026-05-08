# AUTH-1877 Demo - fully self-contained, run from anywhere
# Auto-installs Rust if not present, then builds and runs the demo.
# Usage:  .\run.ps1   (from this folder or the repo root)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot  = (Resolve-Path "$ScriptDir\..\..").Path
$DemoDir   = $ScriptDir
$NodeUrl   = "http://localhost:9334"
$DataDir   = Join-Path $DemoDir "data"
$NodeProc  = $null

Set-Location $RepoRoot

function Cleanup {
    Write-Host ""
    Write-Host "--- Shutting down demo node ---"
    if ($null -ne $NodeProc -and -not $NodeProc.HasExited) {
        $NodeProc.Kill()
        $NodeProc.WaitForExit(5000) | Out-Null
    }
    if (Test-Path $DataDir) {
        Remove-Item -Recurse -Force $DataDir
    }
    Write-Host "Done."
}

try {

    Write-Host ""
    Write-Host "================================================"
    Write-Host "  AUTH-1877 End-to-End Demo"
    Write-Host "  Mobile + Web Auth Delegation"
    Write-Host "================================================"
    Write-Host ""

    # ------------------------------------------------------------------
    # DEP: Rust / cargo
    # ------------------------------------------------------------------
    Write-Host "[DEP] Checking Rust toolchain..." -ForegroundColor Yellow

    $CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (Test-Path $CargoBin) {
        $env:PATH = $CargoBin + ";" + $env:PATH
    }

    $CargoCmd = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $CargoCmd) {
        Write-Host "      cargo not found - downloading rustup installer..." -ForegroundColor Yellow

        $RustupExe = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $RustupExe

        Write-Host "      Installing Rust (stable, no interaction)..." -ForegroundColor Yellow
        & $RustupExe -y --default-toolchain stable --profile minimal 2>&1 | Out-Null

        $MachinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
        $UserPath    = [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $env:PATH    = $UserPath + ";" + $MachinePath

        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
            Write-Error "Rust installed but cargo still not found. Open a new terminal and re-run."
        }
        Write-Host "      Rust installed." -ForegroundColor Green
    }
    else {
        $ver = (cargo --version 2>&1)
        Write-Host "      Found: $ver" -ForegroundColor Green
    }
    Write-Host ""

    # ------------------------------------------------------------------
    # 1/4  Build
    # ------------------------------------------------------------------
    Write-Host "[1/4] Building zhtp node and demo example..." -ForegroundColor Yellow
    Write-Host "      (first build ~5 min; incremental after that)"

    # Run cargo directly - let output go to console.
    # $ErrorActionPreference does not apply to native exit codes;
    # we check the exit code manually instead.
    $ErrorActionPreference = "Continue"
    cargo build --release -p zhtp
    $buildExit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"

    $NodeBin = Join-Path $RepoRoot "target\release\zhtp.exe"
    if ($buildExit -ne 0 -or -not (Test-Path $NodeBin)) {
        Write-Error "Build failed - see output above."
    }
    Write-Host "      Build complete." -ForegroundColor Green
    Write-Host ""

    # ------------------------------------------------------------------
    # 2/4  Start node
    # ------------------------------------------------------------------
    Write-Host "[2/4] Starting demo node  (chain: auth-demo  port: 9334)..." -ForegroundColor Yellow

    # Kill any lingering node process holding port 9334 or the sled lock
    Get-Process zhtp -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill(); $_.WaitForExit(3000) }
    $sledPath = Join-Path $RepoRoot "data\dev\sled"
    if (Test-Path $sledPath) { Remove-Item -Recurse -Force $sledPath }

    if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir }
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

    $LogFile = Join-Path $DemoDir "node.log"
    $ErrFile = Join-Path $DemoDir "node.err"

    $NodeProc = Start-Process `
        -FilePath $NodeBin `
        -ArgumentList ("--config `"" + $DemoDir + "\node.toml`""), ("--data-dir `"" + $DataDir + "`"") `
        -RedirectStandardOutput $LogFile `
        -RedirectStandardError  $ErrFile `
        -PassThru -NoNewWindow

    Write-Host "      PID $($NodeProc.Id)   logs: demos\auth-1877\node.log"
    Write-Host ""

    # ------------------------------------------------------------------
    # 3/4  Wait for node startup. The node serves QUIC-only on UDP 9334;
    # there is no HTTP listener to probe, so wait a fixed window then
    # confirm UDP:9334 is bound.
    # ------------------------------------------------------------------
    Write-Host "[3/4] Waiting for node startup (60s fixed; QUIC binds asynchronously)..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 60; $i++) {
        if ($NodeProc.HasExited) {
            $tail = ""
            if (Test-Path $LogFile) { $tail = (Get-Content $LogFile -Tail 25) -join "`n" }
            Write-Error ("Node exited unexpectedly (exit code " + $NodeProc.ExitCode + ").`nLast log:`n" + $tail)
        }
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 1
    }
    Write-Host ""
    $udpBound = (netstat -ano | Select-String ":9334\s" | Select-String "UDP").Count -gt 0
    if (-not $udpBound) {
        $tail = ""
        if (Test-Path $LogFile) { $tail = (Get-Content $LogFile -Tail 25) -join "`n" }
        Write-Error ("Node did not bind UDP:9334 within 60s.`nLast log:`n" + $tail)
    }
    Write-Host "      Node ready (UDP:9334 bound)." -ForegroundColor Green
    Write-Host ""

    # ------------------------------------------------------------------
    # 4/4  CLI demo - QUIC client + native ZHTP framing + real Dilithium5
    # ------------------------------------------------------------------
    Write-Host "[4/4] Running CLI demo (real Dilithium5 keys, QUIC + native ZHTP)..." -ForegroundColor Yellow
    Write-Host ""
    $env:NODE_ADDR = "127.0.0.1:9334"
    $env:NODE_URL  = $NodeUrl
    $DemoBin = Join-Path $RepoRoot "target\release\examples\mobile_auth_demo.exe"
    if (-not (Test-Path $DemoBin)) {
        $ErrorActionPreference = "Continue"
        cargo build --release --example mobile_auth_demo --package zhtp
        $ErrorActionPreference = "Stop"
    }
    $ErrorActionPreference = "Continue"
    & $DemoBin
    $runExit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($runExit -ne 0) {
        Write-Error "CLI demo failed - see output above."
    }
    Write-Host ""

    Write-Host "Node is running. Press Ctrl+C to stop and clean up."
    Write-Host ""
    $NodeProc.WaitForExit()

}
finally {
    Cleanup
}
