# Interactive ZHTP node launcher that leaves menu input to the user
param(
    [string]$ConfigFile = "zhtp\configs\test-node1.toml",
    [switch]$Dev,
    [switch]$PureMesh,
    [switch]$EdgeMode,
    [int]$EdgeMaxHeaders = 500
)

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$zhtpExe = Join-Path $repoRoot "target\release\zhtp.exe"

if (-not (Test-Path $zhtpExe)) {
    Write-Host "Binary target\\release\\zhtp.exe not found. Building release binary first..." -ForegroundColor Yellow
    & (Join-Path $repoRoot "build.ps1")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed; cannot start node." -ForegroundColor Red
        exit 1
    }
}

$arguments = @("node", "start")
if ($ConfigFile) {
    $arguments += @("--config", $ConfigFile)
}
if ($Dev) {
    $arguments += "--dev"
}
if ($PureMesh) {
    $arguments += "--pure-mesh"
}
if ($EdgeMode) {
    $arguments += @("--edge-mode", "--edge-max-headers", $EdgeMaxHeaders)
}

Write-Host "Starting ZHTP node interactively..." -ForegroundColor Cyan
Write-Host "When the DID setup menu appears, type '4' to use the quick-start wallet path." -ForegroundColor Green
Write-Host "---" -ForegroundColor DarkGray

& $zhtpExe @arguments
