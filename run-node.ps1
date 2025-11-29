# Sovereign Network ZHTP Node Runner
# PowerShell version for Windows

param(
    [string]$ConfigFile = "zhtp\configs\test-node1.toml"
)

Write-Host "🚀 Starting ZHTP Orchestrator Node..." -ForegroundColor Cyan
Write-Host "📋 Config: $ConfigFile" -ForegroundColor Yellow
Write-Host ""

if (-not (Test-Path "target\release\zhtp-orchestrator.exe")) {
    Write-Host "❌ Binary not found. Building first..." -ForegroundColor Red
    .\build.ps1
    if ($LASTEXITCODE -ne 0) {
        exit 1
    }
}

Write-Host "▶️  Launching node..." -ForegroundColor Green
& ".\target\release\zhtp-orchestrator.exe" --config $ConfigFile
