# Sovereign Network Mono-Repo Build Script
# PowerShell version for Windows

Write-Host "🔨 Building Sovereign Network Mono-Repo..." -ForegroundColor Cyan

# Check for Rust installation
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Cargo not found. Please install Rust from https://rustup.rs/" -ForegroundColor Red
    exit 1
}

Write-Host "📦 Building all workspace crates..." -ForegroundColor Yellow
cargo build --release --workspace

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Build complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Binary location: target\release\zhtp-orchestrator.exe" -ForegroundColor White
    Write-Host ""
    Write-Host "To run a node:" -ForegroundColor Cyan
    Write-Host "  .\run-node.ps1" -ForegroundColor White
    Write-Host "  or" -ForegroundColor White
    Write-Host "  .\target\release\zhtp-orchestrator.exe --config crates\zhtp\configs\test-node1.toml" -ForegroundColor White
} else {
    Write-Host "`n❌ Build failed!" -ForegroundColor Red
    exit 1
}
