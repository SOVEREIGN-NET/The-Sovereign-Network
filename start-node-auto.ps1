# Auto-start ZHTP node with automated wallet setup
param(
    [Parameter(Mandatory=$true)]
    [string]$ConfigFile
)

$nodeExe = "H:\SOV-NET\sovereign-mono-repo\target\release\zhtp.exe"

# Create process start info
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $nodeExe
$psi.Arguments = "node start --config `"$ConfigFile`""
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $false

# Start the process
$process = [System.Diagnostics.Process]::Start($psi)

# Wait a moment for the prompt to appear
Start-Sleep -Seconds 3

# Send "4" for quick start option
$process.StandardInput.WriteLine("4")
$process.StandardInput.Flush()

Write-Host "Started ZHTP node with config: $ConfigFile"
Write-Host "Process ID: $($process.Id)"
Write-Host "Sent quick start option (4)"

# Keep outputting stdout
while (!$process.HasExited) {
    $line = $process.StandardOutput.ReadLine()
    if ($line) {
        Write-Host $line
    }
}
