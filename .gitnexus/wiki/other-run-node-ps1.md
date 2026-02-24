# Other — run-node.ps1

# Documentation for the `run-node.ps1` Module

## Overview

The `run-node.ps1` module is a PowerShell script designed to facilitate the execution of the ZHTP (Zero-Hour Transaction Protocol) Orchestrator Node on Windows systems. This script automates the process of checking for the necessary binary, building it if it is not present, and then launching the node with a specified configuration file.

## Purpose

The primary purpose of this script is to streamline the setup and execution of the ZHTP node, ensuring that developers and operators can easily start the node without manually handling the build process or configuration details.

## Key Components

### Parameters

- **`$ConfigFile`**: This parameter specifies the path to the configuration file for the ZHTP node. By default, it points to `zhtp\configs\test-node1.toml`. Users can override this parameter by providing a different path when executing the script.

### Execution Flow

1. **Initialization**: The script begins by outputting a message indicating that the ZHTP Orchestrator Node is starting, along with the path to the configuration file.
   
2. **Binary Check**: 
   - The script checks for the existence of the ZHTP executable at `target\release\zhtp.exe`.
   - If the binary is not found, it triggers the build process by executing `build.ps1`.
   - If the build fails (indicated by a non-zero exit code), the script exits with an error.

3. **Node Launch**: If the binary is present (or successfully built), the script launches the ZHTP node using the specified configuration file.

### Code Snippet

Here is a simplified version of the script's logic:

```powershell
param(
    [string]$ConfigFile = "zhtp\configs\test-node1.toml"
)

Write-Host "🚀 Starting ZHTP Orchestrator Node..." -ForegroundColor Cyan
Write-Host "📋 Config: $ConfigFile" -ForegroundColor Yellow

if (-not (Test-Path "target\release\zhtp.exe")) {
    Write-Host "❌ Binary not found. Building first..." -ForegroundColor Red
    .\build.ps1
    if ($LASTEXITCODE -ne 0) {
        exit 1
    }
}

Write-Host "▶️  Launching node..." -ForegroundColor Green
& ".\target\release\zhtp.exe" --config $ConfigFile
```

## How It Connects to the Codebase

The `run-node.ps1` script is a standalone module that interacts with the build system and the ZHTP node executable. It relies on the `build.ps1` script to compile the ZHTP binary if it is not already available. The successful execution of this script is crucial for developers who are working on the ZHTP project, as it ensures that they can quickly start the node for testing or development purposes.

### Dependencies

- **`build.ps1`**: This script is responsible for building the ZHTP executable. It must be present in the same directory as `run-node.ps1` for the build process to function correctly.
- **`zhtp.exe`**: The main executable for the ZHTP node, which is launched by this script.

## Conclusion

The `run-node.ps1` module is an essential tool for developers working with the ZHTP project. By automating the build and launch process, it simplifies the workflow and reduces the potential for errors. Understanding this script is crucial for anyone looking to contribute to the ZHTP codebase or run the node for testing purposes. 

For further contributions, developers should ensure that they maintain the integrity of the build process and the configuration management as outlined in this documentation.