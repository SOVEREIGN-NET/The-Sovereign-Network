@echo off
REM ZHTP Node Quick Start Script for Windows
REM Helps users quickly deploy different types of ZHTP nodes

echo 🚀 ZHTP Node Quick Start
echo ========================
echo.

REM Check if zhtp binary exists
set ZHTP_BIN=zhtp.exe
if exist ".\target\release\zhtp.exe" set ZHTP_BIN=.\target\release\zhtp.exe
if exist ".\target\debug\zhtp.exe" set ZHTP_BIN=.\target\debug\zhtp.exe

where %ZHTP_BIN% >nul 2>nul
if errorlevel 1 (
    if not exist "%ZHTP_BIN%" (
        echo ❌ ZHTP binary not found. Please build the project first:
        echo    cargo build --release
        pause
        exit /b 1
    )
)

echo Available Node Types:
echo 1^) Full Node      - Complete blockchain functionality
echo 2^) Validator Node - Consensus participation ^(requires staking^)
echo 3^) Storage Node   - Distributed storage services
echo 4^) Edge Node      - Mesh networking and ISP bypass
echo 5^) Dev Node       - Development and testing
echo.

set /p choice="Select node type (1-5): "

if "%choice%"=="1" (
    set NODE_TYPE=full
    echo 🖥️ Starting Full Node...
    echo This node will run all ZHTP components and provide complete blockchain functionality.
) else if "%choice%"=="2" (
    set NODE_TYPE=validator
    echo ⚡ Starting Validator Node...
    echo ⚠️  WARNING: Validator nodes require staking ZHTP tokens and high uptime!
    echo Make sure you have:
    echo - At least 10,000 ZHTP tokens for staking
    echo - Stable internet connection
    echo - Dedicated server hardware
    set /p confirm="Continue? (y/N): "
    if /i not "%confirm%"=="y" (
        echo Aborted.
        pause
        exit /b 0
    )
) else if "%choice%"=="3" (
    set NODE_TYPE=storage
    echo 💾 Starting Storage Node...
    echo This node will provide distributed storage services to the network.
    echo Make sure you have sufficient disk space ^(1TB+ recommended^).
) else if "%choice%"=="4" (
    set NODE_TYPE=edge
    echo 🌐 Starting Edge Node...
    echo This node will run in pure mesh mode for ISP bypass.
    echo ⚠️  This mode requires mesh hardware ^(Bluetooth, WiFi Direct, or LoRaWAN^).
) else if "%choice%"=="5" (
    set NODE_TYPE=dev
    echo 🛠️ Starting Development Node...
    echo This node uses relaxed security settings for development and testing.
) else (
    echo Invalid choice. Exiting.
    pause
    exit /b 1
)

echo.
echo Starting ZHTP Node...
echo Configuration: .\configs\%NODE_TYPE%-node.toml
echo Press Ctrl+C to stop the node
echo.

REM Start the node
%ZHTP_BIN% --node-type %NODE_TYPE%
pause