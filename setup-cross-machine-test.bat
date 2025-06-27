@echo off
REM ZHTP Cross-Machine Test Setup Script
REM Run this on both machines to prepare for testing

echo.
echo 🚀 ZHTP Cross-Machine Test Setup
echo ================================
echo.

REM Check if we're in the right directory
if not exist "Cargo.toml" (
    echo ❌ Error: Please run this script from the ZHTP directory
    echo Current directory: %CD%
    echo Expected files: Cargo.toml, src\main.rs
    pause
    exit /b 1
)

echo ✅ Found ZHTP project files
echo.

REM Check Rust installation
echo 🔍 Checking Rust installation...
cargo --version > nul 2>&1
if errorlevel 1 (
    echo ❌ Rust not found. Please install Rust from https://rustup.rs/
    pause
    exit /b 1
)
echo ✅ Rust is installed

REM Get system info
echo.
echo 📊 System Information:
echo Computer Name: %COMPUTERNAME%
echo User: %USERNAME%
echo Current Directory: %CD%
echo.

REM Build the project
echo 🔨 Building ZHTP (this may take a few minutes)...
cargo build --release
if errorlevel 1 (
    echo ❌ Build failed. Please check the error messages above.
    pause
    exit /b 1
)
echo ✅ Build completed successfully

REM Check network connectivity
echo.
echo 🌐 Network Configuration:
ipconfig | findstr "IPv4"
echo.

REM Create test directory
if not exist "test-results" mkdir test-results

REM Generate machine-specific identifier
echo %COMPUTERNAME%-%USERNAME%-%DATE%-%TIME% > test-results\machine-id.txt

echo.
echo 🎯 Setup Complete! Next Steps:
echo.
echo 1. Run this script on the second machine
echo 2. On Machine A (Primary): run-zhtp.bat
echo 3. Wait for "HTTP API Server listening on port 8000"
echo 4. On Machine B (Secondary): run-zhtp.bat  
echo 5. Wait for "Bootstrap connections completed"
echo 6. Open browsers on both machines: http://localhost:8000/
echo 7. Follow the Cross-Machine Testing Guide
echo.
echo Machine ID: 
type test-results\machine-id.txt
echo.
echo Press any key to continue...
pause > nul

REM Optional: Open the testing guide
echo.
echo 📖 Would you like to open the testing guide? (y/n)
set /p openguide=
if /i "%openguide%"=="y" (
    start notepad CROSS_MACHINE_TESTING_GUIDE.md
)

echo.
echo 🚀 Ready for cross-machine testing!
echo Run 'run-zhtp.bat' to start your ZHTP node
echo.
