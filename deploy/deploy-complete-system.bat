@echo off
REM ZHTP Complete System Deployment and Testing Script (Windows)
REM This script orchestrates the full deployment and testing of the ZHTP blockchain internet system

setlocal enabledelayedexpansion

echo ==============================================
echo ZHTP Blockchain Internet System Deployment
echo ==============================================
echo Starting complete system deployment and testing...

REM Configuration
set DEPLOYMENT_DIR=%~dp0
set PROJECT_ROOT=%DEPLOYMENT_DIR%..
set COMPOSE_FILE=%DEPLOYMENT_DIR%docker-compose.full-test.yml
set LOG_FILE=%DEPLOYMENT_DIR%deployment-%date:~-4,4%%date:~-10,2%%date:~-7,2%-%time:~0,2%%time:~3,2%%time:~6,2%.log

REM Create necessary directories
mkdir "%DEPLOYMENT_DIR%data" 2>nul
mkdir "%DEPLOYMENT_DIR%logs" 2>nul
mkdir "%DEPLOYMENT_DIR%monitoring\grafana" 2>nul

REM Logging function
set LOG_CMD=echo [%date% %time%] 

REM Function to check prerequisites
:check_prerequisites
%LOG_CMD% Checking prerequisites... >> "%LOG_FILE%"

REM Check Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    %LOG_CMD% ❌ Docker is not installed >> "%LOG_FILE%"
    echo ❌ Docker is not installed
    exit /b 1
)

REM Check Docker Compose
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    %LOG_CMD% ❌ Docker Compose is not installed >> "%LOG_FILE%"
    echo ❌ Docker Compose is not installed
    exit /b 1
)

REM Check if Docker daemon is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    %LOG_CMD% ❌ Docker daemon is not running >> "%LOG_FILE%"
    echo ❌ Docker daemon is not running
    exit /b 1
)

%LOG_CMD% ✅ Prerequisites check passed >> "%LOG_FILE%"
echo ✅ Prerequisites check passed
goto :eof

REM Function to build images
:build_images
%LOG_CMD% Building ZHTP Docker images... >> "%LOG_FILE%"
echo Building ZHTP Docker images...

cd /d "%PROJECT_ROOT%"

REM Build main ZHTP image
%LOG_CMD% Building main ZHTP image... >> "%LOG_FILE%"
echo Building main ZHTP image...
docker build -f deploy\Dockerfile -t zhtp:latest . >> "%LOG_FILE%" 2>&1
if %errorlevel% neq 0 (
    %LOG_CMD% ❌ Failed to build main ZHTP image >> "%LOG_FILE%"
    echo ❌ Failed to build main ZHTP image
    exit /b 1
)

REM Build test image
%LOG_CMD% Building ZHTP test image... >> "%LOG_FILE%"
echo Building ZHTP test image...
docker build -f deploy\Dockerfile.test -t zhtp-test:latest . >> "%LOG_FILE%" 2>&1
if %errorlevel% neq 0 (
    %LOG_CMD% ❌ Failed to build ZHTP test image >> "%LOG_FILE%"
    echo ❌ Failed to build ZHTP test image
    exit /b 1
)

%LOG_CMD% ✅ Docker images built successfully >> "%LOG_FILE%"
echo ✅ Docker images built successfully
goto :eof

REM Function to deploy infrastructure
:deploy_infrastructure
%LOG_CMD% Deploying ZHTP infrastructure... >> "%LOG_FILE%"
echo Deploying ZHTP infrastructure...

cd /d "%DEPLOYMENT_DIR%"

REM Start ceremony and validator infrastructure
%LOG_CMD% Starting ceremony infrastructure... >> "%LOG_FILE%"
echo Starting ceremony infrastructure...
docker-compose -f "%COMPOSE_FILE%" up -d zhtp-ceremony-coordinator zhtp-ceremony-participant-1 zhtp-ceremony-participant-2 zhtp-ceremony-participant-3 >> "%LOG_FILE%" 2>&1

REM Wait for ceremony to be ready
%LOG_CMD% Waiting for ceremony infrastructure... >> "%LOG_FILE%"
echo Waiting for ceremony infrastructure...
timeout /t 60 /nobreak >nul

REM Start validator nodes
%LOG_CMD% Starting validator nodes... >> "%LOG_FILE%"
echo Starting validator nodes...
docker-compose -f "%COMPOSE_FILE%" up -d zhtp-validator-primary zhtp-validator-secondary >> "%LOG_FILE%" 2>&1

REM Wait for validators
%LOG_CMD% Waiting for validators... >> "%LOG_FILE%"
echo Waiting for validators...
timeout /t 45 /nobreak >nul

REM Start remaining infrastructure
%LOG_CMD% Starting remaining infrastructure... >> "%LOG_FILE%"
echo Starting remaining infrastructure...
docker-compose -f "%COMPOSE_FILE%" up -d zhtp-storage-node zhtp-full-node >> "%LOG_FILE%" 2>&1

REM Start monitoring
%LOG_CMD% Starting monitoring infrastructure... >> "%LOG_FILE%"
echo Starting monitoring infrastructure...
docker-compose -f "%COMPOSE_FILE%" up -d zhtp-monitor zhtp-metrics zhtp-logs >> "%LOG_FILE%" 2>&1

%LOG_CMD% ✅ Infrastructure deployed successfully >> "%LOG_FILE%"
echo ✅ Infrastructure deployed successfully
goto :eof

REM Function to wait for system readiness
:wait_for_system_ready
%LOG_CMD% Waiting for system to be fully operational... >> "%LOG_FILE%"
echo Waiting for system to be fully operational...

set /a attempts=0
set /a max_attempts=120

:readiness_loop
set /a attempts+=1
%LOG_CMD% System readiness check attempt %attempts%/%max_attempts%... >> "%LOG_FILE%"
echo System readiness check attempt %attempts%/%max_attempts%...

REM Check if services are running (simplified check)
docker-compose -f "%COMPOSE_FILE%" ps --services --filter "status=running" > temp_services.txt 2>nul
if exist temp_services.txt (
    for /f %%i in ('type temp_services.txt ^| find /c /v ""') do set healthy_services=%%i
    del temp_services.txt
) else (
    set healthy_services=0
)

if %healthy_services% geq 8 (
    %LOG_CMD% ✅ System appears ready (%healthy_services% services running) >> "%LOG_FILE%"
    echo ✅ System appears ready (%healthy_services% services running)
    goto :eof
)

%LOG_CMD% System not ready yet (%healthy_services% services running) >> "%LOG_FILE%"
echo System not ready yet (%healthy_services% services running)

if %attempts% lss %max_attempts% (
    timeout /t 15 /nobreak >nul
    goto readiness_loop
)

%LOG_CMD% ❌ System did not become ready within timeout >> "%LOG_FILE%"
echo ❌ System did not become ready within timeout
exit /b 1

REM Function to run system tests
:run_system_tests
%LOG_CMD% Running comprehensive system tests... >> "%LOG_FILE%"
echo Running comprehensive system tests...

cd /d "%DEPLOYMENT_DIR%"

REM Run the complete test suite
docker-compose -f "%COMPOSE_FILE%" --profile test run --rm zhtp-test-runner >> "%LOG_FILE%" 2>&1
if %errorlevel% neq 0 (
    %LOG_CMD% ❌ System tests failed >> "%LOG_FILE%"
    echo ❌ System tests failed
    exit /b 1
)

%LOG_CMD% ✅ System tests completed successfully >> "%LOG_FILE%"
echo ✅ System tests completed successfully
goto :eof

REM Function to display system status
:show_system_status
%LOG_CMD% System Status Dashboard: >> "%LOG_FILE%"
echo System Status Dashboard:
echo =========================

REM Show running containers
%LOG_CMD% Running Services: >> "%LOG_FILE%"
echo Running Services:
docker-compose -f "%COMPOSE_FILE%" ps

echo.
%LOG_CMD% Service URLs: >> "%LOG_FILE%"
echo Service URLs:
echo - Ceremony Coordinator: http://localhost:8080
echo - Primary Validator: http://localhost:8090
echo - Secondary Validator: http://localhost:8091
echo - Storage Node: http://localhost:8092
echo - Full Node: http://localhost:8093
echo - Monitoring Dashboard: http://localhost:3000 (admin/zhtp123)
echo - Metrics: http://localhost:9090
echo.

%LOG_CMD% Logs and Data: >> "%LOG_FILE%"
echo Logs and Data:
echo - Container logs: docker-compose -f %COMPOSE_FILE% logs [service-name]
echo - Test results: %DEPLOYMENT_DIR%data\test-results\
echo - Deployment log: %LOG_FILE%
goto :eof

REM Function to cleanup
:cleanup
%LOG_CMD% Cleaning up... >> "%LOG_FILE%"
echo Cleaning up...
docker-compose -f "%COMPOSE_FILE%" down -v --remove-orphans >nul 2>&1
docker system prune -f >nul 2>&1
goto :eof

REM Main deployment function
:main
%LOG_CMD% Starting ZHTP complete system deployment... >> "%LOG_FILE%"
echo Starting ZHTP complete system deployment...

REM Phase 1: Prerequisites and Build
call :check_prerequisites
if %errorlevel% neq 0 exit /b 1

call :build_images
if %errorlevel% neq 0 exit /b 1

REM Phase 2: Infrastructure Deployment
call :deploy_infrastructure
if %errorlevel% neq 0 exit /b 1

call :wait_for_system_ready
if %errorlevel% neq 0 exit /b 1

REM Phase 3: System Testing
call :run_system_tests
if %errorlevel% neq 0 exit /b 1

REM Phase 4: Status and Monitoring
call :show_system_status

%LOG_CMD% 🎉 ZHTP system deployed and tested successfully! >> "%LOG_FILE%"
echo 🎉 ZHTP system deployed and tested successfully!
echo The complete blockchain internet system is now operational.
echo.
echo System is running. To stop the system:
echo docker-compose -f "%COMPOSE_FILE%" down

goto :eof

REM Script entry point
if "%1"=="build" (
    call :check_prerequisites
    if %errorlevel% neq 0 exit /b 1
    call :build_images
) else if "%1"=="deploy" (
    call :check_prerequisites
    if %errorlevel% neq 0 exit /b 1
    call :deploy_infrastructure
    if %errorlevel% neq 0 exit /b 1
    call :wait_for_system_ready
    if %errorlevel% neq 0 exit /b 1
    call :show_system_status
) else if "%1"=="test" (
    call :run_system_tests
) else if "%1"=="clean" (
    call :cleanup
) else if "%1"=="status" (
    call :show_system_status
) else (
    call :main
)

endlocal
