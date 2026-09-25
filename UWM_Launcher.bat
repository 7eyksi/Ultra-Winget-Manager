@echo off
SETLOCAL EnableExtensions EnableDelayedExpansion
title ULTRA WINGET MANAGER - STANDALONE EXE LAUNCHER v15.0

:: ---------------------------------------------------------------------
:: STAGE 1: SELF-ELEVATION - NATIVE ADMIN CHECK
:: ---------------------------------------------------------------------
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [BOOT] Administrative privileges required. Elevating process...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Anchor working directory to script root (relative path enforcement)
cd /d "%~dp0"

:: ---------------------------------------------------------------------
:: STAGE 2: EXECUTION POLICY BYPASS (self-contained bootstrapper)
:: ---------------------------------------------------------------------
echo =====================================================================
echo    UWM SELF-CONTAINED BOOTSTRAPPER v15.0
echo    Portable Mode - No external dependencies required
echo =====================================================================

:: Force UTF-8 console encoding
chcp 65001 >nul 2>&1

:: Verify core script exists
if not exist "update.ps1" (
    echo [CRITICAL] 'update.ps1' is missing from the root folder.
    echo Please ensure all files are extracted together.
    pause
    exit /b 1
)

:: User data vault is dynamically resolved to Documents by the engine

:: Connection topology (informational only - non-blocking)
>nul 2>&1 ping -n 1 8.8.8.8 && (
    echo [NET] Online - full hybrid mode available.
) || (
    echo [NET] Offline/air-gapped - running in local vault mode.
)

:: ---------------------------------------------------------------------
:: STAGE 3: DEPLOYMENT
:: ---------------------------------------------------------------------
echo ---------------------------------------------------------------------
echo [LAUNCH] Spawning PowerShell engine with bypass policy...
echo ---------------------------------------------------------------------

powershell -NoProfile -NoLogo -ExecutionPolicy Bypass -File "update.ps1"
set "UWM_EXIT_CODE=%errorLevel%"

echo ---------------------------------------------------------------------
if %UWM_EXIT_CODE% EQU 0 (
    echo [OK] Execution completed successfully.
) else (
    echo [ALERT] Execution completed with exit code [%UWM_EXIT_CODE%].
)

:FINALIZATION
echo [DONE] Control returned to bootstrap terminal.
pause
exit /b %UWM_EXIT_CODE%
