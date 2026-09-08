@echo off
REM ============================================================================
REM  Active Directory Access Report - double-click launcher
REM
REM  Double-clicking a .ps1 opens it in Notepad rather than running it, so this
REM  batch file exists purely to start PowerShell correctly. All of the actual
REM  work, and every prompt the user sees, lives in Start-AccessReport.ps1.
REM
REM  -ExecutionPolicy Bypass applies to this process only; it does not change
REM  any machine setting. It is needed because the default policy on a member
REM  server blocks unsigned local scripts.
REM ============================================================================

cd /d "%~dp0"

if not exist "%~dp0Start-AccessReport.ps1" (
    echo.
    echo   Could not find Start-AccessReport.ps1 next to this file.
    echo.
    echo   Make sure you copied the WHOLE folder, not just this one file.
    echo   The folder needs to contain:
    echo       Run-AccessReport.bat        ^(this file^)
    echo       Start-AccessReport.ps1
    echo       Export-ADGroupMembership.ps1
    echo.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-AccessReport.ps1"

REM PowerShell handles its own pause on exit. If it failed to start at all
REM (missing or blocked powershell.exe), pause here so the error stays visible.
if errorlevel 1 (
    echo.
    echo   The report tool closed unexpectedly. Please show this window to IT.
    echo.
    pause
)
