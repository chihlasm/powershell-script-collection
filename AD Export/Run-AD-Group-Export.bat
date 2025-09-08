@echo off
REM Batch file to run AD Group Members Export script
REM Usage: Run-AD-Group-Export.bat "Group1" "Group2" "Group3"

echo ========================================
echo Active Directory Group Members Export
echo ========================================
echo.

if "%~1"=="" (
    echo ERROR: No group names provided!
    echo.
    echo Usage: %0 "Group Name 1" "Group Name 2" "Group Name 3"
    echo.
    echo Example: %0 "Domain Admins" "Enterprise Admins"
    echo.
    echo Or run the PowerShell script directly for more options:
    echo powershell.exe -ExecutionPolicy Bypass -File "Export-MultipleADGroupMembers.ps1" -GroupNames "Group1", "Group2"
    echo.
    pause
    exit /b 1
)

echo Building group list...
set "GROUPS="
:loop
if "%~1"=="" goto :run
if defined GROUPS (
    set "GROUPS=%GROUPS%, "%~1""
) else (
    set "GROUPS="%~1""
)
shift
goto :loop

:run
echo.
echo Groups to export: %GROUPS%
echo.

echo Checking if PowerShell script exists...
if not exist "Export-MultipleADGroupMembers.ps1" (
    echo ERROR: Export-MultipleADGroupMembers.ps1 not found in current directory!
    echo Please ensure the script is in the same directory as this batch file.
    pause
    exit /b 1
)

echo Starting PowerShell script...
echo.

powershell.exe -ExecutionPolicy Bypass -Command "& '.\Export-MultipleADGroupMembers.ps1' -GroupNames %GROUPS%"

echo.
echo ========================================
echo Export completed!
echo Check the current directory for CSV files and logs.
echo ========================================
echo.
pause
