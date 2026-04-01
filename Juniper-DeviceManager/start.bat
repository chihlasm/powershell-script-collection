@echo off
cd /d "%~dp0"
if exist portable\python\python.exe (
    echo Starting Juniper Device Manager with portable Python...
    portable\python\python.exe juniper_device_manager.py %*
) else (
    echo Portable Python not found. Trying system Python...
    python juniper_device_manager.py %*
    if errorlevel 1 (
        echo.
        echo ERROR: Python not found. Either:
        echo   1. Install Python and run: pip install junos-eznc
        echo   2. Set up portable Python with setup_portable.bat
        pause
    )
)
