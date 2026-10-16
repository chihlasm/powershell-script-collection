@echo off
rem Starts M365 Synced User Fixes without leaving a PowerShell console window open.
rem
rem Why a .cmd and not a .vbs: VBScript is deprecated and Microsoft is removing it from
rem future Windows releases; .cmd works on every Windows version. If the window does not
rem appear, the script shows a message box saying why (missing AD module, missing file).
rem
rem To run elevated, right-click this file and choose "Run as administrator".
cd /d "%~dp0"
rem Kept so the old 'Block 365 Sign-in' shortcut name still works: opens the Block sign-in page.
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0Start-M365SyncedUserFixes.ps1" -Tab BlockSignIn %*
