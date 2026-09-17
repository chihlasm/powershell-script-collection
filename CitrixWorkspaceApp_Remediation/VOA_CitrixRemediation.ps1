$DryRun = $false
$CleanupUtilityUrl = "https://www.gallier.us/citrix/ReceiverCleanupUtility.zip"
$CleanupUtilityZip = "C:\temp\ReceiverCleanupUtility.zip"
$CleanupUtilityExe = "C:\temp\ReceiverCleanupUtility.exe"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] $Message"
}

function Invoke-Action {
    param([string]$Description, [scriptblock]$Action)
    if ($DryRun) {
        Write-Log "[DRY RUN] Would: $Description"
    } else {
        Write-Log "$Description"
        & $Action
    }
}

function Remove-TempFiles {
    Write-Log "Cleaning up temp files..."
    Remove-Item -Path $CleanupUtilityExe -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CleanupUtilityZip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\temp\config.xml" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\temp\RCU Readme.txt" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\temp\VOA_CitrixRemediation.ps1" -Force -ErrorAction SilentlyContinue
}

if ($DryRun) {
    Write-Log "=== DRY RUN MODE - No changes will be made ==="
}
Write-Log "=== VOA Citrix Workspace App Remediation Script Started ==="

Write-Log "Downloading Receiver Cleanup Utility..."
try {
    Invoke-WebRequest -Uri $CleanupUtilityUrl -OutFile $CleanupUtilityZip -UseBasicParsing -ErrorAction Stop
    Write-Log "Download completed."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($CleanupUtilityZip, "C:\temp")
    Write-Log "Receiver Cleanup Utility extracted."
} catch {
    Write-Log "Failed to download or extract Receiver Cleanup Utility: $_" "ERROR"
    Remove-TempFiles
    Read-Host "Press Enter to close"
    exit 1
}

Write-Log "Starting background window killer for any installer UI popups..."
$windowKiller = Start-Job -ScriptBlock {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class WinAPI {
        [DllImport("user32.dll")]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
        [DllImport("user32.dll")]
        public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
        [DllImport("user32.dll")]
        public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr hWnd);
        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    }
"@
    $WM_CLOSE = 0x0010
    while ($true) {
        [WinAPI]::EnumWindows([WinAPI+EnumWindowsProc]{
            param($hwnd, $lparam)
            $sb = New-Object System.Text.StringBuilder 256
            [WinAPI]::GetWindowText($hwnd, $sb, 256) | Out-Null
            $title = $sb.ToString()
            if ($title -match "Windows Installer" -or $title -match "Are you sure") {
                [WinAPI]::PostMessage($hwnd, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
            }
            return $true
        }, [IntPtr]::Zero) | Out-Null
        Start-Sleep -Milliseconds 500
    }
}

Write-Log "Checking for Citrix-related processes..."

$processesToKill = @(
    "pnamain", "ssonsvr", "selfservice", "selfserviceplugin",
    "receiver", "updater", "wfcrun32", "wfica32", "concentr",
    "radeobj", "Redirector", "AuthManSvr", "WebHelper",
    "CitrixWorkspaceApp", "CitrixWorkspace"
)

$procs = Get-Process -Name $processesToKill -ErrorAction SilentlyContinue
if ($procs) {
    foreach ($proc in $procs) {
        Invoke-Action -Description "Stop process: $($proc.Name) (PID $($proc.Id))" -Action {
            $proc | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 5
} else {
    Write-Log "No Citrix processes found running."
}

$svc = Get-Service -Name "ARPriv" -ErrorAction SilentlyContinue
if ($svc) {
    Invoke-Action -Description "Stop service: ARPriv" -Action {
        Stop-Service -Name "ARPriv" -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Log "ARPriv service not found, skipping."
}

Invoke-Action -Description "choco uninstall vc3_workspaceappweb --yes --force --skip-autouninstaller" -Action {
    & choco uninstall vc3_workspaceappweb --yes --force --skip-autouninstaller 2>&1 | Write-Output
}

Invoke-Action -Description "choco uninstall vc3_workspaceapp --yes --force --skip-autouninstaller" -Action {
    $result = & choco uninstall vc3_workspaceapp --yes --force --skip-autouninstaller 2>&1
    if ($result -match "is not installed") {
        Write-Log "vc3_workspaceapp is not installed, skipping."
    } else {
        Write-Output $result
    }
}

Write-Log "Running Receiver Cleanup Utility..."
Invoke-Action -Description "ReceiverCleanupUtility /silent" -Action {
    try {
        Start-Process -FilePath $CleanupUtilityExe -ArgumentList "/silent" -Wait -NoNewWindow -ErrorAction Stop
        Write-Log "Receiver Cleanup Utility completed."
    } catch {
        Write-Log "Error running Receiver Cleanup Utility: $_" "WARN"
    }
}

Write-Log "Stopping background window killer..."
Stop-Job -Job $windowKiller -ErrorAction SilentlyContinue
Remove-Job -Job $windowKiller -ErrorAction SilentlyContinue

if ($DryRun) {
    Write-Log "=== DRY RUN COMPLETE - No changes were made ==="
    Write-Log "Review the output above to see what the script would do."
    Write-Log "Set DryRun to false at the top of the script to run for real."
    Remove-TempFiles
    Read-Host "Press Enter to close"
    exit 0
}

Write-Log "Clearing any pending reboot flags before install..."
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
Write-Log "Pending reboot flags cleared."

Write-Log "Clearing Chocolatey download cache..."
Remove-Item -Path "C:\Windows\Temp\chocolatey\vc3_workspaceappweb" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\chocolatey\vc3_workspaceapp" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\chocolatey\lib\vc3_workspaceappweb" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\chocolatey\lib-bad\vc3_workspaceappweb" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\chocolatey\lib\vc3_workspaceapp" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\chocolatey\lib-bad\vc3_workspaceapp" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -Path "$($_.FullName)\AppData\Local\Temp\chocolatey\vc3_workspaceappweb" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$($_.FullName)\AppData\Local\Temp\chocolatey\vc3_workspaceapp" -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Log "Chocolatey download cache cleared."

Write-Log "Installing vc3_workspaceappweb via Chocolatey..."

& choco install vc3_workspaceappweb --yes --force 2>&1 | Write-Output

if ($LASTEXITCODE -ne 0) {
    Write-Log "Chocolatey install returned exit code $LASTEXITCODE. Review output above." "ERROR"
    Remove-TempFiles
    Read-Host "Press Enter to close"
    exit $LASTEXITCODE
}

Write-Log "vc3_workspaceappweb installed successfully."
Remove-TempFiles
Write-Log "=== Script Completed Successfully ==="
Read-Host "Press Enter to close"
exit 0