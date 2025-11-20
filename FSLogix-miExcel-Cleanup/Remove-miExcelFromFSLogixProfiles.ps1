# === CONFIGURATION ===
$ProfileShare   = "\\FILESERVER\FSLogixProfiles"
$MountBase      = "C:\FSLogixMount"   # Local folder on VDA
$LogFile        = "C:\Temp\miExcel-Cleanup.log"

# Create mount & log dirs
New-Item -ItemType Directory -Path $MountBase -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path $LogFile -Parent) -Force | Out-Null

# === FUNCTIONS ===
function Log($msg) { "$(Get-Date -f 'yyyy-MM-dd HH:mm:ss') $msg" | Out-File -Append -FilePath $LogFile }

function Clean-UserVHDX {
    param($VHDPath)

    $user = [IO.Path]::GetFileNameWithoutExtension($VHDPath) -replace '^Profile_',''
    Log "Processing $user -> $VHDPath"

    try {
        # Mount read-write
        $drive = (Mount-VHD -Path $VHDPath -PassThru | Get-Disk | Get-Partition | Get-Volume).DriveLetter
        if (-not $drive) { throw "Failed to get drive letter" }
        $drive = "$($drive):"
        Log "  Mounted as $drive"

        # --- DELETE FILES ---
        $pathsToDelete = @(
            # Standard Excel add-in locations
            "$drive\AppData\Roaming\Microsoft\AddIns\miExcel*"
            "$drive\AppData\Roaming\Microsoft\Excel\XLSTART\miExcel*"

            # Application data
            "$drive\AppData\Roaming\miExcel"
            "$drive\AppData\Local\miExcel"
            "$drive\Documents\miExcel"

            # Additional common locations
            "$drive\AppData\Local\Microsoft\Office\miExcel*"
        )
        foreach ($p in $pathsToDelete) {
            if (Test-Path $p) {
                Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
                Log "    Deleted: $p"
            }
        }

        # --- CLEAN REGISTRY (load NTUSER.DAT) ---
        $ntuser = "$drive\NTUSER.DAT"
        if (Test-Path $ntuser) {
            $hive = "HKU\FSLogixTemp"
            reg load $hive "$ntuser" 2>$null
            if ($?) {
                $regPaths = @(
                    # Excel add-in registration
                    "Software\Microsoft\Office\Excel\Addins\miExcel*"
                    "Software\Microsoft\Office\16.0\Excel\Addins\miExcel*"

                    # Application settings
                    "Software\miExcel"

                    # Additional registry cleanup
                    "Software\Microsoft\Office\Excel\Options"  # May contain miExcel references
                )
                foreach ($rp in $regPaths) {
                    $full = "$hive\$rp"
                    if (Test-Path $full) {
                        Remove-Item $full -Recurse -Force
                        Log "    Deleted registry: $full"
                    }
                }
                reg unload $hive
            }
        }

        # --- UNMOUNT ---
        Dismount-VHD -Path $VHDPath
        Log "  Unmounted"

        # --- COMPACT VHDX (optional, reduces size) ---
        Optimize-VHD -Path $VHDPath -Mode Full
        Log "  Compacted VHDX"

    } catch {
        Log "  ERROR: $_"
        try { Dismount-VHD -Path $VHDPath -ErrorAction SilentlyContinue } catch {}
    }
}

# === MAIN ===
Log "=== miExcel FSLogix Cleanup Started ==="

$vhds = Get-ChildItem "$ProfileShare\*.vhdx" | Where-Object {
    $_.Name -match "^Profile_.*\.vhdx$"
}

foreach ($vhd in $vhds) {
    Clean-UserVHDX -VHDPath $vhd.FullName
}

Log "=== Cleanup Completed ==="
