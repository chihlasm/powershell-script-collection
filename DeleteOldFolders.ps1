param(
    [Parameter(Mandatory=$true)]
    [string]$DrivePath,

    [int]$DaysOld = 14,

    [switch]$WhatIf,

    [switch]$SkipConfirmation,

    [string]$LogFile
)

# Function to write to log file
function Write-Log {
    param(
        [string]$Message,
        [string]$LogFile
    )

    if ($LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
}

# Function to get all directories recursively, handling long paths
function Get-AllDirectories {
    param(
        [string]$Path
    )

    $directories = New-Object System.Collections.Generic.List[string]

    try {
        # Use .NET to enumerate directories, which supports long paths better
        $enumDirs = [System.IO.Directory]::EnumerateDirectories($Path, "*", [System.IO.SearchOption]::AllDirectories)
        foreach ($dir in $enumDirs) {
            $directories.Add($dir)
        }
    } catch [System.UnauthorizedAccessException] {
        Write-Warning "Access denied to some directories in $Path. Skipping inaccessible areas."
    } catch {
        Write-Warning "Error enumerating directories in $Path`: $($_.Exception.Message)"
    }

    return $directories
}

# Function to delete folders ending with .old
function Remove-OldFolders {
    param(
        [string]$Path,
        [int]$DaysOld,
        [switch]$WhatIf,
        [switch]$SkipConfirmation,
        [string]$LogFile
    )

    try {
        # Get all directories recursively
        $allFolders = Get-AllDirectories -Path $Path

        # Calculate cutoff date
        $cutoffDate = (Get-Date).AddDays(-$DaysOld)

        # Filter folders that end with .old and are older than specified days
        $oldFolders = $allFolders | Where-Object {
            $folderName = [System.IO.Path]::GetFileName($_)
            if ($folderName -like "*.old") {
                try {
                    $folderInfo = Get-Item $_
                    # Check both LastWriteTime and CreationTime, use the older one
                    $folderDate = $folderInfo.LastWriteTime
                    if ($folderInfo.CreationTime -lt $folderDate) {
                        $folderDate = $folderInfo.CreationTime
                    }
                    return $folderDate -lt $cutoffDate
                } catch {
                    # If we can't get folder info, skip it
                    return $false
                }
            }
            return $false
        }

        if ($oldFolders.Count -eq 0) {
            Write-Host "No folders ending with '.old' found in $Path"
            Write-Log -Message "No folders ending with '.old' found in $Path" -LogFile $LogFile
            return
        }

        Write-Host "Found $($oldFolders.Count) folder(s) ending with '.old':"
        Write-Log -Message "Found $($oldFolders.Count) folder(s) ending with '.old'" -LogFile $LogFile
        foreach ($folder in $oldFolders) {
            Write-Host "  - $folder"
        }

        if ($WhatIf) {
            Write-Host "`nWhatIf mode: The following folders would be deleted:"
            foreach ($folder in $oldFolders) {
                Write-Host "  - $folder"
            }
        } elseif (-not $SkipConfirmation) {
            # Confirm deletion
            $confirmation = Read-Host "`nAre you sure you want to delete these $($oldFolders.Count) folder(s)? (y/N)"
            if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
                Write-Host "Operation cancelled."
                return
            }
        }

        # Delete the folders (only if not in WhatIf mode)
        if (-not $WhatIf) {
            Write-Log -Message "Starting deletion of $($oldFolders.Count) folders" -LogFile $LogFile
            foreach ($folder in $oldFolders) {
                try {
                    # Use .NET Directory.Delete for better long path support
                    [System.IO.Directory]::Delete($folder, $true)
                    Write-Host "Deleted: $folder"
                    Write-Log -Message "Successfully deleted: $folder" -LogFile $LogFile
                } catch [System.UnauthorizedAccessException] {
                    Write-Warning "Access denied: Failed to delete $folder. You may need elevated permissions."
                    Write-Log -Message "Access denied: Failed to delete $folder" -LogFile $LogFile
                } catch [System.IO.IOException] {
                    Write-Warning "IO Error: Failed to delete $folder. The folder may be in use or contain locked files."
                    Write-Log -Message "IO Error: Failed to delete $folder" -LogFile $LogFile
                } catch {
                    Write-Warning "Failed to delete $folder`: $($_.Exception.Message)"
                    Write-Log -Message "Failed to delete $folder`: $($_.Exception.Message)" -LogFile $LogFile
                }
            }
        }
    } catch {
        Write-Error "An error occurred: $($_.Exception.Message)"
    }
}

# Validate the drive path using .NET for better long path support
if (-not [System.IO.Directory]::Exists($DrivePath)) {
    Write-Error "The specified path '$DrivePath' does not exist."
    exit 1
}

# Log script start
Write-Log -Message "Script started. Path: $DrivePath, DaysOld: $DaysOld, WhatIf: $WhatIf, SkipConfirmation: $SkipConfirmation" -LogFile $LogFile

# Execute the deletion
Remove-OldFolders -Path $DrivePath -DaysOld $DaysOld -WhatIf:$WhatIf -SkipConfirmation:$SkipConfirmation -LogFile $LogFile

Write-Host "Operation completed."
Write-Log -Message "Script completed successfully" -LogFile $LogFile
