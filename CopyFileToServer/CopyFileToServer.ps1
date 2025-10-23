param(
    [Parameter(Mandatory=$true)]
    [string]$SourceFile,

    [Parameter(Mandatory=$true)]
    [string[]]$DestServers,  # Array of destination server names

    [Parameter(Mandatory=$true)]
    [string]$DestPath  # e.g., "share\folder" or "C$\Scripts\Folder"
)

# Check if source file exists
if (!(Test-Path $SourceFile)) {
    Write-Error "Source file does not exist: $SourceFile"
    exit 1
}

# Process each destination server
foreach ($DestServer in $DestServers) {
    # Construct full destination folder UNC path
    $destFolder = "\\$DestServer\$DestPath"

    # Check if destination folder exists, create if not
    if (!(Test-Path $destFolder)) {
        try {
            New-Item -ItemType Directory -Path $destFolder -Force
            Write-Host "Created destination folder: $destFolder"
        } catch {
            Write-Error "Failed to create destination folder: $destFolder - $_"
            continue  # Continue to next server on failure
        }
    }

    # Copy the file
    try {
        Copy-Item -Path $SourceFile -Destination $destFolder
        Write-Host "File copied successfully to: $destFolder"
    } catch {
        Write-Error "Failed to copy file to $destFolder - $_"
        continue  # Continue to next server on failure
    }
}
