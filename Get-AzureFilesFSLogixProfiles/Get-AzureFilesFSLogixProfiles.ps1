#Requires -Version 5.1
<#
.SYNOPSIS
    Lists FSLogix profile/ODFC containers (.vhd/.vhdx) stored on Azure Files shares, with sizes.

.DESCRIPTION
    Read-only inventory of FSLogix containers on Azure Files, performed entirely over the
    Azure APIs - no SMB mapping, no file server, no line of sight to the share required.

    With only -TenantId supplied the script discovers everything itself:
      1. Signs in to the tenant (browser popup).
      2. Walks every enabled subscription the account can see.
      3. Finds every storage account and every SMB file share in it.
      4. Recursively lists each share (to -MaxDepth) and records every .vhd/.vhdx file.

    Use -SubscriptionId, -StorageAccountName, -ShareName and -Path to narrow the scan when
    you already know where the profiles live.

    For each container the report gives the user name and SID (parsed from the FSLogix
    folder/file naming convention), container type (Profile / ODFC / Other), size, and
    last-modified time. Shares that could not be read are reported with the reason.

    Output:
      - <base>.csv  one row per VHD(X) file
      - <base>.log  console transcript, per-share totals, and any access failures

.PARAMETER TenantId
    Client tenant ID (GUID) or primary domain (e.g. contoso.onmicrosoft.com).

.PARAMETER SubscriptionId
    Limit the scan to one or more subscriptions. Default: all enabled subscriptions in the tenant.

.PARAMETER StorageAccountName
    Limit the scan to one or more storage accounts. Default: all storage accounts.

.PARAMETER ShareName
    Limit the scan to one or more file shares. Default: all SMB shares.

.PARAMETER Path
    Folder inside the share to start from (e.g. "Profiles"). Default: the share root.

.PARAMETER MaxDepth
    How many folder levels below the start folder to search. FSLogix normally stores
    containers one level down (<share>\<SID_user>\Profile_user.vhdx), so the default of 3
    covers profiles nested a couple of folders deep without crawling large unrelated trees.

.PARAMETER AuthMode
    How to read file share contents:
      Auto     (default) Use the storage account key if the account can list it, else Entra ID.
      Key      Storage account key only. Needs Owner, Contributor, or Storage Account Key Operator.
      EntraId  Entra ID (OAuth) only. Needs Storage File Data Privileged Reader (or Contributor).

.PARAMETER OutputPath
    Folder for the CSV and log. Default: current directory.

.PARAMETER UseDeviceAuthentication
    Sign in with a device code (https://microsoft.com/devicelogin) in your normal browser
    instead of the built-in Windows sign-in window (WAM). Use this when the sign-in window
    shows "Update your browser" / "Keep your account secure" - that window cannot complete
    MFA registration or some Conditional Access prompts.

.EXAMPLE
    .\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.onmicrosoft.com

    Discovers every storage account and share in the tenant and inventories all VHD(X) files.

.EXAMPLE
    .\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.com -StorageAccountName stavdprofiles01 -ShareName fslogix

    Scans a single known share.

.EXAMPLE
    .\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.com -UseDeviceAuthentication

    Signs in with a device code in the normal browser instead of the Windows sign-in window.

.EXAMPLE
    .\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.com -AuthMode EntraId -OutputPath C:\Temp

    Uses Entra ID data-plane access only (for storage accounts with shared key access disabled).

.NOTES
    Requires Az.Accounts and Az.Storage (installed to CurrentUser automatically if missing).

    PERMISSIONS - this is Azure RBAC, not Microsoft Graph or an Entra directory role.
    Global Administrator alone grants NO access to Azure resources.
      Discovery : Reader on the subscription(s) / resource group(s).
      Contents  : Owner, Contributor, or Storage Account Key Operator Service Role (key)
                  -or- Storage File Data Privileged Reader (Entra ID).

    NETWORK - listing contents goes to <account>.file.core.windows.net over HTTPS (443).
    Accounts restricted to private endpoints or selected networks will be reported as
    inaccessible unless run from an allowed network.

    REFERENCES
      https://learn.microsoft.com/powershell/azure/authenticate-interactive
      https://learn.microsoft.com/powershell/module/az.storage/get-azstoragefile
      https://learn.microsoft.com/powershell/module/az.storage/new-azstoragecontext
      https://learn.microsoft.com/powershell/module/az.storage/get-azrmstorageshare
      https://learn.microsoft.com/dotnet/api/microsoft.windowsazure.commands.common.storage.resourcemodel.azurestoragefile
      https://learn.microsoft.com/rest/api/storageservices/authorize-with-azure-active-directory
      https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage
      https://learn.microsoft.com/fslogix/reference-configuration-settings
      https://learn.microsoft.com/fslogix/concepts-container-types
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [string[]]$SubscriptionId,

    [string[]]$StorageAccountName,

    [string[]]$ShareName,

    [string]$Path,

    [ValidateRange(0, 10)]
    [int]$MaxDepth = 3,

    [ValidateSet('Auto', 'Key', 'EntraId')]
    [string]$AuthMode = 'Auto',

    [string]$OutputPath = (Get-Location).Path,

    [switch]$UseDeviceAuthentication
)

#region Logging
$script:LogLines = New-Object System.Collections.Generic.List[string]

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'NONE')]
        [string]$Level = 'NONE'
    )
    $colors = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan'; NONE = 'Gray' }
    $line = if ($Level -eq 'NONE') { $Message } else { "[$Level] $Message" }
    Write-Host $line -ForegroundColor $colors[$Level]
    $script:LogLines.Add(('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $line))
}
#endregion

#region Helpers
function Get-FSLogixIdentity {
    <#
        Parses user name / SID from the FSLogix folder and file names.
        Folder defaults per FSLogix SIDDirNamePattern = %sid%_%username%; with
        FlipFlopProfileDirectoryName = 1 it is %username%_%sid%.
        File defaults per VHDNamePattern = Profile_%username% (Profiles) and
        ODFC_%username% (ODFC); VolumeType selects .vhd or .vhdx.
        https://learn.microsoft.com/fslogix/reference-configuration-settings
        Entra-only (cloud) users have SIDs beginning S-1-12-1, so the SID pattern is
        not restricted to S-1-5-21.
    #>
    param([string]$FolderName, [string]$FileName)

    $sid = 'S-1-\d+(?:-\d+)+'
    $result = [ordered]@{ UserName = $null; SID = $null; FolderNaming = 'Unrecognized'; ContainerType = 'Other' }

    if ($FolderName -match "^($sid)_(.+)$") {
        $result.SID = $Matches[1]; $result.UserName = $Matches[2]; $result.FolderNaming = 'SID_Username'
    }
    elseif ($FolderName -match "^(.+)_($sid)$") {
        $result.UserName = $Matches[1]; $result.SID = $Matches[2]; $result.FolderNaming = 'Username_SID (FlipFlop)'
    }

    if ($FileName -match '^(Profile|ODFC)_(.+?)\.vhdx?$') {
        $result.ContainerType = $Matches[1]
        # File name is the fallback when the folder uses a custom pattern or
        # NoProfileContainingFolder places files at the share root.
        if (-not $result.UserName) { $result.UserName = $Matches[2] }
    }
    [pscustomobject]$result
}

function Get-ErrorHint {
    param([string]$Message)
    switch -Regex ($Message) {
        'AuthorizationPermissionMismatch' { 'Signed-in account lacks a Storage File Data role on this account (EntraId mode).'; break }
        'AuthorizationFailure|not authorized to perform this operation' { 'Commonly the storage account firewall / private endpoint blocking this workstation, or shared key access disabled.'; break }
        'No such host|could not be resolved|NameResolutionFailure' { 'File endpoint did not resolve - account may be private-endpoint only.'; break }
        'KeyBasedAuthenticationNotPermitted' { 'Shared key access is disabled on this account - rerun with -AuthMode EntraId.'; break }
        'ShareNotFound' { 'Share not found.'; break }
        default { '' }
    }
}

function Find-VhdFiles {
    <#
        Recursively lists a share directory and returns every .vhd/.vhdx file.
        Get-AzStorageFile returns AzureStorageFile and AzureStorageFileDirectory objects;
        Length and LastModified come from the list response, so no per-file round trip
        (FileProperties would issue an extra server call per file).
        https://learn.microsoft.com/powershell/module/az.storage/get-azstoragefile
    #>
    param(
        [Parameter(Mandatory)]$Items,
        [string]$RelativePath,
        [int]$Depth
    )
    foreach ($item in $Items) {
        $itemPath = if ($RelativePath) { "$RelativePath/$($item.Name)" } else { $item.Name }

        if ($item.GetType().Name -eq 'AzureStorageFileDirectory') {
            if ($Depth -ge $MaxDepth) { continue }
            try {
                $children = @($item | Get-AzStorageFile -ErrorAction Stop)
            }
            catch {
                Write-Log "Could not list '$itemPath': $($_.Exception.Message)" WARN
                continue
            }
            if ($children.Count) { Find-VhdFiles -Items $children -RelativePath $itemPath -Depth ($Depth + 1) }
        }
        elseif ($item.Name -match '\.vhdx?$') {
            [pscustomobject]@{ File = $item; RelativePath = $itemPath }
        }
    }
}
#endregion

#region Modules
foreach ($module in 'Az.Accounts', 'Az.Storage') {
    try {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Log "$module not found - installing for the current user..." INFO
            Install-Module -Name $module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
        }
        Import-Module $module -ErrorAction Stop
    }
    catch {
        Write-Log "Could not load $module : $($_.Exception.Message)" FAIL
        Write-Log "Run: Install-Module $module -Scope CurrentUser" INFO
        return
    }
}
#endregion

#region Output paths
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$safeTen  = $TenantId -replace '[^\w\.-]', '_'
$baseName = "FSLogixProfiles_${safeTen}_$stamp"
$csvPath  = Join-Path $OutputPath "$baseName.csv"
$logPath  = Join-Path $OutputPath "$baseName.log"
#endregion

#region Sign in
try {
    $connectParams = @{ TenantId = $TenantId; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($SubscriptionId) { $connectParams.SubscriptionId = $SubscriptionId[0] }
    # Az 12+ signs in through Web Account Manager (WAM) on Windows. WAM's embedded window
    # cannot complete MFA registration ("Keep your account secure" / "Update your browser");
    # device code flow moves sign-in to the user's real browser.
    # https://learn.microsoft.com/powershell/azure/authenticate-interactive
    if ($UseDeviceAuthentication) {
        $connectParams.UseDeviceAuthentication = $true
        Write-Log "Signing in to tenant $TenantId - open https://microsoft.com/devicelogin and enter the code shown below." INFO
    }
    else {
        Write-Log "Signing in to tenant $TenantId (a sign-in window will open)..." INFO
        Write-Log "If it shows 'Update your browser', close it and rerun with -UseDeviceAuthentication." INFO
    }
    $null = Connect-AzAccount @connectParams
    $ctx = Get-AzContext
    Write-Log "Signed in as $($ctx.Account.Id) to tenant $($ctx.Tenant.Id)" PASS
}
catch {
    Write-Log "Sign-in failed: $($_.Exception.Message)" FAIL
    return
}

try {
    $subs = @(Get-AzSubscription -TenantId $ctx.Tenant.Id -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
}
catch {
    Write-Log "Could not list subscriptions: $($_.Exception.Message)" FAIL
    return
}
if ($SubscriptionId) {
    $subs = @($subs | Where-Object { $SubscriptionId -contains $_.Id -or $SubscriptionId -contains $_.Name })
}
if (-not $subs.Count) {
    Write-Log 'No enabled subscriptions visible to this account. Azure RBAC (Reader or higher) is required - an Entra admin role alone does not grant it.' FAIL
    return
}
Write-Log "Subscriptions to scan: $($subs.Count)" INFO
#endregion

#region Scan
$results     = New-Object System.Collections.Generic.List[object]
$shareTotals = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subs) {
    Write-Log "Subscription: $($sub.Name) ($($sub.Id))" INFO
    try {
        $null = Set-AzContext -SubscriptionId $sub.Id -TenantId $ctx.Tenant.Id -ErrorAction Stop -WarningAction SilentlyContinue
        $accounts = @(Get-AzStorageAccount -ErrorAction Stop)
    }
    catch {
        Write-Log "  Could not list storage accounts: $($_.Exception.Message)" FAIL
        continue
    }
    if ($StorageAccountName) {
        $accounts = @($accounts | Where-Object { $StorageAccountName -contains $_.StorageAccountName })
    }
    if (-not $accounts.Count) { Write-Log '  No matching storage accounts.' INFO; continue }

    foreach ($sa in $accounts) {
        $saName = $sa.StorageAccountName
        $rg     = $sa.ResourceGroupName

        # Share list comes from the management plane (ARM), so it works even when the
        # storage firewall blocks this workstation from the data plane.
        # https://learn.microsoft.com/powershell/module/az.storage/get-azrmstorageshare
        try {
            $shares = @(Get-AzRmStorageShare -ResourceGroupName $rg -StorageAccountName $saName -ErrorAction Stop)
        }
        catch {
            Write-Log "  [$saName] Could not list shares: $($_.Exception.Message)" WARN
            continue
        }
        # FSLogix uses SMB; NFS shares are skipped.
        $shares = @($shares | Where-Object { $_.EnabledProtocols -ne 'NFS' })
        if ($ShareName) { $shares = @($shares | Where-Object { $ShareName -contains $_.Name }) }
        if (-not $shares.Count) { continue }

        # Build candidate data-plane contexts in preference order.
        $contexts = New-Object System.Collections.Generic.List[object]
        $sharedKeyDisabled = ($sa.AllowSharedKeyAccess -eq $false)

        if ($AuthMode -in 'Auto', 'Key') {
            if ($sharedKeyDisabled) {
                Write-Log "  [$saName] Shared key access is disabled on this account." INFO
            }
            else {
                try {
                    # listkeys requires Owner, Contributor or Storage Account Key Operator Service Role.
                    # https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage
                    $key = (Get-AzStorageAccountKey -ResourceGroupName $rg -Name $saName -ErrorAction Stop)[0].Value
                    $contexts.Add([pscustomobject]@{
                        Mode    = 'Key'
                        Context = New-AzStorageContext -StorageAccountName $saName -StorageAccountKey $key -ErrorAction Stop
                    })
                }
                catch {
                    Write-Log "  [$saName] Cannot read account key ($($_.Exception.Message.Split([Environment]::NewLine)[0]))" INFO
                }
            }
        }
        if ($AuthMode -in 'Auto', 'EntraId') {
            # -EnableFileBackupRequestIntent is required for OAuth against Azure Files; needs
            # a Storage File Data Privileged Reader/Contributor role assignment.
            # https://learn.microsoft.com/powershell/module/az.storage/new-azstoragecontext
            $contexts.Add([pscustomobject]@{
                Mode    = 'EntraId'
                Context = New-AzStorageContext -StorageAccountName $saName -UseConnectedAccount -EnableFileBackupRequestIntent
            })
        }
        if (-not $contexts.Count) {
            Write-Log "  [$saName] No usable authentication method for -AuthMode $AuthMode." FAIL
            foreach ($share in $shares) {
                $shareTotals.Add([pscustomobject]@{
                    Subscription = $sub.Name; StorageAccount = $saName; Share = $share.Name
                    Status = 'No access'; AuthUsed = ''; VhdCount = 0; TotalGB = 0
                    Detail = 'No usable authentication method'
                })
            }
            continue
        }

        foreach ($share in $shares) {
            $label   = "$saName/$($share.Name)"
            $rootItems = $null; $usedMode = $null; $lastErr = $null

            foreach ($c in $contexts) {
                try {
                    if ($Path) {
                        $rootItems = @(Get-AzStorageFile -ShareName $share.Name -Path $Path -Context $c.Context -ErrorAction Stop |
                            Get-AzStorageFile -ErrorAction Stop)
                    }
                    else {
                        $rootItems = @(Get-AzStorageFile -ShareName $share.Name -Context $c.Context -ErrorAction Stop)
                    }
                    $usedMode = $c.Mode
                    break
                }
                catch {
                    $lastErr = $_.Exception.Message
                }
            }

            if (-not $usedMode) {
                $hint = Get-ErrorHint $lastErr
                Write-Log "  [$label] Cannot read share contents: $($lastErr.Split([Environment]::NewLine)[0])" FAIL
                if ($hint) { Write-Log "    $hint" INFO }
                $shareTotals.Add([pscustomobject]@{
                    Subscription = $sub.Name; StorageAccount = $saName; Share = $share.Name
                    Status = 'No access'; AuthUsed = ''; VhdCount = 0; TotalGB = 0
                    Detail = ("$hint $($lastErr.Split([Environment]::NewLine)[0])").Trim()
                })
                continue
            }

            Write-Log "  [$label] Scanning (auth: $usedMode, max depth $MaxDepth)..." INFO
            $startPath = if ($Path) { $Path.Trim('/', '\') -replace '\\', '/' } else { '' }
            $found = @(Find-VhdFiles -Items $rootItems -RelativePath $startPath -Depth 0)

            $shareBytes = [long]0
            foreach ($f in $found) {
                $file       = $f.File
                $segments   = $f.RelativePath -split '/'
                $folderName = if ($segments.Count -gt 1) { $segments[-2] } else { '' }
                $folderPath = if ($segments.Count -gt 1) { ($segments[0..($segments.Count - 2)] -join '/') } else { '' }
                $identity   = Get-FSLogixIdentity -FolderName $folderName -FileName $file.Name
                $bytes      = [long]$file.Length
                $shareBytes += $bytes
                $modified   = if ($file.LastModified) { $file.LastModified.LocalDateTime } else { $null }

                $results.Add([pscustomobject]@{
                    UserName        = $identity.UserName
                    SID             = $identity.SID
                    ContainerType   = $identity.ContainerType
                    FileName        = $file.Name
                    SizeGB          = [math]::Round($bytes / 1GB, 2)
                    SizeBytes       = $bytes
                    LastModified    = if ($modified) { $modified.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                    DaysSinceModified = if ($modified) { [int]((Get-Date) - $modified).TotalDays } else { '' }
                    FolderPath      = $folderPath
                    FolderNaming    = $identity.FolderNaming
                    Share           = $share.Name
                    StorageAccount  = $saName
                    ResourceGroup   = $rg
                    Subscription    = $sub.Name
                    UncPath         = "\\$saName.file.core.windows.net\$($share.Name)\$($f.RelativePath -replace '/', '\')"
                })
            }

            $shareGB = [math]::Round($shareBytes / 1GB, 2)
            $level   = if ($found.Count) { 'PASS' } else { 'INFO' }
            Write-Log "  [$label] $($found.Count) VHD(X) files, $shareGB GB" $level
            $shareTotals.Add([pscustomobject]@{
                Subscription = $sub.Name; StorageAccount = $saName; Share = $share.Name
                Status = 'Scanned'; AuthUsed = $usedMode; VhdCount = $found.Count; TotalGB = $shareGB
                Detail = if ($Path) { "Start path: $Path" } else { '' }
            })
        }
    }
}
#endregion

#region Report
Write-Log '' NONE
Write-Log '===== Per-share totals =====' NONE
foreach ($line in ($shareTotals | Format-Table Subscription, StorageAccount, Share, Status, AuthUsed, VhdCount, TotalGB -AutoSize | Out-String -Width 200).Split([Environment]::NewLine)) {
    if ($line.Trim()) { Write-Log $line NONE }
}
$failed = @($shareTotals | Where-Object Status -ne 'Scanned')
foreach ($s in $failed) { Write-Log "$($s.StorageAccount)/$($s.Share): $($s.Detail)" WARN }

$sorted = $results | Sort-Object SizeBytes -Descending
$totalBytes = ($results | Measure-Object SizeBytes -Sum).Sum
$users = @($results | Where-Object UserName | Select-Object -ExpandProperty UserName -Unique)

Write-Log '' NONE
Write-Log "VHD(X) files found : $($results.Count)" INFO
Write-Log "Distinct users     : $($users.Count)" INFO
Write-Log ("Total size         : {0:N2} GB" -f ($totalBytes / 1GB)) INFO

if ($results.Count) {
    $sorted | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Detail CSV : $csvPath" PASS
}
else {
    Write-Log 'No VHD(X) files were found - no CSV written. Check the per-share table above for access failures, or raise -MaxDepth.' WARN
}
$script:LogLines | Set-Content -LiteralPath $logPath -Encoding UTF8
Write-Host "Log        : $logPath" -ForegroundColor Green
#endregion
