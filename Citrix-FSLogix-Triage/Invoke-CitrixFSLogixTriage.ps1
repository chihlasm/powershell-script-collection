# 3.0 so this runs on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) as shipped; Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    "My profile is broken / I got a temporary profile" - read-only FSLogix health check of one
    Citrix, RDS or AVD session host, in plain English.
.DESCRIPTION
    Built for the service desk. Point it at the server the user signs in to and the first line
    of output is the answer:

        FSLogix check for RDSH01 (user jdoe):  PROBLEMS FOUND / WARNINGS / LOOKS HEALTHY

    Each finding follows with a one-line "What to do". The tool is READ-ONLY: it reads
    services, registry, event logs and disk space, and changes nothing.

    WHAT IT CHECKS (on the session host you name)

      1. The server answers a ping
      2. FSLogix services are running: FSLogix Apps Services (frxsvc) and the Cloud Cache
         service (frxccds)
      3. FSLogix profile containers are switched on (Enabled = 1)
      4. The profile storage setting is sane: VHDLocations or CCDLocations is set, not both,
         and Cloud Cache entries use the exact (case-sensitive) spelling FSLogix requires
      5. Recent errors and warnings in the FSLogix and Remote Desktop session logs
      6. Free space on the server's local disks
      7. The profile share can be reached from the server (and from your PC, for comparison)

    WHAT THIS DOES NOT CHECK: the user's own container file (size, locks, corruption), the
    FSLogix text logs, or Citrix broker state. See Parse-FSLogixLogs, FSLogix-ProfileDiskRepair
    and Citrix-FSLogix-HealthCollector for those.

    Checks that cannot run (blocked firewall, no permission, service not reachable) are
    reported as WARNINGS and never as healthy.
.PARAMETER ComputerName
    The session host the user signs in to. Defaults to this computer. Alias: AffectedDevice.
.PARAMETER UserName
    Optional user name. Used to fill %username% in the profile path before it is tested, and
    shown in the report. Alias: AffectedUser.
.PARAMETER EventLookbackHours
    How many hours of FSLogix and Remote Desktop events to read. Default 24, maximum 168.
.PARAMETER OutputPath
    Optional folder. When given, a text report ready to paste into a ticket and a CSV of the
    findings are written there, named FSLogixTriage_<computer>_<yyyy-MM-dd_HHmmss>. When
    omitted the tool is console-only. With -TicketNumber, this is the folder that holds
    Ticket_<number>.
.PARAMETER TicketNumber
    Optional ticket number (letters, digits, - or _, up to 32 characters). The text report, the
    CSV and the ticket note are saved in <root>\Ticket_<number>, where root is -OutputPath if
    given, else %USERPROFILE%\Documents\TicketNotes. TicketNote\Join-TicketNotes.ps1 later
    joins every tool's note in that folder into one. A number that does not fit is refused
    with a [FAIL] line and exit code 3, before anything is checked.
.PARAMETER NoClipboard
    Do not copy the ticket note to the clipboard. Without it the note goes to the clipboard,
    where it can enter clipboard history (Win+V) or the cloud clipboard on Windows PowerShell
    5.0 and later, and travels over RDP clipboard redirection.
.PARAMETER FullDetail
    Keep IP addresses and share paths in the ticket note. By default the note is paste-safe:
    they are replaced by [IP removed] / [share path removed]. The question at the top is
    never changed.
.PARAMETER PassThru
    Return the result object (CheckId, Status, Summary, Evidence, RecommendedNextSteps,
    RawOutput, StartedAt, FinishedAt, Error, TicketNote) instead of setting an exit code. Use
    this when another tool calls the script and reads the result.
.PARAMETER Quiet
    Do not write the console report. Combine with -PassThru or -OutputPath. Also leaves the
    clipboard alone, because another script is the caller.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without running a check (used by the tests).
.EXAMPLE
    .\Invoke-CitrixFSLogixTriage.ps1 -ComputerName RDSH01 -UserName jdoe
    Check the server jdoe signs in to.
.EXAMPLE
    .\Invoke-CitrixFSLogixTriage.ps1 -ComputerName RDSH01 -OutputPath C:\Temp
    Same, and save a text report and CSV for the ticket.
.EXAMPLE
    $r = .\Invoke-CitrixFSLogixTriage.ps1 -ComputerName RDSH01 -PassThru -Quiet
    Get the result object for another script to use.
.EXAMPLE
    .\Invoke-CitrixFSLogixTriage.ps1 -ComputerName RDSH01 -UserName jdoe -TicketNumber 482113
    Same check; the text report, the CSV and the ticket note go into
    %USERPROFILE%\Documents\TicketNotes\Ticket_482113, and the note is copied to the clipboard.
.NOTES
    Exit codes (without -PassThru): 0 = looks healthy, 1 = warnings, 2 = problems found,
    3 = an unusable -TicketNumber.

    TICKET NOTE. Every run ends with a four-part note (Checked, Ruled out, Could not check,
    Next step) copied to the clipboard. It is also saved as Note_<time>_Citrix-FSLogix-Triage.txt
    when -TicketNumber or -OutputPath is given. A check is only "Ruled out" when it really ran:
    anything the tool could not read (ping, services, registry, event logs, disks), a profile
    share it could not confirm from the server, and a Cloud Cache location it does not test
    are listed under "Could not check". The FSLogix settings and Cloud Cache entries stay out
    of the note. The note never changes the verdict or the exit code. It is built by
    CaseKit.ps1 in this folder (a copy of TicketNote\CaseKit.ps1); if it is missing the check
    still runs, without a note.

    Remote checks need, on the target: ping (ICMP), WinRM for CIM and Invoke-Command, the
    Remote Registry service, and Event Log access (RPC). Run as an account that is a local
    administrator on the session host.

    Formerly the citrix.fslogix.triage check of the retired MSP-TroubleshootingWorkbench
    folder. The result object keeps the same shape so callers that read it still work.

    REFERENCES
      Profile settings live under HKLM\SOFTWARE\FSLogix\Profiles (ODFC settings under
      HKLM\SOFTWARE\Policies\FSLogix\ODFC); VHDLocations / CCDLocations must not both be
      present; CCDLocations parameters and values are case sensitive (type=smb, connectionString=)
        https://learn.microsoft.com/fslogix/reference-configuration-settings
      Enabled = 1 is required for profile containers
        https://learn.microsoft.com/fslogix/tutorial-cloud-cache-containers
      VHDLocations / CCDLocations may be REG_SZ (semicolon-delimited) or REG_MULTI_SZ
        https://learn.microsoft.com/fslogix/troubleshooting-old-temp-local-profiles
      Services frxsvc (FSLogix Apps Services) and frxccds (Cloud Caching Service), both Automatic
        https://learn.microsoft.com/fslogix/reference-service-drivers-components
      Event logs Microsoft-FSLogix-Apps/Admin and /Operational
        https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics
        https://learn.microsoft.com/azure/virtual-desktop/insights-glossary#windows-event-logs
      Get-Service has no -ComputerName in PowerShell 6+, so services are read with Win32_Service
        https://learn.microsoft.com/powershell/scripting/whats-new/differences-from-windows-powershell
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service
      Ticket note clipboard (in CaseKit.ps1): Set-Clipboard is 5.0, so it is used behind a
      Get-Command check with a WinForms fallback; STA is the default since 3.0; never clip.exe,
      because $OutputEncoding is ASCII in 5.1 and would mangle non-ASCII names
        https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-clipboard?view=powershell-5.1
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1
      Clipboard history / cloud clipboard opt-out formats (CanIncludeInClipboardHistory,
      CanUploadToCloudClipboard; set by the kit's WinForms path, not by Set-Clipboard)
        https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats

    NOT VERIFIED ON LEARN: the free-disk-space thresholds (see Get-DiskSpaceStatus) are this
    tool's own rule of thumb, not a Microsoft figure.
#>
[CmdletBinding()]
param(
    [Alias('AffectedDevice')]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName = $env:COMPUTERNAME,

    [Alias('AffectedUser')]
    [string]$UserName = '',

    [ValidateRange(1, 168)]
    [int]$EventLookbackHours = 24,

    [string]$OutputPath,

    # Checked in the script body (Test-TicketNumber in CaseKit.ps1), not with ValidatePattern,
    # so a mistyped number gets a plain-English [FAIL] line instead of a parameter-binding error.
    [string]$TicketNumber,

    [switch]$NoClipboard,

    [switch]$FullDetail,

    [switch]$PassThru,

    [switch]$Quiet,

    [switch]$LoadFunctionsOnly
)

# FSLogix documents profile settings only under this key.
# https://learn.microsoft.com/fslogix/reference-configuration-settings
$script:ProfileKeyPath = 'SOFTWARE\FSLogix\Profiles'
$script:PolicyProfileKeyPath = 'SOFTWARE\Policies\FSLogix\Profiles'

function New-EvidenceItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Warn', 'Fail')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Detail,

        [string]$Action = '',

        # The check could not run at all (no access, service unreachable), as opposed to running
        # and finding something. The Status stays as given (Warn), so the verdict is unchanged;
        # only the ticket note moves the item to "Could not check".
        [switch]$NotChecked
    )

    [PSCustomObject]@{
        Name       = $Name
        Status     = $Status
        Detail     = $Detail
        Action     = $Action
        NotChecked = [bool]$NotChecked
    }
}

function ConvertTo-StringArray {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Array]) {
        $items = @()
        foreach ($item in @($Value)) {
            if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
                $items += [string]$item
            }
        }

        return @($items)
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return @()
    }

    return @($text)
}

function ConvertTo-ProfilePathForTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$UserName
    )

    $resolvedPath = $Path
    if (-not [string]::IsNullOrWhiteSpace($UserName)) {
        # '$' is special in a .NET replacement string; double it so a user name is inserted literally.
        $replacement = $UserName.Replace('$', '$$')
        $resolvedPath = [regex]::Replace($resolvedPath, '(?i)%username%', $replacement)
        $resolvedPath = [regex]::Replace($resolvedPath, '(?i)#username#', $replacement)
    }

    return $resolvedPath
}

function Split-FSLogixRegistryLocationEntries {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    $entries = @()
    foreach ($item in @(ConvertTo-StringArray -Value $Value)) {
        foreach ($entry in ([string]$item -split ';')) {
            $trimmedEntry = $entry.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmedEntry)) {
                $entries += $trimmedEntry
            }
        }
    }

    return @($entries)
}

function Split-FSLogixCloudCacheProviderEntries {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    $entries = @()
    foreach ($item in @(ConvertTo-StringArray -Value $Value)) {
        foreach ($entry in ([regex]::Split([string]$item, '\s*;\s*(?=type\s*=)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))) {
            $trimmedEntry = $entry.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmedEntry)) {
                $entries += $trimmedEntry
            }
        }
    }

    return @($entries)
}

function Get-FSLogixCloudCacheProviderField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProviderString,

        [Parameter(Mandatory)]
        [string]$FieldName
    )

    $pattern = '(?i)(?:^|,)\s*{0}\s*=\s*(.*?)(?=,\s*\w+\s*=|$)' -f [regex]::Escape($FieldName)
    $match = [regex]::Match($ProviderString, $pattern)
    if ($match.Success) {
        return $match.Groups[1].Value.Trim()
    }

    return ''
}

function Test-FSLogixCloudCacheProviderSpelling {
    <#
    .SYNOPSIS
        Returns the spelling problems in one CCDLocations entry (empty when it is correct).
    .DESCRIPTION
        FSLogix documents CCDLocations parameters and values as case sensitive: type=smb is
        correct and type=SMB is not; connectionString= is correct and connectionstring= is not.
        https://learn.microsoft.com/fslogix/reference-configuration-settings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProviderString
    )

    $problems = @()
    $typeMatch = [regex]::Match($ProviderString, '(?i)(?:^|,)\s*(type)\s*=\s*([^,]*)')
    if (-not $typeMatch.Success) {
        $problems += 'it has no type= part'
    }
    else {
        if ($typeMatch.Groups[1].Value -cne 'type') {
            $problems += ("'{0}=' must be written 'type='" -f $typeMatch.Groups[1].Value)
        }

        $typeValue = $typeMatch.Groups[2].Value.Trim()
        if (@('smb', 'azure') -cnotcontains $typeValue) {
            $problems += ("type '{0}' must be exactly 'smb' or 'azure' (lower case)" -f $typeValue)
        }
    }

    $connectionMatch = [regex]::Match($ProviderString, '(?i)(?:^|,)\s*(connectionstring)\s*=')
    if (-not $connectionMatch.Success) {
        $problems += 'it has no connectionString= part'
    }
    elseif ($connectionMatch.Groups[1].Value -cne 'connectionString') {
        $problems += ("'{0}=' must be written 'connectionString='" -f $connectionMatch.Groups[1].Value)
    }

    return @($problems)
}

function ConvertTo-RedactedFSLogixCloudCacheProviderEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProviderString
    )

    $providerType = (Get-FSLogixCloudCacheProviderField -ProviderString $ProviderString -FieldName 'type').ToLowerInvariant()
    $providerName = Get-FSLogixCloudCacheProviderField -ProviderString $ProviderString -FieldName 'name'
    $connectionString = Get-FSLogixCloudCacheProviderField -ProviderString $ProviderString -FieldName 'connectionString'
    $parts = @()

    if (-not [string]::IsNullOrWhiteSpace($providerType)) {
        $parts += "type=$providerType"
    }

    if (-not [string]::IsNullOrWhiteSpace($providerName)) {
        $parts += "name=$($providerName.Trim())"
    }

    if (-not [string]::IsNullOrWhiteSpace($connectionString)) {
        $trimmedConnectionString = $connectionString.Trim()
        if ($providerType -eq 'smb' -and $trimmedConnectionString.StartsWith('\\')) {
            $parts += "connectionString=$trimmedConnectionString"
        }
        else {
            # An azure provider's connectionString can hold a storage key.
            $parts += 'connectionString=[REDACTED]'
        }
    }

    if ($parts.Count -gt 0) {
        return ($parts -join ',')
    }

    return '[REDACTED]'
}

function ConvertTo-RedactedFSLogixRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ValueName,

        [AllowNull()]
        [object]$Value
    )

    if ($ValueName -eq 'CCDLocations') {
        $redactedProviders = @()
        foreach ($entry in @(Split-FSLogixCloudCacheProviderEntries -Value $Value)) {
            $redactedProviders += ConvertTo-RedactedFSLogixCloudCacheProviderEntry -ProviderString $entry
        }

        return @($redactedProviders)
    }

    if ($ValueName -match '(?i)key|token|password|secret|sas') {
        return '[REDACTED]'
    }

    if ($Value -is [System.Array]) {
        return @(ConvertTo-StringArray -Value $Value)
    }

    if ($null -eq $Value) {
        return ''
    }

    return [string]$Value
}

function Resolve-FSLogixProfileStorageLocations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('VHDLocations', 'CCDLocations')]
        [string]$ValueName,

        [AllowNull()]
        [object]$Value
    )

    $locations = @()
    if ($ValueName -eq 'VHDLocations') {
        foreach ($entry in @(Split-FSLogixRegistryLocationEntries -Value $Value)) {
            $locations += [PSCustomObject]@{
                ValueName      = $ValueName
                SourceValue    = $entry
                ProviderType   = 'direct'
                TestPath       = $entry
                ShouldTestPath = $true
                Detail         = 'Direct VHDLocations path.'
            }
        }

        return @($locations)
    }

    foreach ($entry in @(Split-FSLogixCloudCacheProviderEntries -Value $Value)) {
        $providerType = (Get-FSLogixCloudCacheProviderField -ProviderString $entry -FieldName 'type').ToLowerInvariant()
        $connectionString = Get-FSLogixCloudCacheProviderField -ProviderString $entry -FieldName 'connectionString'
        $redactedSourceValue = ConvertTo-RedactedFSLogixCloudCacheProviderEntry -ProviderString $entry
        if ([string]::IsNullOrWhiteSpace($providerType)) {
            $providerType = 'unknown'
        }

        $shouldTestPath = $false
        $testPath = ''
        $detail = "Cloud Cache location of type '$providerType' is not a file share, so it was not tested."

        if ($providerType -eq 'smb') {
            if (-not [string]::IsNullOrWhiteSpace($connectionString)) {
                $testPath = $connectionString.Trim()
                $shouldTestPath = $true
                $detail = 'Cloud Cache SMB location.'
            }
            else {
                $detail = 'Cloud Cache SMB location has no connectionString path to test.'
            }
        }

        $locations += [PSCustomObject]@{
            ValueName      = $ValueName
            SourceValue    = $redactedSourceValue
            ProviderType   = $providerType
            TestPath       = $testPath
            ShouldTestPath = $shouldTestPath
            Detail         = $detail
        }
    }

    return @($locations)
}

function Test-WinEventNoEventsFoundError {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return ($Message -match '(?i)No events were found that match the specified selection criteria')
}

function Test-WinEventLogMissingError {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return ($Message -match '(?i)There is not an event log on the .* computer that matches')
}

function Get-DiskSpaceStatus {
    <#
    .SYNOPSIS
        Pass / Warn / Fail for free disk space. This tool's own rule of thumb, not a Microsoft figure.
    .DESCRIPTION
        Fail under 5 GB, or under 10 percent when that is also under 20 GB.
        Warn under 10 GB, or under 15 percent when that is also under 40 GB.
        The GB guard stops a large, mostly-free disk (77 GB free of 950 GB) being called full.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double]$FreeGB,
        [Parameter(Mandatory)][double]$FreePercent
    )

    if ($FreeGB -lt 5 -or ($FreePercent -lt 10 -and $FreeGB -lt 20)) { return 'Fail' }
    if ($FreeGB -lt 10 -or ($FreePercent -lt 15 -and $FreeGB -lt 40)) { return 'Warn' }
    return 'Pass'
}

function Test-IsLocalComputerTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $normalized = $ComputerName.Trim()
    return (
        $normalized -eq '.' -or
        $normalized -eq 'localhost' -or
        $normalized -eq '127.0.0.1' -or
        $normalized -eq '::1' -or
        $normalized -ieq $env:COMPUTERNAME
    )
}

function Read-FSLogixProfileRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$LocalMachine,

        [Parameter(Mandatory)]
        [string]$SubKeyPath,

        [Parameter(Mandatory)]
        [string]$Label
    )

    $key = $null
    try {
        $key = $LocalMachine.OpenSubKey($SubKeyPath)
        if ($null -eq $key) {
            return [PSCustomObject]@{
                Label = $Label
                Path  = ('HKLM:\{0}' -f $SubKeyPath)
                Found = $false
                Error = ''
            }
        }

        $values = [ordered]@{}
        foreach ($valueName in @($key.GetValueNames())) {
            $value = $key.GetValue($valueName)
            if ($value -is [System.Array]) {
                $values[$valueName] = @(ConvertTo-StringArray -Value $value)
            }
            elseif ($null -eq $value) {
                $values[$valueName] = ''
            }
            else {
                $values[$valueName] = [string]$value
            }
        }

        return [PSCustomObject]@{
            Label  = $Label
            Path   = ('HKLM:\{0}' -f $SubKeyPath)
            Found  = $true
            Error  = ''
            Values = [PSCustomObject]$values
        }
    }
    catch {
        return [PSCustomObject]@{
            Label = $Label
            Path  = ('HKLM:\{0}' -f $SubKeyPath)
            Found = $false
            Error = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $key) {
            $key.Close()
        }
    }
}

function Get-FSLogixRegistrySnapshot {
    <#
    .SYNOPSIS
        Reads the documented FSLogix profile key and the undocumented Policies key from a host.
        Throws when the registry cannot be opened at all (Remote Registry stopped, no access).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [bool]$IsLocal = $false
    )

    $baseKey = $null
    try {
        if ($IsLocal) {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
        }
        else {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
        }

        return @(
            Read-FSLogixProfileRegistryKey -LocalMachine $baseKey -SubKeyPath $script:ProfileKeyPath -Label 'Profile settings'
            Read-FSLogixProfileRegistryKey -LocalMachine $baseKey -SubKeyPath $script:PolicyProfileKeyPath -Label 'Policies path (not documented for profile settings)'
        )
    }
    finally {
        if ($null -ne $baseKey) {
            $baseKey.Close()
        }
    }
}

function Get-RegistryValueText {
    <#
    .SYNOPSIS
        Reads one value from the FSLogix profile settings key, the only one FSLogix documents.
    .DESCRIPTION
        Earlier versions preferred HKLM\SOFTWARE\Policies\FSLogix\Profiles. FSLogix documents
        profile settings only under HKLM\SOFTWARE\FSLogix\Profiles, so a value under the
        Policies path is reported separately and never treated as the effective setting.
        https://learn.microsoft.com/fslogix/reference-configuration-settings
    #>
    [CmdletBinding()]
    param(
        [object[]]$RegistryKeys,

        [Parameter(Mandatory)]
        [string]$ValueName
    )

    foreach ($registryKey in @($RegistryKeys | Where-Object { $_.Path -eq ('HKLM:\{0}' -f $script:ProfileKeyPath) })) {
        if ($registryKey.Found -and $registryKey.PSObject.Properties.Name -contains 'Values') {
            if ($registryKey.Values.PSObject.Properties.Name -contains $ValueName) {
                return $registryKey.Values.$ValueName
            }
        }
    }

    return ''
}

function Get-FSLogixStorageSettingEvidence {
    <#
    .SYNOPSIS
        Checks VHDLocations / CCDLocations against the documented rules.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$VhdLocations,

        [AllowNull()]
        [object]$CcdLocations
    )

    $evidence = @()
    $hasVhd = @(ConvertTo-StringArray -Value $VhdLocations).Count -gt 0
    $hasCcd = @(ConvertTo-StringArray -Value $CcdLocations).Count -gt 0

    if ($hasVhd -and $hasCcd) {
        # "CCDLocations and VHDLocations must not both be present at the same time."
        # https://learn.microsoft.com/fslogix/reference-configuration-settings
        $evidence += New-EvidenceItem -Name 'Profile storage setting' -Status 'Fail' `
            -Detail 'Both VHDLocations and CCDLocations are set. FSLogix requires only one of them.' `
            -Action 'Ask an engineer to remove the one that is not in use (usually VHDLocations when Cloud Cache is intended).'
    }
    elseif (-not $hasVhd -and -not $hasCcd) {
        $evidence += New-EvidenceItem -Name 'Profile storage setting' -Status 'Fail' `
            -Detail 'Neither VHDLocations nor CCDLocations is set, so FSLogix has nowhere to keep profiles.' `
            -Action 'Check the FSLogix Group Policy or image for this server; the profile share location is missing.'
    }
    else {
        $settingName = if ($hasCcd) { 'CCDLocations (Cloud Cache)' } else { 'VHDLocations' }
        $evidence += New-EvidenceItem -Name 'Profile storage setting' -Status 'Pass' -Detail "Profile location is set in $settingName."
    }

    if ($hasCcd) {
        foreach ($entry in @(Split-FSLogixCloudCacheProviderEntries -Value $CcdLocations)) {
            $problems = @(Test-FSLogixCloudCacheProviderSpelling -ProviderString $entry)
            if ($problems.Count -gt 0) {
                $redacted = ConvertTo-RedactedFSLogixCloudCacheProviderEntry -ProviderString $entry
                $evidence += New-EvidenceItem -Name 'Cloud Cache location spelling' -Status 'Fail' `
                    -Detail ("CCDLocations entry '{0}' is misspelled: {1}. FSLogix treats these names as case sensitive." -f $redacted, ($problems -join '; ')) `
                    -Action "Ask an engineer to correct the CCDLocations value, for example type=smb,connectionString=\\server\share."
            }
        }
    }

    return @($evidence)
}

function New-CitrixFSLogixResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Warn', 'Fail')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Summary,

        [object[]]$Evidence,

        [string[]]$RecommendedNextSteps,

        [object]$RawOutput,

        [string]$StartedAt,

        [string[]]$Errors
    )

    [PSCustomObject]@{
        CheckId              = 'citrix.fslogix.triage'
        Name                 = 'Citrix/FSLogix Triage'
        Category             = 'Citrix'
        Status               = $Status
        Summary              = $Summary
        Evidence             = @($Evidence)
        RecommendedNextSteps = @($RecommendedNextSteps)
        RawOutput            = $RawOutput
        StartedAt            = $StartedAt
        FinishedAt           = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Error                = (@($Errors) -join '; ')
    }
}

function Get-TriageVerdict {
    [CmdletBinding()]
    param(
        [object[]]$Evidence,

        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $failures = @($Evidence | Where-Object { $_.Status -eq 'Fail' })
    $warnings = @($Evidence | Where-Object { $_.Status -eq 'Warn' })

    if ($failures.Count -gt 0) {
        return [PSCustomObject]@{ Status = 'Fail'; Summary = $failures[0].Detail }
    }

    if ($warnings.Count -gt 0) {
        return [PSCustomObject]@{ Status = 'Warn'; Summary = $warnings[0].Detail }
    }

    return [PSCustomObject]@{ Status = 'Pass'; Summary = "No FSLogix problems found on $ComputerName." }
}

function Invoke-CitrixFSLogixTriage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [string]$UserName = '',

        [int]$EventLookbackHours = 24
    )

    $startedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $ComputerName = $ComputerName.Trim()
    $UserName = $UserName.Trim()
    $eventStartTime = (Get-Date).AddHours(-1 * $EventLookbackHours)
    $isLocalTarget = Test-IsLocalComputerTarget -ComputerName $ComputerName
    $evidence = @()
    $errors = @()

    $rawOutput = [ordered]@{
        AffectedDevice     = $ComputerName
        AffectedUser       = $UserName
        EventLookbackHours = $EventLookbackHours
        Reachability       = @()
        Services           = @()
        Registry           = @()
        Events             = @()
        Disks              = @()
        ProfilePaths       = @()
    }

    # --- 1. Ping -------------------------------------------------------------------------
    try {
        $reachable = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop
        $rawOutput.Reachability += [PSCustomObject]@{ Target = $ComputerName; Succeeded = [bool]$reachable; Error = '' }

        if ($reachable) {
            $evidence += New-EvidenceItem -Name 'Server answers' -Status 'Pass' -Detail "$ComputerName answered a ping."
        }
        else {
            $evidence += New-EvidenceItem -Name 'Server answers' -Status 'Warn' `
                -Detail "$ComputerName did not answer a ping." `
                -Action 'Some servers block ping. If the checks below also fail, confirm the server name and that it is switched on.'
        }
    }
    catch {
        $errors += "Reachability: $($_.Exception.Message)"
        $rawOutput.Reachability += [PSCustomObject]@{ Target = $ComputerName; Succeeded = $false; Error = $_.Exception.Message }
        $evidence += New-EvidenceItem -Name 'Server answers' -Status 'Warn' -NotChecked `
            -Detail "Ping could not run: $($_.Exception.Message)" `
            -Action 'Check the server name is spelled correctly.'
    }

    # --- 2. Services ---------------------------------------------------------------------
    # Get-Service lost -ComputerName in PowerShell 6+; Win32_Service works on 3.0 through 7.x.
    try {
        $serviceSplat = @{ ClassName = 'Win32_Service'; Filter = "Name='frxsvc' OR Name='frxccds'"; ErrorAction = 'Stop' }
        if (-not $isLocalTarget) { $serviceSplat.ComputerName = $ComputerName }
        $services = @(Get-CimInstance @serviceSplat)

        $rawOutput.Services = @($services | ForEach-Object {
            [PSCustomObject]@{
                Name        = [string]$_.Name
                DisplayName = [string]$_.DisplayName
                Status      = [string]$_.State
                StartType   = [string]$_.StartMode
            }
        })

        foreach ($service in @($services)) {
            if ([string]$service.State -eq 'Running') {
                $evidence += New-EvidenceItem -Name ('Service {0}' -f $service.Name) -Status 'Pass' -Detail ('{0} is running.' -f $service.DisplayName)
            }
            else {
                $evidence += New-EvidenceItem -Name ('Service {0}' -f $service.Name) -Status 'Fail' `
                    -Detail ('{0} is {1} (start type {2}).' -f $service.DisplayName, $service.State, $service.StartMode) `
                    -Action 'FSLogix cannot load profiles while this service is stopped. Escalate to an engineer to start it and find out why it stopped.'
            }
        }

        foreach ($expectedService in @('frxsvc', 'frxccds')) {
            if (-not (@($services | ForEach-Object { [string]$_.Name }) -contains $expectedService)) {
                $evidence += New-EvidenceItem -Name ('Service {0}' -f $expectedService) -Status 'Warn' `
                    -Detail "$expectedService is not installed on $ComputerName." `
                    -Action 'FSLogix may not be installed on this server. Confirm this is the server the user signs in to.'
            }
        }
    }
    catch {
        $errors += "Services: $($_.Exception.Message)"
        $rawOutput.Services = @([PSCustomObject]@{ Name = ''; DisplayName = ''; Status = ''; StartType = ''; Error = $_.Exception.Message })
        $evidence += New-EvidenceItem -Name 'FSLogix services' -Status 'Warn' -NotChecked `
            -Detail "Could not read services: $($_.Exception.Message)" `
            -Action 'Run as an administrator of the server, and check WinRM is enabled on it.'
    }

    # --- 3/4. Registry configuration -----------------------------------------------------
    $registryKeys = @()
    try {
        $registryKeys = @(Get-FSLogixRegistrySnapshot -ComputerName $ComputerName -IsLocal $isLocalTarget)
        $rawOutput.Registry = @($registryKeys | ForEach-Object {
            $valueSummary = ''
            if ($_.Found -and $_.PSObject.Properties.Name -contains 'Values') {
                $pairs = @()
                foreach ($property in @($_.Values.PSObject.Properties)) {
                    $propertyValue = ConvertTo-RedactedFSLogixRegistryValue -ValueName $property.Name -Value $property.Value
                    if ($propertyValue -is [System.Array]) {
                        $propertyValue = ((ConvertTo-StringArray -Value $propertyValue) -join '; ')
                    }

                    $pairs += ('{0}={1}' -f $property.Name, $propertyValue)
                }
                $valueSummary = $pairs -join '; '
            }

            [PSCustomObject]@{
                Label  = [string]$_.Label
                Path   = [string]$_.Path
                Found  = [bool]$_.Found
                Values = $valueSummary
                Error  = [string]$_.Error
            }
        })

        $profileKey = @($registryKeys | Where-Object { $_.Path -eq ('HKLM:\{0}' -f $script:ProfileKeyPath) })[0]
        $policyKey = @($registryKeys | Where-Object { $_.Path -eq ('HKLM:\{0}' -f $script:PolicyProfileKeyPath) })[0]

        if ($profileKey.Found) {
            $enabled = Get-RegistryValueText -RegistryKeys $registryKeys -ValueName 'Enabled'
            if ($enabled -eq '1') {
                $evidence += New-EvidenceItem -Name 'FSLogix profiles switched on' -Status 'Pass' -Detail 'FSLogix profile containers are enabled (Enabled = 1).'
            }
            elseif ([string]::IsNullOrWhiteSpace($enabled)) {
                $evidence += New-EvidenceItem -Name 'FSLogix profiles switched on' -Status 'Fail' `
                    -Detail 'FSLogix settings exist but Enabled is not set, so profile containers are off.' `
                    -Action 'Users get a local or temporary profile. Escalate: the FSLogix policy is not fully applied to this server.'
            }
            else {
                $evidence += New-EvidenceItem -Name 'FSLogix profiles switched on' -Status 'Fail' `
                    -Detail "FSLogix profile containers are switched off (Enabled = $enabled)." `
                    -Action 'Users get a local or temporary profile. Escalate: check whether this server should be using FSLogix.'
            }

            $evidence += @(Get-FSLogixStorageSettingEvidence `
                -VhdLocations (Get-RegistryValueText -RegistryKeys $registryKeys -ValueName 'VHDLocations') `
                -CcdLocations (Get-RegistryValueText -RegistryKeys $registryKeys -ValueName 'CCDLocations'))
        }
        elseif (-not [string]::IsNullOrWhiteSpace($profileKey.Error)) {
            $errors += "Registry: $($profileKey.Error)"
            $evidence += New-EvidenceItem -Name 'FSLogix settings' -Status 'Warn' -NotChecked `
                -Detail "Could not read the FSLogix settings: $($profileKey.Error)" `
                -Action 'Run as an administrator of the server.'
        }
        else {
            $evidence += New-EvidenceItem -Name 'FSLogix settings' -Status 'Fail' `
                -Detail "No FSLogix profile settings found on $ComputerName (HKLM\$script:ProfileKeyPath is missing)." `
                -Action 'FSLogix is not configured here. Confirm this is the right server, then escalate.'
        }

        if ($null -ne $policyKey -and $policyKey.Found -and $policyKey.PSObject.Properties.Name -contains 'Values' -and @($policyKey.Values.PSObject.Properties).Count -gt 0) {
            $evidence += New-EvidenceItem -Name 'Settings in an unexpected place' -Status 'Warn' `
                -Detail "FSLogix values were found under HKLM\$script:PolicyProfileKeyPath. FSLogix documents profile settings only under HKLM\$script:ProfileKeyPath, so these may have no effect." `
                -Action 'Ask an engineer to check the Group Policy that writes these values.'
        }
    }
    catch {
        $errors += "Registry: $($_.Exception.Message)"
        $rawOutput.Registry = @([PSCustomObject]@{
            Label  = 'Registry'
            Path   = "HKLM:\$script:ProfileKeyPath"
            Found  = $false
            Values = ''
            Error  = $_.Exception.Message
        })
        $evidence += New-EvidenceItem -Name 'FSLogix settings' -Status 'Warn' -NotChecked `
            -Detail "Could not read the server's registry: $($_.Exception.Message)" `
            -Action 'The Remote Registry service may be stopped on the server, or you are not an administrator there.'
    }

    # --- 5. Events -----------------------------------------------------------------------
    $eventLogs = @(
        'Microsoft-FSLogix-Apps/Operational',
        'Microsoft-FSLogix-Apps/Admin',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    )

    foreach ($logName in $eventLogs) {
        $friendlyName = if ($logName -like 'Microsoft-FSLogix-*') { 'Recent FSLogix events' } else { 'Recent Remote Desktop events' }
        try {
            $eventSplat = @{ FilterHashtable = @{ LogName = $logName; StartTime = $eventStartTime }; MaxEvents = 25; ErrorAction = 'Stop' }
            if (-not $isLocalTarget) { $eventSplat.ComputerName = $ComputerName }
            $events = @(Get-WinEvent @eventSplat)
            $errorCount = @($events | Where-Object { $_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Critical' }).Count
            $warningCount = @($events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count

            foreach ($winEvent in @($events | Select-Object -First 10)) {
                $message = [string]$winEvent.Message
                if ($message.Length -gt 180) {
                    $message = $message.Substring(0, 180)
                }

                $rawOutput.Events += [PSCustomObject]@{
                    LogName      = $logName
                    TimeCreated  = $winEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    Id           = [int]$winEvent.Id
                    Level        = [string]$winEvent.LevelDisplayName
                    ProviderName = [string]$winEvent.ProviderName
                    Message      = $message
                    Error        = ''
                }
            }

            if ($errorCount -gt 0) {
                $evidence += New-EvidenceItem -Name $friendlyName -Status 'Fail' `
                    -Detail ('{0} error event(s) in {1} in the last {2} hour(s).' -f $errorCount, $logName, $EventLookbackHours) `
                    -Action 'Open Event Viewer on the server at this log (or use -OutputPath) and include the newest error in the ticket.'
            }
            elseif ($warningCount -gt 0) {
                $evidence += New-EvidenceItem -Name $friendlyName -Status 'Warn' `
                    -Detail ('{0} warning event(s) in {1} in the last {2} hour(s).' -f $warningCount, $logName, $EventLookbackHours) `
                    -Action 'Check whether the warning times match when the user had the problem.'
            }
            else {
                $evidence += New-EvidenceItem -Name $friendlyName -Status 'Pass' -Detail ('No errors or warnings in {0} in the last {1} hour(s).' -f $logName, $EventLookbackHours)
            }
        }
        catch {
            $eventErrorMessage = $_.Exception.Message
            if (Test-WinEventNoEventsFoundError -Message $eventErrorMessage) {
                $rawOutput.Events += [PSCustomObject]@{
                    LogName      = $logName
                    TimeCreated  = ''
                    Id           = 0
                    Level        = ''
                    ProviderName = ''
                    Message      = 'No events found during the selected lookback window.'
                    Error        = ''
                }
                $evidence += New-EvidenceItem -Name $friendlyName -Status 'Pass' -Detail ('No events in {0} in the last {1} hour(s).' -f $logName, $EventLookbackHours)
                continue
            }

            $errors += "Events ${logName}: $eventErrorMessage"
            $logMissing = Test-WinEventLogMissingError -Message $eventErrorMessage
            $rawOutput.Events += [PSCustomObject]@{
                LogName      = $logName
                TimeCreated  = ''
                Id           = 0
                Level        = ''
                ProviderName = ''
                Message      = ''
                Error        = $eventErrorMessage
            }
            if ($logMissing) {
                $missingAction = if ($logName -like 'Microsoft-FSLogix-*') {
                    'This log only exists where FSLogix is installed. Confirm this is the server the user signs in to.'
                }
                else {
                    'This log only exists on Remote Desktop session hosts. Confirm this is the server the user signs in to.'
                }
                $evidence += New-EvidenceItem -Name 'Event log missing' -Status 'Warn' `
                    -Detail "$logName does not exist on $ComputerName." -Action $missingAction
            }
            else {
                $evidence += New-EvidenceItem -Name 'Event log access' -Status 'Warn' -NotChecked `
                    -Detail "Could not read $logName on ${ComputerName}: $eventErrorMessage" `
                    -Action 'Run as an administrator of the server; remote event log access may be blocked by its firewall.'
            }
        }
    }

    # --- 6. Disks ------------------------------------------------------------------------
    try {
        $diskSplat = @{ ClassName = 'Win32_LogicalDisk'; Filter = 'DriveType=3'; ErrorAction = 'Stop' }
        if (-not $isLocalTarget) { $diskSplat.ComputerName = $ComputerName }
        $disks = @(Get-CimInstance @diskSplat)
        foreach ($disk in @($disks)) {
            $sizeGb = 0
            $freeGb = 0
            $freePercent = 0
            if ($disk.Size -gt 0) {
                $sizeGb = [math]::Round(([double]$disk.Size / 1GB), 2)
                $freeGb = [math]::Round(([double]$disk.FreeSpace / 1GB), 2)
                $freePercent = [math]::Round((([double]$disk.FreeSpace / [double]$disk.Size) * 100), 2)
            }

            $rawOutput.Disks += [PSCustomObject]@{
                DeviceId    = [string]$disk.DeviceID
                SizeGB      = [string]$sizeGb
                FreeGB      = [string]$freeGb
                FreePercent = [string]$freePercent
                Error       = ''
            }

            $diskDetail = '{0} GB free of {1} GB ({2} percent).' -f $freeGb, $sizeGb, $freePercent
            $diskStatus = Get-DiskSpaceStatus -FreeGB $freeGb -FreePercent $freePercent
            if ($diskStatus -eq 'Fail') {
                $evidence += New-EvidenceItem -Name ('Disk {0}' -f $disk.DeviceID) -Status 'Fail' -Detail $diskDetail `
                    -Action 'A full disk stops profiles loading. Run Drive-Storage-Report or Cleanup-CitrixVDAStorage on the server, or escalate.'
            }
            elseif ($diskStatus -eq 'Warn') {
                $evidence += New-EvidenceItem -Name ('Disk {0}' -f $disk.DeviceID) -Status 'Warn' -Detail $diskDetail `
                    -Action 'Disk is getting low. Mention it in the ticket so it can be cleaned up.'
            }
            else {
                $evidence += New-EvidenceItem -Name ('Disk {0}' -f $disk.DeviceID) -Status 'Pass' -Detail $diskDetail
            }
        }

        if ($disks.Count -eq 0) {
            $evidence += New-EvidenceItem -Name 'Disk free space' -Status 'Warn' -NotChecked -Detail 'No local disks were returned.'
        }
    }
    catch {
        $errors += "Disks: $($_.Exception.Message)"
        $rawOutput.Disks += [PSCustomObject]@{ DeviceId = ''; SizeGB = ''; FreeGB = ''; FreePercent = ''; Error = $_.Exception.Message }
        $evidence += New-EvidenceItem -Name 'Disk free space' -Status 'Warn' -NotChecked `
            -Detail "Could not read disk space: $($_.Exception.Message)" `
            -Action 'Run as an administrator of the server, and check WinRM is enabled on it.'
    }

    # --- 7. Profile share reachability ---------------------------------------------------
    $configuredLocations = @()
    foreach ($valueName in @('VHDLocations', 'CCDLocations')) {
        $registryValue = Get-RegistryValueText -RegistryKeys $registryKeys -ValueName $valueName
        if (@(ConvertTo-StringArray -Value $registryValue).Count -gt 0) {
            $configuredLocations += @(Resolve-FSLogixProfileStorageLocations -ValueName $valueName -Value $registryValue)
        }
    }

    if ($configuredLocations.Count -gt 0) {
        $testedLocationKeys = @{}
        foreach ($profileLocation in @($configuredLocations)) {
            $locationKey = '{0}|{1}|{2}' -f $profileLocation.ValueName, $profileLocation.SourceValue, $profileLocation.TestPath
            if ($testedLocationKeys.ContainsKey($locationKey)) {
                continue
            }

            $testedLocationKeys[$locationKey] = $true

            if (-not $profileLocation.ShouldTestPath) {
                $rawOutput.ProfilePaths += [PSCustomObject]@{
                    ConfiguredPath = [string]$profileLocation.SourceValue
                    TestedPath     = ''
                    Context        = 'Cloud Cache provider'
                    Reachable      = $false
                    Error          = [string]$profileLocation.Detail
                }
                $evidence += New-EvidenceItem -Name 'Profile storage reachable' -Status 'Warn' -NotChecked -Detail ([string]$profileLocation.Detail) `
                    -Action 'Check this storage location in the Azure portal or with an engineer.'
                continue
            }

            $profilePath = [string]$profileLocation.TestPath
            $pathToTest = ConvertTo-ProfilePathForTest -Path $profilePath -UserName $UserName
            $testContext = if ($isLocalTarget) { 'this computer' } else { $ComputerName }
            $pathReachable = $false
            $pathError = ''
            try {
                if ($isLocalTarget) {
                    $pathReachable = [bool](Test-Path -LiteralPath $pathToTest -ErrorAction Stop)
                }
                else {
                    $pathReachable = [bool](Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        param([string]$LiteralPath)
                        Test-Path -LiteralPath $LiteralPath -ErrorAction Stop
                    } -ArgumentList $pathToTest -ErrorAction Stop)
                }
            }
            catch {
                $pathError = $_.Exception.Message
                $errors += "Profile path ${profilePath}: $pathError"
            }

            $rawOutput.ProfilePaths += [PSCustomObject]@{
                ConfiguredPath = [string]$profileLocation.SourceValue
                TestedPath     = [string]$pathToTest
                Context        = $testContext
                Reachable      = $pathReachable
                Error          = $pathError
            }

            if ($pathReachable) {
                $evidence += New-EvidenceItem -Name 'Profile share reachable' -Status 'Pass' -Detail "$pathToTest can be reached from $testContext."
                continue
            }

            # From a remote session, Windows does not pass your credentials on to a second
            # machine (the "double hop"), so a share test run ON the server can fail even when
            # the share is fine. Testing from this PC as well tells the two cases apart.
            $why = if ($pathError) { " ($pathError)" } else { '' }
            if ($isLocalTarget) {
                $evidence += New-EvidenceItem -Name 'Profile share reachable' -Status 'Fail' `
                    -Detail "$pathToTest cannot be reached from this computer$why." `
                    -Action 'Profiles cannot load if the share is down. Check the file server is up and the share exists, then escalate.'
            }
            else {
                $fromHere = $false
                try { $fromHere = [bool](Test-Path -LiteralPath $pathToTest -ErrorAction Stop) } catch { $fromHere = $false }
                $hereText = if ($fromHere) { 'It CAN be reached from your PC' } else { 'It cannot be reached from your PC either' }
                $evidence += New-EvidenceItem -Name 'Profile share reachable' -Status 'Warn' -NotChecked `
                    -Detail ("{0} could not be confirmed from {1}{2}. {3}." -f $pathToTest, $ComputerName, $why, $hereText) `
                    -Action 'A remote test can fail only because Windows will not pass your sign-in on to the file server. If it works from your PC, sign in to the server itself to confirm; if not, check the file server.'
            }
        }
    }

    $verdict = Get-TriageVerdict -Evidence $evidence -ComputerName $ComputerName

    $nextSteps = @()
    if ($verdict.Status -eq 'Pass') {
        $nextSteps += "The server side of FSLogix looks healthy. Look at the user's own container next (Parse-FSLogixLogs, FSLogix-ProfileDiskRepair) or at the application they are using."
    }
    else {
        $nextSteps += "Start with the first problem listed; it is the most likely cause."
        $nextSteps += "A check that could not run is not proof the server is healthy. Re-run as an administrator of $ComputerName."
    }

    return New-CitrixFSLogixResult -Status $verdict.Status -Summary $verdict.Summary -Evidence $evidence `
        -RecommendedNextSteps $nextSteps -RawOutput ([PSCustomObject]$rawOutput) `
        -StartedAt $startedAt -Errors $errors
}

function Get-TriageHeadline {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Result)

    $target = $Result.RawOutput.AffectedDevice
    $who = if ($Result.RawOutput.AffectedUser) { " (user $($Result.RawOutput.AffectedUser))" } else { '' }
    $word = switch ($Result.Status) { 'Fail' { 'PROBLEMS FOUND' } 'Warn' { 'WARNINGS' } default { 'LOOKS HEALTHY' } }
    return ('FSLogix check for {0}{1}:  {2}' -f $target, $who, $word)
}

function ConvertTo-TriageText {
    <#
    .SYNOPSIS
        Builds the plain-text report (the same content as the console), ready to paste into a ticket.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Result)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add((Get-TriageHeadline -Result $Result))
    $lines.Add(('=' * 70))
    $lines.Add(('Checked: {0}   Events looked back: {1} hour(s)' -f $Result.StartedAt, $Result.RawOutput.EventLookbackHours))

    $sections = @(
        @{ Status = 'Fail'; Title = 'Problems:' },
        @{ Status = 'Warn'; Title = 'Warnings:' },
        @{ Status = 'Pass'; Title = 'Looks fine:' }
    )
    foreach ($section in $sections) {
        $items = @($Result.Evidence | Where-Object { $_.Status -eq $section.Status })
        if ($items.Count -eq 0) { continue }
        $lines.Add('')
        $lines.Add($section.Title)
        foreach ($item in $items) {
            $lines.Add(('  [{0}] {1}: {2}' -f $item.Status.ToUpperInvariant(), $item.Name, $item.Detail))
            if ($item.PSObject.Properties.Name -contains 'Action' -and $item.Action) {
                $lines.Add(('         What to do: {0}' -f $item.Action))
            }
        }
    }

    $lines.Add('')
    $lines.Add('Next steps:')
    foreach ($step in @($Result.RecommendedNextSteps)) {
        $lines.Add(('  - {0}' -f $step))
    }

    $settings = @($Result.RawOutput.Registry | Where-Object { $_.Found -and $_.Values })
    if ($settings.Count -gt 0) {
        $lines.Add('')
        $lines.Add('FSLogix settings (secrets redacted)')
        $lines.Add(('-' * 70))
        foreach ($setting in $settings) {
            $lines.Add(('{0}  [{1}]' -f $setting.Path, $setting.Label))
            foreach ($pair in ($setting.Values -split '; (?=[A-Za-z]+=)')) {
                $lines.Add(('  {0}' -f $pair))
            }
        }
    }

    return $lines.ToArray()
}

function Write-TriageConsole {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Result)

    $headColor = switch ($Result.Status) { 'Fail' { 'Red' } 'Warn' { 'Yellow' } default { 'Green' } }
    foreach ($line in @(ConvertTo-TriageText -Result $Result)) {
        $color = 'Gray'
        if ($line -like 'FSLogix check for *') { $color = $headColor }
        elseif ($line -match '^  \[FAIL\]') { $color = 'Red' }
        elseif ($line -match '^  \[WARN\]') { $color = 'Yellow' }
        elseif ($line -match '^  \[PASS\]') { $color = 'Green' }
        elseif ($line -match '^(Problems|Warnings|Looks fine|Next steps):$' -or $line -like 'FSLogix settings*') { $color = 'White' }
        elseif ($line -match '^[=-]+$') { $color = 'DarkGray' }
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ''
}

function Export-TriageReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][string]$OutputPath
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
    }

    $safeName = ($Result.RawOutput.AffectedDevice -replace '[^A-Za-z0-9._-]', '_')
    $stem = Join-Path $OutputPath ('FSLogixTriage_{0}_{1}' -f $safeName, (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    $textPath = "$stem.txt"
    $csvPath = "$stem.csv"

    ConvertTo-TriageText -Result $Result | Set-Content -LiteralPath $textPath -Encoding UTF8
    @($Result.Evidence) | Select-Object Status, Name, Detail, Action |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    return @($textPath, $csvPath)
}

# =============================================================================
# Ticket note (CaseKit.ps1)
# =============================================================================

function ConvertTo-CitrixFSLogixTriageTicketNote {
    <#
    .SYNOPSIS
        Maps a triage result to a ticket note. The gate decisions for this tool live here.
    .DESCRIPTION
        Pass -> Ruled out (only when the check really ran), Fail -> PROBLEM, Warn -> WARNING.
        A Warn that is NotChecked -> Could not check: ping, services, registry or event log
        that could not be read, disks that could not be read or were not returned, a profile
        share that could not be confirmed from the server (double hop), and a Cloud Cache
        location that is not a file share. Their Status stays Warn, so the verdict is unchanged.

        The FSLogix settings block (RawOutput.Registry) never goes into the note, and neither
        does a Cloud Cache entry: a misspelled-entry finding keeps only what is wrong with it,
        because the entry holds the connection string.

        Next steps are the result's RecommendedNextSteps. The headline is the report's own
        (Get-TriageHeadline), and the stamp scope is the session host that was checked.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Result,
        [string[]]$EvidencePaths = @()
    )

    $target = [string]$Result.RawOutput.AffectedDevice
    $items = New-Object System.Collections.Generic.List[object]

    foreach ($e in @($Result.Evidence)) {
        $text = [string]$e.Detail
        if ($e.Name -eq 'Cloud Cache location spelling') {
            # "CCDLocations entry '<entry>' is misspelled: <problems>. ..." - drop the entry.
            $text = $text -replace "^CCDLocations entry '.*' is misspelled: ", 'A Cloud Cache (CCDLocations) entry is misspelled: '
        }
        elseif ($e.Name -like 'Disk ?:*') {
            # The detail is only the numbers; the drive is in the name.
            $text = '{0} {1}' -f $e.Name, $text
        }

        $notChecked = ($e.PSObject.Properties.Name -contains 'NotChecked') -and [bool]$e.NotChecked
        switch ([string]$e.Status) {
            'Pass' { $items.Add((New-TicketNoteItem -Kind Clear -Text $text -CouldLook (-not $notChecked))) }
            'Fail' { $items.Add((New-TicketNoteItem -Kind Problem -Text $text)) }
            default {
                $kind = if ($notChecked) { 'NotChecked' } else { 'Warning' }
                $items.Add((New-TicketNoteItem -Kind $kind -Text $text))
            }
        }
    }

    $isLocal = (-not [string]::IsNullOrEmpty($target)) -and (Test-IsLocalComputerTarget -ComputerName $target)
    $from = if ($isLocal) { 'on the server itself' } else { 'from {0} over the network' -f $env:COMPUTERNAME }
    $who = if ($Result.RawOutput.AffectedUser) { ' for user {0}' -f $Result.RawOutput.AffectedUser } else { '' }
    $scopeLine = 'FSLogix on {0}{1}, checked {2}: services, profile settings, event logs (last {3} hours), disk space and the profile share.' -f `
        $target, $who, $from, $Result.RawOutput.EventLookbackHours

    $scope = if ($isLocal) { $env:COMPUTERNAME } else { $target }
    $stampArgs = @{ ScopeLabel = 'Computer'; Scope = $scope }
    $started = [datetime]::MinValue
    if ([datetime]::TryParseExact([string]$Result.StartedAt, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$started)) {
        $stampArgs['Now'] = $started
    }
    $stamp = New-TicketNoteStamp @stampArgs

    return New-TicketNote -Tool 'Citrix-FSLogix-Triage' -Headline (Get-TriageHeadline -Result $Result) -ScopeLine $scopeLine `
        -Items $items.ToArray() -NextSteps @($Result.RecommendedNextSteps) -Stamp $stamp -EvidencePaths $EvidencePaths
}

# The ticket-note kit ships beside this script (a copy of TicketNote\CaseKit.ps1). Without it
# the check still runs; only the note is skipped.
$kit = Join-Path $PSScriptRoot 'CaseKit.ps1'
if (Test-Path -LiteralPath $kit) { . $kit } else { $script:CaseKitMissing = $true }

if ($LoadFunctionsOnly) {
    return
}

if ($TicketNumber -and $script:CaseKitMissing) {
    if (-not $Quiet) { Write-Host "[WARN] CaseKit.ps1 is missing from this folder, so -TicketNumber $TicketNumber was ignored: the reports go to -OutputPath (if given) and there is no ticket note this time." -ForegroundColor Yellow }
    $TicketNumber = ''
    $script:CaseKitWarned = $true
}
if ($TicketNumber -and -not (Test-TicketNumber -TicketNumber $TicketNumber)) {
    $msg = "'$TicketNumber' is not a usable ticket number. Use letters, digits, - or _ (up to 32 characters, starting with a letter or digit), for example 482113."
    if (-not $Quiet) { Write-Host "[FAIL] $msg" -ForegroundColor Red }
    if ($PassThru) {
        # -PassThru callers get a result instead of exit 3; nothing was checked.
        $startFailure = New-CitrixFSLogixResult -Status 'Fail' -Summary $msg `
            -Evidence @(New-EvidenceItem -Name 'Input' -Status 'Fail' -Detail $msg) `
            -RecommendedNextSteps @('Run the check again with the ticket number as it appears in the ticket.') `
            -RawOutput ([PSCustomObject]@{ AffectedDevice = $ComputerName; AffectedUser = $UserName; EventLookbackHours = $EventLookbackHours }) `
            -StartedAt (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -Errors @($msg)
        $startFailure | Add-Member -NotePropertyName TicketNote -NotePropertyValue $null -Force
        return $startFailure
    }
    exit 3
}

$result = Invoke-CitrixFSLogixTriage -ComputerName $ComputerName -UserName $UserName -EventLookbackHours $EventLookbackHours

if (-not $Quiet) {
    Write-TriageConsole -Result $result
}

# Where the files go: with -TicketNumber, <OutputPath or the default root>\Ticket_<n> (reports
# and note together, so the note's evidence names sit beside it); with only -OutputPath, that
# folder; with neither, no files (the note goes to the clipboard, or the console).
$folder = $OutputPath
if ($TicketNumber) {
    $root = if ($OutputPath) { $OutputPath } else { Get-TicketNoteDefaultRoot }
    try {
        $folder = Resolve-TicketFolder -TicketNumber $TicketNumber -Root $root
    }
    catch {
        if (-not $Quiet) { Write-Host ("[WARN] Could not create the ticket folder under {0}: {1}" -f $root, $_.Exception.Message) -ForegroundColor Yellow }
    }
}

$evidencePaths = @()
if ($folder) {
    try {
        $files = Export-TriageReport -Result $result -OutputPath $folder
        $evidencePaths = @($files)
        if (-not $Quiet) {
            foreach ($file in $files) { Write-Host ('[INFO] Saved {0}' -f $file) -ForegroundColor Cyan }
        }
    }
    catch {
        Write-Host ("[WARN] Could not write the report to {0}: {1}" -f $folder, $_.Exception.Message) -ForegroundColor Yellow
    }
}

$note = $null
if ($script:CaseKitMissing) {
    if (-not $Quiet -and -not $script:CaseKitWarned) { Write-Host '[WARN] CaseKit.ps1 is missing from this folder - no ticket note this time.' -ForegroundColor Yellow }
}
else {
    # The note is extra: a failure while building or saving it never changes the verdict or the
    # exit code. The check's own result above stands.
    try {
        $note = ConvertTo-CitrixFSLogixTriageTicketNote -Result $result -EvidencePaths $evidencePaths
        if ($Quiet) {
            # Another script is the caller: no console and no clipboard. The note is still saved
            # when a folder is in play, and it is always on the result object.
            if ($folder) { $null = Save-TicketNote -Note $note -Folder $folder -PasteSafe:(-not $FullDetail) }
        }
        else {
            $null = Publish-TicketNote -Note $note -Folder $folder -PasteSafe:(-not $FullDetail) -NoClipboard:$NoClipboard
        }
    }
    catch {
        if (-not $Quiet) { Write-Host ("[WARN] Could not make the ticket note: {0}. The check above is still valid." -f $_.Exception.Message) -ForegroundColor Yellow }
        $note = $null
    }
}
$result | Add-Member -NotePropertyName TicketNote -NotePropertyValue $note -Force

if ($PassThru) {
    return $result
}

exit $(switch ($result.Status) { 'Fail' { 2 } 'Warn' { 1 } default { 0 } })
