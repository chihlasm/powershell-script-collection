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
      8. On an Azure Virtual Desktop (AVD) host only - one with the Remote Desktop Agent
         Loader service (RDAgentBootLoader) or the HKLM\SOFTWARE\Microsoft\RDInfraAgent key:
         the agent service is running, the host is registered to its host pool
         (IsRegistered = 1), no known agent errors in the Application log (events 3277, 3703,
         3019, 3389), and the rdp-sxs listener is in the Listen state (qwinsta). Every AVD
         finding links to Microsoft's fix. Citrix and RDS hosts get no AVD items.

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
    Do not copy the ticket note to the clipboard. Without it the note goes to the clipboard
    marked to stay out of clipboard history (Win+V) and the cloud clipboard; only when that
    fails (e.g. an MTA host) is Set-Clipboard used, which cannot opt out. Either way it
    travels over RDP clipboard redirection.
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
    Remote Registry service, and Event Log access (RPC); on AVD hosts also qwinsta's Remote
    Desktop Services RPC access for the rdp-sxs check. Run as an account that is a local
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
      Ticket note clipboard (in CaseKit.ps1): the WinForms clipboard first; Set-Clipboard is
      5.0, so the fallback is behind a Get-Command check; STA is the default since 3.0; never clip.exe,
      because $OutputEncoding is ASCII in 5.1 and would mangle non-ASCII names
        https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-clipboard?view=powershell-5.1
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1
      Clipboard history / cloud clipboard opt-out formats (CanIncludeInClipboardHistory,
      CanUploadToCloudClipboard; set by the kit's WinForms path, not by Set-Clipboard)
        https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats
      AVD agent: RDAgentBootLoader ("Remote Desktop Agent Loader") stopped = agent not running;
      HKLM\SOFTWARE\Microsoft\RDInfraAgent IsRegistered = 1 once registered; agent events in the
      Application log from WVD-Agent, WVD-Agent-Updater, RDAgentBootLoader, MsiInstaller;
      event 3277 with INVALID_REGISTRATION_TOKEN / EXPIRED_MACHINE_TOKEN (invalid registration
      key), INVALID_FORM (broker blocked: firewall, DNS, ciphers), ENDPOINT_NOT_FOUND (no usable
      session host), InstallMsiException (installer running or msiexec.exe blocked),
      DownloadMsiException (disk space), InstallationHealthCheckFailedException (stack
      listener); 3703 (RD Gateway URLs blocked); 3019 (web socket transport URLs blocked); 3389
      MissingMethodException (update reverted, .NET older than 4.7.2); qwinsta rdp-sxs STATE
      must be Listen, not listed or not Listen = stack issue
        https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent
      SxS Stack Listener health check failing is fatal; Upgrade Failed does not affect sessions
        https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-statuses-checks
      qwinsta /server:<servername>; output columns SESSIONNAME USERNAME ID STATE TYPE DEVICE
        https://learn.microsoft.com/windows-server/administration/windows-commands/qwinsta
      RegistryView.Registry64 for the agent key (OpenBaseKey / OpenRemoteBaseKey overloads)
        https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.openremotebasekey
      Get-WinEvent -FilterHashtable keys LogName, ProviderName, Id, StartTime
        https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent
      Win32_Service StartMode values (Disabled = the agent was switched off on purpose)
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service

    NOT VERIFIED ON LEARN: the free-disk-space thresholds (see Get-DiskSpaceStatus) are this
    tool's own rule of thumb, not a Microsoft figure. The short state words qwinsta prints
    (Active, Conn, Disc, Listen, Down, ...) are not listed on Learn; any word outside that list
    (for example on a non-English Windows) is reported as "could not check", never as healthy.
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

# Azure Virtual Desktop agent facts, all from
# https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent
#   - the agent registers under HKLM\SOFTWARE\Microsoft\RDInfraAgent, IsRegistered = 1 once registered
#   - agent events are in Windows Logs > Application from these sources
#   - each rule's ID, description text, meaning and fix is the page's section of that name
$script:AvdAgentLearnUrl = 'https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent'
$script:AvdAgentKeyPath = 'SOFTWARE\Microsoft\RDInfraAgent'
$script:AvdAgentEventSources = @('WVD-Agent', 'WVD-Agent-Updater', 'RDAgentBootLoader', 'MsiInstaller')
$script:AvdAgentEventIds = @(3277, 3703, 3019, 3389)
# Ticket-note wording for an AVD item that could not be checked (the note never carries the
# exception text; the local report does).
$script:AvdNotCheckedNoteText = @{
    'AVD agent service'          = 'Could not read the AVD agent service.'
    'AVD host pool registration' = 'Could not read the AVD host pool registration.'
    'AVD agent events'           = 'Could not read the Application log for AVD agent errors.'
    'AVD stack listener'         = 'Could not check the AVD rdp-sxs listener.'
}
$script:AvdAgentEventRules = @(
    # Event 3277 "with the description INVALID_REGISTRATION_TOKEN or EXPIRED_MACHINE_TOKEN": the
    # registration key that has been used isn't recognized as valid.
    @{ Id = 3277; Pattern = 'INVALID_REGISTRATION_TOKEN'; Label = 'INVALID_REGISTRATION_TOKEN'; Status = 'Fail'
        Meaning = 'the registration key the agent used is not recognized as valid'
        Fix = 'Escalate to an Azure Virtual Desktop admin: generate a new registration key for the host pool, give it to the agent and restart RDAgentBootLoader, then confirm IsRegistered is 1.' }
    @{ Id = 3277; Pattern = 'EXPIRED_MACHINE_TOKEN'; Label = 'EXPIRED_MACHINE_TOKEN'; Status = 'Fail'
        Meaning = 'the registration key the agent used is not recognized as valid'
        Fix = 'Escalate to an Azure Virtual Desktop admin: generate a new registration key for the host pool, give it to the agent and restart RDAgentBootLoader, then confirm IsRegistered is 1.' }
    # 3277 with INVALID_FORM: the agent can't connect to the broker; firewall or DNS settings,
    # or a cipher policy blocking TLS 1.2 to the broker.
    @{ Id = 3277; Pattern = 'INVALID_FORM'; Label = 'INVALID_FORM'; Status = 'Fail'
        Meaning = 'the agent cannot connect to the AVD broker'
        Fix = 'Escalate to the network team: firewall, proxy or DNS settings are blocking the broker (the BrokerResourceIdURI and BrokerResourceIdURIGlobal addresses in the RDInfraAgent key, each with /api/health added, should load), or a Group Policy cipher setting blocks the TLS 1.2 connection.' }
    # 3277 with ENDPOINT_NOT_FOUND: the broker couldn't find a session host to connect to.
    @{ Id = 3277; Pattern = 'ENDPOINT_NOT_FOUND'; Label = 'ENDPOINT_NOT_FOUND'; Status = 'Fail'
        Meaning = 'the broker could not find a session host to connect the user to'
        Fix = 'Check the host is powered on and still in its host pool, has not reached the session limit, the agent service is running and the stack listener works, and its registration key is valid and not expired.' }
    # 3277 with InstallMsiException: another installer is running, or Group Policy blocks msiexec.exe.
    @{ Id = 3277; Pattern = 'InstallMsiException'; Label = 'InstallMsiException'; Status = 'Fail'
        Meaning = 'the agent could not install an update'
        Fix = 'Another installer was running, or Group Policy blocks msiexec.exe: run rsop.msc and check Computer Configuration > Administrative Templates > Windows Components > Windows Installer > Turn off Windows Installer. If it is Enabled, ask the AD team to allow msiexec.exe.' }
    # 3277 with DownloadMsiException: not enough disk space for the agent.
    @{ Id = 3277; Pattern = 'DownloadMsiException'; Label = 'DownloadMsiException'; Status = 'Fail'
        Meaning = 'there is not enough disk space for the agent'
        # Same advice as this tool's own disk check (step 6): a named tool, or escalate.
        Fix = 'A full system disk stops the agent updating (see the Disk items). Run Drive-Storage-Report or Cleanup-CitrixVDAStorage on the server, or escalate and ask an engineer to enlarge the disk.' }
    # 3277 with InstallationHealthCheckFailedException: the stack listener isn't working.
    @{ Id = 3277; Pattern = 'InstallationHealthCheckFailedException'; Label = 'InstallationHealthCheckFailedException'; Status = 'Fail'
        Meaning = 'the side-by-side stack listener is not working'
        Fix = 'See the AVD stack listener item; if it is not listening, escalate to reinstall the Remote Desktop Services SxS Network Stack.' }
    # 3703 "with RD Gateway Url: is not accessible": the agent can't reach the gateway URLs.
    @{ Id = 3703; Pattern = 'RD Gateway Url'; Label = 'RD Gateway URL not accessible'; Status = 'Fail'
        Meaning = 'the agent cannot reach the RD Gateway URLs, so users cannot connect to this host'
        Fix = 'Escalate to the network team: allow the Azure Virtual Desktop Required URL list through the firewall and proxy, and confirm with the Required URL Check tool.' }
    # 3019: the agent can't reach the web socket transport URLs.
    @{ Id = 3019; Pattern = ''; Label = 'web socket transport blocked'; Status = 'Fail'
        Meaning = 'the agent cannot reach the web socket transport URLs, so users cannot connect to this host'
        Fix = 'Escalate to the network team: allow the Azure Virtual Desktop Required URL list through the firewall, proxy and DNS; a network trace shows where it is blocked.' }
    # 3389 "with MissingMethodException: Method not found": the agent update failed and reverted
    # to an earlier version, likely because .NET Framework is older than 4.7.2. The host keeps
    # working on the old agent ("Upgrade Failed" does not affect sessions,
    # https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-statuses-checks), so Warn.
    @{ Id = 3389; Pattern = 'MissingMethodException'; Label = 'MissingMethodException'; Status = 'Warn'
        Meaning = 'the agent update failed and the agent reverted to an earlier version'
        Fix = 'Escalate to an engineer to schedule a .NET Framework upgrade (4.7.2 or later) in a maintenance window; it needs a restart. The host keeps working on the old agent meanwhile.' }
)

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

# Text that looks like an Azure storage connection string, account key or SAS token. A
# malformed CCDLocations entry (a missing comma, say) can make a field read run on into the
# connection string, so anything matching this is never echoed into a finding or the note.
$script:SecretLikePattern = '(?i)AccountKey|SharedAccessSignature|\bsig=|DefaultEndpointsProtocol|connectionString\s*=\s*\S'

# Every finding about a Cloud Cache entry uses this fixed wording and never repeats a value
# from the entry. Report is the console/report text; Note is the ticket-note text, which also
# avoids the key names so the note never carries "connection string" at all (AC32).
$script:CloudCacheSpellingProblems = @(
    [PSCustomObject]@{ Report = 'it has no type= part'; Note = 'the type part is missing' }
    [PSCustomObject]@{ Report = "the type= key is not written exactly 'type=' (lower case)"; Note = "the word 'type' is not in lower case" }
    [PSCustomObject]@{ Report = "the type is not exactly 'smb' or 'azure' (lower case)"; Note = "the type is not exactly 'smb' or 'azure' (lower case)" }
    [PSCustomObject]@{ Report = 'it has no connectionString= part'; Note = 'the storage location part is missing' }
    [PSCustomObject]@{ Report = "the connectionString= key is not written exactly 'connectionString=' (capital S)"; Note = 'the storage location part is not spelled with the exact capitals FSLogix requires' }
)

$script:CloudCacheLocationDetails = @{
    Smb          = 'Cloud Cache SMB location.'
    SmbNoPath    = 'Cloud Cache SMB location has no share path to test.'
    SmbNotUnc    = 'Cloud Cache SMB location is not a plain file share path, so it was not tested.'
    Azure        = 'Cloud Cache location of type azure is not a file share, so it was not tested.'
    Unknown      = 'Cloud Cache location has no type this tool recognises (smb or azure), so it was not tested.'
    VhdSecret    = 'A VHDLocations entry looks like a storage key rather than a share path, so it was not tested.'
}

function Get-FSLogixCloudCacheProviderType {
    <#
    .SYNOPSIS
        Returns the provider type of one CCDLocations entry as smb, azure or unknown - never the
        raw text, which a malformed entry can run on into the connection string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProviderString
    )

    $rawType = (Get-FSLogixCloudCacheProviderField -ProviderString $ProviderString -FieldName 'type').ToLowerInvariant()
    if (@('smb', 'azure') -contains $rawType) {
        return $rawType
    }

    return 'unknown'
}

function Test-FSLogixPlainSharePath {
    <#
    .SYNOPSIS
        True when a configured location is a plain \\server\share path that is safe to show and
        test. Anything with ; or = in it has run on into other parts of the setting.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Path
    )

    return ($Path.StartsWith('\\') -and $Path -notmatch '[;=]' -and $Path -notmatch $script:SecretLikePattern)
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

    # Each problem is fixed wording from $script:CloudCacheSpellingProblems: it names the part
    # that is wrong and never repeats a value from the entry, which can hold a storage key.
    $problems = @()
    $typeMatch = [regex]::Match($ProviderString, '(?i)(?:^|,)\s*(type)\s*=\s*([^,]*)')
    if (-not $typeMatch.Success) {
        $problems += $script:CloudCacheSpellingProblems[0].Report
    }
    else {
        if ($typeMatch.Groups[1].Value -cne 'type') {
            $problems += $script:CloudCacheSpellingProblems[1].Report
        }

        $typeValue = $typeMatch.Groups[2].Value.Trim()
        if (@('smb', 'azure') -cnotcontains $typeValue) {
            $problems += $script:CloudCacheSpellingProblems[2].Report
        }
    }

    $connectionMatch = [regex]::Match($ProviderString, '(?i)(?:^|,)\s*(connectionstring)\s*=')
    if (-not $connectionMatch.Success) {
        $problems += $script:CloudCacheSpellingProblems[3].Report
    }
    elseif ($connectionMatch.Groups[1].Value -cne 'connectionString') {
        $problems += $script:CloudCacheSpellingProblems[4].Report
    }

    return @($problems)
}

function ConvertTo-RedactedFSLogixCloudCacheProviderEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProviderString
    )

    $providerType = Get-FSLogixCloudCacheProviderType -ProviderString $ProviderString
    $providerName = Get-FSLogixCloudCacheProviderField -ProviderString $ProviderString -FieldName 'name'
    $connectionString = Get-FSLogixCloudCacheProviderField -ProviderString $ProviderString -FieldName 'connectionString'
    $parts = @("type=$providerType")

    if (-not [string]::IsNullOrWhiteSpace($providerName)) {
        # A name that runs on into other parts (a missing comma) can carry the connection string.
        $trimmedName = $providerName.Trim()
        if ($trimmedName -match '[;=]' -or $trimmedName -match $script:SecretLikePattern) {
            $parts += 'name=[REDACTED]'
        }
        else {
            $parts += "name=$trimmedName"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($connectionString)) {
        $trimmedConnectionString = $connectionString.Trim()
        if ($providerType -eq 'smb' -and (Test-FSLogixPlainSharePath -Path $trimmedConnectionString)) {
            $parts += "connectionString=$trimmedConnectionString"
        }
        else {
            # An azure provider's connectionString can hold a storage key.
            $parts += 'connectionString=[REDACTED]'
        }
    }

    return ($parts -join ',')
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
        $items = @()
        foreach ($item in @(ConvertTo-StringArray -Value $Value)) {
            if ($item -match $script:SecretLikePattern) { $items += '[REDACTED]' } else { $items += $item }
        }

        return @($items)
    }

    if ([string]$Value -match $script:SecretLikePattern) {
        # A storage connection string pasted into another setting (VHDLocations, say).
        return '[REDACTED]'
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
            if ($entry -match '=' -or $entry -match $script:SecretLikePattern) {
                # Not a path at all: a storage key or connection string pasted into VHDLocations
                # (split on ';' it becomes Name=value pieces). Never test it (the path would be
                # echoed into the finding) and never show it.
                $locations += [PSCustomObject]@{
                    ValueName      = $ValueName
                    SourceValue    = '[REDACTED]'
                    ProviderType   = 'direct'
                    TestPath       = ''
                    ShouldTestPath = $false
                    Detail         = $script:CloudCacheLocationDetails.VhdSecret
                }
                continue
            }

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

    # Every Detail below is fixed wording from $script:CloudCacheLocationDetails, and the type is
    # only ever smb, azure or unknown: nothing read from the entry is repeated, because a
    # malformed entry can run on into its connection string.
    foreach ($entry in @(Split-FSLogixCloudCacheProviderEntries -Value $Value)) {
        $providerType = Get-FSLogixCloudCacheProviderType -ProviderString $entry
        $connectionString = (Get-FSLogixCloudCacheProviderField -ProviderString $entry -FieldName 'connectionString').Trim()
        $redactedSourceValue = ConvertTo-RedactedFSLogixCloudCacheProviderEntry -ProviderString $entry

        $shouldTestPath = $false
        $testPath = ''
        $detail = $script:CloudCacheLocationDetails.Unknown

        if ($providerType -eq 'azure') {
            $detail = $script:CloudCacheLocationDetails.Azure
        }
        elseif ($providerType -eq 'smb') {
            if ([string]::IsNullOrWhiteSpace($connectionString)) {
                $detail = $script:CloudCacheLocationDetails.SmbNoPath
            }
            elseif (Test-FSLogixPlainSharePath -Path $connectionString) {
                $testPath = $connectionString
                $shouldTestPath = $true
                $detail = $script:CloudCacheLocationDetails.Smb
            }
            else {
                $detail = $script:CloudCacheLocationDetails.SmbNotUnc
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

# =============================================================================
# Azure Virtual Desktop (AVD) agent checks
# =============================================================================
# Every fact below is from "Troubleshoot common Azure Virtual Desktop Agent issues"
# (https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent) unless
# another page is cited. They run only on a host that has the AVD agent: the RDAgentBootLoader
# service ("Remote Desktop Agent Loader") or the HKLM\SOFTWARE\Microsoft\RDInfraAgent key.

function Get-AvdAgentRegistry {
    <#
    .SYNOPSIS
        Reads IsRegistered from HKLM\SOFTWARE\Microsoft\RDInfraAgent on a host.
    .DESCRIPTION
        Returns Found / Error / Values like the FSLogix registry reader; Values holds only
        IsRegistered, as text ('1' once the host is registered to its host pool). The key also
        holds RegistrationToken, a secret, so no other value is read.
        Throws when the registry cannot be opened at all (Remote Registry stopped, no access).

        The 64-bit view is asked for explicitly, so a 32-bit PowerShell does not look under
        WOW6432Node and report a real AVD host as "no agent key". On a 32-bit OS the request
        falls back to the 32-bit view.
        https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.openbasekey
        https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.openremotebasekey
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [bool]$IsLocal = $false
    )

    $baseKey = $null
    $key = $null
    try {
        if ($IsLocal) {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        }
        else {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName, [Microsoft.Win32.RegistryView]::Registry64)
        }

        $path = 'HKLM:\{0}' -f $script:AvdAgentKeyPath
        try {
            $key = $baseKey.OpenSubKey($script:AvdAgentKeyPath)
        }
        catch {
            return [PSCustomObject]@{ Path = $path; Found = $false; Error = $_.Exception.Message }
        }

        if ($null -eq $key) {
            return [PSCustomObject]@{ Path = $path; Found = $false; Error = '' }
        }

        $values = [ordered]@{}
        $isRegistered = $key.GetValue('IsRegistered')
        if ($null -ne $isRegistered) {
            $values['IsRegistered'] = [string]$isRegistered
        }

        return [PSCustomObject]@{ Path = $path; Found = $true; Error = ''; Values = [PSCustomObject]$values }
    }
    finally {
        if ($null -ne $key) { $key.Close() }
        if ($null -ne $baseKey) { $baseKey.Close() }
    }
}

function Get-AvdStackListenerOutput {
    <#
    .SYNOPSIS
        Returns the lines of "qwinsta" (local) or "qwinsta /server:<name>" (remote).
    .DESCRIPTION
        Microsoft's check for the AVD side-by-side stack is to run qwinsta.exe and look at the
        rdp-sxs row. Throws when qwinsta cannot run or prints nothing; anything it does print is
        returned for ConvertFrom-AvdStackListenerOutput to judge.
        https://learn.microsoft.com/windows-server/administration/windows-commands/qwinsta

        qwinsta.exe is 64-bit only on a 64-bit OS; a 32-bit PowerShell reaches System32 through
        the Sysnative alias.
        https://learn.microsoft.com/windows/win32/winprog64/file-system-redirector
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [bool]$IsLocal = $false
    )

    $systemFolder = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { 'Sysnative' } else { 'System32' }
    $qwinsta = Join-Path $env:windir ('{0}\qwinsta.exe' -f $systemFolder)
    $arguments = @()
    if (-not $IsLocal) { $arguments += ('/server:{0}' -f $ComputerName) }

    $lines = @(& $qwinsta @arguments 2>&1 | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) {
        throw ('qwinsta returned nothing (exit code {0}).' -f $LASTEXITCODE)
    }

    return $lines
}

function ConvertTo-AvdStackListenerFacts {
    <#
    .SYNOPSIS
        Reduces qwinsta output to the listener facts this tool keeps; no user names.
    .DESCRIPTION
        qwinsta lists every session with its USERNAME, so its output is never stored. This keeps
        only what the rdp-sxs check needs, and that is all that goes into RawOutput:
          HeaderFound       the English header (SESSIONNAME ... STATE) was printed
          QwinstaError      an "Error [n]: ..." line qwinsta printed instead of a list, or ''
          Listeners         the rdp-sxs listener rows: session name and state only
          SignedInSessions  how many rows have a USERNAME (signed-in or disconnected users), or
                            $null when the USERNAME column could not be found
        https://learn.microsoft.com/windows-server/administration/windows-commands/qwinsta
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Lines = @()
    )

    $headerLine = @($Lines | Where-Object { $_ -match '\bSESSIONNAME\b' -and $_ -match '\bSTATE\b' }) | Select-Object -First 1
    $qwinstaError = ''
    $errorLine = @($Lines | Where-Object { $_ -match '^\s*Error\s*\[\d+\]' }) | Select-Object -First 1
    if ($errorLine) {
        $qwinstaError = $errorLine.Trim()
        if ($qwinstaError.Length -gt 200) { $qwinstaError = $qwinstaError.Substring(0, 200) }
    }

    $listeners = @()
    $signedIn = $null
    if ($headerLine) {
        $userColumn = $headerLine.IndexOf('USERNAME')
        if ($userColumn -ge 0) { $signedIn = 0 }

        foreach ($line in @($Lines)) {
            if ($line -eq $headerLine) { continue }

            # Row: [>]SESSIONNAME [USERNAME] ID STATE [TYPE] [DEVICE]. Only the listener row
            # counts: a user's session on the stack is named rdp-sxs...#<n> and says nothing
            # about the listener.
            if ($line -match '^\s*>?(?<session>rdp-sxs[^\s#]*)\s+(?:\S+\s+)?(?<id>\d+)\s+(?<state>\S+)') {
                $listeners += [PSCustomObject]@{ Session = $Matches['session']; State = $Matches['state'] }
            }

            # A row with something in the USERNAME column is a user's session (signed in or
            # disconnected). Only the count is kept, never the name.
            if ($userColumn -ge 0 -and $line -match '^(?<before>.*)\s\d+\s+[A-Za-z]\S*') {
                $before = $Matches['before']
                if ($before.Length -gt $userColumn -and -not [string]::IsNullOrWhiteSpace($before.Substring($userColumn))) {
                    $signedIn++
                }
            }
        }
    }

    return [PSCustomObject]@{
        HeaderFound      = [bool]$headerLine
        QwinstaError     = $qwinstaError
        Listeners        = @($listeners)
        SignedInSessions = $signedIn
    }
}

function ConvertFrom-AvdStackListenerOutput {
    <#
    .SYNOPSIS
        Judges qwinsta output: the rdp-sxs listener must be in the Listen state.
    .DESCRIPTION
        "If the STATE column for rdp-tcp and rdp-sxs entries isn't Listen, or if rdp-tcp and
        rdp-sxs entries aren't listed, it means that there's a stack issue." The SxS Stack
        Listener health check is fatal: users cannot connect to the session host.
        https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent
        https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-statuses-checks

        qwinsta prints localized headers and state words, so the output is judged only when the
        English header (SESSIONNAME ... STATE) is present and the rdp-sxs state is a word this
        tool knows. Anything else is "could not check" (Warn, NotChecked), never a pass.

        Takes the qwinsta lines, or the facts ConvertTo-AvdStackListenerFacts made from them.
        The fix restarts the host, which signs everyone out, so it is an escalation (D-017).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Lines = @(),

        [object]$Facts = $null
    )

    if ($null -eq $Facts) { $Facts = ConvertTo-AvdStackListenerFacts -Lines $Lines }

    $name = 'AVD stack listener'
    $signedIn = $Facts.SignedInSessions
    $usersPart = if ($null -eq $signedIn) { 'ask anyone signed in to save their work and sign out' }
    elseif ($signedIn -eq 0) { 'no one is signed in now' }
    elseif ($signedIn -eq 1) { 'ask the 1 signed-in user to save their work and sign out' }
    else { 'ask the {0} signed-in users to save their work and sign out' -f $signedIn }
    $fixAction = 'Users cannot connect while the AVD listener is down. Escalate: put the host in drain mode, {0}, then restart it; if rdp-sxs is still not listening, the Remote Desktop Services SxS Network Stack needs reinstalling (Windows Pro does not support it). Steps: {1}' -f $usersPart, $script:AvdAgentLearnUrl
    $couldNotAction = 'On the session host, run qwinsta.exe and check that the rdp-sxs row says Listen. Steps: {0}' -f $script:AvdAgentLearnUrl

    if (-not $Facts.HeaderFound) {
        if ($Facts.QwinstaError) {
            # qwinsta answered with an error instead of a list: usually no rights on the server,
            # or its Remote Desktop Services RPC endpoint cannot be reached from here.
            return New-EvidenceItem -Name $name -Status 'Warn' -NotChecked `
                -Detail ('Could not check the rdp-sxs listener: qwinsta reported "{0}".' -f $Facts.QwinstaError) `
                -Action ('Run as an administrator of the server, and check its firewall allows Remote Desktop Services RPC from your PC (qwinsta /server: uses it); or sign in to the server and run qwinsta.exe there to check the rdp-sxs row says Listen. Steps: {0}' -f $script:AvdAgentLearnUrl)
        }
        return New-EvidenceItem -Name $name -Status 'Warn' -NotChecked `
            -Detail 'Could not check the rdp-sxs listener: qwinsta output was not in a form this tool can read (for example a non-English Windows).' `
            -Action $couldNotAction
    }

    $states = @($Facts.Listeners)
    if ($states.Count -eq 0) {
        return New-EvidenceItem -Name $name -Status 'Fail' `
            -Detail 'No rdp-sxs listener is listed by qwinsta, so the AVD side-by-side stack is not working and users cannot connect.' `
            -Action $fixAction
    }

    $listening = @($states | Where-Object { $_.State -eq 'Listen' })
    if ($listening.Count -gt 0) {
        return New-EvidenceItem -Name $name -Status 'Pass' -Detail ('{0} is in the Listen state.' -f $listening[0].Session)
    }

    # The English state words qwinsta prints (see the qwinsta page example and the session
    # states in WTS_CONNECTSTATE_CLASS); anything else is likely a localized word.
    # https://learn.microsoft.com/windows/win32/api/wtsapi32/ne-wtsapi32-wts_connectstate_class
    $knownStates = @('Active', 'Conn', 'ConnQ', 'Shadow', 'Disc', 'Idle', 'Reset', 'Down', 'Init')
    $known = @($states | Where-Object { $knownStates -contains $_.State })
    if ($known.Count -lt $states.Count) {
        return New-EvidenceItem -Name $name -Status 'Warn' -NotChecked `
            -Detail ("Could not check the rdp-sxs listener: qwinsta shows its state as '{0}', a word this tool does not recognize." -f (@($states | ForEach-Object { $_.State }) -join "', '")) `
            -Action $couldNotAction
    }

    return New-EvidenceItem -Name $name -Status 'Fail' `
        -Detail ('{0} is in the {1} state, not Listen, so the AVD side-by-side stack is not accepting connections.' -f $known[0].Session, $known[0].State) `
        -Action $fixAction
}

function Get-AvdAgentEventRule {
    <#
    .SYNOPSIS
        Returns the $script:AvdAgentEventRules entry an agent event matches, or $null.
    .DESCRIPTION
        A rule matches on the event ID and, when the rule has a Pattern, on the description text.
        The description is only read here; it is never stored.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$WinEvent)

    $message = [string]$WinEvent.Message
    foreach ($candidate in $script:AvdAgentEventRules) {
        if ([int]$WinEvent.Id -ne $candidate.Id) { continue }
        if ($candidate.Pattern -and $message -notmatch $candidate.Pattern) { continue }
        return $candidate
    }
    return $null
}

function Get-AvdAgentEventEvidence {
    <#
    .SYNOPSIS
        Maps AVD agent events from the Application log to documented findings, one item each.
    .DESCRIPTION
        Events from the documented agent sources (WVD-Agent, WVD-Agent-Updater,
        RDAgentBootLoader, MsiInstaller) whose ID and description match a rule in
        $script:AvdAgentEventRules become one evidence item per rule, with the count and the
        newest time. An event with a watched ID that matches no rule is a warning to look it up.
        No events is a pass.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Events = @(),

        [int]$EventLookbackHours = 24
    )

    $agentEvents = @($Events | Where-Object { $script:AvdAgentEventSources -contains [string]$_.ProviderName })
    $findings = [ordered]@{}
    foreach ($winEvent in $agentEvents) {
        $rule = Get-AvdAgentEventRule -WinEvent $winEvent
        $key = if ($null -ne $rule) { '{0}|{1}' -f $rule.Id, $rule.Label } else { '{0}|unknown' -f $winEvent.Id }
        if (-not $findings.Contains($key)) {
            $findings[$key] = [PSCustomObject]@{ Id = [int]$winEvent.Id; Rule = $rule; Seen = 0; Newest = $null }
        }
        $finding = $findings[$key]
        $finding.Seen++
        if ($null -ne $winEvent.TimeCreated -and ($null -eq $finding.Newest -or $winEvent.TimeCreated -gt $finding.Newest)) {
            $finding.Newest = $winEvent.TimeCreated
        }
    }

    if ($findings.Count -eq 0) {
        return @(New-EvidenceItem -Name 'AVD agent events' -Status 'Pass' `
                -Detail ('No AVD agent errors (events {0}) in the Application log in the last {1} hour(s).' -f ($script:AvdAgentEventIds -join ', '), $EventLookbackHours))
    }

    $evidence = @()
    foreach ($finding in @($findings.Values)) {
        $when = if ($null -ne $finding.Newest) { ', newest {0}' -f ([datetime]$finding.Newest).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        $seen = 'Application event {0} ({1} time(s){2})' -f $finding.Id, $finding.Seen, $when
        if ($null -ne $finding.Rule) {
            $evidence += New-EvidenceItem -Name 'AVD agent event' -Status $finding.Rule.Status `
                -Detail ('{0}: {1} - {2}.' -f $seen, $finding.Rule.Label, $finding.Rule.Meaning) `
                -Action ('{0} Steps: {1}' -f $finding.Rule.Fix, $script:AvdAgentLearnUrl)
        }
        else {
            $evidence += New-EvidenceItem -Name 'AVD agent event' -Status 'Warn' `
                -Detail ('{0}: the AVD agent reported an error this tool does not recognize.' -f $seen) `
                -Action ('Open Event Viewer > Windows Logs > Application on the server, read the newest event {0} and look up its description in {1}' -f $finding.Id, $script:AvdAgentLearnUrl)
        }
    }

    return @($evidence)
}

function Get-AvdHostEvidence {
    <#
    .SYNOPSIS
        Runs the AVD agent checks on a host that has the agent; returns nothing for any other host.
    .DESCRIPTION
        Detection: the RDAgentBootLoader service is installed, or the RDInfraAgent key exists.
        When neither can be confirmed (both absent, or a read failed) no AVD item is added, so a
        Citrix or RDS host gets nothing; the FSLogix checks already warn about failed reads.
        Returns Evidence, Errors and Raw.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [bool]$IsLocal = $false,
        [Parameter(Mandatory)][datetime]$EventStartTime,
        [int]$EventLookbackHours = 24
    )

    $evidence = @()
    $errors = @()
    $readAction = 'Run as an administrator of the server, and check WinRM, Remote Registry and remote event log access are allowed on it.'

    # --- Agent service (Win32_Service: Get-Service has no -ComputerName in PowerShell 6+) ---
    $agentService = $null
    $serviceError = ''
    try {
        $serviceSplat = @{ ClassName = 'Win32_Service'; Filter = "Name='RDAgentBootLoader'"; ErrorAction = 'Stop' }
        if (-not $IsLocal) { $serviceSplat.ComputerName = $ComputerName }
        $agentService = @(Get-CimInstance @serviceSplat | Where-Object { [string]$_.Name -eq 'RDAgentBootLoader' })[0]
    }
    catch {
        $serviceError = $_.Exception.Message
    }

    # --- Agent registry ---
    $agentKey = $null
    $registryError = ''
    try {
        $agentKey = Get-AvdAgentRegistry -ComputerName $ComputerName -IsLocal $IsLocal
        if ($null -ne $agentKey -and -not [string]::IsNullOrWhiteSpace([string]$agentKey.Error)) {
            $registryError = [string]$agentKey.Error
        }
    }
    catch {
        $registryError = $_.Exception.Message
    }

    $keyFound = (-not $registryError) -and $null -ne $agentKey -and [bool]$agentKey.Found
    if ($null -eq $agentService -and -not $keyFound) {
        return [PSCustomObject]@{ Evidence = @(); Errors = @(); Raw = $null }
    }

    # Listener holds only the facts from ConvertTo-AvdStackListenerFacts (no qwinsta text, which
    # names every signed-in user); Events holds ID, source, time and matched rule (no message).
    $raw = [ordered]@{ AgentService = ''; IsRegistered = ''; Events = @(); Listener = $null }

    # "RDAgentBootLoader is either stopped or not running" / "There's no status for Remote
    # Desktop Agent Loader" = the agent is not running on the session host. Starting it is left
    # to an engineer, as for the FSLogix services (step 2).
    $serviceAction = 'The host cannot take AVD connections without the agent. Escalate to an engineer to start "Remote Desktop Agent Loader" (RDAgentBootLoader) and find out why it stopped; if it stops again, the host is probably not registered (see the other AVD items). Steps: {0}' -f $script:AvdAgentLearnUrl
    $disabledAction = 'Escalate: someone disabled the AVD agent on purpose (for example to take the host out of service), so do not start it. Ask the Azure Virtual Desktop admin whether this host should be taking users. Steps: {0}' -f $script:AvdAgentLearnUrl
    if ($serviceError) {
        $errors += "AVD agent service: $serviceError"
        $raw.AgentService = "Error: $serviceError"
        $evidence += New-EvidenceItem -Name 'AVD agent service' -Status 'Warn' -NotChecked `
            -Detail "Could not read the AVD agent service (RDAgentBootLoader): $serviceError" -Action $readAction
    }
    elseif ($null -eq $agentService) {
        $raw.AgentService = 'Not installed'
        $evidence += New-EvidenceItem -Name 'AVD agent service' -Status 'Fail' `
            -Detail "The AVD agent key exists but the Remote Desktop Agent Loader service (RDAgentBootLoader) is not installed on $ComputerName." `
            -Action ('If this server is meant to be an AVD session host, escalate: the AVD agent and boot loader need reinstalling and the host re-registering. If it is not (for example it was re-imaged from an AVD host), the key is a leftover. Steps: {0}' -f $script:AvdAgentLearnUrl)
    }
    elseif ([string]$agentService.State -eq 'Running') {
        $raw.AgentService = 'Running'
        $evidence += New-EvidenceItem -Name 'AVD agent service' -Status 'Pass' -Detail 'Remote Desktop Agent Loader (RDAgentBootLoader) is running.'
    }
    else {
        $raw.AgentService = [string]$agentService.State
        $evidence += New-EvidenceItem -Name 'AVD agent service' -Status 'Fail' `
            -Detail ('Remote Desktop Agent Loader (RDAgentBootLoader) is {0} (start type {1}).' -f $agentService.State, $agentService.StartMode) `
            -Action $(# Win32_Service.StartMode is Boot, System, Auto, Manual or Disabled.
                # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service
                if ([string]$agentService.StartMode -eq 'Disabled') { $disabledAction } else { $serviceAction })
    }

    # "verify that IsRegistered is set to 1" after registration.
    $registrationAction = 'Escalate to an Azure Virtual Desktop admin: generate a new registration key for the host pool and re-register this host, then confirm IsRegistered is 1. Steps: {0}' -f $script:AvdAgentLearnUrl
    if ($registryError) {
        $errors += "AVD agent registry: $registryError"
        $raw.IsRegistered = "Error: $registryError"
        $evidence += New-EvidenceItem -Name 'AVD host pool registration' -Status 'Warn' -NotChecked `
            -Detail "Could not read HKLM\$script:AvdAgentKeyPath on ${ComputerName}: $registryError" `
            -Action 'The Remote Registry service may be stopped on the server, or you are not an administrator there.'
    }
    else {
        $isRegistered = ''
        if ($keyFound -and $agentKey.PSObject.Properties.Name -contains 'Values' -and $null -ne $agentKey.Values -and
            $agentKey.Values.PSObject.Properties.Name -contains 'IsRegistered') {
            $isRegistered = [string]$agentKey.Values.IsRegistered
        }

        if (-not $keyFound) {
            $raw.IsRegistered = 'Key missing'
            $evidence += New-EvidenceItem -Name 'AVD host pool registration' -Status 'Fail' `
                -Detail "The host is not registered to its host pool: HKLM\$script:AvdAgentKeyPath is missing although the agent service is installed." `
                -Action $registrationAction
        }
        elseif ($isRegistered -eq '1') {
            $raw.IsRegistered = '1'
            $evidence += New-EvidenceItem -Name 'AVD host pool registration' -Status 'Pass' -Detail 'The host is registered to its host pool (IsRegistered = 1).'
        }
        else {
            $shown = if ([string]::IsNullOrWhiteSpace($isRegistered)) { 'IsRegistered is not set' } elseif ($isRegistered -match '^-?\d{1,10}$') { 'IsRegistered = {0}' -f $isRegistered } else { 'IsRegistered is not 1' }
            $raw.IsRegistered = $shown
            $evidence += New-EvidenceItem -Name 'AVD host pool registration' -Status 'Fail' `
                -Detail ("The host is not registered to its host pool ({0} under HKLM\{1})." -f $shown, $script:AvdAgentKeyPath) `
                -Action $registrationAction
        }
    }

    # --- Agent events (Application log) ---
    # Asked for by agent source as well as ID, so other programs' events with the same IDs
    # cannot crowd the agent's out of the MaxEvents window. A source that is not registered on
    # the host (for example WVD-Agent-Updater before the first update) makes Get-WinEvent
    # refuse the whole provider filter, so that query is asked once more by ID only and the
    # agent sources are picked in memory. Either way only agent events reach the evidence and
    # RawOutput, and RawOutput keeps no message text.
    # FilterHashtable keys LogName, ProviderName, Id, StartTime:
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent
    $events = @()
    $eventErrorMessage = ''
    $eventSplat = @{
        FilterHashtable = @{ LogName = 'Application'; ProviderName = $script:AvdAgentEventSources; Id = $script:AvdAgentEventIds; StartTime = $EventStartTime }
        MaxEvents       = 200
        ErrorAction     = 'Stop'
    }
    if (-not $IsLocal) { $eventSplat.ComputerName = $ComputerName }
    try {
        $events = @(Get-WinEvent @eventSplat)
    }
    catch {
        $firstErrorMessage = $_.Exception.Message
        if (-not (Test-WinEventNoEventsFoundError -Message $firstErrorMessage)) {
            $eventSplat.FilterHashtable = @{ LogName = 'Application'; Id = $script:AvdAgentEventIds; StartTime = $EventStartTime }
            try {
                $events = @(Get-WinEvent @eventSplat)
            }
            catch {
                $retryErrorMessage = $_.Exception.Message
                if (-not (Test-WinEventNoEventsFoundError -Message $retryErrorMessage)) {
                    $eventErrorMessage = $retryErrorMessage
                }
            }
        }
    }

    if ($eventErrorMessage) {
        $errors += "AVD agent events: $eventErrorMessage"
        $evidence += New-EvidenceItem -Name 'AVD agent events' -Status 'Warn' -NotChecked `
            -Detail "Could not read the Application log on ${ComputerName} for AVD agent errors: $eventErrorMessage" `
            -Action 'Run as an administrator of the server; remote event log access may be blocked by its firewall.'
    }
    else {
        $agentEvents = @($events | Where-Object { $script:AvdAgentEventSources -contains [string]$_.ProviderName })
        $raw.Events = @($agentEvents | Select-Object -First 10 | ForEach-Object {
                $rule = Get-AvdAgentEventRule -WinEvent $_
                [PSCustomObject]@{
                    Id           = [int]$_.Id
                    ProviderName = [string]$_.ProviderName
                    TimeCreated  = $(if ($null -ne $_.TimeCreated) { ([datetime]$_.TimeCreated).ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                    Rule         = $(if ($null -ne $rule) { $rule.Label } else { 'not recognized' })
                }
            })
        $evidence += @(Get-AvdAgentEventEvidence -Events $agentEvents -EventLookbackHours $EventLookbackHours)
    }

    # --- Side-by-side stack listener (qwinsta) ---
    # qwinsta lists every session with its user name: only the parsed listener facts are kept.
    try {
        $listenerFacts = ConvertTo-AvdStackListenerFacts -Lines @(Get-AvdStackListenerOutput -ComputerName $ComputerName -IsLocal $IsLocal)
        $raw.Listener = $listenerFacts
        $evidence += ConvertFrom-AvdStackListenerOutput -Facts $listenerFacts
    }
    catch {
        $errors += "AVD stack listener: $($_.Exception.Message)"
        $raw.Listener = [PSCustomObject]@{ Error = $_.Exception.Message }
        $evidence += New-EvidenceItem -Name 'AVD stack listener' -Status 'Warn' -NotChecked `
            -Detail "Could not run qwinsta against ${ComputerName}: $($_.Exception.Message)" `
            -Action 'Run as an administrator of the server, or sign in to it and run qwinsta.exe to check the rdp-sxs row says Listen.'
    }

    return [PSCustomObject]@{ Evidence = @($evidence); Errors = @($errors); Raw = [PSCustomObject]$raw }
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
        Avd                = $null
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
                # Only a short number is repeated; anything else in Enabled is described, not
                # echoed, so a stray value cannot carry data into the report or the note.
                $enabledShown = if ([string]$enabled -match '^-?\d{1,10}$') { 'Enabled = {0}' -f $enabled } else { 'Enabled is set, but not to 1' }
                $evidence += New-EvidenceItem -Name 'FSLogix profiles switched on' -Status 'Fail' `
                    -Detail "FSLogix profile containers are switched off ($enabledShown)." `
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
                    Context        = $(if ($profileLocation.ValueName -eq 'CCDLocations') { 'Cloud Cache provider' } else { 'VHDLocations entry' })
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

    # --- 8. Azure Virtual Desktop agent (AVD hosts only) ---------------------------------
    $avd = Get-AvdHostEvidence -ComputerName $ComputerName -IsLocal $isLocalTarget -EventStartTime $eventStartTime -EventLookbackHours $EventLookbackHours
    $evidence += @($avd.Evidence)
    $errors += @($avd.Errors)
    $rawOutput.Avd = $avd.Raw

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
        because the entry holds the connection string. Spelling and not-tested Cloud Cache lines
        are rebuilt from the tool's fixed wording, and any line that still looks like a
        connection string, account key or SAS token ($script:SecretLikePattern) is replaced.

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
            # Built from fixed wording only: the report's detail quotes the (redacted) entry, and
            # the note says what is wrong without the entry or its key names.
            $wrong = @($script:CloudCacheSpellingProblems | Where-Object { $text.Contains($_.Report) } | ForEach-Object { $_.Note })
            $text = if ($wrong.Count -gt 0) {
                'A Cloud Cache (CCDLocations) entry is misspelled: {0}. FSLogix treats these names as case sensitive.' -f ($wrong -join '; ')
            }
            else {
                'A Cloud Cache (CCDLocations) entry is misspelled. FSLogix treats these names as case sensitive.'
            }
        }
        elseif ($e.Name -eq 'Profile storage reachable') {
            # A location that was not tested; only the tool's own fixed sentences pass through.
            if (@($script:CloudCacheLocationDetails.Values) -notcontains $text) {
                $text = 'A profile storage location was not tested.'
            }
        }
        elseif ($e.Name -like 'Disk ?:*') {
            # The detail is only the numbers; the drive is in the name.
            $text = '{0} {1}' -f $e.Name, $text
        }
        elseif ($e.Name -like 'AVD *' -and ($e.PSObject.Properties.Name -contains 'NotChecked') -and [bool]$e.NotChecked) {
            # An AVD read that failed: fixed wording only. The exception text stays in the local
            # report and Errors.
            $text = if ($script:AvdNotCheckedNoteText.Contains([string]$e.Name)) { $script:AvdNotCheckedNoteText[[string]$e.Name] } else { 'Could not check the Azure Virtual Desktop agent.' }
        }

        # Last line of defence: whatever the wording above, a line that looks like a connection
        # string, account key or SAS token never reaches the note (or the clipboard).
        if ($text -match $script:SecretLikePattern) {
            $text = '{0}: details left out of this note because they looked like a storage key.' -f $e.Name
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
    $avdChecked = ($Result.RawOutput.PSObject.Properties.Name -contains 'Avd') -and ($null -ne $Result.RawOutput.Avd)
    $avdItems = @($Result.Evidence | Where-Object { [string]$_.Name -like 'AVD *' })
    $avdBlind = ($avdItems.Count -gt 0) -and (@($avdItems | Where-Object { -not (($_.PSObject.Properties.Name -contains 'NotChecked') -and [bool]$_.NotChecked) }).Count -eq 0)
    $avdPart = if ($avdChecked -and $avdBlind) { ', the profile share and the Azure Virtual Desktop agent (could not check)' }
    elseif ($avdChecked) { ', the profile share and the Azure Virtual Desktop agent' }
    else { ' and the profile share' }
    $scopeLine = 'FSLogix on {0}{1}, checked {2}: services, profile settings, event logs (last {3} hours), disk space{4}.' -f `
        $target, $who, $from, $Result.RawOutput.EventLookbackHours, $avdPart

    $scope = if ($isLocal) { $env:COMPUTERNAME } else { $target }
    $stampArgs = @{ ScopeLabel = 'Computer'; Scope = $scope }
    $started = [datetime]::MinValue
    if ([datetime]::TryParseExact([string]$Result.StartedAt, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$started)) {
        $stampArgs['Now'] = $started
    }
    $stamp = New-TicketNoteStamp @stampArgs
    $nextSteps = @(@($Result.RecommendedNextSteps) | Where-Object { [string]$_ -notmatch $script:SecretLikePattern })

    return New-TicketNote -Tool 'Citrix-FSLogix-Triage' -Headline (Get-TriageHeadline -Result $Result) -ScopeLine $scopeLine `
        -Items $items.ToArray() -NextSteps $nextSteps -Stamp $stamp -EvidencePaths $EvidencePaths
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
