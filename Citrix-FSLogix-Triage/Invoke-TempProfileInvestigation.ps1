# 3.0 so this runs on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) as shipped; Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    "Why did this user get a temporary profile?" - one user, one session host, one most likely
    cause and the next step, in plain English.
.DESCRIPTION
    Built for the service desk. Give it the user and the session host (or a Citrix Delivery
    Controller, which finds the host) and the first line of output is the answer:

        Temporary profile check for jdoe on CTX07:  CAUSE FOUND

    then the cause in one sentence, for example "The Citrix session on CTX04 is disconnected
    and still holds jdoe's profile disk open on FS01, so FSLogix could not attach it on CTX07.",
    and a "Next step:" line. Every other possible cause follows with its evidence, then what was
    ruled out and what could not be checked (and why).

    The tool is READ-ONLY. It never logs anyone off, closes a file, deletes a profile or starts
    a service. It recommends; it does not act.

    WHAT IT LOOKS AT

      On the session host (through Invoke-CitrixFSLogixTriage.ps1 in this folder): FSLogix
      services, whether profile containers are switched on, the profile location setting,
      recent FSLogix events, free disk space, and whether the profile share can be reached.

      Also on the session host:
        - the user's part of the FSLogix profile log (status, reason and error codes of their
          sign-ins in the lookback window)
        - Service Control Manager events saying the FSLogix service terminated unexpectedly
        - whether the user is signed in right now, and on a temporary profile

      On the profile file server: which computer has the user's profile disk (VHD/VHDX) open.

      With -DeliveryController: the user's Citrix sessions and their state.

    CAUSES, IN THE ORDER THEY ARE RANKED

      1  Profile disk held open by another computer (a session left on another server)
      2  FSLogix service stopped or crashed on the session host
      3  FSLogix profiles are off or not configured on the session host
      4  No permission on the profile share
      5  Cloud Cache storage / profile share unreachable
      6  An existing local profile stopped FSLogix
      7  The server's disk is full

      Each is Confirmed, Possible, Ruled out or Could not check. The top cause is the
      highest-ranked Confirmed one, else the highest-ranked Possible one.

    VERDICT
      CAUSE FOUND      at least one cause is confirmed
      POSSIBLE CAUSE   nothing confirmed, at least one possible
      NO CAUSE FOUND   every check ran and none found anything
      CAN'T TELL       nothing found, but at least one check could not run. A check that could
                       not run is never treated as clean.
.PARAMETER UserName
    The user, as jdoe or CONTOSO\jdoe. A bare name gets this PC's domain (USERDOMAIN).
    Alias: AffectedUser.
.PARAMETER ComputerName
    The session host the user got the temporary profile on. Alias: AffectedDevice. Required
    unless -DeliveryController is given; with both, this host is checked and the Delivery
    Controller only supplies the user's session states.
.PARAMETER DeliveryController
    A Citrix Delivery Controller. The tool asks it for the user's sessions, checks the server
    of the Active session and lists the others (a Disconnected session elsewhere is the usual
    lock holder). Needs the Citrix Broker snap-in (a Delivery Controller or a PC with Studio).
.PARAMETER EventLookbackHours
    Hours of FSLogix log and events to read. Default 24, maximum 168.
.PARAMETER OutputPath
    Optional folder. When given, a text report and a CSV of the causes are written there,
    named TempProfile_<user>_<host>_<yyyy-MM-dd_HHmmss>, and the ticket note is saved beside
    them. With -TicketNumber, this is the folder that holds Ticket_<number>.
.PARAMETER TicketNumber
    Optional ticket number (letters, digits, - or _, up to 32 characters). The report and the
    ticket note go into <root>\Ticket_<number>, where root is -OutputPath if given, else
    %USERPROFILE%\Documents\TicketNotes. A number that does not fit is refused with a [FAIL]
    line and exit code 1, before anything is checked.
.PARAMETER NoClipboard
    Do not copy the ticket note to the clipboard. Without it the note goes to the clipboard,
    where it can enter clipboard history (Win+V) or the cloud clipboard on Windows PowerShell
    5.0 and later, and travels over RDP clipboard redirection.
.PARAMETER FullDetail
    Keep file paths, profile disk names and IP addresses in the ticket note. By default the
    note is paste-safe: they are removed, and server and user names stay.
.PARAMETER PassThru
    Return the result object (CheckId, Status, Verdict, Summary, NextStep, Causes, Evidence,
    RecommendedNextSteps, RawOutput, StartedAt, FinishedAt, Error, ExitCode, TicketNote)
    instead of setting an exit code.
.PARAMETER Quiet
    Do not write the console report. Combine with -PassThru or -OutputPath. Also leaves the
    clipboard alone, because another script is the caller.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without running a check (used by the tests).
.EXAMPLE
    .\Invoke-TempProfileInvestigation.ps1 -UserName jdoe -ComputerName CTX07
    Why did jdoe get a temporary profile on CTX07?
.EXAMPLE
    .\Invoke-TempProfileInvestigation.ps1 -UserName jdoe -DeliveryController CTX-DDC01
    Let Citrix find the server jdoe is on, and show the state of jdoe's other sessions.
.EXAMPLE
    .\Invoke-TempProfileInvestigation.ps1 -UserName jdoe -ComputerName CTX07 -TicketNumber 482113
    Same answer; the report and the ticket note go into
    %USERPROFILE%\Documents\TicketNotes\Ticket_482113, and the note is copied to the clipboard.
.NOTES
    Exit codes (without -PassThru): 2 = CAUSE FOUND, 1 = POSSIBLE CAUSE or CAN'T TELL (also when
    the check could not start: no Citrix session, no Broker snap-in, unusable -TicketNumber,
    unknown user), 0 = NO CAUSE FOUND.

    Rights: a local administrator of the session host (ping, WinRM for CIM and Invoke-Command,
    Remote Registry, remote Event Log), and an administrator of the profile file server for the
    lock check. Without file-server rights the lock check says "could not check", never
    "ruled out". The lock check needs the SmbShare module on this PC (Windows 8 / Server 2012
    or later) and a file server running Server 2012 or later.

    TICKET NOTE. Every run ends with the four-part note from CaseKit.ps1 in this folder
    (Checked, Ruled out, Could not check, Next step). A cause is only "Ruled out" when its check
    really ran; a check that could not run is always under "Could not check". The note is
    paste-safe unless -FullDetail. A failure while making the note never changes the answer or
    the exit code.

    Companions in this folder: Invoke-CitrixFSLogixTriage.ps1 (the host checks, reused, not
    copied), CaseKit.ps1 (the ticket note), FSLogixReference.psd1 (FSLogix codes; a built-in
    copy keeps the tool working if the file is missing).

    REFERENCES
      FSLogix status, reason and error codes (Reason 3 = REASON_LOCAL_PROFILE_EXISTS; error
      codes are Windows System Error Codes); per-session values under
      HKLM\Software\FSLogix\Profiles\Sessions\%sid%
        https://learn.microsoft.com/fslogix/troubleshooting-error-codes
        https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
        https://learn.microsoft.com/windows/win32/debug/system-error-codes--1300-1699-
      FSLogix text logs: C:\ProgramData\FSLogix\Logs\Profile; search "LoadProfile: <sam>";
      follow the session's ID because other users' sessions can run at the same time;
      [INFO], [WARN:xxxxxxxx] and [ERROR:xxxxxxxx] prefixes
        https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics
      Logging settings: HKLM\SOFTWARE\FSLogix\Logging, LogDir (default %ProgramData%\FSLogix\Logs,
      local or UNC), LoggingEnabled (0 = all logs off); FlipFlopProfileDirectoryName
      (%sid%_%username% or %username%_%sid%); VHDLocations (REG_SZ ; separated or MULTI_SZ);
      DeleteLocalProfileWhenVHDShouldApply (deletes the local profile permanently)
        https://learn.microsoft.com/fslogix/reference-configuration-settings
      Temporary profile causes: profile in use on another computer ([ERROR:000000a7]
      AcquireExclusiveLock, ErrorCode 33), access denied ([ERROR:00000005]), local profile
      exists, FSLogix not enabled, VHDLocations/CCDLocations wrong, storage full
        https://learn.microsoft.com/fslogix/troubleshooting-old-temp-local-profiles
      Known issues: frxsvc crash during sign-in gives a temporary profile (2210); Event ID 26
      errors on Entra-only joined devices are expected and are not used as a cause here
        https://learn.microsoft.com/fslogix/troubleshooting-known-issues
      Get-SmbOpenFile: -ClientUserName, -ClientComputerName, -CimSession; output Path,
      ShareRelativePath, ClientComputerName (an IP address), ClientUserName (DOMAIN\name)
        https://learn.microsoft.com/powershell/module/smbshare/get-smbopenfile
      Get-SmbShare: -Name, -CimSession; output Name, Path
        https://learn.microsoft.com/powershell/module/smbshare/get-smbshare
      Win32_UserProfile: SID (key), Loaded, Status bit field (1 = Temporary, 8 = Corrupted)
        https://learn.microsoft.com/previous-versions/windows/desktop/legacy/ee886409(v=vs.85)
      Service Control Manager event 7034, "<service> terminated unexpectedly. It has done this
      X time(s)." in the System log
        https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/error-1053-1067-7034-after-update-openssh-doesnt-start
      Dns.GetHostEntry on an IP address does a reverse lookup and may return the address itself
      as HostName, or throw SocketException
        https://learn.microsoft.com/dotnet/api/system.net.dns.gethostentry
      NTAccount.Translate throws IdentityNotMappedException for an unknown account
        https://learn.microsoft.com/dotnet/api/system.security.principal.ntaccount.translate
      Citrix Broker SDK Get-BrokerSession: -AdminAddress (common Citrix parameter), -UserName
      (DOMAIN\user), -MaxRecordCount; output DNSName, HostedMachineName (hypervisor name, may
      not match DNS), MachineName, SessionState (Connected, Active, Disconnected, ...)
        https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2407/Broker/Get-BrokerSession.html
      Ticket note clipboard (in CaseKit.ps1): Set-Clipboard is 5.0, so it is used behind a
      Get-Command check with a WinForms fallback
        https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
      Import-PowerShellDataFile is 5.0; Import-LocalizedData reads the same file on 3.0 / 4.0
        https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/import-localizeddata

    NOT VERIFIED ON LEARN
      - Service Control Manager event 7031 ("terminated unexpectedly ... The following
        corrective action will be taken", logged instead of 7034 when a recovery action is
        set). Only Microsoft Q&A answers describe it, so it is read alongside 7034 and
        reported as the same crash.
      - The profile log file name. Learn shows Profile_%date%.log; FSLogix writes
        Profile-<yyyyMMdd>.log on current versions. Both are read (Profile*.log).
      - Tying an access-denied line that says "file is locked" to the lock rather than to
        permissions follows the Learn example of a locked disk, not a documented rule.
      - The free-disk thresholds are the triage's own rule of thumb (see that script).
#>
[CmdletBinding(DefaultParameterSetName = 'Host')]
param(
    [Parameter(Mandatory = $true)]
    [Alias('AffectedUser')]
    [string]$UserName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Host')]
    [Parameter(ParameterSetName = 'Broker')]
    [Alias('AffectedDevice')]
    [string]$ComputerName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Broker')]
    [string]$DeliveryController,

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

# No global $ErrorActionPreference change here (the functions are dot-sourced by the tests):
# every call that must stop says -ErrorAction Stop.

$script:TempProfileScriptRoot = $PSScriptRoot

# The cause ids in rank order. Squad decision (spec SQ-003): causes with direct, user-specific
# evidence (a lock held elsewhere, a crashed service) outrank host conditions that may be
# incidental. Every cause is still shown with its evidence, so a wrong top pick is visible.
$script:TempProfileCauseOrder = @('lock-held', 'frxsvc', 'fslogix-off', 'share-denied', 'storage', 'local-profile', 'disk-full')

# Built-in copy of FSLogixReference.psd1, used when the file is missing or unreadable. Must
# stay identical to the psd1 (Tests\Invoke-TempProfileInvestigation.Tests.ps1, AC30).
# https://learn.microsoft.com/fslogix/troubleshooting-error-codes
$script:FSLogixReferenceFallback = @{
    StatusCodes = @{
        '0'   = @{ Text = 'STATUS_SUCCESS: Success'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '1'   = @{ Text = "ERROR: Can't load user's profile"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '2'   = @{ Text = "ERROR_VIRT_DLL: Virtual disk API isn't available on this platform"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '3'   = @{ Text = "ERROR_GET_USER: Can't retrieve user's security identifier"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '4'   = @{ Text = 'ERROR_HANDLE_ODFC: There was an error setting up the Office 365 Container'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '5'   = @{ Text = "ERROR_SECURITY: Can't retrieve security information"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '6'   = @{ Text = "ERROR_VHD_PATH: Can't retrieve virtual disk location"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '7'   = @{ Text = "ERROR_CREATE_DIR: Can't create destination folders"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '8'   = @{ Text = "ERROR_IMPERSONATION: Can't impersonate user"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '9'   = @{ Text = "ERROR_CREATE_VHD: Can't create virtual disk"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '10'  = @{ Text = "ERROR_CLOSE_HANDLE: Can't release virtual disk"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '11'  = @{ Text = "ERROR_OPEN_VHD: Can't open virtual disk"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '12'  = @{ Text = "ERROR_ATTACH_VHD: Can't attach to virtual disk"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '13'  = @{ Text = "ERROR_GET_PHYSICAL_PATH: Can't retrieve virtual disk's physical information"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '14'  = @{ Text = "ERROR_OPEN_DEVICE: Can't open virtual disk's volume"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '15'  = @{ Text = "ERROR_INIT_DISK: Can't initialize virtual disk"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '16'  = @{ Text = "ERROR_GET_VOL_GUID: Can't retrieve virtual disk identifier"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '17'  = @{ Text = 'ERROR_FORMAT_VOL: Error while formatting virtual disk'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '18'  = @{ Text = "ERROR_GET_PROFILE_DIR: Can't retrieve profile directory"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '19'  = @{ Text = "ERROR_SET_MOUNT_POINT: Can't set up directory mount point"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '20'  = @{ Text = "ERROR_REG_IMPORT: Can't import registry information"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '21'  = @{ Text = "ERROR_CHK_GRP_MEMBERSHIP: Can't retrieve user's group"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '22'  = @{ Text = 'ERROR_HANDLE_PROFILE: Error handling profile'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '23'  = @{ Text = "ERROR_PROFILE_SUBFOLDER_REDIRECTION: Can't set up folder redirections"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '24'  = @{ Text = 'ERROR_CREATE_EVENT: Unable to create event'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '25'  = @{ Text = 'ERROR_PER_SESSION_VHD: Maximum sessions reached'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '26'  = @{ Text = "ERROR_DETACH_VHD: Can't detach virtual disk at the provided location"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '27'  = @{ Text = "ERROR_FIND_VHD: Can't find virtual disk at the provided location"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '28'  = @{ Text = 'ERROR_NO_SESSION_CONFIG: No user session config found'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '100' = @{ Text = "STATUS_WAITING_FOR_PROFILE_DIR_SET: Waiting for the Windows Profile Service to determine the user's profile folder"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '200' = @{ Text = 'STATUS_IN_PROGRESS: Setup in progress'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '300' = @{ Text = 'STATUS_ALREADY_ATTACHED: The profile is already attached (differencing disks only)'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
    }

    ReasonCodes = @{
        '0' = @{ Meaning = 'ProfileAttached'; Text = 'REASON_PROFILE_ATTACHED: The container is attached'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '1' = @{ Meaning = 'NotInIncludeGroup'; Text = "REASON_NOT_IN_WHITE_LIST: User isn't a member of the include group"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '2' = @{ Meaning = 'InExcludeGroup'; Text = 'REASON_IN_BLACK_LIST: User is a member of the exclude group'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '3' = @{ Meaning = 'LocalProfileExists'; Text = 'REASON_LOCAL_PROFILE_EXISTS: A local profile for this user exists on this system'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '4' = @{ Meaning = 'NotAppropriateUser'; Text = 'REASON_SHORT_SID: Not an appropriate user type'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '5' = @{ Meaning = 'Unset'; Text = 'REASON_UNSET: Reason initialized to empty state'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '6' = @{ Meaning = 'ComponentNotEnabled'; Text = "REASON_COMPONENT_NOT_ENABLED: Component isn't enabled in product key (legacy)"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '7' = @{ Meaning = 'WindowsTempProfile'; Text = 'REASON_WINDOWS_TEMP_PROFILE: Profile is a Windows temporary profile'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '8' = @{ Meaning = 'NotAvdSession'; Text = "REASON_NOT_WVD_SESSION: Session isn't an Azure Virtual Desktop Session"; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
        '9' = @{ Meaning = 'FailedToLoadProfile'; Text = 'REASON_FAILED_TO_LOAD_PROFILE: Profile load failed'; Url = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes' }
    }

    ErrorCodes = @{
        '2'    = @{ Meaning = 'NotFound'; Text = 'ERROR_FILE_NOT_FOUND: The system cannot find the file specified.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '3'    = @{ Meaning = 'NotFound'; Text = 'ERROR_PATH_NOT_FOUND: The system cannot find the path specified.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '5'    = @{ Meaning = 'AccessDenied'; Text = 'ERROR_ACCESS_DENIED: Access is denied.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '32'   = @{ Meaning = 'FileInUse'; Text = 'ERROR_SHARING_VIOLATION: The process cannot access the file because it is being used by another process.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '33'   = @{ Meaning = 'FileInUse'; Text = 'ERROR_LOCK_VIOLATION: The process cannot access the file because another process has locked a portion of the file.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '53'   = @{ Meaning = 'NetworkPathNotFound'; Text = 'ERROR_BAD_NETPATH: The network path was not found.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '67'   = @{ Meaning = 'NetworkPathNotFound'; Text = 'ERROR_BAD_NET_NAME: The network name cannot be found.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '167'  = @{ Meaning = 'FileInUse'; Text = 'ERROR_LOCK_FAILED: Unable to lock a region of a file.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '183'  = @{ Meaning = 'AlreadyExists'; Text = 'ERROR_ALREADY_EXISTS: Cannot create a file when that file already exists.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-' }
        '1326' = @{ Meaning = 'LogonFailure'; Text = 'ERROR_LOGON_FAILURE: The user name or password is incorrect.'; Url = 'https://learn.microsoft.com/windows/win32/debug/system-error-codes--1300-1699-' }
    }
}

# =============================================================================
# Small helpers
# =============================================================================

function Write-TempProfileStatus {
    # Same [PASS]/[WARN]/[FAIL]/[INFO] console style as the other tools.
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level = 'INFO'
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Get-TempProfileShortName {
    # CONTOSO\CTX04 / ctx04.contoso.com / CTX04 -> CTX04 (as given, without domain parts).
    # An IP address is returned unchanged.
    param([AllowEmptyString()][AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $leaf = ($Name.Trim() -split '\\')[-1]
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($leaf.Trim('[', ']'), [ref]$ip)) { return $leaf }
    return ($leaf -split '\.')[0]
}

function Test-TempProfileAccessDenied {
    # True when an error (exception or message) says access was denied.
    # 0x80070005 is E_ACCESSDENIED, ERROR_ACCESS_DENIED (5) as an HRESULT.
    # https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
    param([AllowNull()][object]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $text = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { [string]$ErrorRecord.Exception.Message } else { [string]$ErrorRecord }
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.Exception.PSObject.Properties['NativeErrorCode']) {
        if ([string]$ErrorRecord.Exception.NativeErrorCode -eq 'AccessDenied') { return $true }
    }
    return ($text -match '(?i)access (is )?denied|0x80070005|E_ACCESSDENIED')
}

function New-TempProfileFact {
    # A collector result: one of the documented states plus why (Reason) and what was seen.
    param([Parameter(Mandatory = $true)][string]$State, [string]$Reason = '', [hashtable]$More = @{})
    $o = [ordered]@{ State = $State; Reason = $Reason }
    foreach ($k in $More.Keys) { $o[$k] = $More[$k] }
    return [pscustomobject]$o
}

function Get-TempProfileFactPart {
    # A named fact, or $null when the facts object does not carry it.
    param([AllowNull()][object]$Facts, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Facts) { return $null }
    $p = $Facts.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# =============================================================================
# Reference data
# =============================================================================

function Import-TempProfileDataFile {
    # Import-PowerShellDataFile is PowerShell 5.0+. On 3.0 / 4.0 Import-LocalizedData reads the
    # same file the same way (restricted language, no code run).
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/import-localizeddata
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Get-Command -Name Import-PowerShellDataFile -ErrorAction SilentlyContinue) {
        return Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
    }
    $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    Import-LocalizedData -BaseDirectory (Split-Path -Parent $full) -FileName (Split-Path -Leaf $full) -ErrorAction Stop
}

function Get-FSLogixReference {
    <#
    .SYNOPSIS
        The FSLogix code table: FSLogixReference.psd1 beside this script, else the built-in copy.
    #>
    $root = $script:TempProfileScriptRoot
    if ($root) {
        $path = Join-Path $root 'FSLogixReference.psd1'
        if (Test-Path -LiteralPath $path) {
            try {
                $ref = Import-TempProfileDataFile -Path $path
                if ($ref -and $ref.ContainsKey('ReasonCodes')) { return $ref }
            } catch {
                Write-Verbose "Could not read ${path}, using the built-in copy: $($_.Exception.Message)"
            }
        }
    }
    return $script:FSLogixReferenceFallback
}

# =============================================================================
# Collectors (each returns a three-state fact and never throws for an expected failure)
# =============================================================================

function Get-TempProfileUserSid {
    # The user's SID, without the ActiveDirectory module. Throws IdentityNotMappedException
    # (inside a MethodInvocationException) for an unknown account.
    # https://learn.microsoft.com/dotnet/api/system.security.principal.ntaccount.translate
    param([Parameter(Mandatory = $true)][string]$UserName)
    $account = New-Object System.Security.Principal.NTAccount($UserName)
    return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Resolve-TempProfileClientName {
    # Reverse DNS for an SMB client address; $null when DNS has no name for it. GetHostEntry
    # can return the address itself as HostName when there is no PTR record, or throw.
    # https://learn.microsoft.com/dotnet/api/system.net.dns.gethostentry
    param([Parameter(Mandatory = $true)][string]$Address)
    try {
        $name = [string]([System.Net.Dns]::GetHostEntry($Address)).HostName
        if ([string]::IsNullOrWhiteSpace($name) -or $name -eq $Address) { return $null }
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($name, [ref]$ip)) { return $null }
        return $name
    } catch {
        return $null
    }
}

function ConvertTo-TempProfileShareTarget {
    # \\server\share\... -> @{ Server; Share; Azure }; $null when it is not a UNC path.
    param([Parameter(Mandatory = $true)][string]$Path)
    $m = [regex]::Match($Path.Trim(), '^\\\\(?<server>[^\\/]+)[\\/](?<share>[^\\/]+)')
    if (-not $m.Success) { return $null }
    $server = $m.Groups['server'].Value
    # Azure Files hosts are <account>.file.core.windows.net (or a sovereign-cloud suffix).
    return [pscustomobject]@{ Server = $server; Share = $m.Groups['share'].Value; Azure = ($server -match '(?i)\.file\.core\.') }
}

function Get-TempProfileOpenFile {
    # Get-SmbOpenFile that returns an empty list instead of the "No MSFT_SmbOpenFile objects
    # found" error a CDXML cmdlet raises when a filter matches nothing.
    param([Parameter(Mandatory = $true)][object]$CimSession, [string]$ClientUserName)
    $splat = @{ CimSession = $CimSession; ErrorAction = 'Stop' }
    if ($ClientUserName) { $splat.ClientUserName = $ClientUserName }
    try {
        return @(Get-SmbOpenFile @splat)
    } catch {
        if ($_.Exception.Message -match '(?i)No MSFT_SmbOpenFile objects found') { return @() }
        throw
    }
}

function Get-TempProfileLockFact {
    <#
    .SYNOPSIS
        Which computer has the user's profile disk open on the profile file server(s).
    .DESCRIPTION
        File servers come from VHDLocations and the SMB providers in CCDLocations (the host part
        of each \\server\share). For each one:
          - Azure Files: Could not check (needs Az; out of scope for this version).
          - Get-SmbShare -Name <share> must find the share there first. If it does not (for
            example \\files\profiles is a DFS namespace), the server is the wrong place to look
            and "no open files" would be a false all-clear, so this is Could not check.
          - Get-SmbOpenFile -ClientUserName DOMAIN\user, keeping VHD/VHDX files under the share
            (not ODFC_ disks). When none, every open file is searched for the user's profile
            folder, <SID>_<user> or (FlipFlopProfileDirectoryName) <user>_<SID>, because a Cloud
            Cache disk is opened by the session host's machine account.
          - Access denied anywhere is Could not check, with the right that is missing.
        Held when any server shows an open disk; else Could not check when any server could not
        be checked; else NotHeld.
        https://learn.microsoft.com/powershell/module/smbshare/get-smbopenfile
        https://learn.microsoft.com/powershell/module/smbshare/get-smbshare
        https://learn.microsoft.com/fslogix/reference-configuration-settings
    #>
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [string]$Sid,
        [string[]]$VhdLocations = @(),
        [string[]]$CcdLocations = @()
    )
    $sam = ($UserName -split '\\')[-1]
    $targets = New-Object System.Collections.Generic.List[object]
    $notShares = New-Object System.Collections.Generic.List[string]
    $azure = $false

    foreach ($entry in @(Split-FSLogixRegistryLocationEntries -Value @($VhdLocations))) {
        $t = ConvertTo-TempProfileShareTarget -Path $entry
        if ($null -eq $t) { $notShares.Add($entry); continue }
        if ($t.Azure) { $azure = $true } else { $targets.Add($t) }
    }
    foreach ($entry in @(Split-FSLogixCloudCacheProviderEntries -Value @($CcdLocations))) {
        $type = (Get-FSLogixCloudCacheProviderField -ProviderString $entry -FieldName 'type').ToLowerInvariant()
        if ($type -eq 'azure') { $azure = $true; continue }
        $connection = Get-FSLogixCloudCacheProviderField -ProviderString $entry -FieldName 'connectionString'
        $t = $null
        if ($connection) { $t = ConvertTo-TempProfileShareTarget -Path $connection }
        if ($null -eq $t) { $notShares.Add("Cloud Cache provider of type '$type'"); continue }
        if ($t.Azure) { $azure = $true } else { $targets.Add($t) }
    }

    $seen = @{}
    $results = New-Object System.Collections.Generic.List[object]
    if ($azure) {
        $results.Add((New-TempProfileFact -State 'CouldNotCheck' -Reason 'lock holders on Azure Files are not checked by this version (look in the Azure portal: the storage account, File shares, Handles)' -More @{ FileServer = 'Azure Files' }))
    }
    foreach ($location in $notShares) {
        $results.Add((New-TempProfileFact -State 'CouldNotCheck' -Reason ("the profile location '{0}' is not a \\server\share path, so no file server was asked" -f $location) -More @{ FileServer = '' }))
    }

    if ($targets.Count -gt 0 -and -not (Get-Command -Name Get-SmbOpenFile -ErrorAction SilentlyContinue)) {
        try {
            Import-Module SmbShare -ErrorAction Stop
        } catch {
            return (New-TempProfileFact -State 'CouldNotCheck' -Reason 'the SmbShare PowerShell module is not on this PC (it needs Windows 8 / Server 2012 or later); run this from such a PC' -More @{ FileServer = $targets[0].Server; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true; Detail = '' })
        }
    }

    foreach ($t in $targets) {
        $key = ('{0}\{1}' -f $t.Server, $t.Share).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $results.Add((Get-TempProfileLockFactForShare -Target $t -UserName $UserName -Sam $sam -Sid $Sid))
    }

    $blank = @{ FileServer = ''; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true; Detail = ''; Holders = @() }
    if ($results.Count -eq 0) {
        return (New-TempProfileFact -State 'CouldNotCheck' -Reason 'no profile location (VHDLocations or CCDLocations) to check' -More $blank)
    }

    $held = @($results | Where-Object { $_.State -eq 'Held' })
    if ($held.Count -gt 0) {
        $first = $held[0]
        $holders = @($held | ForEach-Object { @($_.Holders) })
        return (New-TempProfileFact -State 'Held' -More @{
                FileServer = $first.FileServer; FileName = $first.FileName; ClientComputer = $first.ClientComputer
                ClientAddress = $first.ClientAddress; ClientResolved = $first.ClientResolved; Detail = ''; Holders = $holders
            })
    }
    $blind = @($results | Where-Object { $_.State -eq 'CouldNotCheck' })
    if ($blind.Count -gt 0) {
        $more = $blank.Clone()
        $more.FileServer = [string]$blind[0].FileServer
        $more.Detail = ((@($results | Where-Object { $_.State -eq 'NotHeld' }) | ForEach-Object { $_.Detail }) -join '; ')
        return (New-TempProfileFact -State 'CouldNotCheck' -Reason ((@($blind) | ForEach-Object { $_.Reason }) -join '; ') -More $more)
    }
    $more = $blank.Clone()
    $more.FileServer = ($results.ToArray() | ForEach-Object { $_.FileServer }) -join ', '
    $more.Detail = ($results.ToArray() | ForEach-Object { $_.Detail }) -join '; '
    return (New-TempProfileFact -State 'NotHeld' -More $more)
}

function Get-TempProfileLockFactForShare {
    # One file server / share of Get-TempProfileLockFact.
    param(
        [Parameter(Mandatory = $true)][object]$Target,
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Sam,
        [string]$Sid
    )
    $server = $Target.Server
    $base = @{ FileServer = $server; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true; Detail = ''; Holders = @() }
    $deniedReason = "access denied on $server; you need to be an administrator of the file server"

    $session = $null
    try {
        $session = New-CimSession -ComputerName $server -ErrorAction Stop
    } catch {
        $why = if (Test-TempProfileAccessDenied $_) { $deniedReason } else { "could not connect to $server ($($_.Exception.Message))" }
        return (New-TempProfileFact -State 'CouldNotCheck' -Reason $why -More $base)
    }

    try {
        $shares = @()
        try {
            $shares = @(Get-SmbShare -CimSession $session -Name $Target.Share -ErrorAction Stop)
        } catch {
            if (Test-TempProfileAccessDenied $_) { return (New-TempProfileFact -State 'CouldNotCheck' -Reason $deniedReason -More $base) }
            if ($_.Exception.Message -notmatch '(?i)No MSFT_SmbShare objects found') {
                return (New-TempProfileFact -State 'CouldNotCheck' -Reason "could not list the shares on $server ($($_.Exception.Message))" -More $base)
            }
            $shares = @()
        }
        if ($shares.Count -eq 0) {
            $why = "$server has no share named $($Target.Share), so the profile path may be a DFS namespace; run against the real file server that holds the profile disks"
            return (New-TempProfileFact -State 'CouldNotCheck' -Reason $why -More $base)
        }
        $sharePath = [string]$shares[0].Path

        try {
            $disks = @(Select-TempProfileDisk -Files (Get-TempProfileOpenFile -CimSession $session -ClientUserName $UserName) -SharePath $sharePath)
            if ($disks.Count -eq 0) {
                # Cloud Cache (and some setups) open the disk as the session host's machine
                # account, so look for the user's profile folder among every open file.
                $disks = @(Select-TempProfileDisk -Files (Get-TempProfileOpenFile -CimSession $session) -SharePath $sharePath -Sam $Sam -Sid $Sid -RequireFolder)
            }
        } catch {
            $why = if (Test-TempProfileAccessDenied $_) { $deniedReason } else { "could not list open files on $server ($($_.Exception.Message))" }
            return (New-TempProfileFact -State 'CouldNotCheck' -Reason $why -More $base)
        }

        if ($disks.Count -eq 0) {
            $base.Detail = "$server shows no open profile disk for $Sam"
            return (New-TempProfileFact -State 'NotHeld' -More $base)
        }

        $holders = New-Object System.Collections.Generic.List[object]
        $seenClients = @{}
        foreach ($d in $disks) {
            $address = ([string]$d.ClientComputerName).Trim().Trim('[', ']')
            if ($seenClients.ContainsKey($address)) { continue }
            $seenClients[$address] = $true
            $ip = $null
            $name = $address
            $resolved = $true
            if ([System.Net.IPAddress]::TryParse($address, [ref]$ip)) {
                $name = Resolve-TempProfileClientName -Address $address
                $resolved = -not [string]::IsNullOrWhiteSpace($name)
            }
            $file = if ($d.ShareRelativePath) { [string]$d.ShareRelativePath } else { [string]$d.Path }
            $holders.Add([pscustomobject]@{
                    FileServer = $server; FileName = $file; ClientAddress = $address; ClientResolved = $resolved
                    ClientComputer = $(if ($resolved) { Get-TempProfileShortName $name } else { '' })
                    ClientFqdn = $(if ($resolved) { [string]$name } else { '' })
                })
        }
        $first = $holders[0]
        $base.FileName = $first.FileName
        $base.ClientComputer = $first.ClientComputer
        $base.ClientAddress = $first.ClientAddress
        $base.ClientResolved = $first.ClientResolved
        $base.Holders = $holders.ToArray()
        return (New-TempProfileFact -State 'Held' -More $base)
    } finally {
        if ($null -ne $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Select-TempProfileDisk {
    # Open files that are a profile disk: .vhd/.vhdx, not an ODFC_ (Office) container, under
    # the share's folder. -RequireFolder also needs the user's profile folder in the path.
    param(
        [object[]]$Files = @(),
        [string]$SharePath,
        [string]$Sam,
        [string]$Sid,
        [switch]$RequireFolder
    )
    $folderPatterns = @()
    if ($Sid) {
        $s = [regex]::Escape($Sid)
        # %sid%_%username% (default) or %username%_%sid% (FlipFlopProfileDirectoryName = 1)
        # https://learn.microsoft.com/fslogix/reference-configuration-settings
        $folderPatterns += ('(^|\\){0}_[^\\]*\\' -f $s)
        $folderPatterns += ('(^|\\)[^\\]*_{0}\\' -f $s)
    } elseif ($Sam) {
        $u = [regex]::Escape($Sam)
        $folderPatterns += ('(^|\\)S-1-[0-9-]+_{0}\\' -f $u)
        $folderPatterns += ('(^|\\){0}_S-1-[0-9-]+\\' -f $u)
    }
    $root = ([string]$SharePath).TrimEnd('\')
    foreach ($f in @($Files)) {
        if ($null -eq $f) { continue }
        $rel = [string]$f.ShareRelativePath
        $full = [string]$f.Path
        $probe = if ($rel) { $rel } else { $full }
        if ($probe -notmatch '(?i)\.vhdx?$') { continue }
        if ((Split-Path -Leaf $probe) -match '(?i)^ODFC') { continue }
        if ($root -and $full -and -not $full.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($RequireFolder) {
            if ($folderPatterns.Count -eq 0) { continue }
            $hit = $false
            foreach ($p in $folderPatterns) { if ($probe -match $p -or $full -match $p) { $hit = $true; break } }
            if (-not $hit) { continue }
        }
        $f
    }
}

function Read-TempProfileLogLines {
    # The lines of one FSLogix log file. FSLogix writes UTF-16LE with a byte order mark;
    # detectEncodingFromByteOrderMarks handles that (and UTF-8 with BOM), UTF-8 otherwise.
    # Same reader as Parse-FSLogixLogs\Parse-FSLogixLogs.ps1. This function's text is also
    # sent to the session host by Get-TempProfileLogFact, so it uses nothing else from here.
    param([Parameter(Mandatory = $true)][string]$Path)
    $reader = $null
    try {
        $reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::UTF8, $true)
        while (-not $reader.EndOfStream) { $reader.ReadLine() }
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
}

function ConvertFrom-TempProfileLog {
    <#
    .SYNOPSIS
        Reads the user's LoadProfile sessions out of FSLogix profile log lines.
    .DESCRIPTION
        A session starts at "===== Begin Session: LoadProfile: <user>" and is followed by its
        thread id ([tid:...]); Learn says to follow that id because other users' sign-ins run
        at the same time. Only the user's sessions are read (matched by name, or by the
        "User: <SID>" line). In them:
          Reason set to N   -> LocalProfile Found when the table's Meaning is LocalProfileExists
          [ERROR:xxxxxxxx]  -> ShareAccess Denied for AccessDenied (5) or LogonFailure (1326);
                               FileInUse codes (and access denied "file is locked") are lock
                               evidence (LockHint)
          a code that is not in the table -> UnknownCodes, shown verbatim, confirms nothing
        No session for the user in the lines -> both Could not check (never a false all-clear).
        https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics
        https://learn.microsoft.com/fslogix/troubleshooting-error-codes
        https://learn.microsoft.com/fslogix/troubleshooting-old-temp-local-profiles
    #>
    param(
        [string[]]$Lines = @(),
        [Parameter(Mandatory = $true)][string]$UserName,
        [string]$Sid,
        [hashtable]$Reference
    )
    if (-not $Reference) { $Reference = Get-FSLogixReference }
    $sam = ($UserName -split '\\')[-1]
    $lineRe = '^\[(?<time>[0-9:.]+)\]\[tid:(?<tid>[^\]]+)\]\[(?<level>[^\]]+)\]\s*(?<msg>.*?)\s*$'

    # Split into sessions, keyed by thread id so interleaved sign-ins stay apart.
    $open = @{}
    $sessions = New-Object System.Collections.Generic.List[object]
    foreach ($raw in @($Lines)) {
        if ($null -eq $raw) { continue }
        $m = [regex]::Match([string]$raw, $lineRe)
        if (-not $m.Success) { continue }
        $tid = $m.Groups['tid'].Value
        $msg = $m.Groups['msg'].Value
        $begin = [regex]::Match($msg, '^=+\s*Begin Session:\s*(?<kind>\w+)(?::\s*(?<who>\S+))?')
        if ($begin.Success) {
            $open.Remove($tid)
            if ($begin.Groups['kind'].Value -eq 'LoadProfile') {
                $who = ($begin.Groups['who'].Value -split '\\')[-1]
                $s = [pscustomobject]@{ Tid = $tid; IsUser = ($who -ieq $sam); Start = $m.Groups['time'].Value; Lines = (New-Object System.Collections.Generic.List[object]) }
                $open[$tid] = $s
                $sessions.Add($s)
            }
            continue
        }
        if (-not $open.ContainsKey($tid)) { continue }
        $current = $open[$tid]
        if ($msg -match '^=+\s*End Session') { $open.Remove($tid); continue }
        if ($Sid -and $msg -match '^User:\s*(?<sid>S-1-[0-9-]+)' -and $Matches['sid'] -eq $Sid) { $current.IsUser = $true }
        $current.Lines.Add([pscustomobject]@{ Time = $m.Groups['time'].Value; Level = $m.Groups['level'].Value.Trim(); Message = $msg })
    }

    $mine = @($sessions | Where-Object { $_.IsUser })
    $unknown = New-Object System.Collections.Generic.List[object]
    $notes = New-Object System.Collections.Generic.List[string]
    if ($mine.Count -eq 0) {
        $why = "the FSLogix profile log has no sign-in by $sam in the time looked at"
        return [pscustomobject]@{
            LocalProfile = (New-TempProfileFact -State 'CouldNotCheck' -Reason $why -More @{ Line = ''; Time = ''; Code = '' })
            ShareAccess  = (New-TempProfileFact -State 'CouldNotCheck' -Reason $why -More @{ Line = ''; Time = '' })
            UnknownCodes = @(); LockHint = $null; Notes = @(); SignIns = 0
        }
    }

    $local = $null; $denied = $null; $lock = $null; $errorNotes = 0
    foreach ($s in $mine) {
        foreach ($l in $s.Lines) {
            $msg = $l.Message
            $r = [regex]::Match($msg, '^Reason set to\s+(?<code>\d+):\s*(?<text>.*)$')
            if ($r.Success) {
                $code = $r.Groups['code'].Value
                $entry = $Reference.ReasonCodes[$code]
                if ($null -eq $entry) { $unknown.Add([pscustomobject]@{ Kind = 'reason'; Code = $code; Text = $r.Groups['text'].Value }); continue }
                if ($entry.Meaning -eq 'LocalProfileExists') { $local = @{ Line = $msg; Time = $l.Time; Code = $code } }
                elseif ($entry.Meaning -ne 'ProfileAttached') { $notes.Add(('FSLogix reason {0} at {1}: {2}' -f $code, $l.Time, $entry.Text)) }
                continue
            }
            $st = [regex]::Match($msg, '^Status set to\s+(?<code>\d+):\s*(?<text>.*)$')
            if ($st.Success) {
                $code = $st.Groups['code'].Value
                $entry = $Reference.StatusCodes[$code]
                if ($null -eq $entry) { $unknown.Add([pscustomobject]@{ Kind = 'status'; Code = $code; Text = $st.Groups['text'].Value }); continue }
                # Status 1-28 are errors; 0 and 100 / 200 / 300 are normal (Learn, FSLogix codes).
                $n = [int]$code
                if ($n -ge 1 -and $n -lt 100) { $notes.Add(('FSLogix status {0} at {1}: {2}' -f $code, $l.Time, $entry.Text)) }
                continue
            }
            $ec = [regex]::Match($msg, '^ErrorCode set to\s+(?<code>\d+)')
            $err = [regex]::Match($l.Level, '^ERROR:\s*(?<hex>[0-9A-Fa-f]+)$')
            $win32 = $null
            if ($err.Success) {
                $value = [Convert]::ToInt64($err.Groups['hex'].Value, 16)
                # 0x8007xxxx is a Win32 error wrapped in an HRESULT.
                if (($value -band 0xFFFF0000) -eq 0x80070000) { $value = $value -band 0xFFFF }
                $win32 = [string]$value
            } elseif ($ec.Success) {
                $win32 = $ec.Groups['code'].Value
            }
            if ($null -eq $win32) { continue }
            $entry = $Reference.ErrorCodes[$win32]
            $meaning = if ($entry) { [string]$entry.Meaning } elseif ($win32 -eq '5') { 'AccessDenied' } else { '' }
            $quoted = if ($err.Success) { '[{0}] {1}' -f $l.Level, $msg } else { $msg }
            $isLock = ($meaning -eq 'FileInUse') -or ($meaning -eq 'AccessDenied' -and $msg -match '(?i)file is locked')
            if ($isLock) { $lock = @{ Line = $quoted; Time = $l.Time } }
            elseif ($meaning -eq 'AccessDenied' -or $meaning -eq 'LogonFailure') { $denied = @{ Line = $quoted; Time = $l.Time } }
            elseif ($err.Success -and $errorNotes -lt 5) { $notes.Add(('FSLogix error at {0}: {1}' -f $l.Time, $quoted)); $errorNotes++ }
        }
    }

    $localFact = if ($local) { New-TempProfileFact -State 'Found' -More $local } else { New-TempProfileFact -State 'None' -More @{ Line = ''; Time = ''; Code = '' } }
    $deniedFact = if ($denied) { New-TempProfileFact -State 'Denied' -More $denied } else { New-TempProfileFact -State 'NoDenial' -More @{ Line = ''; Time = '' } }
    $lockHint = if ($lock) { [pscustomobject]$lock } else { $null }
    $notes.Insert(0, ('{0} FSLogix sign-in(s) by {1} in the profile log; the latest started at {2}.' -f $mine.Count, $sam, $mine[$mine.Count - 1].Start))
    return [pscustomobject]@{
        LocalProfile = $localFact; ShareAccess = $deniedFact; UnknownCodes = $unknown.ToArray()
        LockHint = $lockHint; Notes = $notes.ToArray(); SignIns = $mine.Count
    }
}

function Get-TempProfileLogFact {
    <#
    .SYNOPSIS
        Reads the user's part of the FSLogix profile log on the session host.
    .DESCRIPTION
        The log folder is LogDir under HKLM\SOFTWARE\FSLogix\Logging (default
        %ProgramData%\FSLogix\Logs), then \Profile; files written in the lookback window are
        read on the host (Invoke-Command) and only the lines that matter come back. When
        LoggingEnabled is 0, or the folder is missing, both facts are Could not check.
        https://learn.microsoft.com/fslogix/reference-configuration-settings
        https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$UserName,
        [string]$Sid,
        [int]$EventLookbackHours = 24
    )
    $since = (Get-Date).AddHours(-1 * $EventLookbackHours)
    $reader = ${function:Read-TempProfileLogLines}.ToString()
    $block = {
        param([string]$ReaderText, [datetime]$Since)
        $read = [scriptblock]::Create($ReaderText)
        $settings = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\FSLogix\Logging' -ErrorAction SilentlyContinue
        $enabled = if ($settings -and $null -ne $settings.LoggingEnabled) { [string]$settings.LoggingEnabled } else { '' }
        $dir = if ($settings -and $settings.LogDir) { [string]$settings.LogDir } else { '%ProgramData%\FSLogix\Logs' }
        $folder = Join-Path ([Environment]::ExpandEnvironmentVariables($dir)) 'Profile'
        $out = [pscustomobject]@{ Folder = $folder; LoggingEnabled = $enabled; Found = $false; Files = @(); Lines = @() }
        if (-not (Test-Path -LiteralPath $folder)) { return $out }
        $out.Found = $true
        $files = @(Get-ChildItem -LiteralPath $folder -Filter 'Profile*.log' -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $Since } | Sort-Object LastWriteTime)
        $out.Files = @($files | ForEach-Object { $_.Name })
        $keep = 'Begin Session|End Session|\]\s*User:|Status set to|Reason set to|ErrorCode set to|\[ERROR:'
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($f in $files) {
            foreach ($line in @(& $read -Path $f.FullName)) { if ($line -match $keep) { $lines.Add($line) } }
        }
        $out.Lines = $lines.ToArray()
        return $out
    }

    $splat = @{ ScriptBlock = $block; ArgumentList = @($reader, $since); ErrorAction = 'Stop' }
    if (-not (Test-IsLocalComputerTarget -ComputerName $ComputerName)) { $splat.ComputerName = $ComputerName }
    $read = Invoke-Command @splat

    $sam = ($UserName -split '\\')[-1]
    $blindWith = {
        param([string]$Why)
        [pscustomobject]@{
            LocalProfile = (New-TempProfileFact -State 'CouldNotCheck' -Reason $Why -More @{ Line = ''; Time = ''; Code = '' })
            ShareAccess  = (New-TempProfileFact -State 'CouldNotCheck' -Reason $Why -More @{ Line = ''; Time = '' })
            UnknownCodes = @(); LockHint = $null; Notes = @(); SignIns = 0
        }
    }
    if ($read.LoggingEnabled -eq '0') { return (& $blindWith "FSLogix logging is turned off on $ComputerName (LoggingEnabled = 0)") }
    if (-not $read.Found) { return (& $blindWith "there is no FSLogix profile log folder on $ComputerName ($($read.Folder))") }
    if (@($read.Files).Count -eq 0) { return (& $blindWith "no FSLogix profile log on $ComputerName was written in the last $EventLookbackHours hour(s)") }
    $parsed = ConvertFrom-TempProfileLog -Lines @($read.Lines) -UserName $UserName -Sid $Sid -Reference (Get-FSLogixReference)
    if ($parsed.SignIns -eq 0) {
        $why = "the FSLogix profile log on $ComputerName has no sign-in by $sam in the last $EventLookbackHours hour(s)"
        $parsed.LocalProfile.Reason = $why
        $parsed.ShareAccess.Reason = $why
    }
    return $parsed
}

function Get-TempProfileCrashFact {
    <#
    .SYNOPSIS
        Did the FSLogix service (frxsvc) crash in the lookback window?
    .DESCRIPTION
        System log, Service Control Manager event 7034 ("terminated unexpectedly"), and 7031
        (the same, when a recovery action is set; NOT VERIFIED ON LEARN, see .NOTES), for the
        FSLogix Apps Services service. The newest one is returned.
        https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/error-1053-1067-7034-after-update-openssh-doesnt-start
        https://learn.microsoft.com/fslogix/troubleshooting-known-issues
    #>
    param([Parameter(Mandatory = $true)][string]$ComputerName, [int]$EventLookbackHours = 24)
    $splat = @{
        FilterHashtable = @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = @(7034, 7031); StartTime = (Get-Date).AddHours(-1 * $EventLookbackHours) }
        ErrorAction     = 'Stop'
    }
    if (-not (Test-IsLocalComputerTarget -ComputerName $ComputerName)) { $splat.ComputerName = $ComputerName }
    try {
        $events = @(Get-WinEvent @splat)
    } catch {
        if (Test-WinEventNoEventsFoundError -Message $_.Exception.Message) { return (New-TempProfileFact -State 'None' -More @{ Time = ''; EventId = 0 }) }
        return (New-TempProfileFact -State 'CouldNotCheck' -Reason "could not read the System log on ${ComputerName}: $($_.Exception.Message)" -More @{ Time = ''; EventId = 0 })
    }
    # The first insertion string is the service's display name; the message is the fallback.
    $frx = @($events | Where-Object {
            $first = if ($_.Properties -and @($_.Properties).Count -gt 0) { [string]@($_.Properties)[0].Value } else { '' }
            ($first -match '(?i)FSLogix Apps Services|frxsvc') -or ([string]$_.Message -match '(?i)FSLogix Apps Services|frxsvc')
        } | Sort-Object TimeCreated -Descending)
    if ($frx.Count -eq 0) { return (New-TempProfileFact -State 'None' -More @{ Time = ''; EventId = 0 }) }
    return (New-TempProfileFact -State 'Crashed' -More @{ Time = $frx[0].TimeCreated; EventId = [int]$frx[0].Id; Count = $frx.Count })
}

function Get-TempProfileLoadedProfileFact {
    <#
    .SYNOPSIS
        Is the user signed in to the host right now, and on a temporary profile?
    .DESCRIPTION
        Win32_UserProfile for the user's SID: Loaded, and Status bit 1 = Temporary ("will be
        deleted after the user logs off"). Evidence only; it never changes the verdict.
        https://learn.microsoft.com/previous-versions/windows/desktop/legacy/ee886409(v=vs.85)
    #>
    param([Parameter(Mandatory = $true)][string]$ComputerName, [Parameter(Mandatory = $true)][string]$Sid)
    $splat = @{ ClassName = 'Win32_UserProfile'; Filter = ("SID='{0}'" -f $Sid); ErrorAction = 'Stop' }
    if (-not (Test-IsLocalComputerTarget -ComputerName $ComputerName)) { $splat.ComputerName = $ComputerName }
    try {
        $profiles = @(Get-CimInstance @splat)
    } catch {
        return (New-TempProfileFact -State 'CouldNotCheck' -Reason "could not read the user profiles on ${ComputerName}: $($_.Exception.Message)")
    }
    $loaded = @($profiles | Where-Object { $_.SID -eq $Sid -and $_.Loaded })
    if ($loaded.Count -eq 0) { return (New-TempProfileFact -State 'NotSignedIn') }
    $status = [int64]$loaded[0].Status
    $corrupted = (($status -band 8) -ne 0)
    if (($status -band 1) -ne 0) { return (New-TempProfileFact -State 'Temporary' -More @{ Corrupted = $corrupted }) }
    return (New-TempProfileFact -State 'LoadedNormal' -More @{ Corrupted = $corrupted })
}

function Import-CitrixBrokerSdk {
    <#
    .SYNOPSIS
        Loads the Citrix Broker SDK, trying the legacy PSSnapin before the module.
    .DESCRIPTION
        Copy of the one in Citrix-FSLogix-HealthCollector\Get-CitrixFSLogixHealth.ps1 (that
        folder is not a companion of this one), checking for Get-BrokerSession instead.
        Loaded at runtime rather than via #Requires -Modules, because #Requires blocks
        execution before the script starts on servers where the SDK is present but not
        formally registered. Returns $true when Get-BrokerSession is callable afterwards.
    #>
    [CmdletBinding()]
    param()

    if (Get-Command Get-BrokerSession -ErrorAction SilentlyContinue) {
        return $true
    }

    try {
        Add-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction Stop
        return $true
    }
    catch {
        Write-Verbose "PSSnapin Citrix.Broker.Admin.V2 unavailable: $_"
    }

    try {
        Import-Module Citrix.Broker.Admin.V2 -ErrorAction Stop
        return $true
    }
    catch {
        Write-Verbose "Module Citrix.Broker.Admin.V2 unavailable: $_"
    }

    return $false
}

function ConvertFrom-TempProfileTriage {
    <#
    .SYNOPSIS
        Turns an Invoke-CitrixFSLogixTriage result into this tool's host facts.
    .DESCRIPTION
        Reads the triage's evidence items by name (the triage is in this folder and its tests
        pin those names) and its RawOutput. Anything the triage could not read becomes Could
        not check, never clean. The host counts as unreachable only when it did not answer a
        ping AND neither its services nor its registry could be read (some servers block ping).
    #>
    param([AllowNull()][object]$Triage, [Parameter(Mandatory = $true)][string]$ComputerName, [string]$TriageError)

    $blind = if ($TriageError) { "the host checks failed on ${ComputerName}: $TriageError" } else { "the host checks did not run on $ComputerName" }
    if ($null -eq $Triage) {
        return [pscustomobject]@{
            HostReach     = (New-TempProfileFact -State 'Unreachable' -Reason $(if ($TriageError) { $TriageError } else { 'the host checks did not run' }))
            Service       = (New-TempProfileFact -State 'CouldNotCheck' -Reason $blind -More @{ Detail = '' })
            FslogixConfig = (New-TempProfileFact -State 'CouldNotCheck' -Reason $blind -More @{ Detail = '' })
            Storage       = (New-TempProfileFact -State 'CouldNotCheck' -Reason $blind -More @{ Kind = 'ProfileShare'; Unreachable = @(); Total = 0 })
            Disk          = (New-TempProfileFact -State 'CouldNotCheck' -Reason $blind -More @{ Detail = '' })
            VhdLocations  = @(); CcdLocations = @(); HostNotes = @(); FslogixEvents = @()
        }
    }

    $evidence = @($Triage.Evidence)
    $raw = $Triage.RawOutput
    $item = { param([string]$Name) @($evidence | Where-Object { $_.Name -eq $Name }) }

    # --- Reachability ---
    $ping = @(& $item 'Server answers')
    $servicesRead = (@(& $item 'FSLogix services').Count -eq 0)
    $registryRows = @($raw.Registry)
    $registryRead = ($registryRows.Count -gt 0 -and @($registryRows | Where-Object { $_.Error }).Count -eq 0)
    $reach = if (($ping.Count -gt 0 -and $ping[0].Status -eq 'Pass') -or $servicesRead -or $registryRead) {
        New-TempProfileFact -State 'Reached'
    } else {
        $why = if ($ping.Count -gt 0) { [string]$ping[0].Detail } else { "$ComputerName did not answer." }
        New-TempProfileFact -State 'Unreachable' -Reason ('{0}. Its services and registry could not be read either.' -f $why.TrimEnd('.'))
    }

    # --- Profile locations (configured values, from the triage's ProfilePaths rows) ---
    $rows = @($raw.ProfilePaths)
    $ccd = @($rows | Where-Object { [string]$_.ConfiguredPath -match '^\s*type\s*=' } | ForEach-Object { [string]$_.ConfiguredPath })
    $vhd = @($rows | Where-Object { [string]$_.ConfiguredPath -notmatch '^\s*type\s*=' } | ForEach-Object { [string]$_.ConfiguredPath })
    $isCloudCache = ($ccd.Count -gt 0)

    # --- FSLogix service (frxsvc; with Cloud Cache also frxccds, which Cloud Cache needs) ---
    # https://learn.microsoft.com/fslogix/reference-service-drivers-components
    $svcError = @(& $item 'FSLogix services')
    $frx = @(& $item 'Service frxsvc')
    $ccds = @(& $item 'Service frxccds')
    if ($svcError.Count -gt 0) {
        $service = New-TempProfileFact -State 'CouldNotCheck' -Reason ("could not read the services on {0}: {1}" -f $ComputerName, $svcError[0].Detail) -More @{ Detail = '' }
    } elseif ($frx.Count -eq 0) {
        $service = New-TempProfileFact -State 'CouldNotCheck' -Reason "the FSLogix service was not read on $ComputerName" -More @{ Detail = '' }
    } elseif ($frx[0].Status -eq 'Fail') {
        $service = New-TempProfileFact -State 'Stopped' -More @{ Detail = [string]$frx[0].Detail }
    } elseif ($frx[0].Status -eq 'Warn') {
        $service = New-TempProfileFact -State 'NotInstalled' -More @{ Detail = [string]$frx[0].Detail }
    } elseif ($isCloudCache -and $ccds.Count -gt 0 -and $ccds[0].Status -eq 'Fail') {
        $service = New-TempProfileFact -State 'Stopped' -More @{ Detail = ('{0} Cloud Cache needs it.' -f $ccds[0].Detail) }
    } else {
        $service = New-TempProfileFact -State 'Running' -More @{ Detail = [string]$frx[0].Detail }
    }

    # --- Profiles switched on and a location set ---
    $on = @(& $item 'FSLogix profiles switched on')
    $settings = @(& $item 'FSLogix settings')
    if ($on.Count -gt 0 -and $on[0].Status -eq 'Pass') {
        if ($rows.Count -eq 0) {
            $config = New-TempProfileFact -State 'NotConfigured' -More @{ Detail = 'FSLogix is switched on but no profile location (VHDLocations or CCDLocations) is set.' }
        } else {
            $config = New-TempProfileFact -State 'On' -More @{ Detail = [string]$on[0].Detail }
        }
    } elseif ($on.Count -gt 0) {
        $config = New-TempProfileFact -State 'Off' -More @{ Detail = [string]$on[0].Detail }
    } elseif ($settings.Count -gt 0 -and $settings[0].Status -eq 'Fail') {
        $config = New-TempProfileFact -State 'NotConfigured' -More @{ Detail = [string]$settings[0].Detail }
    } elseif ($settings.Count -gt 0) {
        $config = New-TempProfileFact -State 'CouldNotCheck' -Reason ([string]$settings[0].Detail) -More @{ Detail = '' }
    } else {
        $config = New-TempProfileFact -State 'CouldNotCheck' -Reason "the FSLogix settings were not read on $ComputerName" -More @{ Detail = '' }
    }

    # --- Profile storage reachable ---
    # The triage tests each SMB location from the host and, when that fails remotely, from this
    # PC too (the double hop). Unreachable = failed from the host and from this PC.
    $kind = if ($isCloudCache) { 'CloudCache' } else { 'ProfileShare' }
    $shareItems = @(& $item 'Profile share reachable')
    $tested = @($rows | Where-Object { $_.TestedPath })
    $unreachable = New-Object System.Collections.Generic.List[string]
    $unknown = 0
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($row in $tested) {
        $path = [string]$row.TestedPath
        $match = @($shareItems | Where-Object { ([string]$_.Detail).StartsWith($path, [System.StringComparison]::OrdinalIgnoreCase) })
        if ($match.Count -eq 0) { $unknown++; continue }
        $it = $match[0]
        if ($it.Status -eq 'Pass') { continue }
        if ($it.Status -eq 'Fail' -or ([string]$it.Detail -match 'cannot be reached from your PC either')) { $unreachable.Add($path); continue }
        if ([string]$it.Detail -match 'CAN be reached from your PC') { $notes.Add(('{0} could not be confirmed from {1} (the remote "double hop"), but it can be reached from this PC.' -f $path, $ComputerName)); continue }
        $unknown++
    }
    if ($config.State -eq 'CouldNotCheck') {
        $storage = New-TempProfileFact -State 'CouldNotCheck' -Reason $config.Reason -More @{ Kind = $kind; Unreachable = @(); Total = 0 }
    } elseif ($rows.Count -eq 0) {
        $storage = New-TempProfileFact -State 'CouldNotCheck' -Reason "no profile location is set on $ComputerName" -More @{ Kind = $kind; Unreachable = @(); Total = 0 }
    } elseif ($tested.Count -eq 0) {
        $storage = New-TempProfileFact -State 'CouldNotCheck' -Reason 'the profile storage is not a file share (Azure storage is not tested by this version)' -More @{ Kind = $kind; Unreachable = @(); Total = 0 }
    } elseif ($unreachable.Count -eq $tested.Count) {
        $storage = New-TempProfileFact -State 'AllUnreachable' -More @{ Kind = $kind; Unreachable = $unreachable.ToArray(); Total = $tested.Count }
    } elseif ($unreachable.Count -gt 0) {
        $storage = New-TempProfileFact -State 'SomeUnreachable' -More @{ Kind = $kind; Unreachable = $unreachable.ToArray(); Total = $tested.Count }
    } elseif ($unknown -gt 0) {
        $storage = New-TempProfileFact -State 'CouldNotCheck' -Reason "the profile share test on $ComputerName did not give a clear answer" -More @{ Kind = $kind; Unreachable = @(); Total = $tested.Count }
    } else {
        $storage = New-TempProfileFact -State 'Reachable' -More @{ Kind = $kind; Unreachable = @(); Total = $tested.Count; Notes = $notes.ToArray() }
    }

    # --- Disk space (the triage's Fail / Warn thresholds) ---
    $diskItems = @($evidence | Where-Object { $_.Name -like 'Disk *' -and $_.Name -ne 'Disk free space' })
    $diskError = @(& $item 'Disk free space')
    if ($diskItems.Count -eq 0) {
        $why = if ($diskError.Count -gt 0) { [string]$diskError[0].Detail } else { "disk space was not read on $ComputerName" }
        $disk = New-TempProfileFact -State 'CouldNotCheck' -Reason $why -More @{ Detail = '' }
    } else {
        $worst = 'Pass'
        if (@($diskItems | Where-Object { $_.Status -eq 'Fail' }).Count -gt 0) { $worst = 'Fail' }
        elseif (@($diskItems | Where-Object { $_.Status -eq 'Warn' }).Count -gt 0) { $worst = 'Warn' }
        $shown = if ($worst -eq 'Pass') { $diskItems } else { @($diskItems | Where-Object { $_.Status -eq $worst }) }
        $detail = (@($shown) | ForEach-Object { '{0} {1}' -f ($_.Name -replace '^Disk\s+', ''), $_.Detail }) -join ' '
        $disk = New-TempProfileFact -State $worst -More @{ Detail = $detail }
    }

    # --- Everything else the triage flagged, kept as evidence ---
    $used = @('Server answers', 'Service frxsvc', 'FSLogix services', 'FSLogix profiles switched on', 'FSLogix settings', 'Profile share reachable', 'Profile storage reachable', 'Disk free space')
    $hostNotes = @($evidence | Where-Object { $_.Status -ne 'Pass' -and $used -notcontains $_.Name -and $_.Name -notlike 'Disk *' } |
            ForEach-Object { 'Host check ({0}) {1}: {2}' -f $_.Status.ToUpperInvariant(), $_.Name, $_.Detail })
    $hostNotes += @($notes.ToArray())

    $fslogixEvents = @(@($raw.Events) | Where-Object { [string]$_.LogName -like 'Microsoft-FSLogix-*' -and $_.Message -and -not $_.Error })

    return [pscustomobject]@{
        HostReach = $reach; Service = $service; FslogixConfig = $config; Storage = $storage; Disk = $disk
        VhdLocations = $vhd; CcdLocations = $ccd; HostNotes = $hostNotes; FslogixEvents = $fslogixEvents
    }
}

# =============================================================================
# Ranker (pure: no I/O)
# =============================================================================

function New-TempProfileCause {
    param(
        [string]$Id, [string]$Title, [string]$State, [string[]]$Evidence = @(), [string]$NextStep = '',
        [string]$Summary = '', [string]$Reason = '', [string]$CheckName = ''
    )
    $rank = [array]::IndexOf($script:TempProfileCauseOrder, $Id) + 1
    return [pscustomobject]@{
        Id = $Id; Title = $Title; State = $State; Evidence = @($Evidence | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        NextStep = $NextStep; Rank = $rank; Summary = $Summary; Reason = $Reason; CheckName = $CheckName
    }
}

function Get-TempProfileVerdict {
    <#
    .SYNOPSIS
        Ranks the seven causes from the facts and picks the verdict. Pure: no I/O.
    .DESCRIPTION
        Every rule is evaluated (no short-circuit) and the result always has all seven causes.
        A fact that is missing never fires a rule; it counts as a check that could not run.
        Top cause: the highest-ranked Confirmed, else the highest-ranked Possible. With neither,
        NO CAUSE FOUND only when no check was blind, else CAN'T TELL.
    #>
    param([Parameter(Mandatory = $true)][object]$Facts)

    $user = [string](Get-TempProfileFactPart $Facts 'UserName')
    if (-not $user) { $user = 'the user' }
    $hostName = [string](Get-TempProfileFactPart $Facts 'ComputerName')
    if (-not $hostName) { $hostName = 'the server' }
    $notRun = 'this check did not run'
    $causes = New-Object System.Collections.Generic.List[object]
    $sessions = @(Get-TempProfileFactPart $Facts 'Sessions' | Where-Object { $_ })

    # --- 1. Profile disk held open by another computer ---
    $lockTitle = 'Profile disk held open by another computer'
    $lockCheck = 'the profile disk lock check'
    $lock = Get-TempProfileFactPart $Facts 'Lock'
    $lockHint = Get-TempProfileFactPart $Facts 'LockHint'
    $lockState = if ($lock) { [string]$lock.State } else { '' }
    if ($lockState -eq 'Held') {
        $holders = @($lock.Holders | Where-Object { $_ })
        if ($holders.Count -eq 0) { $holders = @($lock) }
        $hostShort = Get-TempProfileShortName $hostName
        $elsewhere = @($holders | Where-Object { -not $_.ClientResolved -or -not $_.ClientComputer -or ((Get-TempProfileShortName $_.ClientComputer) -ine $hostShort) })
        $h = if ($elsewhere.Count -gt 0) { $elsewhere[0] } else { $holders[0] }
        $holderName = if ($h.ClientResolved -and $h.ClientComputer) { [string]$h.ClientComputer } else { '{0} (name not found in DNS)' -f $h.ClientAddress }
        $server = [string]$h.FileServer
        if (-not $server) { $server = [string]$lock.FileServer }
        $ev = @("File server: $server", "File: $($h.FileName)")
        $ev += $(if ($h.ClientResolved -and $h.ClientComputer) { "Open from: $($h.ClientComputer) ($($h.ClientAddress))" } else { "Open from: $holderName" })
        foreach ($other in @($holders | Where-Object { $_ -ne $h })) { $ev += ('Also open from: {0} ({1})' -f $(if ($other.ClientComputer) { $other.ClientComputer } else { 'name not found in DNS' }), $other.ClientAddress) }
        $session = $null
        if ($h.ClientResolved -and $h.ClientComputer) {
            $session = @($sessions | Where-Object { (Get-TempProfileShortName $_.Machine) -ieq (Get-TempProfileShortName $h.ClientComputer) })[0]
        }
        if ($session) { $ev += ('Citrix session on {0}: {1}' -f (Get-TempProfileShortName $session.Machine), $session.State) }

        if ($elsewhere.Count -eq 0) {
            $causes.Add((New-TempProfileCause -Id 'lock-held' -Title $lockTitle -State 'Possible' -Evidence $ev -CheckName $lockCheck `
                        -Summary ("{0}'s profile disk is open from {1} itself, so an older session of {0} on {1} may still hold it." -f $user, $hostName) `
                        -NextStep ("Check Citrix Director or Studio (or Task Manager > Users on {1}) for a second session of {0} on {1}; log it off, then have {0} sign in again." -f $user, $hostName)))
        } elseif ($session -and [string]$session.State -eq 'Disconnected') {
            $causes.Add((New-TempProfileCause -Id 'lock-held' -Title $lockTitle -State 'Confirmed' -Evidence $ev -CheckName $lockCheck `
                        -Summary ("The Citrix session on {0} is disconnected and still holds {1}'s profile disk open on {2}, so FSLogix could not attach it on {3}." -f $holderName, $user, $server, $hostName) `
                        -NextStep ("Log off {0}'s disconnected session on {1} in Citrix Director or Studio, then have {0} sign out of {2} and sign in again." -f $user, $holderName, $hostName)))
        } elseif ($session) {
            $causes.Add((New-TempProfileCause -Id 'lock-held' -Title $lockTitle -State 'Confirmed' -Evidence $ev -CheckName $lockCheck `
                        -Summary ("{0} is also signed in on {1} ({2} Citrix session), and that session holds the profile disk open on {3}, so FSLogix could not attach it on {4}." -f $user, $holderName, ([string]$session.State).ToLowerInvariant(), $server, $hostName) `
                        -NextStep ("Ask {0} to sign out of {1} (or log that session off in Citrix Director or Studio), then sign out of {2} and sign in again." -f $user, $holderName, $hostName)))
        } elseif (-not ($h.ClientResolved -and $h.ClientComputer)) {
            $causes.Add((New-TempProfileCause -Id 'lock-held' -Title $lockTitle -State 'Confirmed' -Evidence $ev -CheckName $lockCheck `
                        -Summary ("{0}'s profile disk is held open on {1} by {2}, so FSLogix could not attach it on {3}." -f $user, $server, $holderName, $hostName) `
                        -NextStep ("Find the computer with address {0} (it is not in DNS), log off {1}'s session there, then have {1} sign in again." -f $h.ClientAddress, $user)))
        } else {
            $causes.Add((New-TempProfileCause -Id 'lock-held' -Title $lockTitle -State 'Confirmed' -Evidence $ev -CheckName $lockCheck `
                        -Summary ("{0}'s profile disk is held open on {1} by {2}, so FSLogix could not attach it on {3}." -f $user, $server, $holderName, $hostName) `
                        -NextStep ("Find {0}'s session on {1} (Citrix Director or Studio, or Task Manager > Users on {1}), log it off, then have {0} sign in again." -f $user, $holderName)))
        }
    } elseif ($lockState -eq 'NotHeld') {
        $causes.Add((New-TempProfileCause -Id 'lock-held' -Title $lockTitle -State 'RuledOut' -Evidence @([string]$lock.Detail) -CheckName $lockCheck))
    } else {
        $why = if ($lock -and $lock.Reason) { [string]$lock.Reason } else { $notRun }
        if ($lockHint) {
            $causes.Add((New-TempProfileCause -Id 'lock-held' -Title $lockTitle -State 'Possible' -CheckName $lockCheck -Reason $why `
                        -Evidence @(('FSLogix log at {0}: {1}' -f $lockHint.Time, $lockHint.Line), "The file server could not be checked: $why") `
                        -Summary ("{0}'s FSLogix log says the profile disk was locked (in use somewhere else), but the file server could not be checked to say where: {1}." -f $user, $why) `
                        -NextStep ("Look in Citrix Director or Studio for another session of {0} (often a disconnected one); log it off, then have {0} sign in again." -f $user)))
        } else {
            $causes.Add((New-TempProfileCause -Id 'lock-held' -Title $lockTitle -State 'CouldNotCheck' -Reason $why -CheckName $lockCheck))
        }
    }

    # --- 2. FSLogix service stopped or crashed ---
    $svcCheck = 'the FSLogix service check'
    $svc = Get-TempProfileFactPart $Facts 'Service'
    $crash = Get-TempProfileFactPart $Facts 'ServiceCrash'
    $svcState = if ($svc) { [string]$svc.State } else { '' }
    $crashState = if ($crash) { [string]$crash.State } else { '' }
    $crashLine = ''
    if ($crashState -eq 'Crashed') {
        $when = if ($crash.Time -is [datetime]) { $crash.Time.ToString('yyyy-MM-dd HH:mm:ss') } else { [string]$crash.Time }
        $crashLine = 'Service Control Manager event {0} at {1}: FSLogix Apps Services (frxsvc) terminated unexpectedly.' -f $crash.EventId, $when
    }
    if ($svcState -eq 'Stopped') {
        $causes.Add((New-TempProfileCause -Id 'frxsvc' -Title "FSLogix service stopped on $hostName" -State 'Confirmed' -Evidence @([string]$svc.Detail, $crashLine) -CheckName $svcCheck `
                    -Summary ("The FSLogix service is stopped on {0}, so no FSLogix profile can load there." -f $hostName) `
                    -NextStep ("Escalate: the FSLogix service is stopped on {0}. An engineer needs to start it and find out why it stopped." -f $hostName)))
    } elseif ($crashState -eq 'Crashed') {
        $causes.Add((New-TempProfileCause -Id 'frxsvc' -Title "FSLogix service crashed on $hostName" -State 'Confirmed' -Evidence @($crashLine, [string]$(if ($svc) { $svc.Detail })) -CheckName $svcCheck `
                    -Summary ("The FSLogix service crashed on {0} ({1}); a sign-in at that time gets a temporary profile." -f $hostName, $crashLine) `
                    -NextStep ("Escalate: FSLogix crashed on {0}. Attach this note; an engineer should check the FSLogix version against the FSLogix known issues." -f $hostName)))
    } elseif ($svcState -eq 'NotInstalled') {
        $causes.Add((New-TempProfileCause -Id 'frxsvc' -Title "FSLogix service not installed on $hostName" -State 'Confirmed' -Evidence @([string]$svc.Detail) -CheckName $svcCheck `
                    -Summary ("FSLogix is not installed on {0}, so profiles there are local Windows profiles." -f $hostName) `
                    -NextStep ("Confirm {0} is the server {1} signs in to. If it is, escalate: FSLogix is missing from it." -f $hostName, $user)))
    } elseif ($svcState -eq 'Running' -and $crashState -eq 'None') {
        $causes.Add((New-TempProfileCause -Id 'frxsvc' -Title "FSLogix service stopped or crashed on $hostName" -State 'RuledOut' -CheckName $svcCheck `
                    -Evidence @([string]$svc.Detail, 'No "terminated unexpectedly" event for it in the time looked at.')))
    } else {
        $reasons = @()
        if ($svcState -ne 'Running') { $reasons += $(if ($svc -and $svc.Reason) { [string]$svc.Reason } else { 'the service state was not read' }) }
        if ($crashState -ne 'None') { $reasons += $(if ($crash -and $crash.Reason) { [string]$crash.Reason } else { 'the service crash events were not read' }) }
        $causes.Add((New-TempProfileCause -Id 'frxsvc' -Title "FSLogix service stopped or crashed on $hostName" -State 'CouldNotCheck' -Reason ($reasons -join '; ') -CheckName $svcCheck))
    }

    # --- 3. FSLogix profiles off or not configured ---
    $cfgTitle = "FSLogix profiles are off or not configured on $hostName"
    $cfgCheck = 'the FSLogix settings check'
    $cfg = Get-TempProfileFactPart $Facts 'FslogixConfig'
    $cfgState = if ($cfg) { [string]$cfg.State } else { '' }
    if ($cfgState -eq 'Off' -or $cfgState -eq 'NotConfigured') {
        $causes.Add((New-TempProfileCause -Id 'fslogix-off' -Title $cfgTitle -State 'Confirmed' -Evidence @([string]$cfg.Detail) -CheckName $cfgCheck `
                    -Summary ("FSLogix profile containers are switched off or have no profile location on {0}, so every user there gets a local profile." -f $hostName) `
                    -NextStep ("Confirm {0} is the server {1} signs in to. If it is, escalate: the FSLogix settings (Group Policy or image) are not applied to it." -f $hostName, $user)))
    } elseif ($cfgState -eq 'On') {
        $causes.Add((New-TempProfileCause -Id 'fslogix-off' -Title $cfgTitle -State 'RuledOut' -Evidence @([string]$cfg.Detail) -CheckName $cfgCheck))
    } else {
        $causes.Add((New-TempProfileCause -Id 'fslogix-off' -Title $cfgTitle -State 'CouldNotCheck' -Reason $(if ($cfg -and $cfg.Reason) { [string]$cfg.Reason } else { $notRun }) -CheckName $cfgCheck))
    }

    # --- 4. No permission on the profile share ---
    $shareTitle = 'No permission on the profile share'
    $shareCheck = 'the profile share permission check'
    $share = Get-TempProfileFactPart $Facts 'ShareAccess'
    $shareState = if ($share) { [string]$share.State } else { '' }
    if ($shareState -eq 'Denied') {
        $causes.Add((New-TempProfileCause -Id 'share-denied' -Title $shareTitle -State 'Confirmed' -Evidence @(('FSLogix log at {0}: {1}' -f $share.Time, $share.Line)) -CheckName $shareCheck `
                    -Summary ("FSLogix was refused access to {0}'s profile location, so it could not attach the profile disk." -f $user) `
                    -NextStep ("Escalate: {0} was refused access to the profile share. An engineer should check the share and folder permissions for {0} (FSLogix SMB storage permissions)." -f $user)))
    } elseif ($shareState -eq 'NoDenial') {
        $causes.Add((New-TempProfileCause -Id 'share-denied' -Title $shareTitle -State 'RuledOut' -Evidence @("$user's FSLogix log shows no permission error on the profile location.") -CheckName $shareCheck))
    } else {
        $causes.Add((New-TempProfileCause -Id 'share-denied' -Title $shareTitle -State 'CouldNotCheck' -Reason $(if ($share -and $share.Reason) { [string]$share.Reason } else { $notRun }) -CheckName $shareCheck))
    }

    # --- 5. Profile storage unreachable ---
    $storage = Get-TempProfileFactPart $Facts 'Storage'
    $storageState = if ($storage) { [string]$storage.State } else { '' }
    $storageTitle = if ($storage -and [string]$storage.Kind -eq 'CloudCache') { 'Cloud Cache storage unreachable' } else { 'Profile share unreachable' }
    $storageCheck = 'the profile storage reachability check'
    $where = if ($storage -and [string]$storage.Kind -eq 'CloudCache') { 'Cloud Cache location' } else { 'profile location' }
    if ($storageState -eq 'AllUnreachable' -or $storageState -eq 'SomeUnreachable') {
        $list = @($storage.Unreachable)
        $ev = @(('{0} of {1} {2}(s) cannot be reached from {3} or from this PC: {4}' -f $list.Count, $storage.Total, $where, $hostName, ($list -join ', ')))
        if ($storageState -eq 'AllUnreachable') {
            $causes.Add((New-TempProfileCause -Id 'storage' -Title $storageTitle -State 'Confirmed' -Evidence $ev -CheckName $storageCheck `
                        -Summary ("{0} cannot reach any {1}, so FSLogix has nowhere to load {2}'s profile from." -f $hostName, $where, $user) `
                        -NextStep ("Escalate: the profile storage cannot be reached from {0}. Check the file server is up and reachable from {0}." -f $hostName)))
        } else {
            $causes.Add((New-TempProfileCause -Id 'storage' -Title $storageTitle -State 'Possible' -Evidence $ev -CheckName $storageCheck `
                        -Summary ("{0} cannot reach {1} of its {2} {3}s, which can stop the profile loading." -f $hostName, $list.Count, $storage.Total, $where) `
                        -NextStep ('Escalate: one or more profile storage locations cannot be reached from {0}. Check the file server(s) listed.' -f $hostName)))
        }
    } elseif ($storageState -eq 'Reachable') {
        $ev = @(('Every {0} ({1}) can be reached from {2}.' -f $where, $storage.Total, $hostName))
        $ev += @($storage.Notes | Where-Object { $_ })
        $causes.Add((New-TempProfileCause -Id 'storage' -Title $storageTitle -State 'RuledOut' -Evidence $ev -CheckName $storageCheck))
    } else {
        $causes.Add((New-TempProfileCause -Id 'storage' -Title $storageTitle -State 'CouldNotCheck' -Reason $(if ($storage -and $storage.Reason) { [string]$storage.Reason } else { $notRun }) -CheckName $storageCheck))
    }

    # --- 6. Existing local profile ---
    $localTitle = 'An existing local profile stopped FSLogix'
    $localCheck = 'the local profile check'
    $local = Get-TempProfileFactPart $Facts 'LocalProfile'
    $localState = if ($local) { [string]$local.State } else { '' }
    if ($localState -eq 'Found') {
        # D-017: deleting a local profile destroys data, so tier 1 escalates instead.
        $causes.Add((New-TempProfileCause -Id 'local-profile' -Title $localTitle -State 'Confirmed' -Evidence @(('FSLogix log at {0}: {1}' -f $local.Time, $local.Line)) -CheckName $localCheck `
                    -Summary ("{0} already has a local Windows profile on {1}, so FSLogix used it instead of the profile disk." -f $user, $hostName) `
                    -NextStep ("Escalate: {0} has an old local profile on {1} that stops FSLogix. Removing it deletes data on {1}, so it is an engineer's decision." -f $user, $hostName)))
    } elseif ($localState -eq 'None') {
        $causes.Add((New-TempProfileCause -Id 'local-profile' -Title $localTitle -State 'RuledOut' -Evidence @("$user's FSLogix log shows no 'local profile exists' reason.") -CheckName $localCheck))
    } else {
        $causes.Add((New-TempProfileCause -Id 'local-profile' -Title $localTitle -State 'CouldNotCheck' -Reason $(if ($local -and $local.Reason) { [string]$local.Reason } else { $notRun }) -CheckName $localCheck))
    }

    # --- 7. Server disk full ---
    $diskTitle = "The server's disk is full"
    $diskCheck = 'the server disk space check'
    $disk = Get-TempProfileFactPart $Facts 'Disk'
    $diskState = if ($disk) { [string]$disk.State } else { '' }
    if ($diskState -eq 'Fail') {
        $causes.Add((New-TempProfileCause -Id 'disk-full' -Title $diskTitle -State 'Confirmed' -Evidence @([string]$disk.Detail) -CheckName $diskCheck `
                    -Summary ("{0}'s disk is nearly full, which stops profiles loading." -f $hostName) `
                    -NextStep ("Escalate: {0}'s disk is nearly full ({1}). Drive-Storage-Report shows what is using the space." -f $hostName, $disk.Detail)))
    } elseif ($diskState -eq 'Warn') {
        $causes.Add((New-TempProfileCause -Id 'disk-full' -Title $diskTitle -State 'Possible' -Evidence @([string]$disk.Detail) -CheckName $diskCheck `
                    -Summary ("{0}'s disk is getting low ({1}), which can stop a profile loading." -f $hostName, $disk.Detail) `
                    -NextStep ("Mention the low disk space on {0} in the ticket so it can be cleaned up, and escalate if {1} still gets a temporary profile." -f $hostName, $user)))
    } elseif ($diskState -eq 'Pass') {
        $causes.Add((New-TempProfileCause -Id 'disk-full' -Title $diskTitle -State 'RuledOut' -Evidence @([string]$disk.Detail) -CheckName $diskCheck))
    } else {
        $causes.Add((New-TempProfileCause -Id 'disk-full' -Title $diskTitle -State 'CouldNotCheck' -Reason $(if ($disk -and $disk.Reason) { [string]$disk.Reason } else { $notRun }) -CheckName $diskCheck))
    }

    # --- Evidence that does not decide anything ---
    $evidence = New-Object System.Collections.Generic.List[string]
    $now = Get-TempProfileFactPart $Facts 'TempProfileNow'
    switch ([string]$(if ($now) { $now.State })) {
        'Temporary' { $evidence.Add("$user is on a temporary profile on $hostName right now.") }
        'LoadedNormal' { $evidence.Add("$user is signed in to $hostName with a normal (not temporary) profile right now.") }
        'NotSignedIn' { $evidence.Add("$user is not signed in to $hostName now.") }
        default { $evidence.Add(('Could not see whether {0} is signed in to {1} now: {2}' -f $user, $hostName, $(if ($now -and $now.Reason) { $now.Reason } else { $notRun }))) }
    }
    if ($now -and $now.PSObject.Properties['Corrupted'] -and $now.Corrupted) { $evidence.Add("Windows marks $user's profile on $hostName as corrupted.") }
    foreach ($s in $sessions) { $evidence.Add(('Citrix session on {0}: {1}' -f (Get-TempProfileShortName $s.Machine), $s.State)) }
    foreach ($u in @(Get-TempProfileFactPart $Facts 'UnknownCodes' | Where-Object { $_ })) {
        $kind = if ($u.PSObject.Properties['Kind'] -and $u.Kind) { [string]$u.Kind } else { 'reason' }
        $evidence.Add(('Unrecognized FSLogix {0} {1}: {2}' -f $kind, $u.Code, $u.Text))
    }
    foreach ($n in @(Get-TempProfileFactPart $Facts 'LogNotes' | Where-Object { $_ })) { $evidence.Add([string]$n) }
    foreach ($n in @(Get-TempProfileFactPart $Facts 'HostNotes' | Where-Object { $_ })) { $evidence.Add([string]$n) }

    # --- Verdict ---
    $all = @($causes.ToArray() | Sort-Object Rank)
    $confirmed = @($all | Where-Object { $_.State -eq 'Confirmed' })
    $possible = @($all | Where-Object { $_.State -eq 'Possible' })
    $blind = @($all | Where-Object { $_.State -eq 'CouldNotCheck' })
    $top = $null
    if ($confirmed.Count -gt 0) {
        $top = $confirmed[0]; $verdict = 'CAUSE FOUND'; $status = 'Fail'
        $summary = $top.Summary; $next = $top.NextStep
    } elseif ($possible.Count -gt 0) {
        $top = $possible[0]; $verdict = 'POSSIBLE CAUSE'; $status = 'Warn'
        $summary = $top.Summary; $next = $top.NextStep
    } elseif ($blind.Count -gt 0) {
        $verdict = "CAN'T TELL"; $status = 'Warn'
        $reach = Get-TempProfileFactPart $Facts 'HostReach'
        if ($reach -and [string]$reach.State -eq 'Unreachable') {
            $summary = '{0} could not be reached: {1}' -f $hostName, $reach.Reason
            $next = 'Check that {0} is switched on and that the name is right, then run this again as an administrator of {0} (it needs ping, WinRM and Remote Registry).' -f $hostName
        } else {
            $summary = 'No cause was found, but {0} check(s) could not run, so this is not an all-clear.' -f $blind.Count
            $more = if ($blind.Count -gt 1) { ' (and {0} other check(s), listed under "Could not check")' -f ($blind.Count - 1) } else { '' }
            $next = 'Fix what blocked {0} ({1}){2}, then run this again.' -f $blind[0].CheckName, $blind[0].Reason, $more
        }
    } else {
        $verdict = 'NO CAUSE FOUND'; $status = 'Pass'
        $summary = 'Every check ran and none found a reason for a temporary profile on {0}.' -f $hostName
        $next = 'Escalate with the ticket note attached: every check came back clean, so this needs an engineer.'
    }
    $others = @(@($confirmed + $possible) | Where-Object { $_ -ne $top })

    return [pscustomobject]@{
        Verdict = $verdict; Status = $status; Summary = $summary; NextStep = $next
        TopCause = $top; Causes = $all; OtherCauses = $others; Evidence = $evidence.ToArray()
    }
}

function Get-TempProfileExitCode {
    # Same numbers as the triage: 2 = cause found, 1 = possible / can't tell, 0 = nothing found.
    param([Parameter(Mandatory = $true)][string]$Verdict)
    switch ($Verdict) {
        'CAUSE FOUND' { return 2 }
        'NO CAUSE FOUND' { return 0 }
        default { return 1 }
    }
}

# =============================================================================
# Output
# =============================================================================

function Get-TempProfileHeadline {
    param([Parameter(Mandatory = $true)][object]$Result)
    return ('Temporary profile check for {0} on {1}:  {2}' -f $Result.UserName, $Result.ComputerName, $Result.Verdict)
}

function ConvertTo-TempProfileText {
    <#
    .SYNOPSIS
        The console report as lines: verdict, cause sentence and next step first, then the
        other causes, what was ruled out, what could not be checked, and the evidence.
    #>
    param([Parameter(Mandatory = $true)][object]$Result)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add((Get-TempProfileHeadline -Result $Result))
    $lines.Add(('=' * 70))
    $lines.Add([string]$Result.Summary)
    $lines.Add('Next step: ' + $Result.NextStep)

    $causes = @($Result.Causes)
    $top = @($causes | Where-Object { $_.State -eq 'Confirmed' -or $_.State -eq 'Possible' } | Sort-Object @{ Expression = { if ($_.State -eq 'Confirmed') { 0 } else { 1 } } }, Rank)
    if ($top.Count -gt 0 -and @($top[0].Evidence).Count -gt 0) {
        $lines.Add('')
        $lines.Add('Why:')
        foreach ($e in @($top[0].Evidence)) { $lines.Add("  - $e") }
    }
    $others = @($top | Select-Object -Skip 1)
    if ($others.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Other possible causes:')
        foreach ($c in $others) {
            $lines.Add(('  [{0}] {1}' -f $c.State.ToUpperInvariant(), $c.Title))
            foreach ($e in @($c.Evidence)) { $lines.Add("      $e") }
            if ($c.NextStep) { $lines.Add("      What to do: $($c.NextStep)") }
        }
    }
    $ruled = @($causes | Where-Object { $_.State -eq 'RuledOut' })
    if ($ruled.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Ruled out:')
        foreach ($c in $ruled) { $lines.Add(('  - {0}: {1}' -f $c.Title, (@($c.Evidence) -join ' '))) }
    }
    $blind = @($causes | Where-Object { $_.State -eq 'CouldNotCheck' })
    if ($blind.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Could not check:')
        foreach ($c in $blind) { $lines.Add(('  - {0}: {1}' -f $c.Title, $c.Reason)) }
    }
    $evidence = @($Result.Evidence | Where-Object { $_ })
    if ($evidence.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Evidence:')
        foreach ($e in $evidence) { $lines.Add("  - $e") }
    }
    $lines.Add('')
    $lines.Add(('Checked: {0}   Logs and events looked back: {1} hour(s)' -f $Result.StartedAt, $Result.EventLookbackHours))
    return $lines.ToArray()
}

function Write-TempProfileConsole {
    param([Parameter(Mandatory = $true)][object]$Result)
    $headColor = switch ($Result.Verdict) { 'CAUSE FOUND' { 'Red' } 'NO CAUSE FOUND' { 'Green' } default { 'Yellow' } }
    $section = ''
    foreach ($line in @(ConvertTo-TempProfileText -Result $Result)) {
        $color = 'Gray'
        if ($line -like 'Temporary profile check for *') { $color = $headColor }
        elseif ($line -like 'Next step: *') { $color = 'White' }
        elseif ($line -match '^(Why|Other possible causes|Ruled out|Could not check|Evidence):$') { $color = 'White'; $section = $line }
        elseif ($line -match '^[=-]+$') { $color = 'DarkGray' }
        elseif ($line -match '^  \[CONFIRMED\]') { $color = 'Red' }
        elseif ($line -match '^  \[POSSIBLE\]') { $color = 'Yellow' }
        elseif ($line -match '^  - ' -and $section -eq 'Ruled out:') { $color = 'Green' }
        elseif ($line -match '^  - ' -and $section -eq 'Could not check:') { $color = 'Yellow' }
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ''
}

function Export-TempProfileReport {
    # TempProfile_<user>_<host>_<yyyy-MM-dd_HHmmss>.txt (the console report) and .csv (one row
    # per cause), the same pattern as the triage's Export-TriageReport.
    param([Parameter(Mandatory = $true)][object]$Result, [Parameter(Mandatory = $true)][string]$OutputPath)
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
    }
    $safe = { param([string]$s) $s -replace '[^A-Za-z0-9._-]', '_' }
    $stem = Join-Path $OutputPath ('TempProfile_{0}_{1}_{2}' -f (& $safe $Result.UserName), (& $safe $Result.ComputerName), (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    $textPath = "$stem.txt"
    $csvPath = "$stem.csv"
    ConvertTo-TempProfileText -Result $Result | Set-Content -LiteralPath $textPath -Encoding UTF8
    @($Result.Causes) | Select-Object Rank, Id, Title, State,
    @{ Name = 'Evidence'; Expression = { (@($_.Evidence) -join ' | ') } },
    @{ Name = 'CouldNotCheckReason'; Expression = { $_.Reason } }, NextStep |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    return @($textPath, $csvPath)
}

function Protect-TempProfileNoteText {
    # Paste-safe for this tool's own data, before CaseKit removes share paths and IP addresses:
    # profile disk files and paths (VHD/VHDX), user profile folders named after a SID, and
    # local paths such as C:\Users\TEMP.
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return [string]$Text }
    $t = [regex]::Replace($Text, '[^\s"''()<>|,;]*\.vhdx?\b', '[disk file removed]', 'IgnoreCase')
    $t = [regex]::Replace($t, '[^\s"''()<>|,;]*S-1-5-[0-9-]+_[^\s"''()<>|,;]*|[^\s"''()<>|,;\\]+_S-1-5-[0-9-]+[^\s"''()<>|,;]*', '[profile folder removed]')
    $t = [regex]::Replace($t, '(?<![\w\\])[A-Za-z]:\\[^\s"''()<>|,;]*', '[path removed]')
    return $t
}

function ConvertTo-TempProfileTicketNote {
    <#
    .SYNOPSIS
        Maps a result to the CaseKit ticket note. The gate decisions for this tool live here.
    .DESCRIPTION
        Confirmed cause -> PROBLEM, Possible -> WARNING, evidence -> INFO, Ruled out -> Clear
        with -CouldLook $true (the rule only rules out when its check ran), Could not check ->
        NotChecked. The Next step is the console's next step first. Unless -FullDetail, profile
        disk names, SID folders and local paths are removed here and CaseKit removes share
        paths and IP addresses when the note is written.
    #>
    param([Parameter(Mandatory = $true)][object]$Result, [string[]]$EvidencePaths = @(), [switch]$FullDetail)
    $clean = { param([string]$s) if ($FullDetail) { $s } else { Protect-TempProfileNoteText -Text $s } }
    $items = New-Object System.Collections.Generic.List[object]
    $causes = @($Result.Causes)
    $ranked = @($causes | Where-Object { $_.State -eq 'Confirmed' -or $_.State -eq 'Possible' } | Sort-Object @{ Expression = { if ($_.State -eq 'Confirmed') { 0 } else { 1 } } }, Rank)
    $first = $true
    foreach ($c in $ranked) {
        $kind = if ($c.State -eq 'Confirmed') { 'Problem' } else { 'Warning' }
        $text = if ($first -and $c.Summary) { $c.Summary } else { '{0}: {1}' -f $c.Title, (@($c.Evidence) -join ' ') }
        $items.Add((New-TicketNoteItem -Kind $kind -Text (& $clean $text)))
        $first = $false
    }
    foreach ($c in @($causes | Where-Object { $_.State -eq 'RuledOut' })) {
        $items.Add((New-TicketNoteItem -Kind Clear -Text (& $clean ('{0}: {1}' -f $c.Title, (@($c.Evidence) -join ' '))) -CouldLook $true))
    }
    foreach ($c in @($causes | Where-Object { $_.State -eq 'CouldNotCheck' })) {
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text (& $clean ('{0}: {1}' -f $c.Title, $c.Reason))))
    }
    if (@($causes).Count -eq 0 -and $Result.Summary) { $items.Add((New-TicketNoteItem -Kind NotChecked -Text (& $clean $Result.Summary))) }
    foreach ($e in @($Result.Evidence | Where-Object { $_ })) { $items.Add((New-TicketNoteItem -Kind Info -Text (& $clean $e))) }

    $next = New-Object System.Collections.Generic.List[string]
    $next.Add((& $clean $Result.NextStep))
    foreach ($c in @($ranked | Select-Object -Skip 1)) { if ($c.NextStep) { $next.Add((& $clean $c.NextStep)) } }

    $scope = 'User {0} on session host {1}; FSLogix log and events from the last {2} hour(s).' -f $Result.UserName, $Result.ComputerName, $Result.EventLookbackHours
    if ($Result.DeliveryController) { $scope += " Citrix sessions from $($Result.DeliveryController)." }
    $stampArgs = @{ ScopeLabel = 'Computer'; Scope = [string]$Result.ComputerName }
    if ($Result.StartedAtTime -is [datetime]) { $stampArgs['Now'] = $Result.StartedAtTime }
    $stamp = New-TicketNoteStamp @stampArgs
    $headline = 'Temporary profile check for {0} on {1}: {2}' -f $Result.UserName, $Result.ComputerName, $Result.Verdict
    return New-TicketNote -Tool 'TempProfileInvestigation' -Headline $headline -ScopeLine $scope -Items $items.ToArray() `
        -NextSteps $next.ToArray() -Stamp $stamp -EvidencePaths $EvidencePaths
}

# =============================================================================
# The investigation
# =============================================================================

function New-TempProfileResult {
    param(
        [Parameter(Mandatory = $true)][object]$Verdict, [string]$UserName, [string]$ComputerName, [string]$DeliveryController,
        [int]$EventLookbackHours, [datetime]$StartedAt, [object]$RawOutput, [string[]]$Errors = @()
    )
    $steps = New-Object System.Collections.Generic.List[string]
    $steps.Add([string]$Verdict.NextStep)
    foreach ($c in @($Verdict.OtherCauses)) { if ($c.NextStep -and -not $steps.Contains($c.NextStep)) { $steps.Add($c.NextStep) } }
    return [pscustomobject]@{
        CheckId              = 'fslogix.tempprofile'
        Name                 = 'Temporary profile investigation'
        Status               = $Verdict.Status
        Verdict              = $Verdict.Verdict
        Summary              = $Verdict.Summary
        NextStep             = $Verdict.NextStep
        Causes               = @($Verdict.Causes)
        Evidence             = @($Verdict.Evidence)
        RecommendedNextSteps = $steps.ToArray()
        RawOutput            = $RawOutput
        UserName             = $UserName
        ComputerName         = $ComputerName
        DeliveryController   = $DeliveryController
        EventLookbackHours   = $EventLookbackHours
        StartedAt            = $StartedAt.ToString('yyyy-MM-dd HH:mm:ss')
        StartedAtTime        = $StartedAt
        FinishedAt           = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Error                = (@($Errors | Where-Object { $_ }) -join '; ')
        ExitCode             = (Get-TempProfileExitCode -Verdict $Verdict.Verdict)
        TicketNote           = $null
    }
}

function New-TempProfileStartFailure {
    # A result for a check that could not start (no Citrix session, no Broker snap-in, unknown
    # user): CAN'T TELL with every cause under "Could not check", exit code 1.
    param([Parameter(Mandatory = $true)][string]$Message, [string]$UserName, [string]$ComputerName, [string]$DeliveryController, [int]$EventLookbackHours, [datetime]$StartedAt, [string]$NextStep)
    $display = if ($ComputerName) { $ComputerName } else { 'the server' }
    $v = Get-TempProfileVerdict -Facts ([pscustomobject]@{ UserName = $UserName; ComputerName = $display })
    foreach ($c in @($v.Causes)) { $c.Reason = 'the check did not start' }
    $v.Summary = $Message
    $v.NextStep = $NextStep
    $v.Evidence = @()
    return (New-TempProfileResult -Verdict $v -UserName $UserName -ComputerName $display -DeliveryController $DeliveryController `
            -EventLookbackHours $EventLookbackHours -StartedAt $StartedAt -Errors @($Message))
}

function Invoke-TempProfileInvestigation {
    <#
    .SYNOPSIS
        Runs the whole investigation and returns the result object (always), carrying ExitCode
        and TicketNote. Console output unless -Quiet; files with -OutputPath / -TicketNumber.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [string]$ComputerName,
        [string]$DeliveryController,
        [int]$EventLookbackHours = 24,
        [string]$OutputPath,
        [string]$TicketNumber,
        [switch]$NoClipboard,
        [switch]$FullDetail,
        [switch]$Quiet
    )
    $started = Get-Date
    $UserName = $UserName.Trim()
    # Bare names take this PC's domain (spec SQ-003): it is how techs type names, and the SID
    # lookup below fails loudly when it is wrong.
    $qualified = if ($UserName -match '[\\@]') { $UserName } else { '{0}\{1}' -f $(if ($env:USERDOMAIN) { $env:USERDOMAIN } else { $env:COMPUTERNAME }), $UserName }
    $sam = (($qualified -split '\\')[-1] -split '@')[0]
    $errors = New-Object System.Collections.Generic.List[string]
    $common = @{ UserName = $sam; DeliveryController = $DeliveryController; EventLookbackHours = $EventLookbackHours; StartedAt = $started }
    $result = $null

    # --- The user's SID ---
    $sid = $null
    try {
        $sid = Get-TempProfileUserSid -UserName $qualified
    } catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        if ($inner -is [System.Security.Principal.IdentityNotMappedException]) {
            $msg = "No account named $qualified was found. Check the spelling (jdoe or CONTOSO\jdoe) and run this again."
            if (-not $Quiet) { Write-TempProfileStatus $msg 'FAIL' }
            $result = New-TempProfileStartFailure -Message $msg -ComputerName $ComputerName -NextStep 'Check the user name and run this again.' @common
        } else {
            $errors.Add("SID lookup: $($inner.Message)")
        }
    }

    # --- Citrix: the user's sessions, and the host when none was given ---
    $sessions = @()
    $target = $ComputerName
    $chosenMachine = $null
    if (-not $result -and $DeliveryController) {
        if (-not (Import-CitrixBrokerSdk)) {
            $msg = 'The Citrix Broker snap-in (Citrix.Broker.Admin.V2) is not on this PC. Run this on a Delivery Controller or a PC with Citrix Studio, or use -ComputerName instead.'
            if (-not $Quiet) { Write-TempProfileStatus $msg 'FAIL' }
            $result = New-TempProfileStartFailure -Message $msg -ComputerName $ComputerName -NextStep 'Run this on a Delivery Controller or a PC with Citrix Studio, or use -ComputerName instead.' @common
        } else {
            $brokerUser = if ($qualified -match '\\') { $qualified } else { $UserName }
            try {
                # -MaxRecordCount is always passed: without it Broker cmdlets stop at 250 records
                # with only a warning (see Get-CitrixFSLogixHealth.ps1).
                $found = @(Get-BrokerSession -AdminAddress $DeliveryController -UserName $brokerUser -MaxRecordCount 100 -ErrorAction Stop)
                $sessions = @($found | ForEach-Object {
                        $machine = if ($_.MachineName) { Get-TempProfileShortName ([string]$_.MachineName) } elseif ($_.DNSName) { Get-TempProfileShortName ([string]$_.DNSName) } else { [string]$_.HostedMachineName }
                        [pscustomobject]@{ Machine = $machine; State = [string]$_.SessionState; DNSName = [string]$_.DNSName; HostedMachineName = [string]$_.HostedMachineName }
                    })
            } catch {
                $msg = "Could not ask $DeliveryController for ${sam}'s Citrix sessions: $($_.Exception.Message)"
                if (-not $Quiet) { Write-TempProfileStatus $msg 'FAIL' }
                $result = New-TempProfileStartFailure -Message $msg -ComputerName $ComputerName -NextStep "Check the Delivery Controller name and your Citrix admin rights, or use -ComputerName <the server $sam last used>." @common
            }
            if (-not $result -and -not $target) {
                if ($sessions.Count -eq 0) {
                    $msg = "$sam has no Citrix session the Delivery Controller knows about. Run again with -ComputerName <the server $sam last used>."
                    if (-not $Quiet) { Write-TempProfileStatus $msg 'WARN' }
                    $result = New-TempProfileStartFailure -Message $msg -NextStep "Run again with -ComputerName <the server $sam last used>." @common
                } else {
                    # The session the user is in now (the one with the temporary profile) is the
                    # Active one; Connected next; else the first listed.
                    $pick = @($sessions | Where-Object { $_.State -eq 'Active' }) + @($sessions | Where-Object { $_.State -eq 'Connected' }) + @($sessions)
                    $chosen = $pick[0]
                    # DNSName is the connection target; HostedMachineName is the hypervisor's
                    # name and need not match DNS (Citrix SDK, Get-BrokerSession).
                    $target = if ($chosen.DNSName) { $chosen.DNSName } else { $chosen.Machine }
                    $chosenMachine = $chosen.Machine
                }
            }
        }
    }

    if (-not $result) {
        $display = if ($chosenMachine) { $chosenMachine } else { Get-TempProfileShortName $target }
        if (-not $display) { $display = $target }
        $progress = { param([string]$Step) if (-not $Quiet) { Write-Progress -Activity "Temporary profile check for $sam on $display" -Status $Step } }

        # --- Host evidence from the triage in this folder ---
        $triage = $null
        $triageError = ''
        if (Get-Command -Name Invoke-CitrixFSLogixTriage -ErrorAction SilentlyContinue) {
            & $progress 'FSLogix services, settings, events and disk space on the server'
            try {
                $triage = Invoke-CitrixFSLogixTriage -ComputerName $target -UserName $sam -EventLookbackHours $EventLookbackHours
            } catch {
                $triageError = $_.Exception.Message
                $errors.Add("Host checks: $triageError")
            }
        } else {
            $triageError = 'Invoke-CitrixFSLogixTriage.ps1 is missing from this folder'
            $errors.Add($triageError)
        }
        $hostFacts = ConvertFrom-TempProfileTriage -Triage $triage -ComputerName $display -TriageError $triageError
        $reached = ([string]$hostFacts.HostReach.State -eq 'Reached')
        $unreachableWhy = "$display could not be reached"

        # --- Who holds the profile disk ---
        if (@($hostFacts.VhdLocations).Count + @($hostFacts.CcdLocations).Count -gt 0) {
            & $progress 'Who has the profile disk open on the file server'
            try {
                $lock = Get-TempProfileLockFact -UserName $qualified -Sid $sid -VhdLocations @($hostFacts.VhdLocations) -CcdLocations @($hostFacts.CcdLocations)
            } catch {
                $errors.Add("Lock check: $($_.Exception.Message)")
                $lock = New-TempProfileFact -State 'CouldNotCheck' -Reason "the lock check failed: $($_.Exception.Message)" -More @{ FileServer = ''; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true; Detail = '' }
            }
        } else {
            $why = if ($reached) { "no profile location is set on $display, so there is no file server to ask" } else { "the profile location could not be read from $display" }
            $lock = New-TempProfileFact -State 'CouldNotCheck' -Reason $why -More @{ FileServer = ''; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true; Detail = '' }
        }

        # --- The user's FSLogix log, service crashes, and whether they are on a temp profile now ---
        $log = $null
        $crash = $null
        $now = $null
        if ($reached) {
            & $progress "$sam's FSLogix profile log, service crashes and signed-in profile"
            try { $log =Get-TempProfileLogFact -ComputerName $target -UserName $qualified -Sid $sid -EventLookbackHours $EventLookbackHours }
            catch { $errors.Add("FSLogix log: $($_.Exception.Message)"); $log = $null; $logWhy = "could not read the FSLogix profile log on ${display}: $($_.Exception.Message)" }
            try { $crash = Get-TempProfileCrashFact -ComputerName $target -EventLookbackHours $EventLookbackHours }
            catch { $crash = New-TempProfileFact -State 'CouldNotCheck' -Reason "could not read the System log on ${display}: $($_.Exception.Message)" -More @{ Time = ''; EventId = 0 } }
            if ($sid) {
                try { $now = Get-TempProfileLoadedProfileFact -ComputerName $target -Sid $sid }
                catch { $now = New-TempProfileFact -State 'CouldNotCheck' -Reason "could not read the user profiles on ${display}: $($_.Exception.Message)" }
            } else {
                $now = New-TempProfileFact -State 'CouldNotCheck' -Reason "the SID of $qualified could not be looked up"
            }
        } else {
            $logWhy = $unreachableWhy
            $crash = New-TempProfileFact -State 'CouldNotCheck' -Reason $unreachableWhy -More @{ Time = ''; EventId = 0 }
            $now = New-TempProfileFact -State 'CouldNotCheck' -Reason $unreachableWhy
        }
        if ($null -eq $log) {
            $log = [pscustomobject]@{
                LocalProfile = (New-TempProfileFact -State 'CouldNotCheck' -Reason $logWhy -More @{ Line = ''; Time = ''; Code = '' })
                ShareAccess  = (New-TempProfileFact -State 'CouldNotCheck' -Reason $logWhy -More @{ Line = ''; Time = '' })
                UnknownCodes = @(); LockHint = $null; Notes = @()
            }
        }

        # An FSLogix event saying access was denied for this user counts like the log line.
        $shareAccess = $log.ShareAccess
        if ([string]$shareAccess.State -ne 'Denied') {
            $deniedEvent = @(@($hostFacts.FslogixEvents) | Where-Object { [string]$_.Message -match '(?i)access is denied' -and [string]$_.Message -match ('(?i)\b{0}\b' -f [regex]::Escape($sam)) -and [string]$_.Message -notmatch '(?i)file is locked' })
            if ($deniedEvent.Count -gt 0) {
                $shareAccess = New-TempProfileFact -State 'Denied' -More @{ Line = ('FSLogix event {0}: {1}' -f $deniedEvent[0].Id, $deniedEvent[0].Message); Time = [string]$deniedEvent[0].TimeCreated }
            }
        }

        $facts = [pscustomobject]@{
            UserName       = $sam
            ComputerName   = $display
            HostReach      = $hostFacts.HostReach
            Lock           = $lock
            LockHint       = $log.LockHint
            Service        = $hostFacts.Service
            ServiceCrash   = $crash
            FslogixConfig  = $hostFacts.FslogixConfig
            ShareAccess    = $shareAccess
            Storage        = $hostFacts.Storage
            LocalProfile   = $log.LocalProfile
            Disk           = $hostFacts.Disk
            UnknownCodes   = @($log.UnknownCodes)
            TempProfileNow = $now
            Sessions       = @($sessions)
            LogNotes       = @($log.Notes)
            HostNotes      = @($hostFacts.HostNotes)
        }
        if (-not $Quiet) { Write-Progress -Activity "Temporary profile check for $sam on $display" -Completed }
        $verdict = Get-TempProfileVerdict -Facts $facts
        $raw = [pscustomobject]@{ Facts = $facts; Sid = $sid; Target = $target; Triage = $(if ($triage) { $triage.RawOutput } else { $null }) }
        $result = New-TempProfileResult -Verdict $verdict -ComputerName $display -RawOutput $raw -Errors $errors.ToArray() @common
        if (-not $Quiet) { Write-TempProfileConsole -Result $result }
    }

    # --- Files: with -TicketNumber, <OutputPath or the default root>\Ticket_<n>; with only
    # -OutputPath, that folder; with neither, no files (the note goes to the clipboard). ---
    $caseKit = [bool](Get-Command -Name New-TicketNote -ErrorAction SilentlyContinue)
    $folder = $OutputPath
    if ($TicketNumber -and $caseKit) {
        $root = if ($OutputPath) { $OutputPath } else { Get-TicketNoteDefaultRoot }
        try {
            $folder = Resolve-TicketFolder -TicketNumber $TicketNumber -Root $root
        } catch {
            if (-not $Quiet) { Write-TempProfileStatus "Could not create the ticket folder under ${root}: $($_.Exception.Message)" 'WARN' }
        }
    }
    $evidencePaths = @()
    if ($folder) {
        try {
            $evidencePaths = @(Export-TempProfileReport -Result $result -OutputPath $folder)
            if (-not $Quiet) { foreach ($f in $evidencePaths) { Write-TempProfileStatus "Saved $f" 'INFO' } }
        } catch {
            if (-not $Quiet) { Write-TempProfileStatus "Could not write the report to ${folder}: $($_.Exception.Message)" 'WARN' }
        }
    }

    # --- The ticket note is extra: a failure here never changes the answer or the exit code ---
    $note = $null
    if (-not $caseKit) {
        if (-not $Quiet) { Write-TempProfileStatus 'CaseKit.ps1 is missing from this folder - no ticket note this time.' 'WARN' }
    } else {
        try {
            $note = ConvertTo-TempProfileTicketNote -Result $result -EvidencePaths $evidencePaths -FullDetail:$FullDetail
            if ($Quiet) {
                # Another script is the caller: no console and no clipboard. The note is still
                # saved when a folder is in play, and it is always on the result object.
                if ($folder) { $null = Save-TicketNote -Note $note -Folder $folder -PasteSafe:(-not $FullDetail) }
            } else {
                Write-Host ''
                $null = Publish-TicketNote -Note $note -Folder $folder -PasteSafe:(-not $FullDetail) -NoClipboard:$NoClipboard
            }
        } catch {
            if (-not $Quiet) { Write-TempProfileStatus "Could not make the ticket note: $($_.Exception.Message). The check above is still valid." 'WARN' }
            $note = $null
        }
    }
    $result.TicketNote = $note
    return $result
}

# =============================================================================
# Companions: the host checks and the ticket-note kit, both beside this script
# =============================================================================

# Dot-sourcing the triage runs its param block in THIS scope, which resets the parameters the
# two scripts share (UserName, ComputerName, EventLookbackHours, OutputPath, PassThru, Quiet,
# LoadFunctionsOnly) to the triage's defaults. Keep ours and put them back.
$triagePath = Join-Path $PSScriptRoot 'Invoke-CitrixFSLogixTriage.ps1'
if (Test-Path -LiteralPath $triagePath) {
    $ownParameters = @{
        UserName = $UserName; ComputerName = $ComputerName; EventLookbackHours = $EventLookbackHours
        OutputPath = $OutputPath; PassThru = $PassThru; Quiet = $Quiet; LoadFunctionsOnly = $LoadFunctionsOnly
    }
    . $triagePath -LoadFunctionsOnly
    $UserName = $ownParameters.UserName
    $ComputerName = $ownParameters.ComputerName
    $EventLookbackHours = $ownParameters.EventLookbackHours
    $OutputPath = $ownParameters.OutputPath
    $PassThru = $ownParameters.PassThru
    $Quiet = $ownParameters.Quiet
    $LoadFunctionsOnly = $ownParameters.LoadFunctionsOnly
} else {
    $script:TriageMissing = $true
}

# The ticket-note kit (a copy of TicketNote\CaseKit.ps1). Without it the check still runs.
$kit = Join-Path $PSScriptRoot 'CaseKit.ps1'
if (Test-Path -LiteralPath $kit) { . $kit } else { $script:CaseKitMissing = $true }

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

if ($script:TriageMissing) {
    $msg = "Invoke-CitrixFSLogixTriage.ps1 is missing from $PSScriptRoot. Copy the whole Citrix-FSLogix-Triage folder and run this again."
    if (-not $Quiet) { Write-TempProfileStatus $msg 'FAIL' }
    exit 1
}
if ($TicketNumber -and $script:CaseKitMissing) {
    if (-not $Quiet) { Write-TempProfileStatus "CaseKit.ps1 is missing from this folder, so -TicketNumber $TicketNumber was ignored: the reports go to -OutputPath (if given) and there is no ticket note this time." 'WARN' }
    $TicketNumber = ''
}
if ($TicketNumber -and -not (Test-TicketNumber -TicketNumber $TicketNumber)) {
    $msg = "'$TicketNumber' is not a usable ticket number. Use letters, digits, - or _ (up to 32 characters, starting with a letter or digit), for example 482113."
    if (-not $Quiet) { Write-TempProfileStatus $msg 'FAIL' }
    if ($PassThru) {
        return (New-TempProfileStartFailure -Message $msg -UserName $UserName -ComputerName $ComputerName -DeliveryController $DeliveryController `
                -EventLookbackHours $EventLookbackHours -StartedAt (Get-Date) -NextStep 'Run it again with a ticket number such as 482113.')
    }
    exit 1
}

$investigation = @{
    UserName = $UserName; EventLookbackHours = $EventLookbackHours; OutputPath = $OutputPath; TicketNumber = $TicketNumber
    NoClipboard = $NoClipboard; FullDetail = $FullDetail; Quiet = $Quiet
}
if ($ComputerName) { $investigation.ComputerName = $ComputerName }
if ($DeliveryController) { $investigation.DeliveryController = $DeliveryController }
$r = Invoke-TempProfileInvestigation @investigation

if ($PassThru) { return $r }
exit $r.ExitCode
