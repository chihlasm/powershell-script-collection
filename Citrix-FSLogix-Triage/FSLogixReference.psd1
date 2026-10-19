# FSLogix status, reason and error codes used by Invoke-TempProfileInvestigation.ps1.
#
# This file is the single source of truth. The script carries an identical built-in copy
# ($script:FSLogixReferenceFallback) so it still runs when copied to a server on its own;
# Tests\Invoke-TempProfileInvestigation.Tests.ps1 (AC30) fails the moment the two differ.
#
# StatusCodes / ReasonCodes: "FSLogix Codes and what they mean". Status 1-28 are errors,
# 0 and 100 / 200 / 300 are normal. Reason codes only qualify normal Status codes.
#   https://learn.microsoft.com/fslogix/troubleshooting-error-codes
# ErrorCodes: the [ERROR:xxxxxxxx] / [WARN:xxxxxxxx] codes in the profile log "come from
# Windows" and "correspond to System Error Codes" (same page). Only the codes this tool acts
# on or explains are listed; the texts are the System Error Codes descriptions.
#   https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
#   https://learn.microsoft.com/windows/win32/debug/system-error-codes--1300-1699-
#
# Meaning is this tool's own label for a code. The rules read it: ReasonCodes Meaning
# 'LocalProfileExists' confirms "an existing local profile stopped FSLogix"; ErrorCodes
# Meaning 'AccessDenied' / 'LogonFailure' confirm "no permission on the profile share" and
# 'FileInUse' is evidence that the profile disk is open somewhere else.
@{
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
